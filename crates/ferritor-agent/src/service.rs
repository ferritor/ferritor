//! `run` under the Windows service control manager. The same command line
//! either way: a service created with `sc.exe create` or `New-Service` on
//! `ferritor-agent.exe run --config …` finds the manager here and reports to
//! it (it would otherwise kill a service that never answers); started from a
//! console, there's no manager and `run` goes on as a console program.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

/// `StartServiceCtrlDispatcherW`'s answer in a process the service control
/// manager didn't start.
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

/// A service of its own process: the manager ignores the name, given to
/// it and to the control handler alike, so any service name works.
const NAME: &str = "ferritor-agent";

/// The dispatcher calls `service_main` with the arguments the service was
/// started with, not the command line, so the config travels here.
static CONFIG: OnceLock<PathBuf> = OnceLock::new();
static EXIT: OnceLock<ExitCode> = OnceLock::new();

/// Runs the agent as a service if the service control manager started this
/// process, returning once the service has stopped; `None` if it didn't
/// (a console, a scheduled task), for `run` to go on as usual.
pub fn run_if_service(config: &Path) -> Option<ExitCode> {
    if CONFIG.set(config.to_path_buf()).is_err() {
        return Some(ExitCode::FAILURE);
    }
    match service_dispatcher::start(NAME, ffi_service_main) {
        Ok(()) => Some(EXIT.get().copied().unwrap_or(ExitCode::FAILURE)),
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) =>
        {
            None
        }
        Err(e) => {
            tracing::error!(error = %crate::error_chain(&e), "connecting to the service control manager");
            Some(ExitCode::FAILURE)
        }
    }
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<std::ffi::OsString>) {
    let Some(config) = CONFIG.get() else {
        return;
    };
    if let Err(e) = run_service(config) {
        tracing::error!(error = %crate::error_chain(&e), "the service control manager refused a status");
    }
}

fn status(
    state: ServiceState,
    accepted: ServiceControlAccept,
    exit: ServiceExitCode,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code: exit,
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn run_service(config: &Path) -> windows_service::Result<()> {
    let stop = Arc::new(tokio::sync::Notify::new());
    let stopping = Arc::clone(&stop);
    // The handler needs the handle registering it returns.
    let registered = Arc::new(OnceLock::<ServiceStatusHandle>::new());
    let handler_handle = Arc::clone(&registered);
    let handle = service_control_handler::register(NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            // Before returning: whoever asked (`Restart-Service`) looks at
            // the state at once, and fails on one still Running.
            if let Some(handle) = handler_handle.get() {
                let pending = status(
                    ServiceState::StopPending,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::Win32(0),
                );
                if let Err(e) = handle.set_service_status(pending) {
                    tracing::warn!(error = %crate::error_chain(&e), "the service control manager refused StopPending");
                }
            }
            // Kept as a permit if the agent isn't waiting yet.
            stopping.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let _ = registered.set(handle);
    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
    ))?;
    let stopped = async move { stop.notified().await };
    let code = crate::block_on(crate::serve_until(config, None, stopped, |message| {
        tracing::error!("{message}")
    }));
    let _ = EXIT.set(code);
    let exit = if code == ExitCode::SUCCESS {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
    ))
}
