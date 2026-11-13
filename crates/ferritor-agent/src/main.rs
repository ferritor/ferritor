use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ferritor_agent::agent::{Agent, error_chain};
use ferritor_agent::config::Config;
use tracing_subscriber::EnvFilter;

#[cfg(windows)]
mod service;

/// Keeps an application's secrets current as files.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Render the files, then keep them current until stopped. On Windows
    /// also a service's command line (`sc.exe create`, `New-Service`).
    Run {
        #[arg(long, env = "FERRITOR_AGENT_CONFIG")]
        config: PathBuf,
        /// Where the logs go, appended, instead of stderr: a service has
        /// no console.
        #[cfg(windows)]
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// Render the files once, then exit: 0 when every required secret is
    /// written (an init container, a deploy step).
    Once {
        #[arg(long, env = "FERRITOR_AGENT_CONFIG")]
        config: PathBuf,
        /// How long to keep retrying an unreachable or unready server.
        #[arg(long, default_value_t = 60)]
        wait_secs: u64,
    },
}

fn main() -> ExitCode {
    // First of all, before any key or value is read: the application next
    // to the agent may run as the same user.
    if let Err(e) = protect_memory() {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    let cli = Cli::parse();
    match cli.command {
        #[cfg(not(windows))]
        Command::Run { config } => {
            log_to_stderr();
            block_on(serve(&config, None))
        }
        #[cfg(windows)]
        Command::Run { config, log_file } => {
            match &log_file {
                Some(path) => {
                    if let Err(e) = log_to(path) {
                        eprintln!("error: {}: {e}", path.display());
                        return ExitCode::FAILURE;
                    }
                }
                None => log_to_stderr(),
            }
            if let Some(code) = service::run_if_service(&config) {
                return code;
            }
            block_on(serve(&config, None))
        }
        Command::Once { config, wait_secs } => {
            log_to_stderr();
            block_on(serve(&config, Some(Duration::from_secs(wait_secs))))
        }
    }
}

/// Linux: no core dumps, no same-user ptrace or /proc/<pid>/mem. Windows:
/// the process's and its threads' access lists let its own account do no
/// more than wait for it, end it and query it
/// (`ferritor_winsec::protect_current_process`).
fn protect_memory() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| format!("marking the process undumpable: {e}"))?;
    #[cfg(windows)]
    ferritor_winsec::protect_current_process()
        .map_err(|e| format!("locking the process against other processes: {e}"))?;
    Ok(())
}

/// Logs to stderr; never values.
fn log_to_stderr() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        // No colour codes in a file, the journal or a pod's log.
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(log_filter())
        .init();
}

/// Logs appended to `path`, without colour; never values.
#[cfg(windows)]
fn log_to(path: &Path) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    tracing_subscriber::fmt()
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false)
        .with_env_filter(log_filter())
        .init();
    Ok(())
}

fn log_filter() -> EnvFilter {
    EnvFilter::try_from_env("FERRITOR_AGENT_LOG").unwrap_or_else(|_| EnvFilter::new("info"))
}

fn block_on(future: impl Future<Output = ExitCode>) -> ExitCode {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(future),
        Err(e) => {
            eprintln!("error: starting the runtime: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Loads the config and runs the agent: once (`Some(wait)`), or until
/// stopped by a signal, Ctrl+C or a console's close.
async fn serve(path: &Path, once: Option<Duration>) -> ExitCode {
    serve_until(path, once, stopped(), |message| {
        eprintln!("error: {message}")
    })
    .await
}

/// As `serve`, stopped by `stop` (the service manager's stop, for a
/// service), telling `fail` why it couldn't start or finish (stderr on a
/// console; a service has none, so the log).
async fn serve_until(
    path: &Path,
    once: Option<Duration>,
    stop: impl Future<Output = ()>,
    fail: fn(&str),
) -> ExitCode {
    let config = match Config::load(path) {
        Ok(config) => config,
        Err(e) => {
            fail(&format!("{}: {}", path.display(), error_chain(&e)));
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        server = config.server.addr(),
        outputs = config.outputs.len(),
        "starting"
    );
    let mut agent = match Agent::new(config) {
        Ok(agent) => agent,
        Err(e) => {
            fail(&error_chain(&e));
            return ExitCode::FAILURE;
        }
    };
    match once {
        Some(wait) => match ferritor_agent::run::once(&mut agent, wait).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                fail(&e.to_string());
                ExitCode::FAILURE
            }
        },
        None => {
            ferritor_agent::run::run(&mut agent, stop).await;
            tracing::info!("stopped; the files stay as they are");
            ExitCode::SUCCESS
        }
    }
}

/// SIGTERM or SIGINT.
#[cfg(unix)]
async fn stopped() {
    let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        // Without the handler, Ctrl-C alone stops it.
        tokio::signal::ctrl_c().await.ok();
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

/// Ctrl+C or Ctrl+Break, the console closing, the user logging off or the
/// system shutting down.
#[cfg(windows)]
async fn stopped() {
    use tokio::signal::windows;
    let (Ok(mut brk), Ok(mut close), Ok(mut shutdown)) = (
        windows::ctrl_break(),
        windows::ctrl_close(),
        windows::ctrl_shutdown(),
    ) else {
        tokio::signal::ctrl_c().await.ok();
        return;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = brk.recv() => {}
        _ = close.recv() => {}
        _ = shutdown.recv() => {}
    }
}
