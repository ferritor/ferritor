//! Telling an application its files changed (`on_change`): a signal to a
//! process, or a command. Failures are logged, never retried in a loop.

use std::time::Duration;

use rustix::process::{Pid, Signal as RawSignal, kill_process};

use crate::config::{Notify, Signal, SignalTarget};

/// How long a command may run before it's left to itself and logged.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// The kernel's process name (`/proc/<pid>/comm`) is cut at 15 bytes.
const COMM_LEN: usize = 15;

fn raw(signal: Signal) -> RawSignal {
    match signal {
        Signal::Hup => RawSignal::HUP,
        Signal::Int => RawSignal::INT,
        Signal::Term => RawSignal::TERM,
        Signal::Usr1 => RawSignal::USR1,
        Signal::Usr2 => RawSignal::USR2,
    }
}

/// Tells the application, as configured. Runs a command in the background
/// (the loop doesn't wait for it); a signal is sent at once.
pub fn changed(notify: &Notify) {
    match notify {
        Notify::Nothing => {}
        Notify::Signal { signal, target } => {
            let pids = match target {
                SignalTarget::PidFile(path) => match std::fs::read_to_string(path) {
                    Ok(text) => text.trim().parse::<i32>().ok().into_iter().collect(),
                    Err(e) => {
                        tracing::warn!(pid_file = %path.display(), error = %e, "no process to signal");
                        return;
                    }
                },
                SignalTarget::Process(name) => processes_named(name),
            };
            if pids.is_empty() {
                tracing::warn!(?target, "no process to signal");
            }
            for pid in pids {
                let sent = Pid::from_raw(pid)
                    .ok_or_else(|| std::io::Error::other("pid 0"))
                    .and_then(|pid| kill_process(pid, raw(*signal)).map_err(Into::into));
                match sent {
                    Ok(()) => tracing::info!(pid, ?signal, "signalled the application"),
                    Err(e) => {
                        tracing::warn!(pid, ?signal, error = %e, "signalling the application failed")
                    }
                }
            }
        }
        Notify::Command(command) => {
            let command = command.clone();
            tokio::spawn(async move {
                let Some((program, args)) = command.split_first() else {
                    return;
                };
                let run = tokio::process::Command::new(program).args(args).status();
                match tokio::time::timeout(COMMAND_TIMEOUT, run).await {
                    Ok(Ok(status)) if status.success() => {
                        tracing::info!(?command, "on_change command ran");
                    }
                    Ok(Ok(status)) => tracing::warn!(?command, %status, "on_change command failed"),
                    Ok(Err(e)) => {
                        tracing::warn!(?command, error = %e, "on_change command didn't start")
                    }
                    Err(_) => {
                        tracing::warn!(?command, "on_change command still running; left to itself")
                    }
                }
            });
        }
    }
}

/// Every process named `name` (as `/proc/<pid>/comm` has it), but this one.
fn processes_named(name: &str) -> Vec<i32> {
    let wanted = &name.as_bytes()[..name.len().min(COMM_LEN)];
    let own = std::process::id();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| *pid != own)
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/comm"))
                .is_ok_and(|comm| comm.strip_suffix(b"\n").unwrap_or(&comm) == wanted)
        })
        .filter_map(|pid| i32::try_from(pid).ok())
        .collect()
}
