use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ferritor_agent::agent::{Agent, error_chain};
use ferritor_agent::config::Config;
use tracing_subscriber::EnvFilter;

/// Keeps an application's secrets current as files.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Render the files, then keep them current until stopped.
    Run {
        #[arg(long, env = "FERRITOR_AGENT_CONFIG")]
        config: PathBuf,
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

#[tokio::main]
async fn main() -> ExitCode {
    // First of all, before any key or value is read: no core dumps, no
    // same-user ptrace or /proc/<pid>/mem (the application next to the
    // agent may run as the same user).
    #[cfg(target_os = "linux")]
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        eprintln!("error: marking the process undumpable: {e}");
        return ExitCode::FAILURE;
    }
    // Logs to stderr; never values.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        // No colour codes in a file, the journal or a pod's log.
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(
            EnvFilter::try_from_env("FERRITOR_AGENT_LOG")
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let (path, once) = match &cli.command {
        Command::Run { config } => (config, None),
        Command::Once { config, wait_secs } => (config, Some(Duration::from_secs(*wait_secs))),
    };
    let config = match Config::load(path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("error: {}: {}", path.display(), error_chain(&e));
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
            eprintln!("error: {}", error_chain(&e));
            return ExitCode::FAILURE;
        }
    };
    match once {
        Some(wait) => match ferritor_agent::run::once(&mut agent, wait).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        None => {
            ferritor_agent::run::run(&mut agent, stopped()).await;
            tracing::info!("stopped; the files stay as they are");
            ExitCode::SUCCESS
        }
    }
}

/// SIGTERM or SIGINT.
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
