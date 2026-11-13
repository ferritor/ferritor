//! The provider itself, on Unix: it serves the driver on a Unix socket.

use std::io::IsTerminal as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use ferritor_agent::agent::error_chain;
use ferritor_agent::csi::config::ProviderConfig;
use ferritor_agent::csi::proto::csi_driver_provider_server::CsiDriverProviderServer;
use ferritor_agent::csi::provider::Provider;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tracing_subscriber::EnvFilter;

/// Serves ferritor secrets to the Secrets Store CSI Driver on this node.
#[derive(Parser)]
// Its own name: it's a binary of the ferritor-agent package, whose name
// clap would show (`--version`) otherwise.
#[command(name = "ferritor-csi-provider", version)]
struct Cli {
    #[arg(long, env = "FERRITOR_CSI_PROVIDER_CONFIG")]
    config: PathBuf,
}

#[tokio::main]
pub async fn main() -> ExitCode {
    // First of all, before any token, key or value is in memory: no core
    // dumps, no same-user ptrace or /proc/<pid>/mem.
    #[cfg(target_os = "linux")]
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        eprintln!("error: marking the process undumpable: {e}");
        return ExitCode::FAILURE;
    }
    // Logs to stderr; never tokens or values.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(
            EnvFilter::try_from_env("FERRITOR_CSI_PROVIDER_LOG")
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let config = match ProviderConfig::load(&cli.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("error: {}: {}", cli.config.display(), error_chain(&e));
            return ExitCode::FAILURE;
        }
    };
    match serve(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: ProviderConfig) -> Result<(), String> {
    let socket = config.socket.clone();
    // A socket left by a provider that didn't stop cleanly: bind fails on it.
    match std::fs::remove_file(&socket) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(format!("removing the old {}: {e}", socket.display()));
        }
        _ => {}
    }
    // Created owner-only, no window with the umask's mode (the provider
    // writes no other file).
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    let listener = UnixListener::bind(&socket)
        .map_err(|e| format!("listening on {}: {e}", socket.display()))?;
    // The driver (root) only: a pod reaching the socket could ask for any
    // volume. Already so from the umask; said again, explicitly.
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("restricting {}: {e}", socket.display()))?;
    tracing::info!(
        socket = %socket.display(),
        server = config.server,
        exchange = config.exchange,
        "serving the Secrets Store CSI Driver"
    );
    let provider = Arc::new(Provider::new(config));
    let served = tonic::transport::Server::builder()
        .add_service(CsiDriverProviderServer::new(provider))
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), stopped())
        .await;
    std::fs::remove_file(&socket).ok();
    tracing::info!("stopped");
    served.map_err(|e| format!("serving: {e}"))
}

/// SIGTERM or SIGINT.
async fn stopped() {
    let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        tokio::signal::ctrl_c().await.ok();
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
