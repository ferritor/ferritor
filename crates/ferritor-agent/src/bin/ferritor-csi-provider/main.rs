//! `ferritor-csi-provider`: the ferritor provider for the Kubernetes Secrets Store
//! CSI Driver (`docs/src/content/docs/guides/csi.md`), one per node, on the driver's provider socket.
//! Linux only: elsewhere the binary says so and exits.

#[cfg(unix)]
mod unix;

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    unix::main()
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "error: ferritor-csi-provider runs on Linux nodes only, next to the Secrets Store CSI Driver"
    );
    std::process::ExitCode::FAILURE
}
