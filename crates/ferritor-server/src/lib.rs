//! The ferritor server: seal state machine, secret CRUD, their gRPC services
//! and the JSON API. A library so integration tests can drive it directly; `main.rs`
//! only wires it up.

pub mod audit;
pub mod authz;
pub mod auto_unseal;
#[cfg(feature = "aws-kms")]
pub mod aws_kms;
pub mod config;
pub mod crl;
pub mod destroy;
#[cfg(feature = "gcp-kms")]
pub mod gcp_kms;
pub mod grpc;
pub mod health;
pub mod http;
pub mod identity;
pub mod keyring;
pub mod metrics;
pub mod namespaces;
pub mod policies;
pub mod policy;
pub mod policy_store;
pub mod purge;
pub mod ratelimit;
pub mod rewrap;
pub mod root_ledger;
pub mod seal;
pub mod secrets;
pub mod tls;
pub mod watch;

/// Makes this process undumpable (`PR_SET_DUMPABLE` 0): no core dump, and
/// no ptrace or `/proc/<pid>/mem` for other processes of the same user,
/// whatever `kernel.yama.ptrace_scope` says (root still can). The unsealed
/// server holds the root key and every KEK in memory (docs/src/content/docs/concepts/security.md).
/// `main` calls it first of all, before anything secret is read. Linux
/// only; elsewhere it does nothing.
pub fn forbid_memory_access() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    Ok(())
}

/// SHA-256 of `bytes`, lowercase hex: how the audit log names a policy or
/// a certificate (neither secret, and a hash reveals even less).
pub fn fingerprint(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `error: source: source…`, like anyhow's `{:#}`, for logs and client-safe
/// status messages.
pub fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut chain = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        chain.push_str(": ");
        chain.push_str(&s.to_string());
        source = s.source();
    }
    chain
}
