//! Auto-unseal (`docs/src/content/docs/operations/key-management.md`): the
//! root key wrapped by a key management service the server config names,
//! stored in the keys database (`seal_wraps`), so a server can unseal itself
//! at start. The Shamir shares stay shares of the same root key, the
//! recovery shares: this is a second way to open it, and an unwrapped key
//! passes the same checks a shares unseal does (`root_check`, the root
//! commitment, the floor).
//!
//! The key always comes from the config: every unwrap names it, so a row in
//! the keys database pointing elsewhere is never followed.
//!
//! [`AutoUnseal`] is what a provider implements; [`MemoryKms`] is one that
//! keeps its key in memory, for tests.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use ferritor_core::crypto::RootKey;
use zeroize::Zeroizing;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why a provider call failed. The kind decides what the start loop
/// ([`keep_unsealed`]) does: `Unavailable` is retried with backoff,
/// `Denied` (a key policy, a disabled key: a person's fix, which takes a
/// while) looked at again every [`MAX_WAIT`], and `Mismatch` (the stored
/// wrap isn't the configured key's) not retried until the server is
/// unsealed some other way.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AutoUnsealError {
    /// The service didn't answer, or answered "try later" (throttled).
    #[error("the key management service is unavailable: {0}")]
    Unavailable(String),
    /// Refused: no permission, or the key disabled or scheduled for deletion.
    #[error("the key management service refused: {0}")]
    Denied(String),
    /// The ciphertext doesn't decrypt under the configured key with its
    /// context: another key's, another generation's, or changed.
    #[error("the stored wrap doesn't decrypt under the configured key: {0}")]
    Mismatch(String),
}

impl AutoUnsealError {
    /// For metrics and the status: a small fixed set.
    pub fn result(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "kms_unavailable",
            Self::Denied(_) => "denied",
            Self::Mismatch(_) => "mismatch",
        }
    }
}

/// What [`AutoUnseal::wrap`] made: the ciphertext, and the key that
/// actually wrapped it (an alias resolved at that call).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wrapped {
    pub key_id: String,
    pub ciphertext: Vec<u8>,
}

/// A way to protect the root key outside ferritor.
pub trait AutoUnseal: Send + Sync {
    /// The provider's name, for `seal_wraps.provider`, the status and the
    /// audit log (`awskms`).
    fn provider(&self) -> &'static str;
    /// The configured key as the provider names it (an alias resolved to
    /// its key's ARN): what a stored wrap must name.
    fn key_id(&self) -> BoxFuture<'_, Result<String, AutoUnsealError>>;
    /// Wraps `root`, bound to `generation` (the encryption context).
    fn wrap<'a>(
        &'a self,
        root: &'a RootKey,
        generation: u32,
    ) -> BoxFuture<'a, Result<Wrapped, AutoUnsealError>>;
    /// The root key from a wrap made for `generation`, with the configured
    /// key.
    fn unwrap<'a>(
        &'a self,
        ciphertext: &'a [u8],
        generation: u32,
    ) -> BoxFuture<'a, Result<RootKey, AutoUnsealError>>;
}

/// What a [`MemoryKms`] wrapped, by handle: the generation, the key bytes.
type InMemory = HashMap<Vec<u8>, (u32, Zeroizing<Vec<u8>>)>;

/// A provider keeping its "key" in memory, for tests: what it wraps can be
/// unwrapped by this instance only, for the generation it was wrapped for.
/// Its availability can be switched off, and it counts its calls. It
/// passes for `awskms` unless named otherwise ([`MemoryKms::named`]).
pub struct MemoryKms {
    provider: &'static str,
    key_id: String,
    wrapped: Mutex<InMemory>,
    available: AtomicBool,
    unwraps: AtomicU64,
    /// How long an unwrap takes, in milliseconds.
    delay_ms: AtomicU64,
}

impl MemoryKms {
    pub fn new(key_id: &str) -> Self {
        Self::named(AWS_KMS, key_id)
    }

    /// Passing for `provider` (`gcpkms`, say).
    pub fn named(provider: &'static str, key_id: &str) -> Self {
        Self {
            provider,
            key_id: key_id.to_owned(),
            wrapped: Mutex::new(HashMap::new()),
            available: AtomicBool::new(true),
            unwraps: AtomicU64::new(0),
            delay_ms: AtomicU64::new(0),
        }
    }

    /// Makes every unwrap take `delay` (a slow service).
    pub fn set_delay(&self, delay: std::time::Duration) {
        self.delay_ms.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    /// Off: every call is `Unavailable`.
    pub fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::SeqCst);
    }

    /// Unwrap calls so far, failed ones included.
    pub fn unwraps(&self) -> u64 {
        self.unwraps.load(Ordering::SeqCst)
    }

    fn check(&self) -> Result<(), AutoUnsealError> {
        if self.available.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(AutoUnsealError::Unavailable("switched off".to_owned()))
        }
    }
}

impl AutoUnseal for MemoryKms {
    fn provider(&self) -> &'static str {
        self.provider
    }

    fn key_id(&self) -> BoxFuture<'_, Result<String, AutoUnsealError>> {
        Box::pin(async move {
            self.check()?;
            Ok(self.key_id.clone())
        })
    }

    fn wrap<'a>(
        &'a self,
        root: &'a RootKey,
        generation: u32,
    ) -> BoxFuture<'a, Result<Wrapped, AutoUnsealError>> {
        Box::pin(async move {
            self.check()?;
            let mut handle = vec![0u8; 16];
            getrandom::fill(&mut handle)
                .map_err(|e| AutoUnsealError::Unavailable(e.to_string()))?;
            let bytes = Zeroizing::new(root.bytes_for_wrapping().to_vec());
            self.wrapped
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(handle.clone(), (generation, bytes));
            Ok(Wrapped {
                key_id: self.key_id.clone(),
                ciphertext: handle,
            })
        })
    }

    fn unwrap<'a>(
        &'a self,
        ciphertext: &'a [u8],
        generation: u32,
    ) -> BoxFuture<'a, Result<RootKey, AutoUnsealError>> {
        Box::pin(async move {
            self.unwraps.fetch_add(1, Ordering::SeqCst);
            let delay = self.delay_ms.load(Ordering::SeqCst);
            if delay > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
            self.check()?;
            let wrapped = self.wrapped.lock().unwrap_or_else(PoisonError::into_inner);
            match wrapped.get(ciphertext) {
                Some((wrapped_for, bytes)) if *wrapped_for == generation => {
                    RootKey::from_unwrapped(bytes)
                        .map_err(|e| AutoUnsealError::Mismatch(e.to_string()))
                }
                Some(_) => Err(AutoUnsealError::Mismatch(
                    "wrapped for another generation".to_owned(),
                )),
                None => Err(AutoUnsealError::Mismatch("not this key's".to_owned())),
            }
        })
    }
}

/// The first wait between two attempts; it doubles up to [`MAX_WAIT`].
pub const FIRST_WAIT: std::time::Duration = std::time::Duration::from_secs(1);
/// The longest wait between two attempts, and how often a held (or
/// waiting) server looks again: a release elsewhere brings it up within it.
pub const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Keeps `seal` unsealed through its auto-unseal provider, for the life of
/// the process (`main` spawns it when `[seal]` names one): whenever the
/// server is sealed, it tries, retrying what may pass with backoff
/// ([`FIRST_WAIT`] doubling to [`MAX_WAIT`]); looking again every
/// [`MAX_WAIT`] while held (cheap reads, no call to the service), waiting
/// for an operator, refused by KMS's policy (`denied`), or refused for a
/// missing root commitment or a generation below the floor (one `Decrypt` a
/// minute: a `--recommit` or a floor fix on another server brings this one
/// up too); and stopping on a wrap that isn't this deployment's key
/// (`mismatch`) until the server is unsealed some other way. Each unseal is
/// audited, and a failure when it starts or changes.
pub async fn keep_unsealed(
    seal: std::sync::Arc<crate::seal::Seal>,
    gate: std::sync::Arc<crate::audit::Gate>,
    store: ferritor_datastore::Datastore,
) {
    keep_unsealed_with(seal, gate, store, FIRST_WAIT, MAX_WAIT).await;
}

/// [`keep_unsealed`] with other waits (tests).
pub async fn keep_unsealed_with(
    seal: std::sync::Arc<crate::seal::Seal>,
    gate: std::sync::Arc<crate::audit::Gate>,
    store: ferritor_datastore::Datastore,
    first_wait: std::time::Duration,
    max_wait: std::time::Duration,
) {
    use crate::seal::AutoOutcome;

    let Some(provider) = seal.auto_unseal_provider() else {
        return;
    };
    let mut sealed = seal.sealed_changes();
    let mut wait = first_wait;
    let mut reported: Option<(&'static str, Option<String>)> = None;
    loop {
        if !*sealed.borrow_and_update() {
            if sealed.changed().await.is_err() {
                return;
            }
            continue;
        }
        let outcome = seal.auto_unseal().await;
        let report = seal.auto_report();
        let result = report.result.unwrap_or("failed");
        if !matches!(outcome, AutoOutcome::NotNeeded) {
            crate::metrics::metrics().auto_unseal(result);
        }
        let now = (result, report.error.clone());
        let changed = reported.as_ref() != Some(&now);
        match &outcome {
            AutoOutcome::Unsealed => {
                gate.auto_unsealed("ok", provider, seal.auto_key_id(), None);
                crate::grpc::unsealed(&seal, &gate, &store, "auto_unseal");
                (wait, reported) = (first_wait, None);
                continue;
            }
            AutoOutcome::NotNeeded => continue,
            AutoOutcome::Held | AutoOutcome::Waiting(_) => {
                if changed {
                    tracing::warn!(
                        result,
                        reason = report.error,
                        "auto-unseal waits: looking again every {}s",
                        max_wait.as_secs()
                    );
                }
                wait = max_wait;
            }
            AutoOutcome::Retry(e) => {
                if matches!(
                    e,
                    crate::seal::SealError::AutoUnseal(AutoUnsealError::Denied(_))
                ) {
                    wait = max_wait;
                }
                if changed {
                    tracing::warn!(
                        result,
                        reason = report.error,
                        retry_in_s = wait.as_secs(),
                        "auto-unseal failed; the shares unseal meanwhile"
                    );
                }
            }
            AutoOutcome::Refused(
                crate::seal::SealError::RootUncommitted { .. }
                | crate::seal::SealError::RootBelowFloor { .. },
            ) => {
                if changed {
                    tracing::error!(
                        result,
                        reason = report.error,
                        "AUTO-UNSEAL REFUSED: the data database doesn't vouch for this root key \
                         (see `ferritor status` and \
                         https://ferritor.dev/operations/key-management); looking again every \
                         {}s, so a re-commit or a floor fix elsewhere brings this server up",
                        max_wait.as_secs()
                    );
                }
                wait = max_wait;
            }
            AutoOutcome::Refused(_) => {
                tracing::error!(
                    result,
                    reason = report.error,
                    "AUTO-UNSEAL REFUSED, and won't try again until this server is unsealed \
                     with the shares: see `ferritor status` and \
                     https://ferritor.dev/operations/key-management"
                );
                gate.auto_unsealed(result, provider, seal.auto_key_id(), report.error);
                reported = Some(now);
                // Until a person acts: the next unseal (shares, --recommit).
                if sealed.changed().await.is_err() {
                    return;
                }
                continue;
            }
        }
        if changed {
            gate.auto_unsealed(result, provider, seal.auto_key_id(), report.error);
            reported = Some(now);
        }
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            changed = sealed.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
        if matches!(outcome, AutoOutcome::Retry(_)) {
            wait = (wait * 2).min(max_wait);
        }
    }
}

/// `[seal.awskms]`, checked (see `config`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AwsKmsConfig {
    /// The key's ARN (or an alias ARN, resolved at each call).
    pub key_id: String,
    pub region: String,
    /// A VPC endpoint (https), or a loopback test double.
    pub endpoint: Option<String>,
}

/// `[seal.gcpkms]`, checked (see `config`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcpKmsConfig {
    /// The key's resource name,
    /// `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`: never a
    /// version (decrypt finds it from the ciphertext).
    pub key_name: String,
    /// Default `https://cloudkms.googleapis.com`; a Private Service Connect
    /// endpoint (https), or a loopback test double.
    pub endpoint: Option<String>,
}

/// AWS KMS's provider name (`seal_wraps.provider`, `[seal] provider`,
/// `--seal`).
pub const AWS_KMS: &str = "awskms";
/// Google Cloud KMS's.
pub const GCP_KMS: &str = "gcpkms";

/// The provider `[seal]` names, checked (see `config`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderConfig {
    AwsKms(AwsKmsConfig),
    GcpKms(GcpKmsConfig),
}

impl ProviderConfig {
    /// As [`AutoUnseal::provider`] names it.
    pub fn provider(&self) -> &'static str {
        match self {
            Self::AwsKms(_) => AWS_KMS,
            Self::GcpKms(_) => GCP_KMS,
        }
    }
}
