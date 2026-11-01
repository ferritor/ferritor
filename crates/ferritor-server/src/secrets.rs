//! Secret CRUD with envelope encryption. Transport-agnostic: `grpc` (and
//! later the JSON API) maps it to a protocol.
//!
//! Every operation, in this order: parse the path (rejecting non-canonical
//! ones), ask the authorizer through the [`Gate`] (which records the
//! decision in the audit log), require the server unsealed, then touch the
//! data database.
//!
//! Each put is a new version with its own DEK; the DEK encrypts the value
//! and is wrapped by the active KEK, both bound to the path and version.
//!
//! No keyring is held across an await. An operation records the seal epoch
//! when it starts and takes the keys only right before its crypto, via
//! [`Seal::keyring_at`], which refuses if a seal happened in between. So a
//! request stuck on a slow database can't return plaintext (or encrypt)
//! after a seal returned, and doesn't keep the KEKs in memory while stuck.
//!
//! Seal freezes the data plane too, not just the keys: any operation in
//! flight when a seal happens fails with `Sealed`, and nothing it did is
//! kept. Put and delete write in a transaction and check the epoch again
//! right before committing (dropping the transaction rolls back); list
//! checks before answering.
//!
//! The one window left is the commit itself, which is an await: a seal that
//! lands during that round trip doesn't stop a put or delete from
//! committing (and reporting success). So "however long the database
//! stalls" becomes "one commit round trip", not zero.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use serde_json::json;

use ferritor_core::crypto::{CryptoError, Dek};
use ferritor_core::labels::{self, LabelError, Labels};
use ferritor_core::path::{Namespace, PathError, SecretPath};
use ferritor_datastore::{Datastore, DatastoreError, PathMetadata, SecretMetadata, VersionInfo};
use zeroize::Zeroizing;

use crate::audit::{AuditError, Gate, Outcome, Refused};
use crate::authz::{Action, Caller, Denied, Target};
use crate::metrics::metrics;
use crate::seal::{Keyring, Seal, SealError};

#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    #[error("invalid secret path")]
    InvalidPath(#[source] PathError),
    #[error("the value is {size} bytes; at most {MAX_VALUE_SIZE} are allowed")]
    ValueTooLarge { size: usize },
    #[error("invalid labels")]
    InvalidLabels(#[source] LabelError),
    /// A label change that would leave the path with more than
    /// `labels::MAX_LABELS`; nothing changed.
    #[error("{count} labels; a path holds at most {}", labels::MAX_LABELS)]
    TooManyLabels { count: usize },
    /// Not one this server handed out for the previous page: of a listing
    /// of the same prefix, or of the same path's history.
    #[error(
        "invalid page token; pass back the next_page_token of the previous page of the same \
         listing (the same prefix, or the same path)"
    )]
    InvalidPageToken,
    #[error("permission denied")]
    Denied(#[source] Denied),
    /// Allowed, but the decision couldn't be recorded (see `audit`).
    #[error("{}", ferritor_core::messages::UNAUDITED)]
    Unaudited(#[source] AuditError),
    #[error("{}", ferritor_core::messages::SEALED)]
    Sealed,
    /// Only a stored policy could allow it, and the stored set didn't
    /// verify (see `policy_store`).
    #[error("{}", ferritor_core::messages::POLICY_UNVERIFIED)]
    PolicyUnverified,
    /// Over one of the caller's rate limits (see `ratelimit`).
    #[error("rate limited ({}): too many requests from this caller; retry later", .0.limit.name())]
    Limited(crate::ratelimit::Refused),
    /// No call slot under the server-wide cap came free in time.
    #[error("the server is busy: no call slot came free in time; retry later")]
    Overloaded,
    #[error("secret `{path}` not found")]
    NotFound { path: SecretPath },
    #[error("version {version} of secret `{path}` not found")]
    VersionNotFound { path: SecretPath, version: u32 },
    /// Wrapped by a KEK this server doesn't have even after refreshing its
    /// keyring: the root key was replaced by a rekey elsewhere (see
    /// `keyring`), or the keys database couldn't be read just now.
    #[error(
        "this secret is wrapped by KEK version {0}, which this server couldn't load even \
         after refreshing its keyring; if another server rekeyed, seal and unseal this one \
         with the new shares"
    )]
    UnknownKek(u32),
    /// Retryable. For a put or delete whose commit timed out, the outcome is
    /// unknown: retrying a put that was in fact stored creates one extra
    /// version (harmless, but visible); retrying such a delete gets
    /// `NotFound`.
    #[error("the data database did not respond in time")]
    DataTimeout,
    #[error("too many concurrent writes to `{0}`; retry")]
    Busy(SecretPath),
    /// A put to a path whose first segment isn't a namespace (or one whose
    /// KEKs this server can't use). Asked only after authorization.
    #[error("there is no namespace `{0}`: create it first (`ferritor namespace create`)")]
    NoNamespace(Namespace),
    /// A put wrapped its DEK with a KEK version below the data database's
    /// KEK floor: another server is destroying that KEK, and this one
    /// couldn't bring its keyring up to date (the refresh failed, or was
    /// held back by the cooldown after a failed one). Nothing was stored.
    /// Retryable, unless another server rekeyed: then this one can't
    /// follow until it's sealed and unsealed with the new shares.
    #[error(
        "KEK version {0}, the one this server wraps with, is being destroyed, and this \
         server's keyring couldn't be brought up to date; nothing was stored. If another \
         server rekeyed, seal and unseal this one with the new shares; otherwise retry shortly"
    )]
    StaleKeyring(u32),
    /// No such deleted version: live, purged, or never stored.
    #[error("{}", nothing_to_restore(path, *version))]
    NothingToRestore {
        path: SecretPath,
        version: Option<u32>,
    },
    /// A restore without a version while the path has a live one: that
    /// only undoes a delete. Nothing was restored; name the version.
    #[error(
        "`{path}` has a live version ({latest}): without a version, restore only undoes a \
         delete; name the deleted version to restore it alongside"
    )]
    LiveVersion { path: SecretPath, latest: u32 },
    /// A check-and-set ([`Secrets::put_if`]) found another latest version:
    /// someone else wrote or deleted it since. Read it again, then decide.
    #[error("{}", mismatch(path, *expected, *latest))]
    VersionMismatch {
        path: SecretPath,
        expected: u32,
        latest: Option<u32>,
    },
    /// A watch of nothing, or of more than `watch::MAX_ITEMS`.
    #[error(
        "a watch takes 1 to {} paths and prefixes together, not {count}",
        crate::watch::MAX_ITEMS
    )]
    WatchSize { count: usize },
    /// No subscription (see `watch`).
    #[error("can't watch")]
    Watch(#[source] crate::watch::SubscribeError),
    #[error("data store failure")]
    Store(#[source] DatastoreError),
    #[error("crypto failure")]
    Crypto(#[source] CryptoError),
}

impl From<DatastoreError> for SecretsError {
    fn from(e: DatastoreError) -> Self {
        match e {
            DatastoreError::Timeout => Self::DataTimeout,
            DatastoreError::Busy(path) => Self::Busy(path),
            DatastoreError::BelowKekFloor(version) => Self::StaleKeyring(version),
            DatastoreError::NothingStored(path) => Self::NotFound { path },
            DatastoreError::TooManyLabels { count } => Self::TooManyLabels { count },
            other => Self::Store(other),
        }
    }
}

impl From<CryptoError> for SecretsError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

type Result<T, E = SecretsError> = std::result::Result<T, E>;

/// Runs a secret operation and records it in the metrics: operation,
/// result category, duration.
async fn observed<T>(operation: &'static str, run: impl Future<Output = Result<T>>) -> Result<T> {
    let started = Instant::now();
    let result = run.await;
    let category = result.as_ref().err().map_or("ok", SecretsError::category);
    metrics().secret_request(operation, category, started.elapsed());
    result
}

impl SecretsError {
    /// A bounded name for metrics: what kind of failure, never which path.
    pub fn category(&self) -> &'static str {
        match self {
            Self::InvalidPath(_)
            | Self::ValueTooLarge { .. }
            | Self::InvalidPageToken
            | Self::InvalidLabels(_)
            | Self::TooManyLabels { .. }
            | Self::WatchSize { .. } => "invalid_argument",
            Self::Watch(_) => "unavailable",
            Self::Denied(_) => "denied",
            Self::Unaudited(_) => "unaudited",
            Self::Sealed => "sealed",
            Self::PolicyUnverified => "policy_unverified",
            Self::Limited(_) => "rate_limited",
            Self::Overloaded => "unavailable",
            Self::NotFound { .. }
            | Self::VersionNotFound { .. }
            | Self::NothingToRestore { .. } => "not_found",
            Self::UnknownKek(_) => "unknown_kek",
            Self::DataTimeout => "unavailable",
            Self::Busy(_) => "busy",
            Self::NoNamespace(_) => "no_namespace",
            Self::StaleKeyring(_) => "stale_keyring",
            Self::VersionMismatch { .. } => "version_mismatch",
            Self::LiveVersion { .. } => "live_version",
            Self::Store(_) | Self::Crypto(_) => "internal",
        }
    }
}

/// What a watch covers ([`Secrets::watch`]).
#[derive(Clone, Debug)]
pub struct Watched {
    paths: Vec<SecretPath>,
    prefixes: Vec<SecretPath>,
}

impl Watched {
    /// Whether a change of `path` is one this watch sends.
    pub fn covers(&self, path: &SecretPath) -> bool {
        self.paths.iter().any(|p| p == path)
            || self.prefixes.iter().any(|prefix| path.is_under(prefix))
    }
}

/// A write that failed after authorization, for its audit outcome: failing
/// at the commit means it may have landed anyway (the connection can drop
/// after Postgres commits), so the outcome is unknown, not failed.
struct Failure {
    error: SecretsError,
    at_commit: bool,
}

impl Failure {
    fn at_commit(e: DatastoreError) -> Self {
        Self {
            error: e.into(),
            at_commit: true,
        }
    }

    fn outcome(&self) -> Outcome {
        let error = crate::error_chain(&self.error);
        if self.at_commit {
            Outcome::Unknown(error)
        } else {
            Outcome::Failed {
                error,
                details: None,
            }
        }
    }
}

impl<E: Into<SecretsError>> From<E> for Failure {
    fn from(e: E) -> Self {
        Self {
            error: e.into(),
            at_commit: false,
        }
    }
}

fn nothing_to_restore(path: &SecretPath, version: Option<u32>) -> String {
    match version {
        Some(version) => format!(
            "no deleted version {version} of `{path}` to restore (it's live, was purged, \
             or never existed)"
        ),
        None => format!("`{path}` has no deleted version to restore (none, or all purged)"),
    }
}

fn mismatch(path: &SecretPath, expected: u32, latest: Option<u32>) -> String {
    let now = match latest {
        Some(latest) => format!("its latest version is {latest}"),
        None => "it has no live version".to_owned(),
    };
    let wanted = match expected {
        0 => "expected none (create only)".to_owned(),
        expected => format!("expected {expected}"),
    };
    format!("`{path}` was changed: {now}, {wanted}; read it again")
}

/// A decrypted secret. The value is wiped when dropped.
#[derive(Debug)]
pub struct Secret {
    pub metadata: SecretMetadata,
    pub value: Zeroizing<Vec<u8>>,
}

pub struct Secrets {
    seal: Arc<Seal>,
    store: Datastore,
    gate: Arc<Gate>,
    /// The change feed's hub, for `WatchSecrets` ([`Secrets::with_watch`]).
    watch: Option<Arc<crate::watch::Watch>>,
    /// When a read last finished refreshing the keyring (see
    /// [`Secrets::refresh_due`]).
    refreshed_at: Mutex<Option<Instant>>,
}

impl Secrets {
    pub fn new(seal: Arc<Seal>, store: Datastore, gate: Arc<Gate>) -> Self {
        Self {
            seal,
            store,
            gate,
            watch: None,
            refreshed_at: Mutex::new(None),
        }
    }

    /// Serves watches from `watch`'s change feed; without it, a watch is
    /// refused as unavailable.
    #[must_use]
    pub fn with_watch(mut self, watch: Arc<crate::watch::Watch>) -> Self {
        self.watch = Some(watch);
        self
    }

    /// Authorizes a watch of `paths` (read on each) and `prefixes` (list
    /// on each), every decision recorded, then (unsealed: the stored
    /// policies decide only then) subscribes to the change feed. The
    /// subscription is taken after the decisions, so no change is sent
    /// before the caller may see it.
    pub async fn watch(
        &self,
        caller: &Caller,
        paths: &[String],
        prefixes: &[String],
    ) -> Result<(Watched, crate::watch::Subscription)> {
        let count = paths.len() + prefixes.len();
        if count == 0 || count > crate::watch::MAX_ITEMS {
            return Err(SecretsError::WatchSize { count });
        }
        let watched = Watched {
            paths: paths.iter().map(|p| Self::path(p)).collect::<Result<_>>()?,
            prefixes: prefixes
                .iter()
                .map(|p| Self::path(p))
                .collect::<Result<_>>()?,
        };
        for path in &watched.paths {
            self.authorize(caller, Action::Read, Target::Path(path))
                .await?;
        }
        for prefix in &watched.prefixes {
            self.authorize(caller, Action::List, Target::Below(prefix))
                .await?;
        }
        self.unsealed_epoch()?;
        let hub = self
            .watch
            .as_ref()
            .ok_or(SecretsError::Watch(crate::watch::SubscribeError::NotLive))?;
        let cap = self.gate.max_watch_streams(caller);
        let identity = match caller {
            Caller::Identity(identity) => Some(identity.as_str()),
            Caller::Unauthenticated => None,
        };
        let subscription = hub
            .subscribe(identity.zip(cap))
            .await
            .map_err(SecretsError::Watch)?;
        Ok((watched, subscription))
    }

    /// Whether `caller` may still watch `watched`: asked without a record
    /// first (on every change and every recheck, so the log isn't filled
    /// with them), and only for one it no longer may, the recorded check,
    /// whose refusal ends the stream.
    pub async fn still_watching(&self, caller: &Caller, watched: &Watched) -> Result<()> {
        self.still_watching_where(caller, watched, |_| true).await
    }

    /// [`Secrets::still_watching`], for the paths and prefixes that cover
    /// `path` only: before a change of it is sent.
    pub async fn still_watching_change(
        &self,
        caller: &Caller,
        watched: &Watched,
        path: &SecretPath,
    ) -> Result<()> {
        self.still_watching_where(caller, watched, |item| item == path || path.is_under(item))
            .await
    }

    async fn still_watching_where(
        &self,
        caller: &Caller,
        watched: &Watched,
        relevant: impl Fn(&SecretPath) -> bool,
    ) -> Result<()> {
        for path in watched.paths.iter().filter(|p| relevant(p)) {
            if !self.gate.permits(caller, Action::Read, Target::Path(path)) {
                self.authorize(caller, Action::Read, Target::Path(path))
                    .await?;
            }
        }
        for prefix in watched.prefixes.iter().filter(|p| relevant(p)) {
            if !self
                .gate
                .permits(caller, Action::List, Target::Below(prefix))
            {
                self.authorize(caller, Action::List, Target::Below(prefix))
                    .await?;
            }
        }
        Ok(())
    }

    /// Changes of the seal state, for a watch to end at a seal.
    pub fn sealed_changes(&self) -> tokio::sync::watch::Receiver<bool> {
        self.seal.sealed_changes()
    }

    /// The watch hub, for the transport (its closing, its streams).
    pub fn watch_hub(&self) -> Option<&Arc<crate::watch::Watch>> {
        self.watch.as_ref()
    }

    /// For the transport, to record failed authentication.
    pub(crate) fn gate(&self) -> &Gate {
        &self.gate
    }

    /// Whether a call may trigger a keyring refresh: not within
    /// `ON_DEMAND_COOLDOWN` of the last one a call completed. A call
    /// arriving while one runs isn't held back here: it queues on the admin
    /// lock and returns as soon as the refresh has the KEK it wants.
    fn refresh_due(&self) -> bool {
        self.refreshed_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none_or(|at| at.elapsed() >= crate::keyring::ON_DEMAND_COOLDOWN)
    }

    /// Refreshes the keyring on a call's behalf (a read meeting an unknown
    /// KEK, a put refused by the KEK floor; `trigger` says which, `wanted`
    /// is the KEK a read needs), at most once per `ON_DEMAND_COOLDOWN`
    /// across both: a server that can't refresh (a rekey elsewhere, the
    /// keys database down) would otherwise send every such call to the
    /// admin lock and the database. Does nothing while the cooldown runs.
    async fn refresh_on_demand(&self, trigger: &'static str, wanted: Option<(&Namespace, u32)>) {
        if !self.refresh_due() {
            return;
        }
        let refreshed =
            crate::keyring::refresh(&self.seal, &self.gate, trigger, wanted, true).await;
        // The cooldown runs from the last load, so not from a call that
        // found its KEK already loaded by the refresh it queued behind. A
        // failed load counts: it went to the database.
        let loaded = match refreshed {
            Ok(refreshed) => refreshed.loaded,
            Err(SealError::Sealed) => false,
            Err(_) => true,
        };
        if loaded {
            *self
                .refreshed_at
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        }
    }

    fn path(path: &str) -> Result<SecretPath> {
        SecretPath::parse(path).map_err(SecretsError::InvalidPath)
    }

    /// Authorized and audited (see `audit`).
    async fn authorize(&self, caller: &Caller, action: Action, target: Target<'_>) -> Result<()> {
        self.gate
            .check(caller, action, target)
            .await
            .map_err(|refused| match refused {
                Refused::Denied(denied) => SecretsError::Denied(denied),
                Refused::Unaudited(e) => SecretsError::Unaudited(e),
                Refused::Sealed => SecretsError::Sealed,
                Refused::PolicyUnverified => SecretsError::PolicyUnverified,
                Refused::Limited(refused) => SecretsError::Limited(refused),
                Refused::Overloaded => SecretsError::Overloaded,
            })
    }

    /// The seal epoch if unsealed, else [`SecretsError::Sealed`]. Recorded
    /// when an operation starts; see [`Secrets::keyring_at`].
    fn unsealed_epoch(&self) -> Result<u64> {
        self.seal.unsealed_epoch().map_err(|_| SecretsError::Sealed)
    }

    /// [`SecretsError::Sealed`] if a seal happened since `epoch`. For the
    /// steps that need no keys: before committing, or before answering.
    fn unsealed_since(&self, epoch: u64) -> Result<()> {
        self.seal
            .ensure_unsealed_since(epoch)
            .map_err(|_| SecretsError::Sealed)
    }

    /// The keyring if no seal happened since `epoch`. Take it after the last
    /// await before the crypto, and drop it before the next one.
    fn keyring_at(&self, epoch: u64) -> Result<Arc<Keyring>> {
        self.seal
            .keyring_at(epoch)
            .map_err(|_| SecretsError::Sealed)
    }

    /// `version`, or the latest if `None`.
    pub async fn get(&self, caller: &Caller, path: &str, version: Option<u32>) -> Result<Secret> {
        observed("get", self.read(caller, path, version)).await
    }

    async fn read(&self, caller: &Caller, path: &str, version: Option<u32>) -> Result<Secret> {
        let path = Self::path(path)?;
        self.authorize(caller, Action::Read, Target::Path(&path))
            .await?;
        let epoch = self.unsealed_epoch()?;
        let stored = self.store.get(&path, version).await?;
        // After the await, before anything else (even "not found"): a seal
        // while the database was slow wins.
        let keyring = self.keyring_at(epoch)?;
        let Some(stored) = stored else {
            return Err(match version {
                Some(version) => SecretsError::VersionNotFound { path, version },
                None => SecretsError::NotFound { path },
            });
        };
        let version = stored.metadata.version;
        // A row's KEK is (its path's namespace, its kek_version).
        let namespace = path.namespace();
        let keyring = if keyring.kek(&namespace, stored.kek_version).is_some() {
            keyring
        } else {
            // Wrapped by a KEK another server rotated in (or a namespace it
            // created): refresh (with the root key this server holds) and
            // look again. Not holding the keyring across that await, and a
            // seal meanwhile still wins.
            drop(keyring);
            self.refresh_on_demand("unknown_kek", Some((&namespace, stored.kek_version)))
                .await;
            self.keyring_at(epoch)?
        };
        let kek = keyring
            .kek(&namespace, stored.kek_version)
            .ok_or(SecretsError::UnknownKek(stored.kek_version))?;
        let dek = kek.unwrap_dek(&path, version, &stored.wrapped_dek)?;
        let value = dek.decrypt(&path, version, &stored.ciphertext)?;
        Ok(Secret {
            metadata: stored.metadata,
            value,
        })
    }

    /// Stores `value` as the next version of `path`. Concurrent writes to
    /// the same path take turns on its lock in the data database, so none
    /// fails for losing a race (and the last one wins: see [`Secrets::put_if`]
    /// to avoid lost updates).
    pub async fn put(&self, caller: &Caller, path: &str, value: &[u8]) -> Result<SecretMetadata> {
        self.write(caller, path, value, None, &Labels::new()).await
    }

    /// Check-and-set: [`Secrets::put`], but only if the latest live version
    /// of `path` is still `expected` (as read before deciding what to
    /// write), else [`SecretsError::VersionMismatch`] and nothing is stored.
    /// `expected` 0 means "only if there is no live version": create, never
    /// overwrite. Versions are never reused, so a match can't be a different
    /// secret that happens to have the same number; a delete in between is a
    /// mismatch too (no live version, or a newer one).
    ///
    /// Checked under the path's write lock, which deletes take too, so
    /// nothing changes between the check and the commit.
    pub async fn put_if(
        &self,
        caller: &Caller,
        path: &str,
        value: &[u8],
        expected: u32,
    ) -> Result<SecretMetadata> {
        self.write(caller, path, value, Some(expected), &Labels::new())
            .await
    }

    /// [`Secrets::put`] (or with `expected`, [`Secrets::put_if`]) that also
    /// sets `labels` on the path, merged with its labels, in the put's own
    /// transaction: both or neither. Setting labels needs the `label`
    /// action too (asked only if there are any), on top of `write`.
    pub async fn put_labeled(
        &self,
        caller: &Caller,
        path: &str,
        value: &[u8],
        expected: Option<u32>,
        labels: &Labels,
    ) -> Result<SecretMetadata> {
        self.write(caller, path, value, expected, labels).await
    }

    async fn write(
        &self,
        caller: &Caller,
        path: &str,
        value: &[u8],
        expected: Option<u32>,
        labels: &Labels,
    ) -> Result<SecretMetadata> {
        observed(
            "put",
            self.write_unobserved(caller, path, value, expected, labels),
        )
        .await
    }

    async fn write_unobserved(
        &self,
        caller: &Caller,
        path: &str,
        value: &[u8],
        expected: Option<u32>,
        labels: &Labels,
    ) -> Result<SecretMetadata> {
        let path = Self::path(path)?;
        if value.len() > MAX_VALUE_SIZE {
            return Err(SecretsError::ValueTooLarge { size: value.len() });
        }
        labels::check(labels).map_err(SecretsError::InvalidLabels)?;
        self.authorize(caller, Action::Write, Target::Path(&path))
            .await?;
        if !labels.is_empty() {
            self.authorize(caller, Action::Label, Target::Path(&path))
                .await?;
        }
        // Only now, after authorization, does the namespace matter: telling
        // `NO_NAMESPACE` apart from `PERMISSION_DENIED` to any caller would
        // let anyone enumerate namespace names. A namespace this server
        // hasn't loaded (created on another server): one refresh first.
        let namespace = path.namespace();
        if self.seal.active_kek_version(&namespace).is_none() {
            self.refresh_on_demand("unknown_namespace", None).await;
        }
        let mut result = self.store_version(&path, value, expected, labels).await;
        if let Err(Failure {
            error: SecretsError::StaleKeyring(used),
            ..
        }) = &result
        {
            // The KEK this keyring wraps with is being destroyed (the data
            // database refused it, and nothing was stored): another server
            // rotated and retired it. Refresh (unless another call just
            // did), then once more, but only with a newer active KEK: the
            // same one would be refused again.
            let used = *used;
            if self.seal.active_kek_version(&namespace) == Some(used) {
                self.refresh_on_demand("kek_floor", None).await;
            }
            match self.seal.active_kek_version(&namespace) {
                Some(active) if active != used => {
                    result = self.store_version(&path, value, expected, labels).await;
                }
                // The namespace was deleted elsewhere (its floor raised past
                // every KEK it had), and the refresh dropped it.
                None if self.seal.keyring().is_ok() => {
                    result = Err(Failure {
                        error: SecretsError::NoNamespace(namespace.clone()),
                        at_commit: false,
                    });
                }
                _ => {}
            }
        }
        let outcome = match &result {
            Ok((stored, trimmed)) => {
                metrics().trimmed(*trimmed);
                let mut details = json!({"version": stored.version, "trimmed": trimmed});
                if let Some(expected) = expected {
                    details["expected_version"] = json!(expected);
                }
                if !labels.is_empty() {
                    // Keys only: labels aren't secret, but needn't be in the log.
                    details["labels_set"] = json!(labels.keys().collect::<Vec<_>>());
                }
                Outcome::Succeeded(details)
            }
            Err(failure) => failure.outcome(),
        };
        self.gate
            .outcome(caller, Action::Write, Target::Path(&path), "put", outcome);
        result.map(|(stored, _)| stored).map_err(|f| f.error)
    }

    /// The put itself, once authorized: the stored version and how many
    /// older ones it trimmed (`max_versions`).
    async fn store_version(
        &self,
        path: &SecretPath,
        value: &[u8],
        expected: Option<u32>,
        labels: &Labels,
    ) -> Result<(SecretMetadata, u64), Failure> {
        let epoch = self.unsealed_epoch()?;
        // Holds the path's write lock; dropped (rolled back) on any error
        // below.
        let pending = self.store.begin_put(path).await?;
        if let Some(expected) = expected {
            // After the lock wait, a seal wins over anything else.
            self.unsealed_since(epoch)?;
            let latest = pending.latest();
            if latest != (expected != 0).then_some(expected) {
                return Err(SecretsError::VersionMismatch {
                    path: path.clone(),
                    expected,
                    latest,
                }
                .into());
            }
        }
        // The version is bound into both ciphertexts, so it's fixed first.
        // Then synchronous crypto only: no await while the lock is held.
        let version = pending.version();
        let (kek_version, ciphertext, wrapped_dek) = {
            let keyring = self.keyring_at(epoch)?;
            let namespace = path.namespace();
            let (kek_version, kek) = keyring
                .active_kek(&namespace)
                .ok_or(SecretsError::NoNamespace(namespace))?;
            let dek = Dek::generate()?;
            let ciphertext = dek.encrypt(path, version, value)?;
            (kek_version, ciphertext, kek.wrap_dek(path, version, &dek)?)
        };
        let mut staged = pending
            .insert(&ciphertext, &wrapped_dek, kek_version)
            .await?;
        if !labels.is_empty() {
            staged.set_labels(labels).await?;
        }
        // The insert can stall too: last check before committing.
        self.unsealed_since(epoch)?;
        let trimmed = staged.trimmed();
        let stored = staged.commit().await.map_err(Failure::at_commit)?;
        Ok((stored, trimmed))
    }

    /// Makes a deleted version of `path` live again: `version` (alongside
    /// any live one: an older or trimmed version), or if `None` the newest
    /// deleted one, only while the path has no live version (undoing a
    /// delete; older ones stay deleted), else [`SecretsError::LiveVersion`]
    /// and nothing restored. Only within the retention: a purged version is
    /// gone.
    /// It's a write (the `write` action), done like a put: under the path's
    /// write lock, refused on a sealed server, audited (`"restore"`, with
    /// the version). The version limit isn't applied; the next put trims.
    pub async fn restore(
        &self,
        caller: &Caller,
        path: &str,
        version: Option<u32>,
    ) -> Result<SecretMetadata> {
        observed("restore", self.restore_unobserved(caller, path, version)).await
    }

    async fn restore_unobserved(
        &self,
        caller: &Caller,
        path: &str,
        version: Option<u32>,
    ) -> Result<SecretMetadata> {
        let path = Self::path(path)?;
        self.authorize(caller, Action::Write, Target::Path(&path))
            .await?;
        let result = self.restore_version(&path, version).await;
        let outcome = match &result {
            Ok(restored) => Outcome::Succeeded(json!({"version": restored.version})),
            Err(failure) => failure.outcome(),
        };
        self.gate.outcome(
            caller,
            Action::Write,
            Target::Path(&path),
            "restore",
            outcome,
        );
        result.map_err(|f| f.error)
    }

    async fn restore_version(
        &self,
        path: &SecretPath,
        version: Option<u32>,
    ) -> Result<SecretMetadata, Failure> {
        let epoch = self.unsealed_epoch()?;
        let pending = self.store.begin_restore(path, version).await?;
        // Before "nothing to restore", like delete: a seal meanwhile wins.
        self.unsealed_since(epoch)?;
        if let Some(latest) = pending.live() {
            return Err(SecretsError::LiveVersion {
                path: path.clone(),
                latest,
            }
            .into());
        }
        let Some(restored) = pending.restored().cloned() else {
            return Err(SecretsError::NothingToRestore {
                path: path.clone(),
                version,
            }
            .into());
        };
        pending.commit().await.map_err(Failure::at_commit)?;
        Ok(restored)
    }

    /// Deletes every version of `path`.
    pub async fn delete(&self, caller: &Caller, path: &str) -> Result<()> {
        observed("delete", self.delete_unobserved(caller, path)).await
    }

    async fn delete_unobserved(&self, caller: &Caller, path: &str) -> Result<()> {
        let path = Self::path(path)?;
        self.authorize(caller, Action::Delete, Target::Path(&path))
            .await?;
        let result = self.delete_versions(&path).await;
        let outcome = match &result {
            Ok(deleted) => Outcome::Succeeded(json!({"deleted": deleted})),
            Err(failure) => failure.outcome(),
        };
        self.gate.outcome(
            caller,
            Action::Delete,
            Target::Path(&path),
            "delete",
            outcome,
        );
        result.map(drop).map_err(|f| f.error)
    }

    /// The delete itself, once authorized: how many versions it marked.
    async fn delete_versions(&self, path: &SecretPath) -> Result<u64, Failure> {
        let epoch = self.unsealed_epoch()?;
        let pending = self.store.begin_delete(path).await?;
        // Before "not found", like get: a seal while the database was slow
        // wins. Dropping `pending` rolls back.
        self.unsealed_since(epoch)?;
        let deleted = pending.count();
        if deleted == 0 {
            return Err(SecretsError::NotFound { path: path.clone() }.into());
        }
        pending.commit().await.map_err(Failure::at_commit)?;
        Ok(deleted)
    }

    /// Latest version of every secret strictly below `prefix` (by whole
    /// segments), or of every secret if `prefix` is empty, in path order, one
    /// page at a time: `page_token` is empty for the first page, then the
    /// previous page's [`Page::next_page_token`]. `page_size` 0 means
    /// [`DEFAULT_PAGE_SIZE`]; above [`MAX_PAGE_SIZE`] it is lowered to it.
    ///
    /// Pages aren't a snapshot: a secret created or deleted meanwhile may or
    /// may not show up. But no path is listed twice, since each page starts
    /// strictly after the last path of the previous one.
    /// With `labels`, only paths whose labels include every one of them.
    pub async fn list(
        &self,
        caller: &Caller,
        prefix: &str,
        page_size: u32,
        page_token: &str,
        labels: &Labels,
    ) -> Result<Page> {
        observed(
            "list",
            self.list_unobserved(caller, prefix, page_size, page_token, labels),
        )
        .await
    }

    async fn list_unobserved(
        &self,
        caller: &Caller,
        prefix: &str,
        page_size: u32,
        page_token: &str,
        labels: &Labels,
    ) -> Result<Page> {
        let prefix = (!prefix.is_empty())
            .then(|| Self::path(prefix))
            .transpose()?;
        let after = page_token::decode(page_token, prefix.as_ref())?;
        labels::check(labels).map_err(SecretsError::InvalidLabels)?;
        let target = prefix.as_ref().map_or(Target::All, Target::Below);
        self.authorize(caller, Action::List, target).await?;
        let epoch = self.unsealed_epoch()?;
        let size = match page_size {
            0 => DEFAULT_PAGE_SIZE,
            n => n.min(MAX_PAGE_SIZE),
        };
        // One more than asked for: whether it exists says if there's a next
        // page, so a full last page isn't followed by an empty one.
        let mut secrets = self
            .store
            .list(prefix.as_ref(), after.as_ref(), size + 1, labels)
            .await?;
        // Paths are metadata, but can still say a lot: none after a seal.
        self.unsealed_since(epoch)?;
        let next_page_token = if secrets.len() > size as usize {
            secrets.truncate(size as usize);
            secrets
                .last()
                .map(|last| page_token::encode(&last.path))
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Page {
            secrets,
            next_page_token,
        })
    }

    /// The history of `path`: every version still stored, live and deleted
    /// alike (purged ones are gone, so numbers can have gaps), newest
    /// first, metadata only, so a caller can find the version to get or
    /// restore. Paged like [`Secrets::list`]. The `list` action on the
    /// path, not `read`: it's metadata, what a listing shows of the latest
    /// version, so a metadata-only identity can see it, and the audit log
    /// tells it apart from reading a value. Refused while sealed, like
    /// listing. [`SecretsError::NotFound`] if nothing of `path` is stored.
    /// `path`'s metadata as a whole (see [`PathMetadata`]): never values.
    /// Like the history, the `list` action on the path, refused while
    /// sealed, `NotFound` for a path never written.
    pub async fn metadata(&self, caller: &Caller, path: &str) -> Result<PathMetadata> {
        observed("metadata", self.metadata_unobserved(caller, path)).await
    }

    async fn metadata_unobserved(&self, caller: &Caller, path: &str) -> Result<PathMetadata> {
        let path = Self::path(path)?;
        self.authorize(caller, Action::List, Target::Path(&path))
            .await?;
        let epoch = self.unsealed_epoch()?;
        let metadata = self.store.path_metadata(&path).await?;
        self.unsealed_since(epoch)?;
        metadata.ok_or(SecretsError::NotFound { path })
    }

    /// Changes `path`'s labels: `set` added or replaced, `remove` removed
    /// (see `ferritor_core::labels`); returns them after the change. The
    /// `label` action on the path, refused while sealed like a write, and
    /// audited (`"label"`, with the keys set and removed, never values).
    /// `NotFound` for a path never written.
    pub async fn update_labels(
        &self,
        caller: &Caller,
        path: &str,
        set: &Labels,
        remove: &[String],
    ) -> Result<Labels> {
        observed(
            "label",
            self.update_labels_unobserved(caller, path, set, remove),
        )
        .await
    }

    async fn update_labels_unobserved(
        &self,
        caller: &Caller,
        path: &str,
        set: &Labels,
        remove: &[String],
    ) -> Result<Labels> {
        let path = Self::path(path)?;
        labels::check_change(set, remove).map_err(SecretsError::InvalidLabels)?;
        self.authorize(caller, Action::Label, Target::Path(&path))
            .await?;
        let result = async {
            let epoch = self.unsealed_epoch()?;
            let staged = self.store.change_labels(&path, set, remove).await?;
            self.unsealed_since(epoch)?;
            staged.commit().await.map_err(Failure::at_commit)
        }
        .await;
        let outcome = match &result {
            Ok(labels) => Outcome::Succeeded(json!({
                "set": set.keys().collect::<Vec<_>>(),
                "removed": remove,
                "labels": labels.len(),
            })),
            Err(failure) => failure.outcome(),
        };
        self.gate
            .outcome(caller, Action::Label, Target::Path(&path), "label", outcome);
        result.map_err(|f| f.error)
    }

    pub async fn versions(
        &self,
        caller: &Caller,
        path: &str,
        page_size: u32,
        page_token: &str,
    ) -> Result<VersionPage> {
        observed(
            "versions",
            self.versions_unobserved(caller, path, page_size, page_token),
        )
        .await
    }

    async fn versions_unobserved(
        &self,
        caller: &Caller,
        path: &str,
        page_size: u32,
        page_token: &str,
    ) -> Result<VersionPage> {
        let path = Self::path(path)?;
        let before = page_token::decode_version(page_token)?;
        self.authorize(caller, Action::List, Target::Path(&path))
            .await?;
        let epoch = self.unsealed_epoch()?;
        let size = match page_size {
            0 => DEFAULT_PAGE_SIZE,
            n => n.min(MAX_PAGE_SIZE),
        };
        // One more than asked for, as in `list`.
        let mut versions = self.store.versions(&path, before, size + 1).await?;
        self.unsealed_since(epoch)?;
        if before.is_none() && versions.is_empty() {
            return Err(SecretsError::NotFound { path });
        }
        let next_page_token = if versions.len() > size as usize {
            versions.truncate(size as usize);
            versions
                .last()
                .map(|last| page_token::encode_version(last.metadata.version))
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(VersionPage {
            versions,
            next_page_token,
        })
    }
}

/// One page of [`Secrets::versions`].
#[derive(Debug)]
pub struct VersionPage {
    pub versions: Vec<VersionInfo>,
    /// Pass it back for the next page. Empty on the last page.
    pub next_page_token: String,
}

/// The largest value a secret can hold, through any API. The transports'
/// own message limits are sized from it (`grpc::secrets_service`, `http`),
/// so a value stored through one can always be written back through the
/// other.
pub const MAX_VALUE_SIZE: usize = 1024 * 1024;

/// The page size when the caller doesn't ask for one.
pub const DEFAULT_PAGE_SIZE: u32 = 100;
/// The most secrets one page returns, whatever the caller asks for.
pub const MAX_PAGE_SIZE: u32 = 1000;

/// One page of [`Secrets::list`].
#[derive(Debug)]
pub struct Page {
    pub secrets: Vec<SecretMetadata>,
    /// Pass it back for the next page. Empty on the last page.
    pub next_page_token: String,
}

/// A page token is the last path of the previous page, hex-encoded so
/// callers treat it as opaque (and the format can change); for a history
/// ([`Secrets::versions`]), the last version, as 8 hex digits. It's no secret
/// and grants nothing: it holds a path the caller was just shown, and every
/// page is authorized again for its prefix. A token must lie below the
/// listing's prefix, so it only resumes a listing of that same prefix (the
/// query keeps the prefix's range as well, so it couldn't widen it anyway).
mod page_token {
    use ferritor_core::path::SecretPath;

    use super::{Result, SecretsError};

    pub fn encode_version(last: u32) -> String {
        format!("{last:08x}")
    }

    /// `None` for the first page (an empty token). Not bound to a path: it
    /// only bounds the versions of whichever path is asked for, which the
    /// caller is authorized for anyway.
    pub fn decode_version(token: &str) -> Result<Option<u32>> {
        if token.is_empty() {
            return Ok(None);
        }
        // Exactly what `encode_version` makes: no sign, no other length.
        if token.len() != 8 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(SecretsError::InvalidPageToken);
        }
        u32::from_str_radix(token, 16)
            .ok()
            .filter(|&v| v > 0)
            .map(Some)
            .ok_or(SecretsError::InvalidPageToken)
    }

    pub fn encode(last: &SecretPath) -> String {
        last.as_str().bytes().map(|b| format!("{b:02x}")).collect()
    }

    /// `None` for the first page (an empty token).
    pub fn decode(token: &str, prefix: Option<&SecretPath>) -> Result<Option<SecretPath>> {
        if token.is_empty() {
            return Ok(None);
        }
        let invalid = || SecretsError::InvalidPageToken;
        let (pairs, rest) = token.as_bytes().as_chunks::<2>();
        if !rest.is_empty() {
            return Err(invalid());
        }
        let nibble = |c: u8| {
            char::from(c)
                .to_digit(16)
                .and_then(|d| u8::try_from(d).ok())
        };
        let bytes = pairs
            .iter()
            .map(|&[hi, lo]| Some(nibble(hi)? << 4 | nibble(lo)?))
            .collect::<Option<Vec<u8>>>()
            .ok_or_else(invalid)?;
        let path = String::from_utf8(bytes)
            .ok()
            .and_then(|path| SecretPath::parse(&path).ok())
            .ok_or_else(invalid)?;
        match prefix {
            Some(prefix) if !path.is_under(prefix) => Err(invalid()),
            _ => Ok(Some(path)),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn p(path: &str) -> SecretPath {
            SecretPath::parse(path).unwrap()
        }

        #[test]
        fn a_token_round_trips_and_looks_opaque() {
            let token = encode(&p("app/db"));
            assert_eq!(token, "6170702f6462");
            assert_eq!(decode(&token, None).unwrap(), Some(p("app/db")));
            assert_eq!(decode(&token, Some(&p("app"))).unwrap(), Some(p("app/db")));
            assert_eq!(decode("", Some(&p("app"))).unwrap(), None);
        }

        #[test]
        fn a_version_token_round_trips_and_garbage_is_refused() {
            assert_eq!(encode_version(42), "0000002a");
            assert_eq!(decode_version("0000002a").unwrap(), Some(42));
            assert_eq!(decode_version("").unwrap(), None);
            for token in [
                "2a",
                "+000002a",
                "0000002g",
                "00000000",
                "000000002a",
                "é0000000",
            ] {
                assert!(
                    matches!(decode_version(token), Err(SecretsError::InvalidPageToken)),
                    "{token}"
                );
            }
        }

        #[test]
        fn a_token_from_another_prefix_or_garbage_is_refused() {
            let token = encode(&p("app/db"));
            for (token, prefix) in [
                // From another listing: outside this prefix, or the prefix itself.
                (token.as_str(), Some(p("other"))),
                (token.as_str(), Some(p("app/db"))),
                // Not hex, odd length, not UTF-8, not a canonical path.
                ("app/db", None),
                ("617", None),
                ("+f", None),
                ("ff", None),
                ("2f61", None),
                ("é", None),
            ] {
                assert!(
                    matches!(
                        decode(token, prefix.as_ref()),
                        Err(SecretsError::InvalidPageToken)
                    ),
                    "{token} under {prefix:?}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A write that fails at its commit may have landed (the connection
    /// can drop after Postgres commits): its outcome is unknown, not failed.
    /// Anywhere before, nothing was stored.
    #[test]
    fn only_a_failed_commit_is_an_unknown_outcome() {
        assert!(matches!(
            Failure::at_commit(DatastoreError::Timeout).outcome(),
            Outcome::Unknown(_)
        ));
        assert!(matches!(
            Failure::from(DatastoreError::Timeout).outcome(),
            Outcome::Failed { .. }
        ));
        assert!(matches!(
            Failure::from(SecretsError::Sealed).outcome(),
            Outcome::Failed { .. }
        ));
    }
}
