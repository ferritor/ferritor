//! The seal state machine: initialization, unsealing from Shamir shares,
//! sealing, KEK rotation and rekeying. Transport-agnostic; `grpc` maps it to
//! `SystemService`.
//!
//! Admin operations are serialized by one async mutex, held across their
//! keys-DB calls, so within this process they never interleave. The unsealed
//! [`Keyring`] lives behind a separate lock that is never held across an
//! await, so secret operations can read it without queueing behind an admin
//! call. Across processes, the keystore's row locks and generation checks
//! catch conflicts ([`SealError::KeyringChanged`]); this process does not
//! reload a keyring changed elsewhere.
//!
//! Sealing must not wait for an admin call stuck on the database, so
//! [`Seal::seal`] drops the keyring before taking the admin lock. To stop a
//! call already in progress from publishing a keyring afterwards, every seal
//! bumps an epoch, and a publish is refused if the epoch changed since its
//! call began.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use crate::authz::{Stored, StoredPolicies, Target};
use crate::auto_unseal::{AutoUnseal, AutoUnsealError};
use crate::error_chain;
use crate::policy_store::{self, Floor, PolicyView, RevisionFloor, Unverified};
use crate::root_ledger::RootLedger;
use ferritor_core::crypto::{self, CryptoError, IssuingRecord, Kek, RootKey, Share, ShareParams};
use ferritor_core::labels::Labels;
use ferritor_core::path::{Namespace, SecretPath};
use ferritor_core::policy::SecretAction;
use tokio::sync::{Mutex, watch};

use ferritor_keystore::{
    DeletedNamespace, INITIAL_GENERATION, IssuingKeyState, IssuingRotation, IssuingSet,
    IssuingTagger, KekInfo, KekState, Keystore, KeystoreError, NamespaceState, Numbering,
    RekeyRewrap, RewrappedKek, SealConfig, SealWrap, StoredKek, StoredNamespace,
};

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("the seal is not initialized")]
    NotInitialized,
    #[error("the seal is already initialized")]
    AlreadyInitialized,
    #[error("{}", ferritor_core::messages::SEALED)]
    Sealed,
    #[error("threshold must be between 2 and the share count, got {threshold} of {shares}")]
    InvalidShareParams { threshold: u8, shares: u8 },
    #[error("invalid share")]
    InvalidShare(#[source] CryptoError),
    #[error("share {0} was already submitted")]
    DuplicateShare(u8),
    #[error("the submitted shares do not reconstruct the root key; progress was reset")]
    WrongShares,
    #[error("a rekey is already in progress")]
    RekeyInProgress,
    #[error("no rekey is in progress")]
    NoRekey,
    #[error("the rekey is verifying: submit the new shares with RekeyVerify")]
    RekeyVerifying,
    #[error("the rekey is still collecting current shares")]
    RekeyAuthorizing,
    #[error(
        "the new root key is already stored (generation {generation}), so the rekey \
         can't be cancelled: the old shares no longer work; keep the new shares"
    )]
    RekeyCommitted { generation: u32 },
    #[error(
        "could not confirm whether the new root key was stored: keep the new \
         shares and retry RekeyVerify"
    )]
    RekeyOutcomeUnknown,
    #[error("nonce does not match the rekey in progress")]
    NonceMismatch,
    /// Another server changed the keyring, or an earlier call here timed out
    /// but was stored (e.g. a rotate): either way this server's keyring is
    /// behind the database.
    #[error(
        "the keyring changed outside this server's view (another server, or an \
         earlier call that timed out but was stored); retry once it's refreshed \
         (on its own within keyring_refresh_secs, or on SIGHUP)"
    )]
    KeyringChanged(#[source] KeystoreError),
    /// Another server rekeyed: the stored KEKs are wrapped by a root key this
    /// server doesn't have, so a refresh can't follow.
    #[error(
        "the root key was replaced by a rekey (generation {stored}; this server has \
         {running}): seal and unseal this server with the new shares"
    )]
    RekeyedElsewhere { running: u32, stored: u32 },
    #[error("KEK version numbers are exhausted")]
    VersionExhausted,
    /// This server's keyring has no active KEK for the namespace: it
    /// doesn't exist, or this server hasn't loaded it yet (refresh first).
    #[error("there is no namespace `{0}` (create it first)")]
    NoNamespace(Namespace),
    #[error("stored keyring is inconsistent: {0}")]
    Corrupt(&'static str),
    /// Retryable. For a write, the outcome is unknown: a rotate may have
    /// been stored (the next unseal loads it), and a rekey commit is resolved
    /// separately (see `Seal::is_committed`).
    #[error("the keys database did not respond in time")]
    KeysTimeout,
    /// A rekey can't re-wrap the stored policy key: it doesn't open under
    /// the current root key. Nothing was committed.
    #[error(
        "the stored policy key doesn't open under the current root key, so a rekey can't re-wrap \
         it; repair the stored policies first (`ferritor policy apply --prune` from their source of \
         truth creates a new key), then rekey. Nothing was changed: the current shares still work"
    )]
    PolicyKeyUnusable,
    /// A rekey can't re-wrap the active issuing key: it doesn't open under
    /// the current root key. Nothing was committed.
    #[error(
        "the stored issuing key doesn't open under the current root key, so a rekey can't re-wrap \
         it; rotate it first (`ferritor identity rotate --now`), then rekey. Nothing was changed: the \
         current shares still work"
    )]
    IssuingKeyUnusable,
    #[error("the workload-identity issuing CA already exists: rotate it instead")]
    IssuingKeyExists,
    #[error("there is no workload-identity issuing CA: initialize one (`ferritor identity init`)")]
    NoIssuingKey,
    /// The stored issuing keys don't verify, or were rolled back.
    #[error(
        "the stored issuing keys don't verify under the root key, or were rolled back (changed \
         in the keys database): only `ferritor identity rotate --now` replaces them, revoking every \
         one"
    )]
    IssuingKeysUnverified,
    /// The issuing revision floor (data database) couldn't be read, so no
    /// write to the issuing keys can be checked against it.
    #[error("the issuing revision floor couldn't be read: {0}")]
    IssuingFloor(String),
    #[error("the issuing CA")]
    Identity(#[source] crate::identity::ca::CaError),
    /// The root key's generation is below the data database's floor: the
    /// keys database went back (a restore, or a failover that lost a
    /// rekey's commit).
    #[error("{}", below_floor_message(*generation, *floor))]
    RootBelowFloor { generation: u32, floor: u32 },
    /// No commitment in the data database verifies under this root key.
    #[error(
        "no root commitment in the data database matches this root key (generation \
         {generation}): either the data database lost it (restored from before a rekey, or a \
         failover lost the write), or the keys database holds a root key that isn't this \
         deployment's. With a threshold of shares, `ferritor unseal --recommit` re-commits it if \
         the data database proves it's the key the data was written under"
    )]
    RootUncommitted { generation: u32 },
    /// A re-commit's continuity check: no stored version opens.
    #[error(
        "re-committing refused: no stored secret version opens under this root key, so it isn't \
         the one the data was written under: the keys database substituted, or every stored \
         version is on a KEK that's lost or destroyed. Nothing was changed"
    )]
    RecommitDiscontinuous,
    /// A re-commit with nothing in the data database to prove continuity.
    #[error(
        "re-committing refused: the data database holds no secret version to prove this root \
         key's continuity with; see https://ferritor.dev/operations/backup-restore for the \
         deliberate path"
    )]
    RecommitNothingStored,
    /// An init after one committed (the floor is set), whatever the keys
    /// database says.
    #[error(
        "init refused: a root key already committed in the data database (generation floor \
         {floor}); a keys database that looks uninitialized doesn't start a new deployment. See \
         https://ferritor.dev/operations/backup-restore"
    )]
    InitAfterCommit { floor: u32 },
    /// The root commitments or the floor (data database) couldn't be read
    /// or written.
    #[error("the root commitments (data database) couldn't be read or written: {0}")]
    RootLedger(String),
    /// The auto-unseal key management service.
    #[error("auto-unseal")]
    AutoUnseal(#[source] AutoUnsealError),
    /// The unwrapped root key isn't the one the seal config's `root_check`
    /// names: the wrap is of another deployment's (or an older) key.
    #[error(
        "the root key the key management service unwrapped doesn't match the seal config: the \
         stored wrap isn't this deployment's current root key"
    )]
    WrapMismatch,
    /// A rekey through this server would change how the root key is
    /// protected for every server, unasked.
    #[error(
        "this rekey would change how the root key is protected for every server: the \
         deployment's is {stored}, this server's config says {here}. Rekey through a server \
         configured like the others, or, to change it on purpose, `ferritor rekey start --seal \
         {suggest}`"
    )]
    RekeyWouldChangeSeal {
        stored: String,
        here: String,
        suggest: &'static str,
    },
    /// A rekey asked to change the protection to what this server isn't
    /// configured for.
    #[error(
        "this rekey asks for --seal {asked}, but this server's config says {here}: configure \
         [seal] on it first (and restart it)"
    )]
    SealChangeUnconfigured { asked: &'static str, here: String },
    #[error("keystore failure")]
    Keystore(#[source] KeystoreError),
    #[error("crypto failure")]
    Crypto(#[source] CryptoError),
}

type Result<T, E = SealError> = std::result::Result<T, E>;

fn below_floor_message(generation: u32, floor: u32) -> String {
    let behind = if generation.checked_add(1) == Some(floor) {
        "one generation behind: if it failed over and lost a rekey's commit, see \
         https://ferritor.dev/operations/high-availability (the old shares are the right ones; \
         set the new ones aside)"
    } else {
        "a keys database older than the last rekey (a restore?): see \
         https://ferritor.dev/operations/backup-restore"
    };
    format!(
        "the keys database's root key is generation {generation}, below the data database's \
         root-generation floor {floor}: {behind}"
    )
}

/// The longest wait between two retries of a floor raise.
const FLOOR_RETRY_MAX: Duration = Duration::from_secs(60);

const DEFAULT_COMMIT_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

impl From<KeystoreError> for SealError {
    fn from(e: KeystoreError) -> Self {
        match e {
            KeystoreError::NotInitialized => Self::NotInitialized,
            KeystoreError::AlreadyInitialized => Self::AlreadyInitialized,
            KeystoreError::GenerationMismatch { .. }
            | KeystoreError::RotateConflict { .. }
            | KeystoreError::IssuingKeyConflict { .. }
            | KeystoreError::KekSetMismatch => Self::KeyringChanged(e),
            KeystoreError::Timeout => Self::KeysTimeout,
            KeystoreError::IssuingKeyExists => Self::IssuingKeyExists,
            KeystoreError::NoIssuingKey => Self::NoIssuingKey,
            KeystoreError::IssuingKeyUnusable => Self::IssuingKeyUnusable,
            KeystoreError::IssuingKeysUnverified => Self::IssuingKeysUnverified,
            other => Self::Keystore(other),
        }
    }
}

impl From<CryptoError> for SealError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::InvalidShareParams { threshold, shares } => {
                Self::InvalidShareParams { threshold, shares }
            }
            other => Self::Crypto(other),
        }
    }
}

/// What a [`Seal::refresh`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refreshed {
    /// Each namespace's active KEK version now (a namespace whose KEKs are
    /// all vanished has none).
    pub active: Vec<(Namespace, u32)>,
    /// Whether that differs from what this server had.
    pub changed: bool,
    /// Whether the KEKs were read at all: false when the keyring already
    /// had the version asked for, so nothing was loaded.
    pub loaded: bool,
    /// KEKs this server holds that the keys database no longer has (and
    /// didn't destroy): kept for reading only (see [`Keyring`]).
    pub vanished: Vec<(Namespace, u32)>,
}

/// One namespace's KEKs in a [`Keyring`].
#[derive(Clone)]
struct NamespaceKeys {
    keks: BTreeMap<u32, Arc<Kek>>,
    /// The KEK that wraps new DEKs: always a stored one. `None` only for a
    /// namespace the keys database lost entirely (every KEK vanished).
    active: Option<(u32, Arc<Kek>)>,
    /// Versions in `keks` that the keys database doesn't have.
    vanished: BTreeSet<u32>,
}

/// A namespace's keys without the key material: the active version, every
/// version held, the vanished ones.
type KeysSummary = (Option<u32>, Vec<u32>, Vec<u32>);

impl NamespaceKeys {
    /// What a refresh compares to tell whether anything changed.
    fn summary(&self) -> KeysSummary {
        (
            self.active.as_ref().map(|(v, _)| *v),
            self.keks.keys().copied().collect(),
            self.vanished.iter().copied().collect(),
        )
    }
}

/// The unsealed key material: the root key, and each namespace's KEKs.
/// Immutable; rotate, rekey and namespace changes publish a new one.
///
/// It may also hold **vanished** KEKs: ones this server loaded that the keys
/// database no longer has, without having destroyed them (a failover that
/// lost a rotation or a namespace's creation, a restore of an older backup).
/// This server's copy is then the only one left, so a refresh keeps them,
/// for reading only: they unwrap the rows they wrapped (and rewrap moves
/// those rows onto their namespace's active KEK, rescuing them), but never
/// wrap a new DEK; an active KEK is always a stored one. They live until the
/// server seals, or until the keys database has the version again (then the
/// stored one wins).
pub struct Keyring {
    root: Arc<RootKey>,
    generation: u32,
    namespaces: BTreeMap<Namespace, NamespaceKeys>,
    issuing: IssuingKeys,
}

/// The workload-identity issuing keys this server holds: the active one,
/// loaded (its private key unwrapped by the root key, so it goes with the
/// keyring at seal), and every stored key's certificate and state, for
/// trusting what each signed.
#[derive(Clone, Debug, Default)]
pub struct IssuingKeys {
    pub active: Option<Arc<crate::identity::ca::IssuingCa>>,
    pub stored: Vec<IssuingKeyInfo>,
    /// The set's revision (0: none).
    pub revision: u64,
}

/// Why the stored issuing keys aren't trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssuingUnverified {
    /// The set's tag doesn't verify under the root key (or is missing next
    /// to keys): added, changed or removed without it.
    Tag,
    /// A set below the floor or the highest revision this server saw: an
    /// older one written back, or the keys wiped.
    Rollback { revision: u64, floor: u64 },
    /// The floor couldn't be read, so a rollback couldn't be ruled out.
    Floor(String),
}

impl std::fmt::Display for IssuingUnverified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tag => f.write_str(
                "their tag doesn't verify under the root key: added, changed or removed in the \
                 keys database by someone without it",
            ),
            Self::Rollback { revision, floor } => write!(
                f,
                "revision {revision} is below {floor}, the highest written: an older set written \
                 back, or the keys wiped"
            ),
            Self::Floor(error) => write!(f, "the issuing revision floor couldn't be read: {error}"),
        }
    }
}

/// The root key, tagging and verifying the issuing set for the keystore.
struct Tagger<'a>(&'a RootKey);

impl IssuingTagger for Tagger<'_> {
    fn tag(&self, revision: u64, records: &[IssuingRecord<'_>]) -> Option<Vec<u8>> {
        self.0.tag_issuing_set(revision, records).ok()
    }

    fn verifies(&self, set: &IssuingSet) -> bool {
        set.tag.as_ref().is_some_and(|tag| {
            self.0
                .verifies_issuing_set(set.revision, &set.records(), tag)
        })
    }
}

/// A stored issuing key, without its private part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuingKeyInfo {
    pub version: u32,
    pub state: IssuingKeyState,
    /// DER.
    pub certificate: Vec<u8>,
    pub created_at: time::OffsetDateTime,
    pub retired_at: Option<time::OffsetDateTime>,
}

/// A rekey commit's re-wrapping, from the current root key to the new.
struct Rewrapping<'a> {
    current: &'a RootKey,
    new: &'a RootKey,
    /// The new root key's KMS wrap (auto-unseal), or none.
    wrap: Option<SealWrap>,
}

impl RekeyRewrap for Rewrapping<'_> {
    fn seal_wrap(&self) -> Option<&SealWrap> {
        self.wrap.as_ref()
    }

    fn policy_key(&self, wrapped: &[u8]) -> Option<Vec<u8>> {
        let key = self.current.unwrap_policy_key(wrapped).ok()?;
        self.new.wrap_policy_key(&key).ok()
    }

    fn issuing_key(&self, version: u32, wrapped: &[u8]) -> Option<Vec<u8>> {
        let key = self.current.unwrap_issuing_key(version, wrapped).ok()?;
        self.new.wrap_issuing_key(version, &key).ok()
    }

    /// Only a set the current root key vouches for is vouched for by the
    /// new one.
    fn issuing_tag(&self, set: &IssuingSet) -> Option<Vec<u8>> {
        Tagger(self.current)
            .verifies(set)
            .then(|| self.new.tag_issuing_set(set.revision, &set.records()).ok())
            .flatten()
    }
}

impl IssuingKeys {
    /// From the stored set, if it verifies under `root` at a revision not
    /// below `floor`: every certificate, and the active key loaded. A set
    /// that doesn't is trusted not at all (the caller keeps what it had, or
    /// nothing). An active key that doesn't open (or doesn't match its
    /// certificate) is logged and left out: no certificate is issued until
    /// it's rotated, but nothing else depends on it, so unsealing and
    /// secrets go on.
    fn load(
        root: &RootKey,
        set: IssuingSet,
        floor: u64,
    ) -> std::result::Result<Self, IssuingUnverified> {
        if set.revision < floor {
            return Err(IssuingUnverified::Rollback {
                revision: set.revision,
                floor,
            });
        }
        if set.keys.is_empty() && set.tag.is_none() {
            return Ok(Self::default());
        }
        if !Tagger(root).verifies(&set) {
            return Err(IssuingUnverified::Tag);
        }
        let revision = set.revision;
        let mut active = None;
        let mut infos = Vec::with_capacity(set.keys.len());
        for key in set.keys {
            if let (IssuingKeyState::Active, Some(wrapped)) = (key.state, &key.wrapped_key) {
                let loaded = root
                    .unwrap_issuing_key(key.version, wrapped)
                    .map_err(|e| error_chain(&e))
                    .and_then(|pkcs8| {
                        crate::identity::ca::IssuingCa::load(key.version, &pkcs8, &key.certificate)
                            .map_err(|e| error_chain(&e))
                    });
                match loaded {
                    Ok(ca) => active = Some(Arc::new(ca)),
                    Err(error) => tracing::error!(
                        version = key.version,
                        error,
                        "the active issuing key doesn't load: no workload certificate is issued \
                         until it's rotated (`ferritor identity rotate --now`)"
                    ),
                }
            }
            infos.push(IssuingKeyInfo {
                version: key.version,
                state: key.state,
                certificate: key.certificate,
                created_at: key.created_at,
                retired_at: key.retired_at,
            });
        }
        Ok(Self {
            active,
            stored: infos,
            revision,
        })
    }

    fn summary(&self) -> (u64, Vec<(u32, IssuingKeyState, bool)>) {
        (self.revision, self.summary_keys())
    }

    fn summary_keys(&self) -> Vec<(u32, IssuingKeyState, bool)> {
        self.stored
            .iter()
            .map(|k| {
                let loaded = self
                    .active
                    .as_ref()
                    .is_some_and(|a| a.version() == k.version);
                (k.version, k.state, loaded)
            })
            .collect()
    }
}

impl Keyring {
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The workload-identity issuing keys (see [`IssuingKeys`]).
    pub fn issuing(&self) -> &IssuingKeys {
        &self.issuing
    }

    /// The KEK that wraps `namespace`'s new DEKs, with its version; `None`
    /// for a namespace this keyring doesn't have (or lost entirely).
    pub fn active_kek(&self, namespace: &Namespace) -> Option<(u32, &Kek)> {
        self.namespaces
            .get(namespace)?
            .active
            .as_ref()
            .map(|(version, kek)| (*version, &**kek))
    }

    pub fn kek(&self, namespace: &Namespace, version: u32) -> Option<&Kek> {
        self.namespaces
            .get(namespace)?
            .keks
            .get(&version)
            .map(|k| &**k)
    }

    /// The namespaces this keyring holds KEKs of, by name.
    pub fn namespaces(&self) -> impl Iterator<Item = &Namespace> + '_ {
        self.namespaces.keys()
    }

    /// Every KEK version of `namespace` this keyring holds, ascending
    /// (vanished ones included: they're what rewrap rescues rows from).
    pub fn versions(&self, namespace: &Namespace) -> Vec<u32> {
        self.namespaces
            .get(namespace)
            .map(|keys| keys.keks.keys().copied().collect())
            .unwrap_or_default()
    }

    /// `namespace`'s vanished KEK versions (see [`Keyring`]), ascending.
    pub fn vanished(&self, namespace: &Namespace) -> Vec<u32> {
        self.namespaces
            .get(namespace)
            .map(|keys| keys.vanished.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Every vanished KEK, of every namespace.
    pub fn all_vanished(&self) -> Vec<(Namespace, u32)> {
        self.namespaces
            .iter()
            .flat_map(|(ns, keys)| keys.vanished.iter().map(move |v| (ns.clone(), *v)))
            .collect()
    }

    fn summary(&self) -> BTreeMap<&Namespace, KeysSummary> {
        self.namespaces
            .iter()
            .map(|(ns, keys)| (ns, keys.summary()))
            .collect()
    }

    /// A copy with `namespace`'s keys replaced by `keys` (removed if `None`).
    fn with(&self, namespace: &Namespace, keys: Option<NamespaceKeys>) -> Self {
        let mut namespaces = self.namespaces.clone();
        match keys {
            Some(keys) => {
                namespaces.insert(namespace.clone(), keys);
            }
            None => {
                namespaces.remove(namespace);
            }
        }
        Self {
            root: Arc::clone(&self.root),
            generation: self.generation,
            namespaces,
            issuing: self.issuing.clone(),
        }
    }

    /// A copy with the issuing keys replaced.
    fn with_issuing(&self, issuing: IssuingKeys) -> Self {
        Self {
            root: Arc::clone(&self.root),
            generation: self.generation,
            namespaces: self.namespaces.clone(),
            issuing,
        }
    }
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring")
            .field("generation", &self.generation)
            .field("namespaces", &self.summary())
            .field("issuing", &self.issuing.summary())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub initialized: bool,
    pub sealed: bool,
    pub shares: u8,
    pub threshold: u8,
    /// Current seal generation (0 if uninitialized): the one valid shares
    /// carry. Tells operators which set to keep after a rekey.
    pub generation: u32,
    /// Shares received toward the current unseal attempt.
    pub progress: usize,
    /// The rekey collecting shares, if any.
    pub rekey: Option<RekeyStatus>,
    /// This unseal re-committed the root key (`unseal --recommit`).
    pub recommitted: bool,
    /// Auto-unseal and the hold: in a status call's answer only.
    pub auto_unseal: Option<AutoUnsealStatus>,
}

/// A rekey in progress, as `status` reports it, so operators can recover a
/// nonce lost with `rekey_start`'s reply. The nonce guards against applying
/// shares to the wrong attempt. Cancel needs only the nonce, so replies show
/// it only to callers who may `Rekey` (`grpc::seal_status`; see `authz`);
/// others still see phase and progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RekeyStatus {
    pub nonce: String,
    pub phase: RekeyPhase,
    pub progress: usize,
    pub required: u8,
    /// While verifying, the generation the new shares carry. If the stored
    /// generation already equals it, the commit landed unconfirmed.
    pub generation: Option<u32>,
}

/// What [`Seal::seal`] did with a rekey in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingRekey {
    /// Nothing was pending.
    None,
    /// Dropped; the current shares still work.
    Discarded,
    /// It was already stored: only the new shares unseal now.
    Committed,
    /// Couldn't confirm either way: keep both sets until an unseal succeeds.
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealOutcome {
    /// `None` if the keys database couldn't be read after sealing.
    pub status: Option<Status>,
    pub pending_rekey: PendingRekey,
    /// Whether the auto-unseal hold landed in both databases. If not, the
    /// server is sealed but a restart could unseal it: the write is
    /// retried in the background.
    pub hold_set: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RekeyPhase {
    /// Collecting current shares.
    Authorizing,
    /// New shares issued; collecting them back. Nothing committed yet.
    Verifying,
    /// The new root key is stored; the old shares no longer work.
    Complete,
    Cancelled,
}

#[derive(Debug)]
pub struct RekeyProgress {
    pub nonce: String,
    pub phase: RekeyPhase,
    /// Shares submitted toward the current phase.
    pub progress: usize,
    /// Shares the current phase needs.
    pub required: u8,
    /// The new shares, only on the submit that ends [`RekeyPhase::Authorizing`].
    pub new_shares: Vec<Share>,
    /// The new generation: when [`RekeyPhase::Complete`], and while
    /// [`RekeyPhase::Verifying`] (the generation the new shares carry).
    pub generation: Option<u32>,
}

/// A new root key issued to operators but not yet stored. If the shares
/// never come back, it is simply dropped (and zeroized) and the current
/// shares keep working.
struct PendingRoot {
    root: RootKey,
    /// `root`'s root check: confirms the shares submitted back rebuild it,
    /// and is what gets stored on commit.
    root_check: Vec<u8>,
    /// Generation the rekey was authorized against.
    base_generation: u32,
    /// `base_generation + 1`, carried by the new shares.
    generation: u32,
}

enum Stage {
    Authorizing,
    Verifying(PendingRoot),
}

struct RekeyAttempt {
    nonce: String,
    new_params: ShareParams,
    /// Current threshold: shares needed to authorize.
    current_threshold: u8,
    stage: Stage,
    /// Shares toward the current stage.
    submitted: Vec<Share>,
}

impl RekeyAttempt {
    fn phase(&self) -> RekeyPhase {
        match self.stage {
            Stage::Authorizing => RekeyPhase::Authorizing,
            Stage::Verifying(_) => RekeyPhase::Verifying,
        }
    }

    fn required(&self) -> u8 {
        match self.stage {
            Stage::Authorizing => self.current_threshold,
            Stage::Verifying(_) => self.new_params.threshold(),
        }
    }

    fn status(&self) -> RekeyStatus {
        RekeyStatus {
            nonce: self.nonce.clone(),
            phase: self.phase(),
            progress: self.submitted.len(),
            required: self.required(),
            generation: self.pending_generation(),
        }
    }

    /// While verifying, the generation the new shares carry.
    fn pending_generation(&self) -> Option<u32> {
        match &self.stage {
            Stage::Authorizing => None,
            Stage::Verifying(pending) => Some(pending.generation),
        }
    }

    fn progress(&self) -> RekeyProgress {
        RekeyProgress {
            nonce: self.nonce.clone(),
            phase: self.phase(),
            progress: self.submitted.len(),
            required: self.required(),
            new_shares: Vec::new(),
            generation: self.pending_generation(),
        }
    }

    fn check_nonce(&self, nonce: &str) -> Result<()> {
        if self.nonce != nonce {
            return Err(SealError::NonceMismatch);
        }
        Ok(())
    }
}

/// State only admin operations touch. Pending shares are secret material;
/// `Share` zeroizes on drop.
#[derive(Default)]
struct Admin {
    unseal: Vec<Share>,
    rekey: Option<RekeyAttempt>,
}

pub struct Seal {
    keystore: Keystore,
    admin: Mutex<Admin>,
    published: RwLock<Published>,
    /// Whether sealed, for whoever follows it ([`Seal::sealed_changes`]):
    /// set where the keyring is dropped or published, under the same lock,
    /// so it can't disagree with [`Seal::is_sealed`] for long.
    sealed: watch::Sender<bool>,
    commit_check_timeout: Duration,
    /// The highest stored-policy revision this process verified: kept
    /// across seal and unseal (it isn't secret), so a set put back while
    /// sealed is caught at the next unseal. Only a restart forgets it.
    policy_seen: AtomicU64,
    /// Serializes this server's loads of the stored policies, so a slow,
    /// older read can't overwrite a newer one.
    policy_loads: Mutex<()>,
    /// The revision floors outside the keys database, the policies' and
    /// the issuing keys' ([`Seal::with_revision_floor`]); `main` always
    /// sets it.
    policy_floor: Option<Arc<dyn RevisionFloor>>,
    /// The floor as this server last read or raised it: a verified set
    /// above it raises it ([`Seal::catch_up_policy_floor`]), so not every
    /// load writes. A read replaces it, even with a lower value (a
    /// data-database failover that lost a raise): it's the floor as it
    /// stands, which a load compares against right after reading it.
    policy_floor_known: AtomicU64,
    /// The highest issuing-set revision this process verified or wrote,
    /// across seal and unseal, like `policy_seen`.
    issuing_seen: AtomicU64,
    /// The issuing revision floor as last read or raised (see
    /// `policy_floor_known`).
    issuing_floor_known: AtomicU64,
    /// The last reason the stored issuing keys weren't trusted, so a
    /// refresh logs it when it starts or changes, not every time.
    issuing_failure: std::sync::Mutex<Option<String>>,
    /// The root commitments and their floor ([`Seal::with_root_ledger`]);
    /// `main` always sets it.
    root_ledger: Option<Arc<dyn RootLedger>>,
    /// Floor raises being retried in the background.
    root_floor_pending: Arc<AtomicU64>,
    /// Auto-unseal's provider ([`Seal::with_auto_unseal`]), from the config.
    auto: Option<Arc<dyn AutoUnseal>>,
    /// The last auto-unseal attempt's result and error, for the status.
    auto_report: std::sync::Mutex<AutoReport>,
    /// The configured key as the last attempt resolved it, so a status
    /// never calls the service.
    auto_key_id: std::sync::Mutex<Option<String>>,
    /// Hold writes (a seal's, a release's) being retried in the background.
    hold_pending: Arc<AtomicU64>,
    /// This process's own hold: set by `seal_now`, in the critical section
    /// that drops the keyring, so this server's auto-unseal loop (woken by
    /// that very seal) can't undo it before the databases' hold is written,
    /// or if it never is. Cleared only when an unseal publishes a keyring
    /// (shares, `--auto`, init), which an auto-unseal reaches only unheld.
    local_hold: std::sync::atomic::AtomicBool,
}

/// The last auto-unseal attempt, as the status shows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AutoReport {
    /// A small fixed set: `ok`, `kms_unavailable`, `denied`, `mismatch`,
    /// `root_commitment`, `below_floor`, `no_wrap`, `failed`.
    pub result: Option<&'static str>,
    /// What went wrong, as the provider or the store said it (may name
    /// accounts and roles: shown only to callers who may unseal).
    pub error: Option<String>,
}

/// One database's half of the auto-unseal hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HoldHalf {
    pub hold: u64,
    pub released: u64,
    /// Whether it could be read: one that couldn't counts as held.
    pub readable: bool,
}

impl HoldHalf {
    fn held(&self) -> bool {
        !self.readable || self.released < self.hold
    }
}

/// The auto-unseal hold, as both databases have it ([`Seal::hold`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hold {
    pub keys: HoldHalf,
    /// `None` without a root ledger (tests).
    pub data: Option<HoldHalf>,
    /// This server's own hold: it was sealed explicitly, and hasn't been
    /// unsealed since (it governs this process only; the databases' hold,
    /// every server and every start).
    pub here: bool,
}

impl Hold {
    /// Held unless both databases show `released >= hold` and this server
    /// holds nothing of its own; a database that couldn't be read counts
    /// as held, never as released.
    pub fn held(&self) -> bool {
        self.here || self.keys.held() || self.data.is_some_and(|data| data.held())
    }

    /// The higher of the two databases' holds, as read.
    fn highest(&self) -> u64 {
        self.keys.hold.max(self.data.map_or(0, |data| data.hold))
    }
}

/// Auto-unseal as a status shows it ([`Seal::status`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AutoUnsealStatus {
    /// The provider this server is configured with; `None`: Shamir only.
    pub provider: Option<&'static str>,
    /// The configured key, as the last attempt resolved it.
    pub key_id: Option<String>,
    /// Whether the keys database has a wrap at the current generation (for
    /// the configured key, once it's known).
    pub wrapped: bool,
    pub report: AutoReport,
    pub hold: Hold,
}

/// How the root key is protected, besides the shares: what a rekey keeps,
/// unless asked to change it ([`Seal::rekey_start_changing`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealMode {
    /// The shares alone.
    Shamir,
    /// Wrapped by AWS KMS too (auto-unseal).
    AwsKms,
}

impl SealMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shamir => "shamir",
            Self::AwsKms => "awskms",
        }
    }
}

/// What [`Seal::auto_unseal`] did.
#[derive(Debug)]
pub enum AutoOutcome {
    Unsealed,
    /// Nothing to do: unsealed already, or no auto-unseal configured.
    NotNeeded,
    /// Waiting for an operator: not initialized yet, or no wrap for the
    /// configured key (a Shamir deployment, until a rekey adds one).
    Waiting(&'static str),
    /// Failed in a way that may pass (the service, a database): try again.
    Retry(SealError),
    /// Refused in a way that needs a person (no commitment, below the
    /// floor, a wrap that isn't this deployment's): not retried.
    Refused(SealError),
    /// An explicit seal holds every server's auto-unseal until it's
    /// released (`ferritor unseal --auto`, `--release-hold`).
    Held,
}

/// The keyring secret operations see, the stored policies in force next to
/// it, and how many seals there have been.
#[derive(Default)]
struct Published {
    /// Bumped by every seal.
    epoch: u64,
    keyring: Option<Arc<Keyring>>,
    /// Sealed whenever `keyring` is `None`; published with it at unseal.
    policies: PolicyView,
}

/// What [`Seal::refresh_policies`] did.
#[derive(Clone, Debug)]
pub enum PolicyRefresh {
    /// Same revision as in force; nothing read.
    Unchanged,
    /// A verified set is now in force (`changed`: a different one than
    /// before).
    Loaded {
        revision: u64,
        policies: usize,
        fingerprint: String,
        changed: bool,
    },
    /// The stored set didn't verify. `kept`: the last verified set stays in
    /// force; otherwise none is.
    Failed { reason: Unverified, kept: bool },
    /// Not attempted: sealed, a seal during the load, or another server
    /// rekeyed (this one can't open the key any more).
    Skipped(&'static str),
}

impl Seal {
    /// Starts sealed.
    pub fn new(keystore: Keystore) -> Self {
        Self {
            keystore,
            admin: Mutex::new(Admin::default()),
            published: RwLock::new(Published::default()),
            sealed: watch::Sender::new(true),
            commit_check_timeout: DEFAULT_COMMIT_CHECK_TIMEOUT,
            policy_seen: AtomicU64::new(0),
            policy_loads: Mutex::new(()),
            policy_floor: None,
            policy_floor_known: AtomicU64::new(0),
            issuing_seen: AtomicU64::new(0),
            issuing_floor_known: AtomicU64::new(0),
            issuing_failure: std::sync::Mutex::new(None),
            root_ledger: None,
            root_floor_pending: Arc::new(AtomicU64::new(0)),
            auto: None,
            auto_report: std::sync::Mutex::new(AutoReport::default()),
            auto_key_id: std::sync::Mutex::new(None),
            hold_pending: Arc::new(AtomicU64::new(0)),
            local_hold: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// How many hold writes are being retried.
    pub fn hold_pending(&self) -> u64 {
        self.hold_pending.load(Ordering::SeqCst)
    }

    /// The auto-unseal hold as both databases have it now.
    pub async fn hold(&self) -> Hold {
        let keys = match self.keystore.auto_unseal_hold().await {
            Ok((hold, released)) => HoldHalf {
                hold,
                released,
                readable: true,
            },
            Err(_) => HoldHalf::default(),
        };
        let data = match &self.root_ledger {
            None => None,
            Some(ledger) => Some(match ledger.hold().await {
                Ok((hold, released)) => HoldHalf {
                    hold,
                    released,
                    readable: true,
                },
                Err(_) => HoldHalf::default(),
            }),
        };
        Hold {
            keys,
            data,
            here: self.local_hold.load(Ordering::SeqCst),
        }
    }

    /// Writes `value` as the hold (`release`: as the released hold) to
    /// both databases, with GREATEST. Whether both took it; what didn't is
    /// retried in the background until it does.
    async fn write_hold(&self, value: u64, release: bool) -> bool {
        let keys = self.keystore.clone();
        let ledger = self.root_ledger.clone();
        let write_keys = move |keys: Keystore| async move {
            if release {
                keys.release_auto_unseal_hold(value).await
            } else {
                keys.raise_auto_unseal_hold(value).await
            }
            .map_err(|e| error_chain(&e))
        };
        let write_data = move |ledger: Arc<dyn RootLedger>| async move {
            if release {
                ledger.release_hold(value).await
            } else {
                ledger.raise_hold(value).await
            }
        };
        let keys_ok = write_keys(keys.clone()).await.is_ok();
        let data_ok = match &ledger {
            Some(ledger) => write_data(Arc::clone(ledger)).await.is_ok(),
            None => true,
        };
        if keys_ok && data_ok {
            return true;
        }
        let what = if release { "release" } else { "hold" };
        tracing::error!(
            value,
            keys_database = keys_ok,
            data_database = data_ok,
            "the auto-unseal {what} is NOT written to both databases yet; retrying in the \
             background"
        );
        let pending = Arc::clone(&self.hold_pending);
        pending.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let (mut keys_ok, mut data_ok) = (keys_ok, data_ok);
            let mut wait = Duration::from_secs(1);
            while !(keys_ok && data_ok) {
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(FLOOR_RETRY_MAX);
                if !keys_ok {
                    keys_ok = write_keys(keys.clone()).await.is_ok();
                }
                if !data_ok && let Some(ledger) = &ledger {
                    data_ok = write_data(Arc::clone(ledger)).await.is_ok();
                }
            }
            tracing::info!(value, "the auto-unseal {what} is written to both databases");
            pending.fetch_sub(1, Ordering::SeqCst);
        });
        false
    }

    /// Releases the auto-unseal hold: `released` set to the higher of the
    /// two holds read, in both databases (with GREATEST, so a seal landing
    /// meanwhile stays in force). Whether both took it.
    pub async fn release_hold(&self) -> bool {
        let hold = self.hold().await;
        self.write_hold(hold.highest(), true).await
    }

    /// Auto-unseal through `provider`: init and rekey wrap the root key
    /// with it, and [`Seal::auto_unseal`] unwraps it.
    pub fn with_auto_unseal(mut self, provider: Arc<dyn AutoUnseal>) -> Self {
        self.auto = Some(provider);
        self
    }

    /// The auto-unseal provider's name, if one is configured.
    pub fn auto_unseal_provider(&self) -> Option<&'static str> {
        self.auto.as_ref().map(|auto| auto.provider())
    }

    /// The configured key, as the last auto-unseal attempt resolved it.
    pub fn auto_key_id(&self) -> Option<String> {
        self.auto_key_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The last auto-unseal attempt.
    pub fn auto_report(&self) -> AutoReport {
        self.auto_report
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn report_auto(&self, result: &'static str, error: Option<String>) {
        *self
            .auto_report
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = AutoReport {
            result: Some(result),
            error,
        };
    }

    /// `root` (of `generation`) wrapped by the auto-unseal provider, or
    /// `None` without one.
    async fn wrap_root(&self, root: &RootKey, generation: u32) -> Result<Option<SealWrap>> {
        let Some(auto) = &self.auto else {
            return Ok(None);
        };
        let wrapped = auto
            .wrap(root, generation)
            .await
            .map_err(SealError::AutoUnseal)?;
        Ok(Some(SealWrap {
            provider: auto.provider().to_owned(),
            key_id: wrapped.key_id,
            generation,
            ciphertext: wrapped.ciphertext,
        }))
    }

    /// Unseals with the root key the auto-unseal provider unwraps from the
    /// stored wrap for the configured key, after the same checks a shares
    /// unseal makes (`root_check`, the root commitment, the floor read
    /// first). One attempt: `main` retries what may pass.
    pub async fn auto_unseal(&self) -> AutoOutcome {
        self.auto_unseal_with(true).await
    }

    /// [`Seal::auto_unseal`] past the hold, for an explicit `unseal --auto`
    /// (which released it, but perhaps not in both databases yet).
    pub async fn auto_unseal_released(&self) -> AutoOutcome {
        self.auto_unseal_with(false).await
    }

    async fn auto_unseal_with(&self, heed_hold: bool) -> AutoOutcome {
        let Some(auto) = &self.auto else {
            return AutoOutcome::NotNeeded;
        };
        if !self.is_sealed() {
            return AutoOutcome::NotNeeded;
        }
        let epoch = self.epoch();
        let outcome = self
            .auto_unseal_attempt(auto.as_ref(), epoch, heed_hold)
            .await;
        let (result, error) = match &outcome {
            AutoOutcome::Unsealed => ("ok", None),
            AutoOutcome::NotNeeded => return outcome,
            AutoOutcome::Held => ("held", None),
            AutoOutcome::Waiting(why) => ("no_wrap", Some((*why).to_owned())),
            AutoOutcome::Retry(e) | AutoOutcome::Refused(e) => (
                match e {
                    SealError::AutoUnseal(e) => e.result(),
                    SealError::RootUncommitted { .. } => "root_commitment",
                    SealError::RootBelowFloor { .. } => "below_floor",
                    SealError::WrapMismatch => "mismatch",
                    _ => "failed",
                },
                Some(error_chain(e)),
            ),
        };
        self.report_auto(result, error);
        outcome
    }

    /// One attempt. The hold, the floor, the snapshot and the service's
    /// calls (seconds, at worst) run without the admin lock, so `status`
    /// and submitted shares never wait behind a slow KMS; then, under it:
    /// still sealed, still the generation unwrapped, the commitment, the
    /// keyring, the hold once more, and the publish (refused if a seal came
    /// since `epoch`).
    async fn auto_unseal_attempt(
        &self,
        auto: &dyn AutoUnseal,
        epoch: u64,
        heed_hold: bool,
    ) -> AutoOutcome {
        // An early read, to spare the service pointless calls.
        if heed_hold && self.hold().await.held() {
            return AutoOutcome::Held;
        }
        // The floor first: it only rises after a keys-database commit, so
        // read after, a rekey elsewhere in between would refuse this start.
        let floor = match self.root_floor().await {
            Ok(floor) => floor,
            Err(e) => return AutoOutcome::Retry(e),
        };
        let key_id = match auto.key_id().await {
            Ok(key_id) => key_id,
            Err(e) => return AutoOutcome::Retry(SealError::AutoUnseal(e)),
        };
        *self
            .auto_key_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(key_id.clone());
        // The config and the wraps from one snapshot, so the wrap's
        // generation is the config's.
        let (config, wraps) = match self.keystore.seal_config_and_wraps(auto.provider()).await {
            Ok(read) => read,
            Err(e) => return AutoOutcome::Retry(e.into()),
        };
        let Some(config) = config else {
            return AutoOutcome::Waiting("not initialized: `ferritor init`");
        };
        let Some(wrap) = wraps.into_iter().find(|w| w.key_id == key_id) else {
            return AutoOutcome::Waiting(
                "no wrap for the configured key: unseal with the shares, then rekey to store \
                 one (or the config names another key than the wrap's)",
            );
        };
        if wrap.generation != config.generation {
            return AutoOutcome::Refused(SealError::WrapMismatch);
        }
        let root = match auto.unwrap(&wrap.ciphertext, wrap.generation).await {
            Ok(root) => root,
            Err(e @ AutoUnsealError::Mismatch(_)) => {
                return AutoOutcome::Refused(SealError::AutoUnseal(e));
            }
            Err(e) => return AutoOutcome::Retry(SealError::AutoUnseal(e)),
        };
        if root.verify_root_check(&config.root_check).is_err() {
            return AutoOutcome::Refused(SealError::WrapMismatch);
        }

        let _admin = self.admin.lock().await;
        if !self.is_sealed() {
            return AutoOutcome::NotNeeded;
        }
        // A rekey may have committed while the service answered.
        match self.keystore.seal_config().await {
            Ok(Some(now)) if now.generation == config.generation => {}
            Ok(Some(now)) => {
                return AutoOutcome::Retry(SealError::RekeyedElsewhere {
                    running: config.generation,
                    stored: now.generation,
                });
            }
            Ok(None) => return AutoOutcome::Retry(SealError::NotInitialized),
            Err(e) => return AutoOutcome::Retry(e.into()),
        }
        match self
            .check_root(&root, config.generation, floor, false)
            .await
        {
            Ok(_) => {}
            Err(e @ SealError::RootLedger(_)) => return AutoOutcome::Retry(e),
            Err(e) => return AutoOutcome::Refused(e),
        }
        let keyring = match self.load_keyring(root, config.generation).await {
            Ok(keyring) => keyring,
            Err(e) => return AutoOutcome::Retry(e),
        };
        let _loading = self.policy_loads.lock().await;
        let policies = self.load_policies(&keyring.root, config.generation).await;
        // Again right before publishing, this server's hold and both
        // databases': an attempt takes seconds, and a seal here or elsewhere
        // meanwhile must win. (A seal elsewhere landing after this read
        // looks like the server having been up already: the databases' hold
        // governs future starts. One here bumps the epoch, and the publish
        // below is refused.)
        if heed_hold && self.hold().await.held() {
            return AutoOutcome::Held;
        }
        if self.publish_unsealed(epoch, keyring, policies) {
            AutoOutcome::Unsealed
        } else {
            AutoOutcome::NotNeeded
        }
    }

    /// Checks every root key an unseal reconstructs against the root
    /// commitments in the data database, and has init and rekey write
    /// them (see `root_ledger`).
    pub fn with_root_ledger(mut self, ledger: Arc<dyn RootLedger>) -> Self {
        self.root_ledger = Some(ledger);
        self
    }

    /// How many root-generation floor raises are being retried.
    pub fn root_floor_pending(&self) -> u64 {
        self.root_floor_pending.load(Ordering::SeqCst)
    }

    /// The root-generation floor, read now: **before** the keys database,
    /// since it only rises after a keys-database commit (as for the
    /// revision floors). `None` without a ledger.
    async fn root_floor(&self) -> Result<Option<u32>> {
        match &self.root_ledger {
            Some(ledger) => Ok(Some(ledger.floor().await.map_err(SealError::RootLedger)?)),
            None => Ok(None),
        }
    }

    /// Raises the root-generation floor to `generation` after a commit,
    /// retrying in the background until it lands: a missed raise would let
    /// an older keys database back in until another server catches it up.
    fn raise_root_floor_later(&self, generation: u32) {
        let Some(ledger) = self.root_ledger.clone() else {
            return;
        };
        let pending = Arc::clone(&self.root_floor_pending);
        pending.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let mut wait = Duration::from_secs(1);
            let mut warned = false;
            loop {
                match ledger.raise_floor(generation).await {
                    Ok(()) => {
                        if warned {
                            tracing::info!(generation, "raised the root-generation floor");
                        }
                        break;
                    }
                    Err(error) => {
                        if !warned {
                            tracing::warn!(
                                generation,
                                error,
                                "couldn't raise the root-generation floor; retrying in the \
                                 background"
                            );
                            warned = true;
                        }
                    }
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(FLOOR_RETRY_MAX);
            }
            pending.fetch_sub(1, Ordering::SeqCst);
        });
    }

    /// Whether `root` (of `generation`) is this deployment's, by the root
    /// commitments: its generation not below `floor` (read before the keys
    /// database), and a commitment for it verifying. With `recommit` and no
    /// commitment verifying, it proves continuity instead (a stored
    /// version opens under it) and stores one: shares alone prove *a* root
    /// key, not the one the data was written under. Returns whether it
    /// re-committed. Without a ledger, every root key passes.
    async fn check_root(
        &self,
        root: &RootKey,
        generation: u32,
        floor: Option<u32>,
        recommit: bool,
    ) -> Result<bool> {
        let (Some(ledger), Some(floor)) = (&self.root_ledger, floor) else {
            return Ok(false);
        };
        if generation < floor {
            return Err(SealError::RootBelowFloor { generation, floor });
        }
        let commitments = ledger
            .commitments(generation)
            .await
            .map_err(SealError::RootLedger)?;
        if commitments
            .iter()
            .any(|mac| root.verifies_root_commitment(generation, mac))
        {
            if generation > floor {
                self.raise_root_floor_later(generation);
            }
            return Ok(false);
        }
        if !recommit {
            return Err(SealError::RootUncommitted { generation });
        }
        // Each KEK on its own: under a root key that isn't this deployment's,
        // the genuine ones don't open, which is the answer, not an error.
        let keks: BTreeMap<(Namespace, u32), Kek> = self
            .keystore
            .keks()
            .await?
            .into_iter()
            .filter_map(|row| {
                let kek = root
                    .unwrap_kek(&row.namespace, row.version, &row.wrapped_key)
                    .ok()?;
                Some(((row.namespace, row.version), kek))
            })
            .collect();
        let stored = ledger
            .version_per_kek()
            .await
            .map_err(SealError::RootLedger)?;
        if stored.is_empty() {
            return Err(SealError::RecommitNothingStored);
        }
        let opens = stored.iter().any(|row| {
            keks.get(&(row.path.namespace(), row.kek_version))
                .is_some_and(|kek| {
                    kek.unwrap_dek(&row.path, row.version, &row.wrapped_dek)
                        .and_then(|dek| dek.decrypt(&row.path, row.version, &row.ciphertext))
                        .is_ok()
                })
        });
        if !opens {
            return Err(SealError::RecommitDiscontinuous);
        }
        ledger
            .insert(generation, root.root_commitment(generation)?.to_vec())
            .await
            .map_err(SealError::RootLedger)?;
        tracing::error!(
            generation,
            "RE-COMMITTED THE ROOT KEY with shares: the data database had no commitment matching \
             it, and a stored secret version proved it's the key the data was written under. \
             Expected after restoring the data database from before a rekey, or a failover that \
             lost the write; otherwise find out who changed the data database"
        );
        if generation > floor {
            self.raise_root_floor_later(generation);
        }
        Ok(true)
    }

    /// The lowest revision the stored issuing set may have: the floor
    /// (read now, so **before** the keys database, as for the policies)
    /// and the highest this process saw.
    async fn issuing_floor(&self) -> std::result::Result<u64, String> {
        if let Some(floor) = &self.policy_floor {
            let revision = floor.read(Floor::IssuingKeys).await?;
            self.issuing_floor_known.store(revision, Ordering::SeqCst);
            self.issuing_seen.fetch_max(revision, Ordering::SeqCst);
        }
        Ok(self.issuing_seen.load(Ordering::SeqCst))
    }

    /// A set at `revision` verified, or was written: remembered, and the
    /// floor raised to it if it's above the floor as known (a raise a write
    /// missed is caught up by the next server to verify the set). Failing,
    /// it only warns.
    async fn issuing_verified(&self, revision: u64) {
        self.issuing_seen.fetch_max(revision, Ordering::SeqCst);
        if revision <= self.issuing_floor_known.load(Ordering::SeqCst) {
            return;
        }
        if let Some(floor) = &self.policy_floor {
            match floor.raise(Floor::IssuingKeys, revision).await {
                Ok(()) => {
                    self.issuing_floor_known
                        .fetch_max(revision, Ordering::SeqCst);
                }
                Err(error) => tracing::warn!(
                    revision,
                    error,
                    "couldn't raise the issuing revision floor; the next load will"
                ),
            }
        }
    }

    /// Loads the stored issuing set read after `floor`, logging a failure
    /// when it starts or changes (`None`: not trusted).
    fn load_issuing(
        &self,
        root: &RootKey,
        floor: std::result::Result<u64, String>,
        set: IssuingSet,
    ) -> Option<IssuingKeys> {
        let loaded = floor
            .map_err(IssuingUnverified::Floor)
            .and_then(|floor| IssuingKeys::load(root, set, floor));
        let mut failure = self
            .issuing_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match loaded {
            Ok(keys) => {
                if failure.take().is_some() {
                    tracing::info!(
                        revision = keys.revision,
                        "the stored issuing keys verify again"
                    );
                }
                Some(keys)
            }
            Err(why) => {
                let reason = why.to_string();
                if failure.as_deref() != Some(reason.as_str()) {
                    tracing::error!(
                        reason,
                        "THE STORED ISSUING KEYS AREN'T TRUSTED: none newly loaded (a refresh keeps \
                         those in force; an unseal has none), so nothing they signed is trusted \
                         unless already in force; `ferritor identity rotate --now` replaces them"
                    );
                    *failure = Some(reason);
                }
                None
            }
        }
    }

    /// Refuses a stored-policy set, or an issuing set, below `floor`'s
    /// revision too, not only below the highest this process verified:
    /// every load reads it first, and every write raises it after
    /// committing (see [`RevisionFloor`]).
    pub fn with_revision_floor(mut self, floor: Arc<dyn RevisionFloor>) -> Self {
        self.policy_floor = Some(floor);
        self
    }

    /// Takes the policy revision floor into the highest revision seen, so a
    /// verification after it refuses a set below it. Read **before** the
    /// keys database's snapshot: the floor only rises after a keys-database
    /// commit, so a snapshot read later is never below it.
    pub async fn sync_policy_floor(&self) -> std::result::Result<(), String> {
        if let Some(floor) = &self.policy_floor {
            let revision = floor.read(Floor::Policies).await?;
            // The floor now, lowered or not (see `policy_floor_known`); a
            // concurrent raise at worst costs one extra, harmless raise.
            self.policy_floor_known.store(revision, Ordering::SeqCst);
            self.note_policy_revision(revision);
        }
        Ok(())
    }

    /// Raises the policy revision floor to `revision`, after a write
    /// committed it to the keys database.
    pub async fn raise_policy_floor(&self, revision: u64) -> std::result::Result<(), String> {
        match &self.policy_floor {
            Some(floor) => {
                floor.raise(Floor::Policies, revision).await?;
                self.policy_floor_known
                    .fetch_max(revision, Ordering::SeqCst);
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// After a set at `revision` verified: raises the floor to it if it's
    /// above the floor as this server knows it. A raise a write missed (it
    /// failed, or a data-database failover lost it) is caught up by the
    /// next server to verify the set, so a keys-database writer can't roll
    /// back to the revision below meanwhile. Safe: only a set signed with
    /// the policy key verifies, and a keys-database writer can't make one.
    /// Failing, it only warns: the set stays in force.
    async fn catch_up_policy_floor(&self, revision: u64) {
        if revision <= self.policy_floor_known.load(Ordering::SeqCst) {
            return;
        }
        if let Err(e) = self.raise_policy_floor(revision).await {
            tracing::warn!(
                revision,
                error = %e,
                "couldn't raise the policy revision floor to the verified set; the next load will"
            );
        }
    }

    /// How long to wait for an unconfirmed rekey commit to resolve before
    /// reporting [`SealError::RekeyOutcomeUnknown`].
    pub fn with_commit_check_timeout(mut self, timeout: Duration) -> Self {
        self.commit_check_timeout = timeout;
        self
    }

    /// The epoch, if unsealed: what a secret operation records when it starts
    /// and later hands to [`Seal::keyring_at`].
    pub fn unsealed_epoch(&self) -> Result<u64> {
        let published = self
            .published
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        match published.keyring {
            Some(_) => Ok(published.epoch),
            None => Err(SealError::Sealed),
        }
    }

    /// The keyring, but only if no seal happened since `epoch` (from
    /// [`Seal::unsealed_epoch`]); both read under one lock. Secret operations
    /// take it right before their crypto, after every await, and don't hold
    /// it across one: a request that waited on a slow database while the
    /// server was sealed must not decrypt afterwards, even if the server has
    /// been unsealed again since, and must not keep the keys alive meanwhile.
    pub fn keyring_at(&self, epoch: u64) -> Result<Arc<Keyring>> {
        let published = self
            .published
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        if published.epoch != epoch {
            return Err(SealError::Sealed);
        }
        published.keyring.clone().ok_or(SealError::Sealed)
    }

    /// Fails with [`SealError::Sealed`] unless the server is unsealed and no
    /// seal happened since `epoch` (from [`Seal::unsealed_epoch`]). For
    /// secret operations that need no keys: the check before they commit or
    /// answer. Like [`Seal::keyring_at`], without cloning the keyring.
    pub fn ensure_unsealed_since(&self, epoch: u64) -> Result<()> {
        let published = self
            .published
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        if published.epoch != epoch || published.keyring.is_none() {
            return Err(SealError::Sealed);
        }
        Ok(())
    }

    /// The unsealed keyring as of now, for admin code and tests. Secret
    /// operations must not use it: they take [`Seal::unsealed_epoch`] when
    /// they start and [`Seal::keyring_at`] right before their crypto, so a
    /// seal in between wins. This one has no such check.
    pub fn keyring(&self) -> Result<Arc<Keyring>> {
        self.published
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keyring
            .clone()
            .ok_or(SealError::Sealed)
    }

    /// The current seal epoch. Admin calls read it when they begin, before
    /// waiting for the admin lock: a call queued when a seal happens must
    /// neither unseal the server afterwards (`Seal::publish`) nor act on a
    /// keyring from after the seal ([`Seal::ensure_epoch`]).
    fn epoch(&self) -> u64 {
        self.published
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .epoch
    }

    /// Fails with [`SealError::Sealed`] if a seal happened since `epoch` was
    /// read, i.e. while this call was queued for the admin lock. Called right
    /// after taking the lock by every admin call except unseal (which should
    /// still go ahead after a seal).
    ///
    /// Without it, these calls would be safe only because tokio's mutex
    /// grants the lock in request order: a call queued before a seal runs
    /// before any later unseal, so it finds no keyring. If an unseal could
    /// overtake it, a rotate would find the new keyring, store a KEK, have its
    /// publish refused, and leave this process running with a keyring whose
    /// active KEK the database has already demoted.
    fn ensure_epoch(&self, epoch: u64) -> Result<()> {
        if self.epoch() != epoch {
            return Err(SealError::Sealed);
        }
        Ok(())
    }

    /// Drops the keyring at once: no lock to wait for, no await.
    fn seal_now(&self) {
        let mut published = self
            .published
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        published.epoch += 1;
        published.keyring = None;
        published.policies = PolicyView::Sealed;
        self.local_hold.store(true, Ordering::SeqCst);
        self.sealed
            .send_if_modified(|sealed| !std::mem::replace(sealed, true));
    }

    /// Publishes `keyring` unless a seal happened since `epoch` was read, in
    /// which case it's dropped and `false` returned: the seal wins.
    fn publish(&self, epoch: u64, keyring: Keyring) -> bool {
        let mut published = self
            .published
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if published.epoch != epoch {
            tracing::info!("a seal happened during this call; not publishing its keyring");
            return false;
        }
        published.keyring = Some(Arc::new(keyring));
        self.sealed
            .send_if_modified(|sealed| std::mem::replace(sealed, false));
        true
    }

    /// [`Seal::publish`] for an unseal: the keyring and the stored policies
    /// verified with it, together.
    fn publish_unsealed(&self, epoch: u64, keyring: Keyring, policies: PolicyView) -> bool {
        let mut published = self
            .published
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if published.epoch != epoch {
            tracing::info!("a seal happened during this call; not publishing its keyring");
            return false;
        }
        published.keyring = Some(Arc::new(keyring));
        published.policies = policies;
        // Unsealed: this server's own hold is over (an auto-unseal gets
        // here only unheld, or past it when asked explicitly).
        self.local_hold.store(false, Ordering::SeqCst);
        self.sealed
            .send_if_modified(|sealed| std::mem::replace(sealed, false));
        true
    }

    /// Replaces the stored policies in force, unless sealed or a seal
    /// happened since `epoch`.
    fn publish_policies(&self, epoch: u64, policies: PolicyView) -> bool {
        let mut published = self
            .published
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if published.epoch != epoch || published.keyring.is_none() {
            return false;
        }
        published.policies = policies;
        true
    }

    /// The stored policies as this server sees them now.
    pub fn policy_view(&self) -> PolicyView {
        self.published
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .policies
            .clone()
    }

    /// The stored policies in force, as a load's report (after an unseal).
    pub fn policy_report(&self) -> PolicyRefresh {
        match self.policy_view() {
            PolicyView::Loaded(set) => PolicyRefresh::Loaded {
                revision: set.revision,
                policies: set.policies.len(),
                fingerprint: set.fingerprint.clone(),
                changed: true,
            },
            PolicyView::Unverified(reason) => PolicyRefresh::Failed {
                reason,
                kept: false,
            },
            PolicyView::Sealed => PolicyRefresh::Skipped("sealed"),
        }
    }

    /// The highest stored-policy revision this process verified.
    pub fn policy_revision_seen(&self) -> u64 {
        self.policy_seen.load(Ordering::SeqCst)
    }

    /// Records a revision this process verified or wrote: never lowered.
    pub fn note_policy_revision(&self, revision: u64) {
        self.policy_seen.fetch_max(revision, Ordering::SeqCst);
    }

    /// The keys database, for the stored policies' writes (`policies`).
    pub fn keystore(&self) -> &Keystore {
        &self.keystore
    }

    /// What a policy write needs: the root key (to open, or create, the
    /// policy key) and the generation it belongs to, as of `epoch`.
    pub fn policy_write_context(&self, epoch: u64) -> Result<(Arc<RootKey>, u32)> {
        let keyring = self.keyring_at(epoch)?;
        Ok((Arc::clone(&keyring.root), keyring.generation))
    }

    /// Reads and verifies the stored policies with `root` (of
    /// `generation`). Never fails: what can't be loaded is `Unverified`, with
    /// the reason.
    async fn load_policies(&self, root: &RootKey, generation: u32) -> PolicyView {
        if let Err(why) = self.sync_policy_floor().await {
            return PolicyView::Unverified(Unverified::Unreadable(format!(
                "the policy revision floor (data database): {why}"
            )));
        }
        let snapshot = match self.keystore.policy_snapshot().await {
            Ok(snapshot) => snapshot,
            Err(e) => return PolicyView::Unverified(Unverified::Unreadable(error_chain(&e))),
        };
        if snapshot.generation != generation {
            return PolicyView::Unverified(Unverified::Unreadable(format!(
                "the keys database is at generation {}, this server at {generation}",
                snapshot.generation
            )));
        }
        match policy_store::verify(root, &snapshot, self.policy_revision_seen()) {
            Ok(set) => {
                self.note_policy_revision(set.revision);
                self.catch_up_policy_floor(set.revision).await;
                PolicyView::Loaded(Arc::new(set))
            }
            Err(why) => PolicyView::Unverified(why),
        }
    }

    /// Reloads the stored policies. Unless `full`, only if the stored
    /// revision differs from the one in force (one tiny read: the poll);
    /// `full` re-reads and re-verifies the whole set regardless, catching a
    /// row changed without touching the revision. A set that doesn't verify
    /// never replaces a verified one: that stays in force (`kept`).
    pub async fn refresh_policies(&self, full: bool) -> Result<PolicyRefresh> {
        let epoch = self.epoch();
        let (root, generation) = match self.policy_write_context(epoch) {
            Ok(context) => context,
            Err(SealError::Sealed) => return Ok(PolicyRefresh::Skipped("sealed")),
            Err(e) => return Err(e),
        };
        let _loading = self.policy_loads.lock().await;
        let current = self.policy_view();
        if !full
            && let PolicyView::Loaded(set) = &current
            && self.keystore.policy_revision().await? == set.revision
        {
            return Ok(PolicyRefresh::Unchanged);
        }
        // The floor before the snapshot (see `sync_policy_floor`).
        let floor = self.sync_policy_floor().await;
        let snapshot = self.keystore.policy_snapshot().await?;
        if snapshot.generation != generation {
            // Rekeyed elsewhere: the keyring refresh says so; nothing here
            // can open the key until this server is sealed and unsealed.
            return Ok(PolicyRefresh::Skipped("rekeyed elsewhere"));
        }
        let verified = match floor {
            Ok(()) => policy_store::verify(&root, &snapshot, self.policy_revision_seen()),
            Err(why) => Err(Unverified::Unreadable(format!(
                "the policy revision floor (data database): {why}"
            ))),
        };
        let (view, outcome) = match verified {
            Ok(set) => {
                self.note_policy_revision(set.revision);
                self.catch_up_policy_floor(set.revision).await;
                let changed = !matches!(&current, PolicyView::Loaded(old) if **old == set);
                let outcome = PolicyRefresh::Loaded {
                    revision: set.revision,
                    policies: set.policies.len(),
                    fingerprint: set.fingerprint.clone(),
                    changed,
                };
                (PolicyView::Loaded(Arc::new(set)), outcome)
            }
            Err(reason) => match current {
                // The last verified set stays in force.
                PolicyView::Loaded(old) => (
                    PolicyView::Loaded(old),
                    PolicyRefresh::Failed { reason, kept: true },
                ),
                _ => (
                    PolicyView::Unverified(reason.clone()),
                    PolicyRefresh::Failed {
                        reason,
                        kept: false,
                    },
                ),
            },
        };
        if !self.publish_policies(epoch, view) {
            return Ok(PolicyRefresh::Skipped("sealed during the load"));
        }
        Ok(outcome)
    }

    /// Follows whether the server is sealed (`true` at first): the value
    /// now, and a change notification whenever it flips. For the health
    /// service, so a load balancer takes a sealed server out of rotation.
    pub fn sealed_changes(&self) -> watch::Receiver<bool> {
        self.sealed.subscribe()
    }

    /// Whether the server is sealed right now.
    pub fn is_sealed(&self) -> bool {
        self.keyring().is_err()
    }

    /// `namespace`'s active KEK version, while unsealed and if this server
    /// knows the namespace.
    pub fn active_kek_version(&self, namespace: &Namespace) -> Option<u32> {
        self.keyring()
            .ok()
            .and_then(|keyring| keyring.active_kek(namespace).map(|(v, _)| v))
    }

    /// How many namespaces this server holds KEKs of, while unsealed (for
    /// metrics).
    pub fn namespace_count(&self) -> Option<u64> {
        self.keyring()
            .ok()
            .map(|keyring| u64::try_from(keyring.namespaces.len()).unwrap_or(u64::MAX))
    }

    async fn config(&self) -> Result<SealConfig> {
        self.keystore
            .seal_config()
            .await?
            .ok_or(SealError::NotInitialized)
    }

    /// Unseal progress and any rekey come from `admin`, so callers pass the
    /// state they hold the lock for.
    fn status_of(&self, config: Option<&SealConfig>, admin: &Admin) -> Status {
        Status {
            initialized: config.is_some(),
            sealed: self.is_sealed(),
            shares: config.map_or(0, |c| c.params.shares()),
            threshold: config.map_or(0, |c| c.params.threshold()),
            generation: config.map_or(0, |c| c.generation),
            progress: admin.unseal.len(),
            rekey: admin.rekey.as_ref().map(RekeyAttempt::status),
            recommitted: false,
            auto_unseal: None,
        }
    }

    pub async fn status(&self) -> Result<Status> {
        let admin = self.admin.lock().await;
        let config = self.keystore.seal_config().await?;
        let status = self.status_of(config.as_ref(), &admin);
        drop(admin);
        let auto_unseal = if config.is_some() {
            Some(self.auto_unseal_status(status.generation).await)
        } else {
            None
        };
        Ok(Status {
            auto_unseal,
            ..status
        })
    }

    /// Auto-unseal and the hold, for a status. Never calls the service:
    /// the key is the one the last attempt resolved.
    async fn auto_unseal_status(&self, generation: u32) -> AutoUnsealStatus {
        let key_id = self
            .auto_key_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let wrapped = match &self.auto {
            Some(auto) => self
                .keystore
                .seal_config_and_wraps(auto.provider())
                .await
                .is_ok_and(|(_, wraps)| {
                    wraps.iter().any(|w| {
                        w.generation == generation
                            && key_id.as_ref().is_none_or(|key| &w.key_id == key)
                    })
                }),
            None => false,
        };
        AutoUnsealStatus {
            provider: self.auto_unseal_provider(),
            key_id,
            wrapped,
            report: self.auto_report(),
            hold: self.hold().await,
        }
    }

    /// Generates the root key, stores its root check, and returns the
    /// shares. This is the only time they exist outside the operators' hands.
    /// No KEK: there's none until a namespace is created. The server stays
    /// sealed: unseal with the shares as usual.
    ///
    /// Refused once the root-generation floor is set: a keys database that
    /// looks uninitialized (wiped) mustn't start a deployment over the data
    /// database's. The commitment is stored before the keys database
    /// (an init that then fails leaves one nobody has the key of), the
    /// floor raised after.
    pub async fn init(&self, params: ShareParams) -> Result<Vec<Share>> {
        let _admin = self.admin.lock().await;
        if let Some(floor) = self.root_floor().await?
            && floor > 0
        {
            return Err(SealError::InitAfterCommit { floor });
        }
        let epoch = self.epoch();
        let root = RootKey::generate()?;
        let root_check = root.root_check()?;
        let split = crypto::split(&root, params, INITIAL_GENERATION)?;
        // With auto-unseal, wrapped first: if the service fails, nothing is
        // stored anywhere.
        let wrap = self.wrap_root(&root, INITIAL_GENERATION).await?;
        if let Some(ledger) = &self.root_ledger {
            ledger
                .insert(
                    INITIAL_GENERATION,
                    root.root_commitment(INITIAL_GENERATION)?.to_vec(),
                )
                .await
                .map_err(SealError::RootLedger)?;
        }
        self.keystore
            .initialize_wrapped(params, &root_check, wrap.as_ref())
            .await?;
        self.raise_root_floor_later(INITIAL_GENERATION);
        // With auto-unseal it can unseal itself anyway: it does so now.
        if wrap.is_some() {
            let keyring = self.load_keyring(root, INITIAL_GENERATION).await?;
            let _loading = self.policy_loads.lock().await;
            let policies = self.load_policies(&keyring.root, INITIAL_GENERATION).await;
            self.publish_unsealed(epoch, keyring, policies);
            self.report_auto("ok", None);
        }
        Ok(split)
    }

    /// Submits one share (an empty `share` just reports, or resets with
    /// `reset`). Once `threshold` shares are in, reconstructs the root key,
    /// verifies it against the root check and loads the keyring. Progress
    /// resets after every reconstruction attempt, successful or not.
    ///
    /// If the server is sealed while this runs, the keyring isn't published
    /// and the status reports sealed.
    ///
    /// The root key must match a commitment in the data database (see
    /// `root_ledger`); [`Seal::unseal_recommit`] re-commits one that's
    /// missing.
    pub async fn unseal(&self, share: &[u8], reset: bool) -> Result<Status> {
        self.unseal_with(share, reset, false).await
    }

    /// [`Seal::unseal`], re-committing the root key if no commitment in the
    /// data database matches it, once a stored secret version proves it's
    /// the key the data was written under. For a data database restored
    /// from before a rekey, or a failover that lost the commitment.
    pub async fn unseal_recommit(&self, share: &[u8], reset: bool) -> Result<Status> {
        self.unseal_with(share, reset, true).await
    }

    async fn unseal_with(&self, share: &[u8], reset: bool, recommit: bool) -> Result<Status> {
        let epoch = self.epoch();
        let mut admin = self.admin.lock().await;
        if reset {
            admin.unseal.clear();
        }
        if !self.is_sealed() || share.is_empty() {
            let config = self.config().await?;
            return Ok(self.status_of(Some(&config), &admin));
        }
        let floor = self.root_floor().await?;
        let config = self.config().await?;

        let share = accept_share(&admin.unseal, share, config.generation)?;
        admin.unseal.push(share);
        if admin.unseal.len() < usize::from(config.params.threshold()) {
            return Ok(self.status_of(Some(&config), &admin));
        }

        let shares = std::mem::take(&mut admin.unseal);
        let root = reconstruct(&shares, &config)?;
        // Before the keyring loads (which raises the issuing floor): a
        // substituted root key gets no further.
        let recommitted = self
            .check_root(&root, config.generation, floor, recommit)
            .await?;
        let keyring = self.load_keyring(root, config.generation).await?;
        // Verified before anything is published, and published with the
        // keyring: no moment unsealed without the stored policies.
        let _loading = self.policy_loads.lock().await;
        let policies = self.load_policies(&keyring.root, config.generation).await;
        self.publish_unsealed(epoch, keyring, policies);
        Ok(Status {
            recommitted,
            ..self.status_of(Some(&config), &admin)
        })
    }

    /// Reloads the KEKs with the root key this server already holds, so a
    /// rotation, retirement, destroy or namespace change by another server
    /// is picked up without shares: it can then read secrets wrapped by the
    /// new KEKs, and stops wrapping new DEKs with its old active ones.
    /// Publishes only if something changed.
    ///
    /// A rekey elsewhere can't be followed: it replaced the root key, so the
    /// stored KEKs don't open under ours ([`SealError::RekeyedElsewhere`];
    /// seal and unseal with the new shares). The generation is read after the
    /// KEKs, so a rekey landing in between is caught too.
    ///
    /// For each namespace this server holds, one of three cases:
    /// - present: the stored KEKs, and any held KEK the keys database no
    ///   longer has (and didn't destroy) kept as vanished;
    /// - marked deleted (its KEKs destroyed): dropped;
    /// - absent altogether (a failover lost its creation): every KEK kept as
    ///   vanished, with no active one. Otherwise "namespace missing" would
    ///   read as "nothing to load", and the last copy would be dropped.
    ///
    /// Under the admin lock, like rotate, and refused after a seal, like any
    /// publish. With `wanted` (the KEK a read needs), it first checks whether
    /// the keyring already has it once the lock is held, and returns at once
    /// if so: reads that queued behind a refresh that already fetched it
    /// don't each reload every KEK again.
    pub async fn refresh(&self, wanted: Option<(&Namespace, u32)>) -> Result<Refreshed> {
        let epoch = self.epoch();
        let _admin = self.admin.lock().await;
        self.ensure_epoch(epoch)?;
        let current = self.keyring()?;
        if let Some((namespace, version)) = wanted
            && current.kek(namespace, version).is_some()
        {
            return Ok(refreshed(&current, false, false));
        }
        // The issuing floor first, then one snapshot: the KEKs, their
        // states, the namespaces, the issuing keys and the generation
        // always agree (a namespace deleted and created again, or a rekey,
        // lands before all of them or after).
        let issuing_floor = self.issuing_floor().await;
        let snapshot = self.keystore.snapshot().await?;
        let config = snapshot.config.ok_or(SealError::NotInitialized)?;
        if config.generation != current.generation {
            return Err(SealError::RekeyedElsewhere {
                running: current.generation,
                stored: config.generation,
            });
        }
        let mut namespaces = keys_from(&current.root, snapshot.keks)?;
        let (catalog, states) = (snapshot.namespaces, snapshot.states);
        for (namespace, held) in &current.namespaces {
            match catalog
                .iter()
                .find(|n| &n.name == namespace)
                .map(|n| n.state)
            {
                Some(NamespaceState::Deleted) => {}
                None => {
                    namespaces.insert(
                        namespace.clone(),
                        NamespaceKeys {
                            keks: held.keks.clone(),
                            active: None,
                            vanished: held.keks.keys().copied().collect(),
                        },
                    );
                }
                Some(NamespaceState::Active) => {
                    let keys = namespaces
                        .get_mut(namespace)
                        .ok_or(SealError::Corrupt("a live namespace without KEKs"))?;
                    for (version, kek) in &held.keks {
                        if keys.keks.contains_key(version) {
                            continue;
                        }
                        let destroyed = states.iter().any(|k| {
                            &k.namespace == namespace
                                && k.version == *version
                                && k.state == KekState::Destroyed
                        });
                        if !destroyed {
                            keys.keks.insert(*version, Arc::clone(kek));
                            keys.vanished.insert(*version);
                        }
                    }
                }
            }
        }
        // A set that doesn't verify (or a rollback) keeps the keys in force.
        let loaded = self.load_issuing(&current.root, issuing_floor, snapshot.issuing);
        let verified = loaded.as_ref().map(|keys| keys.revision);
        let next = Keyring {
            issuing: loaded.unwrap_or_else(|| current.issuing.clone()),
            root: Arc::clone(&current.root),
            generation: current.generation,
            namespaces,
        };
        let changed = next.summary() != current.summary()
            || next.issuing.summary() != current.issuing.summary();
        let result = refreshed(&next, changed, true);
        if changed {
            self.publish(epoch, next);
        }
        if let Some(revision) = verified {
            self.issuing_verified(revision).await;
        }
        Ok(result)
    }

    async fn load_keyring(&self, root: RootKey, generation: u32) -> Result<Keyring> {
        let namespaces = keys_from(&root, self.keystore.keks().await?)?;
        let floor = self.issuing_floor().await;
        let set = self.keystore.issuing_set().await?;
        let issuing = self.load_issuing(&root, floor, set).unwrap_or_default();
        if issuing.revision > 0 {
            self.issuing_verified(issuing.revision).await;
        }
        Ok(Keyring {
            root: Arc::new(root),
            generation,
            namespaces,
            issuing,
        })
    }

    /// Creates the workload-identity issuing CA (version 1): a new key,
    /// wrapped by the root key, and its self-signed certificate, stored and
    /// published. [`SealError::IssuingKeyExists`] once there is one. Under
    /// the admin lock, refused after a seal, like a KEK rotation.
    pub async fn identity_init(&self) -> Result<IssuingKeyInfo> {
        let epoch = self.epoch();
        let _admin = self.admin.lock().await;
        self.ensure_epoch(epoch)?;
        let keyring = self.keyring()?;
        if !self.keystore.issuing_set().await?.keys.is_empty() {
            return Err(SealError::IssuingKeyExists);
        }
        let known = self
            .issuing_floor()
            .await
            .map_err(SealError::IssuingFloor)?;
        let (pkcs8, certificate) =
            crate::identity::ca::generate(1, time::OffsetDateTime::now_utc())
                .map_err(SealError::Identity)?;
        let wrapped = keyring.root.wrap_issuing_key(1, &pkcs8)?;
        let revision = self
            .keystore
            .create_issuing_key(
                keyring.generation,
                &certificate,
                &wrapped,
                known,
                &Tagger(&keyring.root),
            )
            .await?;
        self.publish_issuing(epoch, &keyring, 1, revision).await
    }

    /// Replaces the active issuing key with a new one (its version + 1).
    /// The old one's certificates stay trusted until they expire, unless
    /// `revoke`: then nothing it signed is trusted from now on (for a key
    /// that may be compromised). Its private key is erased either way.
    pub async fn identity_rotate(&self, revoke: bool) -> Result<IssuingKeyInfo> {
        let epoch = self.epoch();
        let _admin = self.admin.lock().await;
        self.ensure_epoch(epoch)?;
        let keyring = self.keyring()?;
        let known = self
            .issuing_floor()
            .await
            .map_err(SealError::IssuingFloor)?;
        let stored = self.keystore.issuing_set().await?;
        if stored.keys.is_empty() {
            return Err(SealError::NoIssuingKey);
        }
        let version = stored
            .keys
            .iter()
            .map(|k| k.version)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(SealError::VersionExhausted)?;
        let (pkcs8, certificate) =
            crate::identity::ca::generate(version, time::OffsetDateTime::now_utc())
                .map_err(SealError::Identity)?;
        let wrapped = keyring.root.wrap_issuing_key(version, &pkcs8)?;
        // The key this server loaded: only its certificate may be retired
        // (trusted on), never one the keys database has instead.
        let loaded = keyring.issuing().active.as_ref();
        let at = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .map_err(|_| SealError::Corrupt("the time has no whole second"))?;
        let revision = self
            .keystore
            .rotate_issuing_key(
                keyring.generation,
                IssuingRotation {
                    expected_active: loaded.map(|ca| ca.version()),
                    active_certificate: loaded.map(|ca| ca.certificate()),
                    version,
                    certificate: &certificate,
                    wrapped_key: &wrapped,
                    revoke,
                    at,
                    known_revision: known,
                },
                &Tagger(&keyring.root),
            )
            .await?;
        self.publish_issuing(epoch, &keyring, version, revision)
            .await
    }

    /// Reloads the issuing keys after a change and publishes them with the
    /// keyring; returns the key `version` as stored.
    async fn publish_issuing(
        &self,
        epoch: u64,
        keyring: &Keyring,
        version: u32,
        revision: u64,
    ) -> Result<IssuingKeyInfo> {
        self.issuing_verified(revision).await;
        let issuing =
            IssuingKeys::load(&keyring.root, self.keystore.issuing_set().await?, revision)
                .map_err(|_| SealError::Corrupt("the issuing keys just written don't verify"))?;
        let info = issuing
            .stored
            .iter()
            .find(|k| k.version == version)
            .cloned()
            .ok_or(SealError::Corrupt("an issuing key stored, then not found"))?;
        self.publish(epoch, keyring.with_issuing(issuing));
        Ok(info)
    }

    /// The issuing keys in force on this server, without private parts
    /// (for status): as of its last load, from a set that verified.
    /// Unsealed only.
    pub fn issuing_keys(&self) -> Result<Vec<IssuingKeyInfo>> {
        Ok(self.keyring()?.issuing().stored.clone())
    }

    /// The emergency stop. Seals first (drops the keyring, zeroized once
    /// in-flight users release it, and any unseal progress), then works out
    /// what happened to a rekey in progress, so an unresolved rekey commit
    /// can't delay sealing. Never fails: a returned outcome always means
    /// sealed. A pending root key lives only until the end of this call.
    ///
    /// The admin lock stays held until the outcome is known. Otherwise an
    /// unseal could slip in during the check, still accept the old shares
    /// (its plain read doesn't wait for the unfinished commit) and unseal with
    /// the old root key just as the new one lands; and the returned status
    /// could then say unsealed. Other admin calls wait at most the commit
    /// check timeout, and only while the stored state is unresolved.
    ///
    /// The lockdown itself comes before the admin lock: an admin call stuck on
    /// the database delays only this response, never the sealing, and its
    /// own publish is then refused (see `Seal::publish`).
    pub async fn seal(&self) -> SealOutcome {
        self.seal_now();
        let mut admin = self.admin.lock().await;
        let attempt = admin.rekey.take();
        *admin = Admin::default();

        let pending_rekey = match attempt.map(|a| a.stage) {
            None => PendingRekey::None,
            Some(Stage::Authorizing) => PendingRekey::Discarded,
            Some(Stage::Verifying(pending)) => match self.is_committed(&pending).await {
                Ok(false) => PendingRekey::Discarded,
                Ok(true) => {
                    tracing::error!(
                        "sealed while a rekey was already stored: only the NEW shares unseal now"
                    );
                    PendingRekey::Committed
                }
                Err(e) => {
                    tracing::error!(
                        error = %error_chain(&e),
                        "sealed with a rekey whose storage can't be confirmed: \
                         keep both sets of shares until an unseal succeeds"
                    );
                    PendingRekey::Unknown
                }
            },
        };

        let status = match self.keystore.seal_config().await {
            Ok(config) => Some(self.status_of(config.as_ref(), &admin)),
            Err(e) => {
                tracing::error!(error = %error_chain(&e), "sealed, but can't read the seal config");
                None
            }
        };
        drop(admin);
        // The hold, after the keyring is gone (never before: nothing may
        // delay the seal), in both modes: the mode is per-server config, so
        // a Shamir server must hold back KMS ones too. One past the higher
        // of the two holds read.
        let hold = self.hold().await;
        let hold_set = self
            .write_hold(hold.highest().saturating_add(1), false)
            .await;
        if !hold_set {
            tracing::error!(
                "sealed; the auto-unseal hold is NOT set in both databases yet, so a restart \
                 could auto-unseal this server: retrying in the background"
            );
        }
        SealOutcome {
            status,
            pending_rekey,
            hold_set,
        }
    }

    /// KEKs in the keys database that are decrypt-only: superseded by a
    /// rotation, not yet retired. The candidates for retiring.
    pub async fn decrypt_only_versions(&self) -> Result<Vec<(Namespace, u32)>> {
        Ok(self
            .keystore
            .keks()
            .await?
            .into_iter()
            .filter(|k| k.state == KekState::DecryptOnly)
            .map(|k| (k.namespace, k.version))
            .collect())
    }

    /// Marks a decrypt-only KEK retired: bookkeeping only. Its wrapped key
    /// stays stored and loaded, so a row written with it later (by a server
    /// whose keyring is stale) still decrypts, and the next rewrap moves it.
    /// `false` if it wasn't decrypt-only any more (say, retired by another
    /// pass meanwhile).
    pub async fn retire_kek(&self, namespace: &Namespace, version: u32) -> Result<bool> {
        match self.keystore.retire(namespace, version).await {
            Ok(()) => Ok(true),
            Err(KeystoreError::NotDecryptOnly { .. }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Drops vanished KEK `version` of `namespace` (see [`Keyring`]) once no
    /// row uses it: its rows have been rescued, so it's served its purpose,
    /// and keeping it would leave two keys under one number if a rotation
    /// reuses the number (the rotate guard allows that once no row uses
    /// it). A lost namespace whose last vanished KEK goes is dropped from the
    /// keyring altogether. `false` if this keyring doesn't hold it as
    /// vanished. The caller checks the rows (`rewrap`). Nothing on *this*
    /// server wraps with a vanished KEK, so none of its own rows can appear
    /// meanwhile. Another server that hasn't refreshed yet still has it as
    /// its active KEK and may write with it; dropping our copy is still
    /// safe: that server keeps its own (its refresh marks it vanished there,
    /// for its own rewrap), and while such rows exist the rotate guard sees
    /// them and refuses to reuse the number. Under the admin lock, refused
    /// after a seal.
    pub async fn forget_vanished(&self, namespace: &Namespace, version: u32) -> Result<bool> {
        let epoch = self.epoch();
        let _admin = self.admin.lock().await;
        self.ensure_epoch(epoch)?;
        let keyring = self.keyring()?;
        let Some(held) = keyring.namespaces.get(namespace) else {
            return Ok(false);
        };
        if !held.vanished.contains(&version) {
            return Ok(false);
        }
        let mut keys = held.clone();
        keys.keks.remove(&version);
        keys.vanished.remove(&version);
        let keys = (!keys.keks.is_empty()).then_some(keys);
        Ok(self.publish(epoch, keyring.with(namespace, keys)))
    }

    /// How many vanished KEKs this server holds (see [`Keyring`]), while
    /// unsealed (for metrics).
    pub fn vanished_kek_count(&self) -> Option<u64> {
        self.keyring()
            .ok()
            .map(|keyring| u64::try_from(keyring.all_vanished().len()).unwrap_or(u64::MAX))
    }

    /// Every KEK in the keys database and its state, of every namespace,
    /// destroyed ones included.
    pub async fn kek_states(&self) -> Result<Vec<KekInfo>> {
        Ok(self.keystore.kek_states().await?)
    }

    /// Every namespace in the keys database, live and deleted.
    pub async fn stored_namespaces(&self) -> Result<Vec<StoredNamespace>> {
        Ok(self.keystore.namespaces().await?)
    }

    /// Changes a live namespace's labels in the keys database (no keys
    /// involved, so no admin lock).
    pub async fn update_namespace_labels(
        &self,
        namespace: &Namespace,
        set: &Labels,
        remove: &[String],
    ) -> Result<Labels> {
        Ok(self
            .keystore
            .update_namespace_labels(namespace, set, remove)
            .await?)
    }

    /// Creates `namespace` (or re-creates a deleted one) with its first KEK,
    /// and publishes it in this server's keyring; returns the KEK's version
    /// (1, or one past the highest the namespace ever had). Only the keys
    /// side: see `namespaces` for the check that must come first. Under the
    /// admin lock, refused after a seal; the keys database holds the seal
    /// config `FOR SHARE`, so it can't interleave with a rekey's commit.
    pub async fn create_namespace(&self, namespace: &Namespace, labels: &Labels) -> Result<u32> {
        self.create_namespace_from(namespace, labels, None).await
    }

    /// Recreates `namespace` after the keys database lost it, with its
    /// first KEK at `at_least` or above: past every version its rows use
    /// (the caller's part: see `namespaces`) and every version this server
    /// still holds for it (vanished KEKs), so no number goes to a second
    /// key. Those vanished KEKs stay held, for rewrap to move their rows.
    pub async fn recreate_lost_namespace(
        &self,
        namespace: &Namespace,
        labels: &Labels,
        at_least: u32,
    ) -> Result<u32> {
        self.create_namespace_from(namespace, labels, Some(at_least))
            .await
    }

    async fn create_namespace_from(
        &self,
        namespace: &Namespace,
        labels: &Labels,
        past_lost: Option<u32>,
    ) -> Result<u32> {
        let epoch = self.epoch();
        let _admin = self.admin.lock().await;
        self.ensure_epoch(epoch)?;
        let keyring = self.keyring()?;
        let next = self.keystore.next_namespace_version(namespace).await?;
        let held = keyring.namespaces.get(namespace);
        let (version, numbering) = match past_lost {
            None => (next, Numbering::Next),
            Some(at_least) => {
                let past_held = held
                    .and_then(|keys| keys.keks.keys().max())
                    .map_or(Ok(0), |v| {
                        v.checked_add(1).ok_or(SealError::VersionExhausted)
                    })?;
                (next.max(at_least).max(past_held), Numbering::PastLost)
            }
        };
        let kek = Kek::generate()?;
        let wrapped = keyring.root.wrap_kek(namespace, version, &kek)?;
        self.keystore
            .create_namespace(
                keyring.generation,
                namespace,
                version,
                numbering,
                &wrapped,
                labels,
            )
            .await?;
        let kek = Arc::new(kek);
        // A recovery keeps what this server still holds of the lost
        // namespace, for reading only: the rescue's source.
        let mut keks = held.map(|keys| keys.keks.clone()).unwrap_or_default();
        let mut vanished = held.map(|keys| keys.vanished.clone()).unwrap_or_default();
        // A plain create (no rows under the name) may reuse a number only a
        // vanished KEK had: nothing uses that key, the new one replaces it.
        vanished.remove(&version);
        keks.insert(version, Arc::clone(&kek));
        let keys = NamespaceKeys {
            keks,
            active: Some((version, kek)),
            vanished,
        };
        self.publish(epoch, keyring.with(namespace, Some(keys)));
        Ok(version)
    }

    /// Deletes `namespace` in the keys database (destroys its KEKs, marks it
    /// deleted) and drops it from this server's keyring. Only the keys side:
    /// see `namespaces` for what must come first. Under the admin lock,
    /// refused after a seal; seal config `FOR SHARE`, like create.
    pub async fn delete_namespace(&self, namespace: &Namespace) -> Result<DeletedNamespace> {
        let epoch = self.epoch();
        let _admin = self.admin.lock().await;
        self.ensure_epoch(epoch)?;
        let keyring = self.keyring()?;
        let deleted = self
            .keystore
            .delete_namespace(keyring.generation, namespace)
            .await?;
        self.publish(epoch, keyring.with(namespace, None));
        Ok(deleted)
    }

    /// Erases a retired KEK of `namespace` in the keys database and drops it
    /// from this server's keyring; `false` if it was already destroyed. Only
    /// the keys side of destroying: see `destroy` for what must come first.
    /// Under the admin lock, like rotate, and refused after a seal.
    pub async fn destroy_kek(&self, namespace: &Namespace, version: u32) -> Result<bool> {
        let epoch = self.epoch();
        let _admin = self.admin.lock().await;
        self.ensure_epoch(epoch)?;
        let keyring = self.keyring()?;
        if keyring.active_kek(namespace).map(|(v, _)| v) == Some(version) {
            // The keys database refuses it too (not retired); this keeps a
            // stale keyring from ever publishing without its active KEK.
            return Err(KeystoreError::NotRetired {
                namespace: namespace.clone(),
                version,
            }
            .into());
        }
        let destroyed = self
            .keystore
            .destroy(keyring.generation, namespace, version)
            .await?;
        if let Some(held) = keyring.namespaces.get(namespace)
            && held.keks.contains_key(&version)
        {
            let mut keys = held.clone();
            keys.keks.remove(&version);
            keys.vanished.remove(&version);
            self.publish(epoch, keyring.with(namespace, Some(keys)));
        }
        Ok(destroyed)
    }

    /// Adds a new active KEK to `namespace`; its previous one becomes
    /// decrypt-only. Returns the new version. If the server is sealed while
    /// this runs, the KEK is still stored and the next unseal loads it.
    /// [`SealError::NoNamespace`] if this server's keyring has no active KEK
    /// for it (refresh, then retry).
    pub async fn rotate(&self, namespace: &Namespace) -> Result<u32> {
        let epoch = self.epoch();
        let _admin = self.admin.lock().await;
        self.ensure_epoch(epoch)?;
        let keyring = self.keyring()?;
        let held = keyring
            .namespaces
            .get(namespace)
            .filter(|keys| keys.active.is_some())
            .ok_or_else(|| SealError::NoNamespace(namespace.clone()))?;
        let version = held
            .active
            .as_ref()
            .map(|(v, _)| *v)
            .unwrap_or_default()
            .checked_add(1)
            .ok_or(SealError::VersionExhausted)?;
        let kek = Kek::generate()?;
        let wrapped = keyring.root.wrap_kek(namespace, version, &kek)?;
        self.keystore
            .rotate(keyring.generation, namespace, version, &wrapped)
            .await?;

        let kek = Arc::new(kek);
        let mut keys = held.clone();
        keys.keks.insert(version, Arc::clone(&kek));
        // A vanished KEK under the same number is superseded: the keys
        // database has the version now, and the rotate guard made sure no
        // row still uses the old one.
        keys.vanished.remove(&version);
        keys.active = Some((version, kek));
        self.publish(epoch, keyring.with(namespace, Some(keys)));
        Ok(version)
    }

    /// Starts collecting current shares to authorize replacing the root key
    /// with one split per `params`. Requires the server unsealed.
    pub async fn rekey_start(&self, params: ShareParams) -> Result<RekeyProgress> {
        self.rekey_start_changing(params, None).await
    }

    /// [`Seal::rekey_start`], allowed to change how the root key is
    /// protected to `change` (`None`: it must stay as it is). A rekey's
    /// commit stores this server's wrap (or none) and deletes every other,
    /// so through a server configured otherwise than the deployment it would
    /// change every server's mode or key: refused unless asked for here, so
    /// the shares holders approve it knowingly.
    pub async fn rekey_start_changing(
        &self,
        params: ShareParams,
        change: Option<SealMode>,
    ) -> Result<RekeyProgress> {
        // The configured key, resolved before the admin lock (a slow KMS
        // mustn't delay `status`), as an auto-unseal attempt does.
        let here = match &self.auto {
            Some(auto) => Some(auto.key_id().await.map_err(SealError::AutoUnseal)?),
            None => None,
        };
        let epoch = self.epoch();
        let mut admin = self.admin.lock().await;
        self.ensure_epoch(epoch)?;
        self.keyring()?;
        if admin.rekey.is_some() {
            return Err(SealError::RekeyInProgress);
        }
        let config = self.config().await?;
        self.check_seal_change(config.generation, here, change)
            .await?;
        // A policy key that won't open would make the commit fail: refuse
        // now, before anyone hands in shares (the commit checks again).
        if let Some(wrapped) = self.keystore.wrapped_policy_key().await? {
            let keyring = self.keyring_at(epoch)?;
            if keyring.root.unwrap_policy_key(&wrapped).is_err() {
                return Err(SealError::PolicyKeyUnusable);
            }
        }
        // Likewise the active issuing key.
        if let Some(active) = self
            .keystore
            .issuing_set()
            .await?
            .keys
            .into_iter()
            .find(|k| k.state == IssuingKeyState::Active)
            && let Some(wrapped) = &active.wrapped_key
        {
            let keyring = self.keyring_at(epoch)?;
            if keyring
                .root
                .unwrap_issuing_key(active.version, wrapped)
                .is_err()
            {
                return Err(SealError::IssuingKeyUnusable);
            }
        }
        let attempt = RekeyAttempt {
            nonce: new_nonce()?,
            new_params: params,
            current_threshold: config.params.threshold(),
            stage: Stage::Authorizing,
            submitted: Vec::new(),
        };
        let progress = attempt.progress();
        admin.rekey = Some(attempt);
        Ok(progress)
    }

    /// Whether a rekey through this server, whose configured key is `here`
    /// (`None`: the shares alone), keeps the deployment's protection (the
    /// stored wraps at `generation`, or none), or changes it as `change`
    /// asks.
    async fn check_seal_change(
        &self,
        generation: u32,
        here: Option<String>,
        change: Option<SealMode>,
    ) -> Result<()> {
        let stored: Vec<String> = self
            .keystore
            .seal_config_and_wraps("awskms")
            .await?
            .1
            .into_iter()
            .filter(|w| w.generation == generation)
            .map(|w| w.key_id)
            .collect();
        let describe = |keys: &[String]| match keys {
            [] => "shamir (the shares alone)".to_owned(),
            keys => format!("awskms with {}", keys.join(", ")),
        };
        let here_text = describe(here.as_slice());
        match change {
            None => {
                let same = match &here {
                    None => stored.is_empty(),
                    Some(key) => stored.len() == 1 && &stored[0] == key,
                };
                if same {
                    Ok(())
                } else {
                    Err(SealError::RekeyWouldChangeSeal {
                        stored: describe(&stored),
                        here: here_text,
                        suggest: if here.is_some() {
                            SealMode::AwsKms.as_str()
                        } else {
                            SealMode::Shamir.as_str()
                        },
                    })
                }
            }
            Some(SealMode::Shamir) if here.is_some() => Err(SealError::SealChangeUnconfigured {
                asked: SealMode::Shamir.as_str(),
                here: here_text,
            }),
            Some(SealMode::AwsKms) if here.is_none() => Err(SealError::SealChangeUnconfigured {
                asked: SealMode::AwsKms.as_str(),
                here: here_text,
            }),
            Some(_) => Ok(()),
        }
    }

    /// Submits one current share. Once the threshold is in and they rebuild
    /// the current root key, generates the new root key and returns its
    /// shares, without storing anything: the rekey moves to
    /// [`RekeyPhase::Verifying`], and the current shares stay valid until
    /// [`Seal::rekey_verify`] commits.
    pub async fn rekey_submit(&self, nonce: &str, share: &[u8]) -> Result<RekeyProgress> {
        let epoch = self.epoch();
        let mut admin = self.admin.lock().await;
        self.ensure_epoch(epoch)?;
        self.keyring()?;
        let attempt = admin.rekey.as_mut().ok_or(SealError::NoRekey)?;
        attempt.check_nonce(nonce)?;
        if !matches!(attempt.stage, Stage::Authorizing) {
            return Err(SealError::RekeyVerifying);
        }
        let config = self.config().await?;
        let share = accept_share(&attempt.submitted, share, config.generation)?;
        attempt.submitted.push(share);
        if attempt.submitted.len() < usize::from(attempt.current_threshold) {
            return Ok(attempt.progress());
        }

        let submitted = std::mem::take(&mut attempt.submitted);
        reconstruct(&submitted, &config)?;

        let root = RootKey::generate()?;
        let root_check = root.root_check()?;
        let generation = config
            .generation
            .checked_add(1)
            .ok_or(SealError::Corrupt("generation overflow"))?;
        let new_shares = crypto::split(&root, attempt.new_params, generation)?;
        attempt.stage = Stage::Verifying(PendingRoot {
            root,
            root_check,
            base_generation: config.generation,
            generation,
        });
        Ok(RekeyProgress {
            new_shares,
            ..attempt.progress()
        })
    }

    /// Submits one of the new shares. Once the new threshold is in and they
    /// rebuild the pending root key, re-wraps every KEK under it and stores it
    /// all in one transaction. Only then do the old shares stop working.
    /// KEKs are re-wrapped here, not at authorization, so a rotation in
    /// between is covered.
    pub async fn rekey_verify(&self, nonce: &str, share: &[u8]) -> Result<RekeyProgress> {
        let epoch = self.epoch();
        let mut admin = self.admin.lock().await;
        self.ensure_epoch(epoch)?;
        let keyring = self.keyring()?;
        let attempt = admin.rekey.as_mut().ok_or(SealError::NoRekey)?;
        attempt.check_nonce(nonce)?;
        let Stage::Verifying(pending) = &attempt.stage else {
            return Err(SealError::RekeyAuthorizing);
        };
        let share = accept_share(&attempt.submitted, share, pending.generation)?;
        attempt.submitted.push(share);
        if attempt.submitted.len() < usize::from(attempt.new_params.threshold()) {
            return Ok(attempt.progress());
        }

        let submitted = std::mem::take(&mut attempt.submitted);
        crypto::combine(&submitted, pending.generation)?
            .verify_root_check(&pending.root_check)
            .map_err(|_| SealError::WrongShares)?;

        // Only the stored KEKs: the keys database must cover exactly its
        // own versions, and a vanished one isn't one of them.
        let rewrapped = keyring
            .namespaces
            .iter()
            .flat_map(|(namespace, keys)| {
                keys.keks
                    .iter()
                    .filter(|(version, _)| !keys.vanished.contains(version))
                    .map(move |(&version, kek)| (namespace, version, kek))
            })
            .map(|(namespace, version, kek)| {
                Ok(RewrappedKek {
                    namespace: namespace.clone(),
                    version,
                    wrapped_key: pending.root.wrap_kek(namespace, version, kek)?,
                })
            })
            .collect::<Result<Vec<_>, CryptoError>>()?;
        // With auto-unseal, the new root key's wrap, before anything is
        // stored and before the keys database's transaction opens: the KMS
        // call may take seconds, and must never hold seal_config's lock.
        let wrap = self.wrap_root(&pending.root, pending.generation).await?;
        // The new generation's commitment, before the keys database commits:
        // an attempt that then fails leaves one nobody has the key of.
        if let Some(ledger) = &self.root_ledger {
            ledger
                .insert(
                    pending.generation,
                    pending.root.root_commitment(pending.generation)?.to_vec(),
                )
                .await
                .map_err(SealError::RootLedger)?;
        }
        // An error doesn't prove nothing was stored (the connection can drop
        // after Postgres commits), so on error ask the database before
        // treating the attempt as still pending.
        let outcome = self
            .keystore
            .rekey(
                pending.base_generation,
                attempt.new_params,
                &pending.root_check,
                &rewrapped,
                &Rewrapping {
                    current: &keyring.root,
                    new: &pending.root,
                    wrap,
                },
            )
            .await;
        let generation = match outcome {
            Ok(stored) => {
                // Committed: never fail from here on, whatever we find.
                if stored != pending.generation {
                    tracing::error!(
                        stored,
                        expected = pending.generation,
                        "rekey stored an unexpected generation"
                    );
                }
                stored
            }
            Err(e) => match self.is_committed(pending).await {
                // Refused before anything was written.
                Ok(false) if matches!(e, KeystoreError::PolicyKeyUnusable) => {
                    return Err(SealError::PolicyKeyUnusable);
                }
                Ok(false) if matches!(e, KeystoreError::IssuingKeyUnusable) => {
                    return Err(SealError::IssuingKeyUnusable);
                }
                Ok(false) => return Err(e.into()),
                Ok(true) => {
                    tracing::warn!(
                        error = %error_chain(&e),
                        "rekey reported an error but was committed"
                    );
                    pending.generation
                }
                Err(check) => {
                    tracing::error!(
                        error = %error_chain(&e),
                        check = %error_chain(&check),
                        "rekey outcome unknown"
                    );
                    return Err(SealError::RekeyOutcomeUnknown);
                }
            },
        };
        self.adopt(epoch, &mut admin, &keyring, generation)
    }

    /// Abandons the attempt in either phase; a pending new root key is
    /// dropped and the current shares stay valid. Refuses if the database
    /// already holds the pending key (a commit reported as failed): then the
    /// rekey is adopted instead, since the old shares no longer work.
    pub async fn rekey_cancel(&self, nonce: &str) -> Result<RekeyProgress> {
        let epoch = self.epoch();
        let mut admin = self.admin.lock().await;
        self.ensure_epoch(epoch)?;
        let attempt = admin.rekey.as_ref().ok_or(SealError::NoRekey)?;
        attempt.check_nonce(nonce)?;
        if let Stage::Verifying(pending) = &attempt.stage {
            let generation = pending.generation;
            match self.is_committed(pending).await {
                Ok(false) => {}
                Ok(true) => {
                    let keyring = self.keyring()?;
                    self.adopt(epoch, &mut admin, &keyring, generation)?;
                    return Err(SealError::RekeyCommitted { generation });
                }
                Err(e) => {
                    tracing::error!(error = %error_chain(&e), "rekey outcome unknown");
                    return Err(SealError::RekeyOutcomeUnknown);
                }
            }
        }
        let progress = RekeyProgress {
            phase: RekeyPhase::Cancelled,
            progress: 0,
            // Only COMPLETE and VERIFYING carry a generation.
            generation: None,
            ..attempt.progress()
        };
        admin.rekey = None;
        Ok(progress)
    }

    /// Whether the keys database already holds `pending`: the stored root
    /// check opens under the pending root key, at the pending generation.
    ///
    /// Waits (up to the commit-check timeout) for any transaction still
    /// holding the row, such as our own rekey whose COMMIT was sent but not
    /// confirmed: a plain read could still see the old row and answer "not
    /// committed" just before the commit lands. A timeout is an error, which
    /// callers report as [`SealError::RekeyOutcomeUnknown`].
    async fn is_committed(&self, pending: &PendingRoot) -> Result<bool> {
        let config = self
            .keystore
            .settled_seal_config(self.commit_check_timeout)
            .await?
            .ok_or(SealError::NotInitialized)?;
        Ok(config.generation == pending.generation
            && pending.root.verify_root_check(&config.root_check).is_ok())
    }

    /// Ends a verifying attempt whose key is stored: publishes the pending
    /// root key as the keyring's. The rekey is stored either way, so this
    /// reports it complete even if a seal refuses the publish.
    fn adopt(
        &self,
        epoch: u64,
        admin: &mut Admin,
        keyring: &Keyring,
        generation: u32,
    ) -> Result<RekeyProgress> {
        let Some(RekeyAttempt {
            nonce,
            new_params,
            stage: Stage::Verifying(pending),
            ..
        }) = admin.rekey.take()
        else {
            return Err(SealError::Corrupt("no verifying rekey to adopt"));
        };
        self.raise_root_floor_later(generation);
        self.publish(
            epoch,
            Keyring {
                root: Arc::new(pending.root),
                generation,
                namespaces: keyring.namespaces.clone(),
                issuing: keyring.issuing.clone(),
            },
        );
        Ok(RekeyProgress {
            nonce,
            phase: RekeyPhase::Complete,
            progress: usize::from(new_params.threshold()),
            required: new_params.threshold(),
            new_shares: Vec::new(),
            generation: Some(generation),
        })
    }
}

/// The keys of `stored` (the keys database's KEKs not destroyed), unwrapped
/// with `root`, by namespace. A live namespace's active KEK must be there.
fn keys_from(root: &RootKey, stored: Vec<StoredKek>) -> Result<BTreeMap<Namespace, NamespaceKeys>> {
    let mut namespaces: BTreeMap<Namespace, NamespaceKeys> = BTreeMap::new();
    for row in stored {
        let kek = Arc::new(root.unwrap_kek(&row.namespace, row.version, &row.wrapped_key)?);
        let keys = namespaces
            .entry(row.namespace)
            .or_insert_with(|| NamespaceKeys {
                keks: BTreeMap::new(),
                active: None,
                vanished: BTreeSet::new(),
            });
        if row.state == KekState::Active {
            keys.active = Some((row.version, Arc::clone(&kek)));
        }
        keys.keks.insert(row.version, kek);
    }
    if namespaces.values().any(|keys| keys.active.is_none()) {
        return Err(SealError::Corrupt("a namespace without an active KEK"));
    }
    Ok(namespaces)
}

impl StoredPolicies for Seal {
    fn decide(&self, identity: &SecretPath, action: SecretAction, target: Target<'_>) -> Stored {
        let published = self
            .published
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        match &published.policies {
            PolicyView::Sealed => Stored::Sealed,
            PolicyView::Unverified(_) => Stored::Unverified,
            PolicyView::Loaded(set) if set.allows(identity, action, target) => Stored::Allowed,
            PolicyView::Loaded(_) => Stored::Denied,
        }
    }
}

/// A [`Refreshed`] describing `keyring`.
fn refreshed(keyring: &Keyring, changed: bool, loaded: bool) -> Refreshed {
    Refreshed {
        active: keyring
            .namespaces
            .iter()
            .filter_map(|(ns, keys)| keys.active.as_ref().map(|(v, _)| (ns.clone(), *v)))
            .collect(),
        changed,
        loaded,
        vanished: keyring.all_vanished(),
    }
}

/// Parses a submitted share and checks it belongs with the ones already in.
fn accept_share(pending: &[Share], bytes: &[u8], generation: u32) -> Result<Share> {
    let share = Share::from_bytes(bytes).map_err(SealError::InvalidShare)?;
    if share.generation() != generation {
        return Err(SealError::InvalidShare(CryptoError::StaleShare {
            expected: generation,
            found: share.generation(),
        }));
    }
    if pending.iter().any(|p| p.id() == share.id()) {
        return Err(SealError::DuplicateShare(share.id()));
    }
    Ok(share)
}

/// Combines `shares` and confirms the result is the stored root key.
fn reconstruct(shares: &[Share], config: &SealConfig) -> Result<RootKey> {
    let root = crypto::combine(shares, config.generation)?;
    root.verify_root_check(&config.root_check)
        .map_err(|_| SealError::WrongShares)?;
    Ok(root)
}

/// Identifies one rekey attempt: 128 random bits, hex.
fn new_nonce() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| SealError::Crypto(e.into()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
