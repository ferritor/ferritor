//! Access to the keys database (seal config, namespaces, and each
//! namespace's KEKs).
//!
//! Everything here is opaque bytes: KEKs arrive already wrapped by the root
//! key, and the root check already sealed. The server does the crypto.
//!
//! Every write of KEK rows locks the `seal_config` row: rotate, destroy and
//! creating or deleting a namespace `FOR SHARE`, rekey `FOR UPDATE`. So they
//! serialize with a rekey: nothing can add or change a KEK wrapped under the
//! old root key while a rekey is re-wrapping the keyring.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use ferritor_core::crypto::{CryptoError, IssuingRecord, ShareParams};
use ferritor_core::labels::{Labels, MAX_LABELS};
use ferritor_core::path::{Namespace, NamespaceError};
use sqlx::types::Json;
use sqlx::types::time::OffsetDateTime;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};

mod policies;

pub use policies::{
    NewPolicy, PolicyChanges, PolicySnapshot, PolicyState, PolicyWrite, StoredPolicy,
};

/// Migrations in `migrations/`, embedded at compile time.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// Generation of the seal set up by [`Keystore::initialize`]. Shares from the
/// initial split must be made with it.
pub const INITIAL_GENERATION: u32 = 1;

/// Version of a new namespace's first KEK ([`Keystore::create_namespace`]).
pub const FIRST_KEK_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("keys database error")]
    Db(#[source] sqlx::Error),
    #[error("the seal is already initialized")]
    AlreadyInitialized,
    #[error("the seal is not initialized")]
    NotInitialized,
    #[error("seal generation is {found}, expected {expected}")]
    GenerationMismatch { expected: u32, found: u32 },
    #[error(
        "cannot rotate namespace `{namespace}` to KEK version {new_version}: active version is \
         {active:?}"
    )]
    RotateConflict {
        namespace: Namespace,
        new_version: u32,
        active: Option<u32>,
    },
    #[error("re-wrapped KEK versions don't match the keyring")]
    KekSetMismatch,
    #[error("KEK version {version} of namespace `{namespace}` is not decrypt-only")]
    NotDecryptOnly { namespace: Namespace, version: u32 },
    #[error("KEK version {version} of namespace `{namespace}` is not retired")]
    NotRetired { namespace: Namespace, version: u32 },
    #[error("there is no namespace `{0}`")]
    NoNamespace(Namespace),
    #[error("namespace `{0}` already exists")]
    NamespaceExists(Namespace),
    /// A creation that lost a race (another one took the version first).
    #[error("namespace `{namespace}` can't start at KEK version {version}; expected {expected}")]
    CreateConflict {
        namespace: Namespace,
        version: u32,
        expected: u32,
    },
    #[error("{count} labels; a namespace holds at most {MAX_LABELS}")]
    TooManyLabels { count: usize },
    /// Only if a stored row bypassed the `namespaces` CHECK.
    #[error("stored namespace name is invalid")]
    InvalidStoredNamespace(#[source] NamespaceError),
    /// Only if the stored row bypassed the `seal_config` CHECKs.
    #[error("stored share parameters are invalid")]
    InvalidStoredShareParams(#[source] CryptoError),
    #[error("{field} value {value} is out of range")]
    OutOfRange { field: &'static str, value: i64 },
    #[error("unknown KEK state `{0}` in the keys database")]
    UnknownKekState(String),
    #[error("unknown namespace state `{0}` in the keys database")]
    UnknownNamespaceState(String),
    #[error("timed out waiting for a transaction holding the seal config")]
    LockTimeout,
    /// A rekey found a stored policy key it can't re-wrap: it doesn't open
    /// under the current root key (cleared or changed in the database).
    #[error(
        "the stored policy key doesn't open under the current root key, so a rekey can't \
         re-wrap it; repair the stored policies first (`ferritor policy apply --prune` from their \
         source of truth, which creates a new key), then rekey"
    )]
    PolicyKeyUnusable,
    /// A rekey found the active issuing key unable to re-wrap: it doesn't
    /// open under the current root key.
    #[error(
        "the stored issuing key doesn't open under the current root key, so a rekey can't \
         re-wrap it; rotate it first (`ferritor identity rotate --now`), then rekey"
    )]
    IssuingKeyUnusable,
    #[error("the workload-identity issuing CA already exists (rotate it instead)")]
    IssuingKeyExists,
    #[error("there is no active issuing key (initialize one first)")]
    NoIssuingKey,
    /// A rotation that lost a race (another one replaced the key first).
    #[error("can't rotate issuing key {expected}: the active one is {active:?}")]
    IssuingKeyConflict { expected: u32, active: Option<u32> },
    #[error("tagging the issuing keys failed")]
    IssuingTagFailed,
    #[error(
        "the stored issuing keys don't verify under the root key, or were rolled back: only \
         a revoking rotation (`ferritor identity rotate --now`) replaces them"
    )]
    IssuingKeysUnverified,
    #[error("unknown issuing key state `{0}` in the keys database")]
    UnknownIssuingKeyState(String),
    /// The client-side bound ([`Keystore::with_timeout`]) ran out. For a
    /// write, the outcome is unknown: it may have committed.
    #[error("the keys database did not respond in time")]
    Timeout,
}

impl From<sqlx::Error> for KeystoreError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            // No connection free within the pool's acquire timeout: the
            // database is overloaded or unreachable, like a client-side
            // timeout, and must look the same to callers (UNAVAILABLE).
            sqlx::Error::PoolTimedOut => Self::Timeout,
            other => Self::Db(other),
        }
    }
}

type Result<T, E = KeystoreError> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KekState {
    /// Wraps new DEKs. Exactly one KEK per (live) namespace is active.
    Active,
    /// Superseded by a rotation; still unwraps DEKs not yet re-wrapped.
    DecryptOnly,
    /// No DEK references it any more.
    Retired,
    /// Its wrapped key is erased ([`Keystore::destroy`]); only the row
    /// remains, so the version is never reused.
    Destroyed,
}

impl KekState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::DecryptOnly => "decrypt_only",
            Self::Retired => "retired",
            Self::Destroyed => "destroyed",
        }
    }
}

impl FromStr for KekState {
    type Err = KeystoreError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "active" => Ok(Self::Active),
            "decrypt_only" => Ok(Self::DecryptOnly),
            "retired" => Ok(Self::Retired),
            "destroyed" => Ok(Self::Destroyed),
            other => Err(KeystoreError::UnknownKekState(other.to_owned())),
        }
    }
}

impl fmt::Display for KekState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealConfig {
    pub params: ShareParams,
    pub root_check: Vec<u8>,
    pub generation: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredKek {
    pub namespace: Namespace,
    pub version: u32,
    /// Wrapped by the root key of the current generation, bound to the
    /// namespace and version.
    pub wrapped_key: Vec<u8>,
    pub state: KekState,
}

/// A KEK's identity and state, without key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KekInfo {
    pub namespace: Namespace,
    pub version: u32,
    pub state: KekState,
}

/// A KEK re-wrapped under a new root key, for [`Keystore::rekey`].
#[derive(Clone, Debug)]
pub struct RewrappedKek {
    pub namespace: Namespace,
    pub version: u32,
    pub wrapped_key: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamespaceState {
    Active,
    /// Its KEKs are destroyed; the row stays (see the migration).
    Deleted,
}

/// A namespace as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredNamespace {
    pub name: Namespace,
    pub state: NamespaceState,
    pub created_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub labels: Labels,
    pub labels_updated_at: Option<OffsetDateTime>,
}

/// An issuing key's state (see the migration).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssuingKeyState {
    /// Signs; its certificates are trusted.
    Active,
    /// Replaced; its certificates stay trusted until they've expired.
    Retired,
    /// Replaced and cut off: nothing it signed is trusted.
    Revoked,
}

impl IssuingKeyState {
    fn parse(state: &str) -> Result<Self> {
        Ok(match state {
            "active" => Self::Active,
            "retired" => Self::Retired,
            "revoked" => Self::Revoked,
            other => return Err(KeystoreError::UnknownIssuingKeyState(other.to_owned())),
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }
}

/// A workload-identity issuing key as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredIssuingKey {
    pub version: u32,
    /// The CA certificate, DER.
    pub certificate: Vec<u8>,
    pub state: IssuingKeyState,
    /// The private key wrapped by the root key, bound to the version: the
    /// active key's only.
    pub wrapped_key: Option<Vec<u8>>,
    pub created_at: OffsetDateTime,
    pub retired_at: Option<OffsetDateTime>,
}

/// Every issuing key, with the set's revision and tag (`issuing_set`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuingSet {
    /// 0 without a set row.
    pub revision: u64,
    /// The root key's MAC over the revision and every key's record
    /// ([`IssuingSet::records`]); `None` without a set row.
    pub tag: Option<Vec<u8>>,
    /// Oldest first.
    pub keys: Vec<StoredIssuingKey>,
}

impl IssuingSet {
    /// What its tag covers, besides the revision.
    pub fn records(&self) -> Vec<IssuingRecord<'_>> {
        self.keys.iter().map(StoredIssuingKey::record).collect()
    }
}

/// Makes the issuing set's tag for a revision and its records (the root
/// key's, [`ferritor_core::crypto::RootKey::tag_issuing_set`]); `None` if it
/// can't.
pub trait IssuingTagger: Send + Sync {
    fn tag(&self, revision: u64, records: &[IssuingRecord<'_>]) -> Option<Vec<u8>>;
    /// Whether `set`'s tag is this key's.
    fn verifies(&self, set: &IssuingSet) -> bool;
}

impl StoredIssuingKey {
    /// What the set's tag covers of it.
    pub fn record(&self) -> IssuingRecord<'_> {
        IssuingRecord {
            version: self.version,
            state: self.state.as_str(),
            retired_at: self.retired_at.map(OffsetDateTime::unix_timestamp),
            certificate: &self.certificate,
        }
    }
}

/// What a rekey commit re-wraps besides the KEKs, re-read under its lock
/// ([`Keystore::rekey`]): each gives it for the new root key, or `None`
/// when the current root key doesn't open (or vouch for) it.
pub trait RekeyRewrap {
    /// The policy key (`None` refuses the rekey, `PolicyKeyUnusable`).
    fn policy_key(&self, wrapped: &[u8]) -> Option<Vec<u8>>;
    /// The active issuing key (`None` refuses it, `IssuingKeyUnusable`).
    fn issuing_key(&self, version: u32, wrapped: &[u8]) -> Option<Vec<u8>>;
    /// The issuing set's tag, same revision (`None` leaves it, and it then
    /// never verifies again).
    fn issuing_tag(&self, set: &IssuingSet) -> Option<Vec<u8>>;
    /// The new root key wrapped by a KMS (auto-unseal), stored by the
    /// commit, which deletes every other wrap; `None` (a server configured
    /// for Shamir alone) leaves none.
    fn seal_wrap(&self) -> Option<&SealWrap> {
        None
    }
}

/// The root key wrapped by a key management service, for auto-unseal
/// (`seal_wraps`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealWrap {
    /// `awskms`.
    pub provider: String,
    /// The key as the provider names it (an ARN).
    pub key_id: String,
    /// The root key generation it wraps.
    pub generation: u32,
    pub ciphertext: Vec<u8>,
}

/// A rotation of the issuing key ([`Keystore::rotate_issuing_key`]).
#[derive(Clone, Copy, Debug)]
pub struct IssuingRotation<'a> {
    /// The active version as the caller has it loaded (a rotation by
    /// another server since conflicts), or `None` if it has none loaded.
    pub expected_active: Option<u32>,
    /// Its certificate as the caller loaded it with its key (so knows it's
    /// genuine); `None` if it didn't load, which revokes it whatever
    /// `revoke` says.
    pub active_certificate: Option<&'a [u8]>,
    /// The new key: one past the highest stored version, its certificate
    /// and wrapped private key.
    pub version: u32,
    pub certificate: &'a [u8],
    pub wrapped_key: &'a [u8],
    /// Revoke the old key and every retired one.
    pub revoke: bool,
    /// When (whole seconds: the tag covers seconds).
    pub at: OffsetDateTime,
    /// The lowest revision the stored set may have (the caller's floor and
    /// the highest it saw): one below is a rollback.
    pub known_revision: u64,
}

/// What [`Keystore::snapshot`] read, all from one snapshot.
#[derive(Debug)]
pub struct Snapshot {
    pub config: Option<SealConfig>,
    /// As [`Keystore::keks`]: every KEK not destroyed.
    pub keks: Vec<StoredKek>,
    /// As [`Keystore::kek_states`]: every KEK, destroyed ones included.
    pub states: Vec<KekInfo>,
    pub namespaces: Vec<StoredNamespace>,
    /// The issuing keys as a set.
    pub issuing: IssuingSet,
}

/// Where [`Keystore::create_namespace`] lets a namespace's first KEK land.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Numbering {
    /// Exactly one past the highest it ever had here: the normal case.
    Next,
    /// Anywhere above that: only for recovering a namespace this database
    /// lost, past the KEK versions its rows (or a server's memory) still
    /// use, so none of those numbers goes to a different key.
    PastLost,
}

/// What [`Keystore::delete_namespace`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletedNamespace {
    /// KEK versions destroyed by this call.
    pub destroyed: Vec<u32>,
    /// The highest KEK version the namespace ever had.
    pub highest: u32,
    /// `false` if it was already deleted.
    pub deleted: bool,
}

fn namespace_from_db(name: String) -> Result<Namespace> {
    Namespace::parse(&name).map_err(KeystoreError::InvalidStoredNamespace)
}

fn namespace_state(state: &str) -> Result<NamespaceState> {
    match state {
        "active" => Ok(NamespaceState::Active),
        "deleted" => Ok(NamespaceState::Deleted),
        other => Err(KeystoreError::UnknownNamespaceState(other.to_owned())),
    }
}

fn seal_config_from_row(
    shares: i32,
    threshold: i32,
    root_check: Vec<u8>,
    generation: i32,
) -> Result<SealConfig> {
    Ok(SealConfig {
        params: ShareParams::new(
            u8_from_db("shares", shares)?,
            u8_from_db("threshold", threshold)?,
        )
        .map_err(KeystoreError::InvalidStoredShareParams)?,
        root_check,
        generation: u32_from_db("generation", generation)?,
    })
}

fn to_db(field: &'static str, value: u32) -> Result<i32> {
    i32::try_from(value).map_err(|_| KeystoreError::OutOfRange {
        field,
        value: value.into(),
    })
}

fn u32_from_db(field: &'static str, value: i32) -> Result<u32> {
    u32::try_from(value).map_err(|_| KeystoreError::OutOfRange {
        field,
        value: value.into(),
    })
}

fn u8_from_db(field: &'static str, value: i32) -> Result<u8> {
    u8::try_from(value).map_err(|_| KeystoreError::OutOfRange {
        field,
        value: value.into(),
    })
}

/// Row lock taken on `seal_config`.
#[derive(Clone, Copy, Debug)]
enum Lock {
    /// `FOR SHARE`: rotations; conflicts only with a rekey.
    Share,
    /// `FOR UPDATE`: rekey; excludes rotations and other rekeys.
    Update,
}

/// Locks the seal config row and checks its generation.
async fn lock_generation(
    tx: &mut Transaction<'_, Postgres>,
    expected: u32,
    lock: Lock,
) -> Result<()> {
    // Separate literals: `query_scalar!` needs the SQL at compile time.
    let found = match lock {
        Lock::Share => {
            sqlx::query_scalar!("SELECT generation FROM seal_config FOR SHARE")
                .fetch_optional(&mut **tx)
                .await?
        }
        Lock::Update => {
            sqlx::query_scalar!("SELECT generation FROM seal_config FOR UPDATE")
                .fetch_optional(&mut **tx)
                .await?
        }
    };
    let found = u32_from_db("generation", found.ok_or(KeystoreError::NotInitialized)?)?;
    if found != expected {
        return Err(KeystoreError::GenerationMismatch { expected, found });
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Keystore {
    pool: PgPool,
    timeout: Duration,
}

/// Default for [`Keystore::with_timeout`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounds a database operation client-side: a hung connection or a network
/// partition, which Postgres's own timeouts can't see, can't stall the caller
/// for longer than `timeout`.
/// See [`Keystore::seal_config`].
async fn seal_config_in(conn: &mut PgConnection) -> Result<Option<SealConfig>> {
    let row = sqlx::query!("SELECT shares, threshold, root_check, generation FROM seal_config")
        .fetch_optional(conn)
        .await?;
    row.map(|r| seal_config_from_row(r.shares, r.threshold, r.root_check, r.generation))
        .transpose()
}

async fn insert_wrap(conn: &mut PgConnection, wrap: &SealWrap) -> Result<()> {
    sqlx::query!(
        "INSERT INTO seal_wraps (provider, key_id, generation, ciphertext)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (provider, key_id) DO UPDATE
         SET generation = EXCLUDED.generation, ciphertext = EXCLUDED.ciphertext,
             created_at = now()",
        wrap.provider,
        wrap.key_id,
        to_db("generation", wrap.generation)?,
        wrap.ciphertext,
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// See [`Keystore::issuing_set`].
async fn issuing_set_in(conn: &mut PgConnection) -> Result<IssuingSet> {
    let keys = sqlx::query!(
        "SELECT version, certificate, state, wrapped_key, created_at, retired_at
         FROM issuing_keys ORDER BY version"
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok(StoredIssuingKey {
            version: u32_from_db("version", row.version)?,
            certificate: row.certificate,
            state: IssuingKeyState::parse(&row.state)?,
            wrapped_key: row.wrapped_key,
            created_at: row.created_at,
            retired_at: row.retired_at,
        })
    })
    .collect::<Result<Vec<_>>>()?;
    let set = sqlx::query!("SELECT revision, tag FROM issuing_set")
        .fetch_optional(&mut *conn)
        .await?;
    let (revision, tag) = match set {
        Some(row) => (
            u64::try_from(row.revision).map_err(|_| KeystoreError::OutOfRange {
                field: "issuing revision",
                value: row.revision,
            })?,
            Some(row.tag),
        ),
        None => (0, None),
    };
    Ok(IssuingSet {
        revision,
        tag,
        keys,
    })
}

/// Writes the set's revision and its tag over the keys as they now are.
async fn retag_issuing_set(
    conn: &mut PgConnection,
    revision: u64,
    tagger: &impl IssuingTagger,
) -> Result<()> {
    let set = issuing_set_in(conn).await?;
    let tag = tagger
        .tag(revision, &set.records())
        .ok_or(KeystoreError::IssuingTagFailed)?;
    let revision = i64::try_from(revision).map_err(|_| KeystoreError::OutOfRange {
        field: "issuing revision",
        value: i64::MAX,
    })?;
    sqlx::query!(
        "INSERT INTO issuing_set (revision, tag) VALUES ($1, $2)
         ON CONFLICT (singleton) DO UPDATE SET revision = $1, tag = $2",
        revision,
        tag,
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Serializes writes to the issuing keys: the set's row if there is one,
/// and, for the very first write, the table itself (there's no row yet).
async fn lock_issuing_set(conn: &mut PgConnection) -> Result<()> {
    sqlx::query!("LOCK TABLE issuing_set IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The next revision: one past the higher of `stored` and `known`.
fn next_issuing_revision(stored: u64, known: u64) -> Result<u64> {
    stored
        .max(known)
        .checked_add(1)
        .filter(|r| i64::try_from(*r).is_ok())
        .ok_or(KeystoreError::OutOfRange {
            field: "issuing revision",
            value: i64::MAX,
        })
}

async fn keks_in(conn: &mut PgConnection) -> Result<Vec<StoredKek>> {
    // Not null there: the keks_destroyed CHECK.
    sqlx::query!(
        r#"SELECT namespace, version, wrapped_key AS "wrapped_key!", state FROM keks
           WHERE state <> 'destroyed' ORDER BY namespace, version"#
    )
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok(StoredKek {
            namespace: namespace_from_db(row.namespace)?,
            version: u32_from_db("version", row.version)?,
            wrapped_key: row.wrapped_key,
            state: row.state.parse()?,
        })
    })
    .collect()
}

/// See [`Keystore::kek_states`].
async fn kek_states_in(conn: &mut PgConnection) -> Result<Vec<KekInfo>> {
    sqlx::query!("SELECT namespace, version, state FROM keks ORDER BY namespace, version")
        .fetch_all(conn)
        .await?
        .into_iter()
        .map(|row| {
            Ok(KekInfo {
                namespace: namespace_from_db(row.namespace)?,
                version: u32_from_db("version", row.version)?,
                state: row.state.parse()?,
            })
        })
        .collect()
}

/// See [`Keystore::namespaces`].
async fn namespaces_in(conn: &mut PgConnection) -> Result<Vec<StoredNamespace>> {
    sqlx::query!(
        r#"SELECT name, state, created_at, deleted_at,
               labels AS "labels: Json<Labels>", labels_updated_at
           FROM namespaces ORDER BY name"#
    )
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok(StoredNamespace {
            name: namespace_from_db(row.name)?,
            state: namespace_state(&row.state)?,
            created_at: row.created_at,
            deleted_at: row.deleted_at,
            labels: row.labels.0,
            labels_updated_at: row.labels_updated_at,
        })
    })
    .collect()
}

async fn bounded<T>(timeout: Duration, op: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(timeout, op)
        .await
        .map_err(|_| KeystoreError::Timeout)?
}

impl Keystore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Upper bound on every call, transactions included, after which it
    /// fails with [`KeystoreError::Timeout`].
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Stores the seal config at [`INITIAL_GENERATION`] and the first KEK as
    /// [`FIRST_KEK_VERSION`], active.
    /// Stores the seal configuration: the share parameters and the root
    /// check. No KEK: there's none until a namespace is created.
    pub async fn initialize(&self, params: ShareParams, root_check: &[u8]) -> Result<()> {
        self.initialize_wrapped(params, root_check, None).await
    }

    /// [`Keystore::initialize`], storing `wrap` (the root key wrapped by a
    /// KMS, for auto-unseal) in the same transaction.
    pub async fn initialize_wrapped(
        &self,
        params: ShareParams,
        root_check: &[u8],
        wrap: Option<&SealWrap>,
    ) -> Result<()> {
        bounded(self.timeout, async move {
            let mut tx = self.pool.begin().await?;
            let inserted = sqlx::query!(
                "INSERT INTO seal_config (shares, threshold, root_check, generation)
                 VALUES ($1, $2, $3, $4)",
                i32::from(params.shares()),
                i32::from(params.threshold()),
                root_check,
                to_db("generation", INITIAL_GENERATION)?,
            )
            .execute(&mut *tx)
            .await;
            if let Err(sqlx::Error::Database(e)) = &inserted
                && e.constraint() == Some("seal_config_pkey")
            {
                return Err(KeystoreError::AlreadyInitialized);
            }
            inserted?;
            if let Some(wrap) = wrap {
                insert_wrap(&mut tx, wrap).await?;
            }
            tx.commit().await?;
            Ok(())
        })
        .await
    }

    /// The seal config as of now. A plain read: it doesn't wait for a
    /// transaction still committing, so it can return the row from before a
    /// commit that has already been sent. See [`Keystore::settled_seal_config`].
    pub async fn seal_config(&self) -> Result<Option<SealConfig>> {
        bounded(self.timeout, async move {
            seal_config_in(&mut *self.pool.acquire().await?).await
        })
        .await
    }

    /// The seal config once no transaction holds its row, waiting at most
    /// `timeout` ([`KeystoreError::LockTimeout`] after that). A rekey keeps
    /// its `FOR UPDATE` lock until its commit or abort is final, so this
    /// settles a rekey whose commit was sent but not confirmed: it returns the
    /// new row if it committed and the old one if it aborted.
    pub async fn settled_seal_config(&self, timeout: Duration) -> Result<Option<SealConfig>> {
        bounded(self.timeout, async move {
            let timeout = format!("{}ms", timeout.as_millis().max(1));
            let mut tx = self.pool.begin().await?;
            // `SET LOCAL lock_timeout`, but with a bind parameter.
            sqlx::query_scalar!("SELECT set_config('lock_timeout', $1, true)", timeout)
                .fetch_one(&mut *tx)
                .await?;
            let row = sqlx::query!(
                "SELECT shares, threshold, root_check, generation FROM seal_config FOR SHARE"
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| match &e {
                // lock_not_available: lock_timeout fired.
                sqlx::Error::Database(db) if db.code().as_deref() == Some("55P03") => {
                    KeystoreError::LockTimeout
                }
                _ => KeystoreError::Db(e),
            })?;
            tx.rollback().await?;
            row.map(|r| seal_config_from_row(r.shares, r.threshold, r.root_check, r.generation))
                .transpose()
        })
        .await
    }

    /// The keyring: every KEK not destroyed, of every namespace, by
    /// namespace and version. A deleted namespace's KEKs are all destroyed,
    /// so it has none here.
    pub async fn keks(&self) -> Result<Vec<StoredKek>> {
        bounded(self.timeout, async move {
            keks_in(&mut *self.pool.acquire().await?).await
        })
        .await
    }

    /// Every KEK of every namespace and its state, destroyed ones included,
    /// by namespace and version. No key material.
    pub async fn kek_states(&self) -> Result<Vec<KekInfo>> {
        bounded(self.timeout, async move {
            kek_states_in(&mut *self.pool.acquire().await?).await
        })
        .await
    }

    /// Every namespace, live and deleted, by name.
    pub async fn namespaces(&self) -> Result<Vec<StoredNamespace>> {
        bounded(self.timeout, async move {
            namespaces_in(&mut *self.pool.acquire().await?).await
        })
        .await
    }

    /// The seal config, the keyring, every KEK's state and the namespaces,
    /// read in one REPEATABLE READ transaction: one snapshot, so they always
    /// agree. A namespace deleted and created again, or a rekey, lands
    /// either before all of them or after (what a keyring refresh needs: two
    /// separate reads could see a live namespace without its KEKs, or KEKs
    /// re-wrapped under a root key the config read missed).
    pub async fn snapshot(&self) -> Result<Snapshot> {
        bounded(self.timeout, async move {
            let mut tx = self
                .pool
                .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .await?;
            let snapshot = Snapshot {
                config: seal_config_in(&mut tx).await?,
                keks: keks_in(&mut tx).await?,
                states: kek_states_in(&mut tx).await?,
                namespaces: namespaces_in(&mut tx).await?,
                issuing: issuing_set_in(&mut tx).await?,
            };
            tx.commit().await?;
            Ok(snapshot)
        })
        .await
    }

    /// The version a new (or re-created) `namespace` starts at: 1, or one
    /// past the highest it ever had. A read; [`Keystore::create_namespace`]
    /// checks it again.
    pub async fn next_namespace_version(&self, namespace: &Namespace) -> Result<u32> {
        bounded(self.timeout, async move {
            let highest = sqlx::query_scalar!(
                "SELECT max(version) FROM keks WHERE namespace = $1",
                namespace.as_str()
            )
            .fetch_one(&self.pool)
            .await?;
            next_version(highest)
        })
        .await
    }

    /// Creates `namespace`, or re-creates a deleted one, with its first
    /// active KEK at `version` (`wrapped_key` wrapped for that namespace and
    /// version under the root key of `generation`) and `labels`. `version`
    /// must be what [`Keystore::next_namespace_version`] says, or with
    /// [`Numbering::PastLost`] anything above it, checked here under the
    /// lock ([`KeystoreError::CreateConflict`] otherwise);
    /// [`KeystoreError::NamespaceExists`] if it's live. Holds the seal
    /// config `FOR SHARE`, like a rotation.
    pub async fn create_namespace(
        &self,
        generation: u32,
        namespace: &Namespace,
        version: u32,
        numbering: Numbering,
        wrapped_key: &[u8],
        labels: &Labels,
    ) -> Result<()> {
        bounded(self.timeout, async move {
            let mut tx = self.pool.begin().await?;
            lock_generation(&mut tx, generation, Lock::Share).await?;
            let state = sqlx::query_scalar!(
                "SELECT state FROM namespaces WHERE name = $1 FOR UPDATE",
                namespace.as_str()
            )
            .fetch_optional(&mut *tx)
            .await?;
            match state.as_deref() {
                Some("active") => return Err(KeystoreError::NamespaceExists(namespace.clone())),
                Some(_) => {
                    sqlx::query!(
                        "UPDATE namespaces
                         SET state = 'active', created_at = now(), deleted_at = NULL,
                             labels = $2, labels_updated_at = CASE WHEN $2 = '{}'::jsonb
                                 THEN NULL ELSE now() END
                         WHERE name = $1",
                        namespace.as_str(),
                        Json(labels) as _,
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                None => {
                    sqlx::query!(
                        "INSERT INTO namespaces (name, state, labels, labels_updated_at)
                         VALUES ($1, 'active', $2,
                                 CASE WHEN $2 = '{}'::jsonb THEN NULL ELSE now() END)",
                        namespace.as_str(),
                        Json(labels) as _,
                    )
                    .execute(&mut *tx)
                    .await?;
                }
            }
            let highest = sqlx::query_scalar!(
                "SELECT max(version) FROM keks WHERE namespace = $1",
                namespace.as_str()
            )
            .fetch_one(&mut *tx)
            .await?;
            let expected = next_version(highest)?;
            let fits = match numbering {
                Numbering::Next => version == expected,
                Numbering::PastLost => version >= expected,
            };
            if !fits {
                return Err(KeystoreError::CreateConflict {
                    namespace: namespace.clone(),
                    version,
                    expected,
                });
            }
            sqlx::query!(
                "INSERT INTO keks (namespace, version, wrapped_key, state)
                 VALUES ($1, $2, $3, 'active')",
                namespace.as_str(),
                to_db("version", version)?,
                wrapped_key,
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        })
        .await
    }

    /// Deletes `namespace`: destroys every KEK it has (erases the keys,
    /// keeps the rows), marks it deleted and drops its labels. Only the keys
    /// database's side: the caller must have made sure no row uses its KEKs
    /// and none can any more (the data database's floor). Already deleted:
    /// `deleted` false. Holds the seal config `FOR SHARE`, like a rotation.
    pub async fn delete_namespace(
        &self,
        generation: u32,
        namespace: &Namespace,
    ) -> Result<DeletedNamespace> {
        bounded(self.timeout, async move {
            let mut tx = self.pool.begin().await?;
            lock_generation(&mut tx, generation, Lock::Share).await?;
            let state = sqlx::query_scalar!(
                "SELECT state FROM namespaces WHERE name = $1 FOR UPDATE",
                namespace.as_str()
            )
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| KeystoreError::NoNamespace(namespace.clone()))?;
            let destroyed = sqlx::query_scalar!(
                "UPDATE keks SET state = 'destroyed', wrapped_key = NULL, destroyed_at = now()
                 WHERE namespace = $1 AND state <> 'destroyed'
                 RETURNING version",
                namespace.as_str()
            )
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|v| u32_from_db("version", v))
            .collect::<Result<Vec<_>>>()?;
            let deleted = state != "deleted";
            if deleted {
                sqlx::query!(
                    "UPDATE namespaces
                     SET state = 'deleted', deleted_at = now(), labels = '{}',
                         labels_updated_at = NULL
                     WHERE name = $1",
                    namespace.as_str()
                )
                .execute(&mut *tx)
                .await?;
            }
            let highest = sqlx::query_scalar!(
                "SELECT max(version) FROM keks WHERE namespace = $1",
                namespace.as_str()
            )
            .fetch_one(&mut *tx)
            .await?
            .map(|v| u32_from_db("version", v))
            .transpose()?
            .unwrap_or(0);
            tx.commit().await?;
            Ok(DeletedNamespace {
                destroyed,
                highest,
                deleted,
            })
        })
        .await
    }

    /// Changes a live namespace's labels (`set` added or replaced, `remove`
    /// removed; checked by the caller, the total here) and returns them.
    pub async fn update_namespace_labels(
        &self,
        namespace: &Namespace,
        set: &Labels,
        remove: &[String],
    ) -> Result<Labels> {
        bounded(self.timeout, async move {
            let mut tx = self.pool.begin().await?;
            let labels = sqlx::query_scalar!(
                r#"UPDATE namespaces
                   SET labels = (labels || $2::jsonb) - $3::text[], labels_updated_at = now()
                   WHERE name = $1 AND state = 'active'
                   RETURNING labels AS "labels: Json<Labels>""#,
                namespace.as_str(),
                Json(set) as _,
                remove,
            )
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| KeystoreError::NoNamespace(namespace.clone()))?
            .0;
            if labels.len() > MAX_LABELS {
                return Err(KeystoreError::TooManyLabels {
                    count: labels.len(),
                });
            }
            tx.commit().await?;
            Ok(labels)
        })
        .await
    }

    /// Makes `new_version` the active KEK of `namespace` and demotes its
    /// current one to decrypt-only. `new_version` must be the namespace's
    /// active version + 1 and `wrapped_key` wrapped for it under the root
    /// key of `generation`; a concurrent rotation or rekey makes this fail
    /// rather than interleave.
    pub async fn rotate(
        &self,
        generation: u32,
        namespace: &Namespace,
        new_version: u32,
        wrapped_key: &[u8],
    ) -> Result<()> {
        bounded(self.timeout, async move {
            let new_version_db = to_db("version", new_version)?;
            let mut tx = self.pool.begin().await?;
            lock_generation(&mut tx, generation, Lock::Share).await?;

            let demoted = sqlx::query_scalar!(
                "UPDATE keks SET state = 'decrypt_only'
                 WHERE namespace = $1 AND state = 'active' RETURNING version",
                namespace.as_str()
            )
            .fetch_optional(&mut *tx)
            .await?;
            if demoted.is_none() || demoted != new_version_db.checked_sub(1) {
                return Err(KeystoreError::RotateConflict {
                    namespace: namespace.clone(),
                    new_version,
                    active: demoted.map(|v| u32_from_db("version", v)).transpose()?,
                });
            }
            sqlx::query!(
                "INSERT INTO keks (namespace, version, wrapped_key, state)
                 VALUES ($1, $2, $3, 'active')",
                namespace.as_str(),
                new_version_db,
                wrapped_key,
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        })
        .await
    }

    /// Replaces the root key: stores every KEK re-wrapped under it, the new
    /// root check and share parameters, and bumps the generation, all in one
    /// transaction. `keks` must cover exactly the stored KEKs not destroyed,
    /// of every namespace. Returns the new generation.
    ///
    /// An error does not prove nothing was stored: if the connection drops
    /// during the commit, Postgres may have committed anyway. Callers holding
    /// a new root key must re-read [`Keystore::seal_config`] before discarding
    /// it.
    pub async fn rekey(
        &self,
        generation: u32,
        params: ShareParams,
        root_check: &[u8],
        keks: &[RewrappedKek],
        rewrap: &(impl RekeyRewrap + Sync),
    ) -> Result<u32> {
        bounded(self.timeout, async move {
            let namespaces: Vec<String> =
                keks.iter().map(|k| k.namespace.as_str().to_owned()).collect();
            let versions = keks
                .iter()
                .map(|k| to_db("version", k.version))
                .collect::<Result<Vec<_>>>()?;
            let wrapped: Vec<Vec<u8>> = keks.iter().map(|k| k.wrapped_key.clone()).collect();

            let mut tx = self.pool.begin().await?;
            lock_generation(&mut tx, generation, Lock::Update).await?;

            let stored: Vec<(String, i32)> = sqlx::query!(
                "SELECT namespace, version FROM keks WHERE state <> 'destroyed'
                 ORDER BY namespace, version"
            )
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|row| (row.namespace, row.version))
            .collect();
            let mut given: Vec<(String, i32)> = namespaces
                .iter()
                .cloned()
                .zip(versions.iter().copied())
                .collect();
            given.sort_unstable();
            if given != stored {
                return Err(KeystoreError::KekSetMismatch);
            }

            sqlx::query!(
                "UPDATE keks SET wrapped_key = u.wrapped_key
                 FROM UNNEST($1::text[], $2::int4[], $3::bytea[]) AS u(namespace, version, wrapped_key)
                 WHERE keks.namespace = u.namespace AND keks.version = u.version
                   AND keks.state <> 'destroyed'",
                &namespaces[..],
                &versions[..],
                &wrapped[..],
            )
            .execute(&mut *tx)
            .await?;

            // Re-read under the lock, not taken from the caller's keyring: a
            // policy key another server created since is covered too.
            let wrapped_policy_key =
                sqlx::query_scalar!("SELECT wrapped_policy_key FROM seal_config")
                    .fetch_one(&mut *tx)
                    .await?;
            if let Some(wrapped) = wrapped_policy_key {
                let rewrapped =
                    rewrap.policy_key(&wrapped).ok_or(KeystoreError::PolicyKeyUnusable)?;
                sqlx::query!(
                    "UPDATE seal_config SET wrapped_policy_key = $1",
                    rewrapped
                )
                .execute(&mut *tx)
                .await?;
            }

            // The active issuing key likewise: re-read under the lock, so one
            // another server created or rotated since is covered.
            let issuing = sqlx::query!(
                r#"SELECT version, wrapped_key AS "wrapped_key!" FROM issuing_keys
                   WHERE state = 'active'"#
            )
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(issuing) = issuing {
                let version = u32_from_db("version", issuing.version)?;
                let rewrapped = rewrap.issuing_key(version, &issuing.wrapped_key)
                    .ok_or(KeystoreError::IssuingKeyUnusable)?;
                sqlx::query!(
                    "UPDATE issuing_keys SET wrapped_key = $1 WHERE version = $2 AND state = 'active'",
                    rewrapped,
                    issuing.version,
                )
                .execute(&mut *tx)
                .await?;
            }
            // The issuing set's tag, re-made under the new root key; one
            // that doesn't verify under the old (`None`) is left, and never
            // verifies again: a forged set stays untrusted.
            let set = issuing_set_in(&mut tx).await?;
            if set.tag.is_some()
                && let Some(tag) = rewrap.issuing_tag(&set)
            {
                sqlx::query!("UPDATE issuing_set SET tag = $1", tag)
                    .execute(&mut *tx)
                    .await?;
            }

            // The wraps: only the new generation's, if this server has one.
            sqlx::query!("DELETE FROM seal_wraps")
                .execute(&mut *tx)
                .await?;
            if let Some(wrap) = rewrap.seal_wrap() {
                insert_wrap(&mut tx, wrap).await?;
            }

            let new_generation = sqlx::query_scalar!(
                "UPDATE seal_config
                 SET shares = $1, threshold = $2, root_check = $3,
                     generation = generation + 1, rekeyed_at = now()
                 RETURNING generation",
                i32::from(params.shares()),
                i32::from(params.threshold()),
                root_check,
            )
            .fetch_one(&mut *tx)
            .await?;
            // Convert before committing: nothing may fail after the commit, or a
            // stored rekey would be reported as failed.
            let new_generation = u32_from_db("generation", new_generation)?;
            tx.commit().await?;
            Ok(new_generation)
        })
        .await
    }

    /// The auto-unseal hold, this database's half: `(hold, released)`.
    pub async fn auto_unseal_hold(&self) -> Result<(u64, u64)> {
        bounded(self.timeout, async move {
            let row = sqlx::query!("SELECT hold, released FROM auto_unseal_hold")
                .fetch_one(&self.pool)
                .await?;
            let count = |field, value: i64| {
                u64::try_from(value).map_err(|_| KeystoreError::OutOfRange { field, value })
            };
            Ok((count("hold", row.hold)?, count("released", row.released)?))
        })
        .await
    }

    /// Raises the hold to `hold` (never lowers it). Its own table, so it
    /// never waits behind `seal_config`'s row locks.
    pub async fn raise_auto_unseal_hold(&self, hold: u64) -> Result<()> {
        let hold = i64::try_from(hold).map_err(|_| KeystoreError::OutOfRange {
            field: "hold",
            value: i64::MAX,
        })?;
        bounded(self.timeout, async move {
            sqlx::query!(
                "UPDATE auto_unseal_hold SET hold = GREATEST(hold, $1)",
                hold
            )
            .execute(&self.pool)
            .await?;
            Ok(())
        })
        .await
    }

    /// Raises `released` to `released` (never lowers it).
    pub async fn release_auto_unseal_hold(&self, released: u64) -> Result<()> {
        let released = i64::try_from(released).map_err(|_| KeystoreError::OutOfRange {
            field: "released",
            value: i64::MAX,
        })?;
        bounded(self.timeout, async move {
            sqlx::query!(
                "UPDATE auto_unseal_hold SET released = GREATEST(released, $1)",
                released
            )
            .execute(&self.pool)
            .await?;
            Ok(())
        })
        .await
    }

    /// The seal config and `provider`'s wraps, from one snapshot, so a
    /// wrap's generation can be compared with the config's (an auto-unseal
    /// reads them together).
    pub async fn seal_config_and_wraps(
        &self,
        provider: &str,
    ) -> Result<(Option<SealConfig>, Vec<SealWrap>)> {
        bounded(self.timeout, async move {
            let mut tx = self
                .pool
                .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .await?;
            let config = seal_config_in(&mut tx).await?;
            let wraps = sqlx::query!(
                "SELECT provider, key_id, generation, ciphertext FROM seal_wraps
                 WHERE provider = $1 ORDER BY key_id",
                provider
            )
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|row| {
                Ok(SealWrap {
                    provider: row.provider,
                    key_id: row.key_id,
                    generation: u32_from_db("generation", row.generation)?,
                    ciphertext: row.ciphertext,
                })
            })
            .collect::<Result<Vec<_>>>()?;
            tx.commit().await?;
            Ok((config, wraps))
        })
        .await
    }

    /// Every workload-identity issuing key, with the set's revision and tag.
    pub async fn issuing_set(&self) -> Result<IssuingSet> {
        bounded(self.timeout, async move {
            let mut conn = self.pool.acquire().await?;
            issuing_set_in(&mut conn).await
        })
        .await
    }

    /// Stores the first issuing key, version 1 (`wrapped_key` wrapped for
    /// version 1 under the root key of `generation`), and the set at a
    /// revision past `known_revision` and any stored one, tagged by
    /// `tagger`; returns the revision. [`KeystoreError::IssuingKeyExists`]
    /// if there's a key already, active or not: a second one starts with a
    /// rotation. Holds the seal config `FOR SHARE`, like a KEK rotation, so
    /// a rekey commit re-wraps exactly the stored key.
    pub async fn create_issuing_key(
        &self,
        generation: u32,
        certificate: &[u8],
        wrapped_key: &[u8],
        known_revision: u64,
        tagger: &impl IssuingTagger,
    ) -> Result<u64> {
        bounded(self.timeout, async move {
            let mut tx = self.pool.begin().await?;
            lock_generation(&mut tx, generation, Lock::Share).await?;
            lock_issuing_set(&mut tx).await?;
            let stored = issuing_set_in(&mut tx).await?;
            if !stored.keys.is_empty() {
                return Err(KeystoreError::IssuingKeyExists);
            }
            sqlx::query!(
                "INSERT INTO issuing_keys (version, certificate, state, wrapped_key)
                 VALUES (1, $1, 'active', $2)",
                certificate,
                wrapped_key,
            )
            .execute(&mut *tx)
            .await?;
            let revision = next_issuing_revision(stored.revision, known_revision)?;
            retag_issuing_set(&mut tx, revision, tagger).await?;
            tx.commit().await?;
            Ok(revision)
        })
        .await
    }

    /// Replaces the active issuing key with `rotation`'s new one, and
    /// returns the set's new revision (one past the stored one and
    /// `rotation.known_revision`), tagged by `tagger` (the root key of
    /// `generation`). The old key's wrapped key is erased; it becomes
    /// `revoked` if `rotation.revoke` (nothing it signed is trusted any
    /// more), and so does every retired key (a compromise is found late:
    /// they were held by the same servers), else `retired` (its
    /// certificates stay trusted until they expire). Retired only if its
    /// stored certificate is the one the caller loaded with its key.
    ///
    /// The stored set must verify (`tagger`) at a revision not below
    /// `known_revision`, or it was changed or rolled back without the root
    /// key: then only a revoking rotation goes ahead, revoking every key
    /// (the recovery: nothing is trusted on from a set nobody vouches for),
    /// and any other is [`KeystoreError::IssuingKeysUnverified`]. A
    /// concurrent rotation or rekey makes this fail rather than interleave.
    pub async fn rotate_issuing_key(
        &self,
        generation: u32,
        rotation: IssuingRotation<'_>,
        tagger: &impl IssuingTagger,
    ) -> Result<u64> {
        bounded(self.timeout, async move {
            let at = rotation.at;
            let mut tx = self.pool.begin().await?;
            lock_generation(&mut tx, generation, Lock::Share).await?;
            lock_issuing_set(&mut tx).await?;
            let stored = issuing_set_in(&mut tx).await?;
            let verified = stored.revision >= rotation.known_revision && tagger.verifies(&stored);
            if !verified && !rotation.revoke {
                return Err(KeystoreError::IssuingKeysUnverified);
            }
            let highest = stored.keys.iter().map(|k| k.version).max().unwrap_or(0);
            if rotation.version != highest.saturating_add(1) {
                return Err(KeystoreError::IssuingKeyConflict {
                    expected: rotation.version.saturating_sub(1),
                    active: Some(highest),
                });
            }
            let mut changes = Vec::new();
            if verified {
                let current = stored
                    .keys
                    .iter()
                    .find(|k| k.state == IssuingKeyState::Active)
                    .ok_or(KeystoreError::NoIssuingKey)?;
                if rotation
                    .expected_active
                    .is_some_and(|expected| expected != current.version)
                {
                    return Err(KeystoreError::IssuingKeyConflict {
                        expected: rotation.expected_active.unwrap_or(0),
                        active: Some(current.version),
                    });
                }
                let genuine = rotation.active_certificate == Some(current.certificate.as_slice());
                let state = if rotation.revoke || !genuine {
                    IssuingKeyState::Revoked
                } else {
                    IssuingKeyState::Retired
                };
                changes.push((current, state, at));
                if rotation.revoke {
                    for key in stored
                        .keys
                        .iter()
                        .filter(|k| k.state == IssuingKeyState::Retired)
                    {
                        changes.push((key, IssuingKeyState::Revoked, key.retired_at.unwrap_or(at)));
                    }
                }
            } else {
                // Nobody vouches for these: every one revoked.
                for key in stored
                    .keys
                    .iter()
                    .filter(|k| k.state != IssuingKeyState::Revoked)
                {
                    changes.push((key, IssuingKeyState::Revoked, key.retired_at.unwrap_or(at)));
                }
            }
            for (key, state, retired_at) in changes {
                sqlx::query!(
                    "UPDATE issuing_keys
                     SET state = $2, wrapped_key = NULL, retired_at = $3
                     WHERE version = $1",
                    to_db("version", key.version)?,
                    state.as_str(),
                    retired_at,
                )
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query!(
                "INSERT INTO issuing_keys (version, certificate, state, wrapped_key)
                 VALUES ($1, $2, 'active', $3)",
                to_db("version", rotation.version)?,
                rotation.certificate,
                rotation.wrapped_key,
            )
            .execute(&mut *tx)
            .await?;
            // A set nobody vouches for doesn't lend its revision.
            let base = if verified { stored.revision } else { 0 };
            let revision = next_issuing_revision(base, rotation.known_revision)?;
            retag_issuing_set(&mut tx, revision, tagger).await?;
            tx.commit().await?;
            Ok(revision)
        })
        .await
    }

    /// Destroys a retired KEK of `namespace`: erases its wrapped key for
    /// good (see the migration for what "erased" means to Postgres).
    /// `false` if it was already destroyed; [`KeystoreError::NotRetired`] in
    /// any other state. Holds the seal config `FOR SHARE` of `generation`,
    /// like a rotation, so it can't interleave with a rekey re-wrapping the
    /// keyring.
    ///
    /// Only the keys database's side: the caller must have made sure that
    /// no DEK is, or can any more be, wrapped by it (the data database's
    /// KEK floor).
    pub async fn destroy(
        &self,
        generation: u32,
        namespace: &Namespace,
        version: u32,
    ) -> Result<bool> {
        bounded(self.timeout, async move {
            let version_db = to_db("version", version)?;
            let mut tx = self.pool.begin().await?;
            lock_generation(&mut tx, generation, Lock::Share).await?;
            let destroyed = sqlx::query!(
                "UPDATE keks SET state = 'destroyed', wrapped_key = NULL, destroyed_at = now()
                 WHERE namespace = $1 AND version = $2 AND state = 'retired'",
                namespace.as_str(),
                version_db,
            )
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if destroyed == 0 {
                let state = sqlx::query_scalar!(
                    "SELECT state FROM keks WHERE namespace = $1 AND version = $2",
                    namespace.as_str(),
                    version_db
                )
                .fetch_optional(&mut *tx)
                .await?;
                return match state.as_deref() {
                    Some("destroyed") => Ok(false),
                    _ => Err(KeystoreError::NotRetired {
                        namespace: namespace.clone(),
                        version,
                    }),
                };
            }
            tx.commit().await?;
            Ok(true)
        })
        .await
    }

    /// Marks a decrypt-only KEK of `namespace` as retired once no DEK uses
    /// it any more.
    pub async fn retire(&self, namespace: &Namespace, version: u32) -> Result<()> {
        bounded(self.timeout, async move {
            let updated = sqlx::query!(
                "UPDATE keks SET state = 'retired'
                 WHERE namespace = $1 AND version = $2 AND state = 'decrypt_only'",
                namespace.as_str(),
                to_db("version", version)?,
            )
            .execute(&self.pool)
            .await?;
            if updated.rows_affected() == 0 {
                return Err(KeystoreError::NotDecryptOnly {
                    namespace: namespace.clone(),
                    version,
                });
            }
            Ok(())
        })
        .await
    }
}

/// The version a namespace's next first KEK takes: 1, or one past the
/// highest it ever had (`highest`, from its KEK rows, destroyed included).
fn next_version(highest: Option<i32>) -> Result<u32> {
    match highest {
        None => Ok(FIRST_KEK_VERSION),
        Some(highest) => {
            u32_from_db("version", highest)?
                .checked_add(1)
                .ok_or(KeystoreError::OutOfRange {
                    field: "version",
                    value: i64::from(highest),
                })
        }
    }
}
