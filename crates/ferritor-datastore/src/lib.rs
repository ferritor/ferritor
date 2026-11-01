//! Access to the data database (secret ciphertexts and wrapped DEKs).
//!
//! Like the keystore, everything here is opaque bytes: values arrive already
//! encrypted and DEKs already wrapped. The server does the crypto.
//!
//! One relation per thing (migrations/0001): `namespaces` (each one's KEK
//! floor and version floor), `paths` (every path written: its version
//! counter, times and labels; deleted only with its namespace, whose
//! version floor keeps their numbers from coming round again) and
//! `secret_versions` (every stored version, keyed
//! by its path's id and its number). The APIs speak paths and namespace
//! names; the ids stay in here.
//!
//! Every put is a new version; versions are never reused, not even after a
//! delete, since a delete only marks rows (`deleted_at`). Deleted versions
//! are invisible to [`Datastore::get`] and [`Datastore::list`]. Puts to one
//! path are serialized ([`Datastore::begin_put`]), so they never race for a
//! version number.

use std::time::Duration;

use ferritor_core::labels::{Labels, MAX_LABELS};
use ferritor_core::path::{Namespace, PathError, SecretPath};
use sqlx::types::time::OffsetDateTime;
use sqlx::types::{Json, Uuid};
use sqlx::{PgPool, Postgres, Transaction};

/// Migrations in `migrations/`, embedded at compile time.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

#[derive(Debug, thiserror::Error)]
pub enum DatastoreError {
    #[error("data database error")]
    Db(#[source] sqlx::Error),
    #[error("`{0}` has no more version numbers")]
    VersionsExhausted(SecretPath),
    #[error("{field} value {value} is out of range")]
    OutOfRange { field: &'static str, value: i64 },
    /// A policy or issuing revision past what the database stores (BIGINT).
    #[error("revision {0} is past the largest the data database stores")]
    RevisionOutOfRange(u64),
    /// The client-side bound ([`Datastore::with_timeout`]) ran out. For a
    /// commit, the outcome is unknown: it may have committed.
    #[error("the data database did not respond in time")]
    Timeout,
    /// Waited [`Datastore::with_lock_timeout`] for another put to the same
    /// path to finish.
    #[error("too many concurrent writes to `{0}`; retry")]
    Busy(SecretPath),
    /// The write used a KEK version below the KEK floor
    /// ([`Datastore::raise_kek_floor`]): the writer's keyring is stale, its
    /// active KEK is one being destroyed. Nothing was written.
    #[error("KEK version {0} is below the KEK floor: this server's keyring is out of date")]
    BelowKekFloor(u32),
    /// Waited [`Datastore::with_lock_timeout`] for the writes in flight to
    /// finish before raising the KEK floor.
    #[error("timed out waiting for writes in flight before raising the KEK floor; retry")]
    KekFloorBusy,
    /// Labels for a path with nothing stored: never written, or every
    /// version purged.
    #[error("nothing of `{0}` is stored")]
    NothingStored(SecretPath),
    /// A label change would leave the path with more than
    /// [`MAX_LABELS`]; nothing was changed.
    #[error("{count} labels; a path holds at most {MAX_LABELS}")]
    TooManyLabels { count: usize },
    /// Only if a stored row's namespace isn't a valid name (it's derived
    /// from a checked path, so never).
    #[error("stored namespace `{0}` is not a valid name")]
    InvalidStoredNamespace(String),
    /// Only if a stored row bypassed the `paths.path` CHECK.
    #[error("stored secret path is not canonical")]
    InvalidStoredPath(#[source] PathError),
}

impl From<sqlx::Error> for DatastoreError {
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

/// `lock_not_available`: a `lock_timeout` fired.
fn is_lock_timeout(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("55P03"))
}

/// Raised by the `secret_versions_kek_floor` trigger.
fn is_below_kek_floor(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("FR001"))
}

/// First key of the two-key advisory lock on a namespace's KEK floor
/// (object a hash of its name): writers take it shared (in the trigger), a
/// raise exclusive. Must match the trigger.
const KEK_FLOOR_LOCK_CLASS: i32 = 2;

type Result<T, E = DatastoreError> = std::result::Result<T, E>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMetadata {
    pub path: SecretPath,
    pub version: u32,
    pub created_at: OffsetDateTime,
}

/// One version in a path's history ([`Datastore::versions`]): live, or
/// deleted and not yet purged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    pub metadata: SecretMetadata,
    /// When it was deleted (by a delete or a trim); `None` while live.
    pub deleted_at: Option<OffsetDateTime>,
}

/// What's known about a path as a whole ([`Datastore::path_metadata`]),
/// never its values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathMetadata {
    pub path: SecretPath,
    /// When it was first written.
    pub created_at: OffsetDateTime,
    /// When it was last written by a put (a new version).
    pub updated_at: OffsetDateTime,
    /// The latest live version; `None` if every version is deleted.
    pub current_version: Option<u32>,
    /// The oldest version still stored (live or deleted, not purged).
    pub oldest_version: Option<u32>,
    /// How many versions are stored, live and deleted.
    pub versions: u64,
    pub labels: Labels,
    /// When the labels last changed; `None` without labels.
    pub labels_updated_at: Option<OffsetDateTime>,
}

/// One stored version: its metadata plus the encrypted material.
#[derive(Clone, Debug)]
pub struct StoredSecret {
    pub metadata: SecretMetadata,
    /// The value, encrypted under the DEK.
    pub ciphertext: Vec<u8>,
    /// The DEK, wrapped by KEK `kek_version` (in the keys database).
    pub wrapped_dek: Vec<u8>,
    pub kek_version: u32,
}

/// Which stored version a row is, opaque outside this crate: rewrap's
/// paging cursor ([`Datastore::wrapped_by`]) and its compare-and-set
/// ([`Datastore::rewrap`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowKey {
    path_id: Uuid,
    version: i32,
}

impl RowKey {
    /// Before every row: where paging starts.
    pub const FIRST: Self = Self {
        path_id: Uuid::nil(),
        version: 0,
    };
}

/// A row's DEK as a rewrap pass sees it: which row, and the path and version
/// its wrapping is bound to.
#[derive(Clone, Debug)]
pub struct WrappedDek {
    pub key: RowKey,
    pub path: SecretPath,
    pub version: u32,
    pub wrapped_dek: Vec<u8>,
}

/// A row's DEK re-wrapped, for [`Datastore::rewrap`].
#[derive(Clone, Debug)]
pub struct Rewrapped {
    pub key: RowKey,
    pub wrapped_dek: Vec<u8>,
}

/// First key of the two-key `pg_advisory_xact_lock` for "one write (put or
/// delete) at a time per path", so it can't collide with other advisory lock
/// users.
const WRITE_LOCK_CLASS: i32 = 1;

/// A put in progress: a transaction holding the path's write lock, the
/// version it will store, and the latest live version it found (for a
/// check-and-set, compare before encrypting; see [`PendingPut::latest`]).
/// Encrypt for exactly [`PendingPut::path`] and [`PendingPut::version`],
/// then [`PendingPut::insert`] and [`StagedPut::commit`]. Dropping either
/// instead rolls back and releases the lock.
pub struct PendingPut {
    tx: Transaction<'static, Postgres>,
    path: SecretPath,
    path_id: Uuid,
    namespace_id: Uuid,
    version: u32,
    latest: Option<u32>,
    max_versions: u32,
    timeout: Duration,
}

impl PendingPut {
    pub fn path(&self) -> &SecretPath {
        &self.path
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    /// The latest live (not deleted) version, `None` if there is none: read
    /// under the path's write lock, so it can't change before this put
    /// commits or is dropped (deletes take the lock too).
    pub fn latest(&self) -> Option<u32> {
        self.latest
    }

    /// Writes the version, uncommitted: the caller gets a last chance to
    /// back out (by dropping the [`StagedPut`]) before committing.
    ///
    /// With a version limit ([`Datastore::with_max_versions`]), live versions
    /// older than the newest `max_versions` (this one included) are marked
    /// deleted in the same transaction, under the path's lock: they go the
    /// way of any deleted version (hidden, then purged after the retention).
    /// One index range per put, never a scan; a path not written again
    /// keeps its versions until its next put. The latest version is never
    /// trimmed, so a check-and-set is unaffected.
    pub async fn insert(
        mut self,
        ciphertext: &[u8],
        wrapped_dek: &[u8],
        kek_version: u32,
    ) -> Result<StagedPut> {
        let timeout = self.timeout;
        bounded(timeout, async move {
            let row = sqlx::query!(
                "INSERT INTO secret_versions
                     (path_id, namespace_id, version, ciphertext, wrapped_dek, kek_version)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 RETURNING created_at",
                self.path_id,
                self.namespace_id,
                to_db("version", self.version)?,
                ciphertext,
                wrapped_dek,
                to_db("kek_version", kek_version)?,
            )
            .fetch_one(&mut *self.tx)
            .await
            .map_err(|e| {
                // The transaction's lock_timeout (set in begin_put) also
                // bounds this insert's wait on the primary key. Puts through
                // here are serialized, so that wait needs a row written
                // another way (by hand, or a different server version mid-
                // deploy); it's still contention, so report it as such.
                if is_lock_timeout(&e) {
                    DatastoreError::Busy(self.path.clone())
                } else if is_below_kek_floor(&e) {
                    DatastoreError::BelowKekFloor(kek_version)
                } else {
                    e.into()
                }
            })?;
            let trimmed = match self.max_versions {
                0 => 0,
                max => {
                    // Everything older than the max-th newest live version
                    // (none if there are fewer). This transaction sees its
                    // own new row, so it counts.
                    sqlx::query!(
                        "UPDATE secret_versions SET deleted_at = now()
                         WHERE path_id = $1 AND deleted_at IS NULL AND version < (
                             SELECT version FROM secret_versions
                             WHERE path_id = $1 AND deleted_at IS NULL
                             ORDER BY version DESC
                             OFFSET $2 LIMIT 1
                         )",
                        self.path_id,
                        i64::from(max - 1),
                    )
                    .execute(&mut *self.tx)
                    .await?
                    .rows_affected()
                }
            };
            Ok(StagedPut {
                timeout: self.timeout,
                trimmed,
                path_id: self.path_id,
                tx: self.tx,
                metadata: SecretMetadata {
                    path: self.path,
                    version: self.version,
                    created_at: row.created_at,
                },
            })
        })
        .await
    }
}

/// A written but uncommitted put. [`StagedPut::commit`] to keep it; dropping
/// it rolls back.
pub struct StagedPut {
    tx: Transaction<'static, Postgres>,
    path_id: Uuid,
    metadata: SecretMetadata,
    trimmed: u64,
    timeout: Duration,
}

impl StagedPut {
    /// Older versions this put marked deleted, to stay within the limit
    /// ([`Datastore::with_max_versions`]).
    pub fn trimmed(&self) -> u64 {
        self.trimmed
    }

    /// Sets `labels` on the path (merged with what it has), in this put's
    /// transaction; returns the path's labels now. Checked by the caller
    /// (`ferritor_core::labels`), except the total, checked here
    /// ([`DatastoreError::TooManyLabels`]).
    pub async fn set_labels(&mut self, labels: &Labels) -> Result<Labels> {
        // The put's upsert holds the `paths` row locked, and the version it
        // just wrote is there: nothing to check.
        bounded(
            self.timeout,
            update_labels(&mut self.tx, self.path_id, labels, &[]),
        )
        .await
    }

    pub async fn commit(self) -> Result<SecretMetadata> {
        let timeout = self.timeout;
        bounded(timeout, async move {
            self.tx.commit().await?;
            Ok(self.metadata)
        })
        .await
    }
}

/// Merges a label change into the labels of the path `path_id` in `tx`, and
/// returns them: `set` added or replaced, `remove` removed. Too many
/// afterwards, and nothing is kept (the caller drops `tx`). The caller holds
/// the `paths` row locked and knows a version is stored.
async fn update_labels(
    tx: &mut Transaction<'static, Postgres>,
    path_id: Uuid,
    set: &Labels,
    remove: &[String],
) -> Result<Labels> {
    let Json(labels) = sqlx::query_scalar!(
        r#"UPDATE paths
           SET labels = (labels || $2::jsonb) - $3::text[],
               labels_updated_at = CASE WHEN (labels || $2::jsonb) - $3::text[] = '{}'
                                        THEN NULL ELSE now() END
           WHERE id = $1
           RETURNING labels AS "labels: Json<Labels>""#,
        path_id,
        Json(set) as _,
        remove,
    )
    .fetch_one(&mut **tx)
    .await?;
    if labels.len() > MAX_LABELS {
        return Err(DatastoreError::TooManyLabels {
            count: labels.len(),
        });
    }
    Ok(labels)
}

/// A label change on `path` in `tx` ([`Datastore::change_labels`]): locks
/// its `paths` row, then, in a statement of its own, checks a version is
/// stored, then merges the change.
///
/// Purge clears the labels of a path left with no versions after locking
/// the same row, so the two take turns: a change that found a version keeps
/// its labels until a purge removes that version, and then they go with
/// it. The check must be a new statement after the lock, never a subquery
/// of the locking one, whose snapshot predates the wait: it would miss a
/// version a put committed meanwhile.
async fn change_labels(
    tx: &mut Transaction<'static, Postgres>,
    path: &SecretPath,
    set: &Labels,
    remove: &[String],
) -> Result<Labels> {
    let path_id = sqlx::query_scalar!(
        "SELECT id FROM paths WHERE path = $1 FOR UPDATE",
        path.as_str()
    )
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| DatastoreError::NothingStored(path.clone()))?;
    let stored = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM secret_versions WHERE path_id = $1) AS "stored!""#,
        path_id
    )
    .fetch_one(&mut **tx)
    .await?;
    if !stored {
        return Err(DatastoreError::NothingStored(path.clone()));
    }
    update_labels(tx, path_id, set, remove).await
}

/// A label change, made but uncommitted ([`Datastore::change_labels`]).
/// [`StagedLabels::commit`] to keep it; dropping it rolls back.
pub struct StagedLabels {
    tx: Transaction<'static, Postgres>,
    labels: Labels,
    timeout: Duration,
}

impl StagedLabels {
    /// The path's labels once committed.
    pub fn labels(&self) -> &Labels {
        &self.labels
    }

    pub async fn commit(self) -> Result<Labels> {
        bounded(self.timeout, async move {
            self.tx.commit().await?;
            Ok(self.labels)
        })
        .await
    }
}

/// A delete in progress: every live version of a path marked deleted,
/// uncommitted. [`PendingDelete::commit`] to keep it; dropping it rolls back.
pub struct PendingDelete {
    tx: Transaction<'static, Postgres>,
    count: u64,
    timeout: Duration,
}

impl PendingDelete {
    /// How many versions it marked deleted.
    pub fn count(&self) -> u64 {
        self.count
    }

    pub async fn commit(self) -> Result<()> {
        let timeout = self.timeout;
        bounded(timeout, async move {
            self.tx.commit().await?;
            Ok(())
        })
        .await
    }
}

/// A restore in progress: a deleted version made live again, uncommitted.
/// [`PendingRestore::commit`] to keep it; dropping it rolls back.
pub struct PendingRestore {
    tx: Transaction<'static, Postgres>,
    restored: Option<SecretMetadata>,
    live: Option<u32>,
    timeout: Duration,
}

impl PendingRestore {
    /// The version made live again; `None` if there was nothing to restore
    /// (no such deleted version: live, purged, or never stored), or, with no
    /// version asked for, the path still has a live one ([`Self::live`]).
    pub fn restored(&self) -> Option<&SecretMetadata> {
        self.restored.as_ref()
    }

    /// With no version asked for: the path's latest live version, if it has
    /// one, in which case nothing was restored.
    pub fn live(&self) -> Option<u32> {
        self.live
    }

    pub async fn commit(self) -> Result<()> {
        let timeout = self.timeout;
        bounded(timeout, async move {
            self.tx.commit().await?;
            Ok(())
        })
        .await
    }
}

fn to_db(field: &'static str, value: u32) -> Result<i32> {
    i32::try_from(value).map_err(|_| DatastoreError::OutOfRange {
        field,
        value: value.into(),
    })
}

fn u32_from_db(field: &'static str, value: i32) -> Result<u32> {
    u32::try_from(value).map_err(|_| DatastoreError::OutOfRange {
        field,
        value: value.into(),
    })
}

fn metadata(path: String, version: i32, created_at: OffsetDateTime) -> Result<SecretMetadata> {
    Ok(SecretMetadata {
        path: SecretPath::parse(&path).map_err(DatastoreError::InvalidStoredPath)?,
        version: u32_from_db("version", version)?,
        created_at,
    })
}

#[derive(Clone, Debug)]
pub struct Datastore {
    pool: PgPool,
    timeout: Duration,
    lock_timeout: Duration,
    max_versions: u32,
}

/// Default for [`Datastore::with_timeout`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default for [`Datastore::with_lock_timeout`].
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// Bounds a database operation client-side: a hung connection or a network
/// partition, which Postgres's own timeouts can't see, can't stall the caller
/// for longer than `timeout`.
async fn bounded<T>(timeout: Duration, op: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(timeout, op)
        .await
        .map_err(|_| DatastoreError::Timeout)?
}

impl Datastore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            timeout: DEFAULT_TIMEOUT,
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
            max_versions: 0,
        }
    }

    /// Keep at most `max` live versions per path: each put trims the older
    /// ones (see [`PendingPut::insert`]). 0, the default, keeps all.
    pub fn with_max_versions(mut self, max: u32) -> Self {
        self.max_versions = max;
        self
    }

    /// Upper bound on every call (and on each step of a staged put or
    /// delete), after which it fails with [`DatastoreError::Timeout`].
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How long [`Datastore::begin_put`] and [`Datastore::begin_delete`] wait
    /// for another write to the same path before failing with
    /// [`DatastoreError::Busy`]. Keep it below
    /// [`Datastore::with_timeout`]'s, or the client-side bound fires first and
    /// a busy path looks like an unresponsive database.
    pub fn with_lock_timeout(mut self, lock_timeout: Duration) -> Self {
        self.lock_timeout = lock_timeout;
        self
    }

    /// Starts a write transaction holding `path`'s write lock: puts and
    /// deletes to one path take turns, so a put picks its version number and
    /// checks the latest live version against a state nothing else can
    /// change before it commits.
    ///
    /// The lock is a transaction-scoped advisory lock on a hash of the path;
    /// two paths with the same hash just take turns. It's held until the
    /// commit (or a drop), so keep that stretch short (no awaits beyond the
    /// write itself): other writes to the path wait.
    ///
    /// Each waiter holds a pool connection while it waits. More simultaneous
    /// writes to one path than the pool has connections make every other
    /// request wait for a connection until they drain (no deadlock: the
    /// holder already has its own). The wait is bounded by
    /// [`Datastore::with_lock_timeout`] ([`DatastoreError::Busy`]).
    ///
    /// Must stay READ COMMITTED (Postgres's default): the reads after the
    /// lock see the previous holder's writes only because each statement
    /// takes a fresh snapshot after the lock is granted. Under REPEATABLE
    /// READ or SERIALIZABLE the snapshot would date from before the wait:
    /// a put would miss the previous put's row and hit the UNIQUE
    /// constraint, and a delete would miss it and let it survive.
    async fn lock_path(&self, path: &SecretPath) -> Result<Transaction<'static, Postgres>> {
        let mut tx = self.pool.begin().await?;
        // `SET LOCAL lock_timeout`, with a bind parameter: Postgres itself
        // gives up waiting for the path's lock, rather than leaving a
        // backend waiting after the client-side bound has run out.
        let lock_timeout = format!("{}ms", self.lock_timeout.as_millis().max(1));
        sqlx::query_scalar!("SELECT set_config('lock_timeout', $1, true)", lock_timeout)
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query_scalar!(
            r#"SELECT 1 AS "locked!" FROM pg_advisory_xact_lock($1, hashtext($2))"#,
            WRITE_LOCK_CLASS,
            path.as_str(),
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if is_lock_timeout(&e) {
                DatastoreError::Busy(path.clone())
            } else {
                e.into()
            }
        })?;
        Ok(tx)
    }

    /// Starts a put to `path` under its write lock (see `lock_path`): takes
    /// the next version and reads the latest live one
    /// ([`PendingPut::latest`]). The bump is in this transaction: a put
    /// dropped before committing leaves no gap. Its `paths` row (created on
    /// the path's first write, with its namespace's row on the namespace's
    /// first) stays locked until it commits.
    ///
    /// The next version is one past the higher of two records: the path's
    /// `highest` (which outlives purged rows, so numbers never come round
    /// again) and its highest stored row. Either alone can fall behind: rows
    /// can be purged, and a row can be written without bumping `highest` (by
    /// hand, or a restored backup). A version behind the rows would collide
    /// on the primary key on every put; taking the higher one repairs
    /// `highest` with the next put instead. The rows' highest is one index
    /// lookup, under a lock already held.
    pub async fn begin_put(&self, path: &SecretPath) -> Result<PendingPut> {
        bounded(self.timeout, async move {
            let mut tx = self.lock_path(path).await?;
            let next = match upsert_path(&mut tx, path).await? {
                Some(next) => next,
                // No row: the namespace's first write to this database (it
                // has no row of its own yet), or the path is out of version
                // numbers. The namespace's row is created on its own,
                // committed at once (harmless if this put never commits: a
                // row with floor 1), so a first put to another path of it
                // never waits for this one's transaction; then the put
                // starts over. A put's usual path stays one statement. This
                // transaction ends first, so no put holds two connections.
                None => {
                    tx.rollback().await?;
                    let namespace = path.namespace();
                    sqlx::query!(
                        "INSERT INTO namespaces (name) VALUES ($1) ON CONFLICT (name) DO NOTHING",
                        namespace.as_str()
                    )
                    .execute(&self.pool)
                    .await?;
                    tx = self.lock_path(path).await?;
                    upsert_path(&mut tx, path)
                        .await?
                        .ok_or_else(|| DatastoreError::VersionsExhausted(path.clone()))?
                }
            };
            let latest = sqlx::query_scalar!(
                "SELECT MAX(version) FROM secret_versions
                 WHERE path_id = $1 AND deleted_at IS NULL",
                next.id,
            )
            .fetch_one(&mut *tx)
            .await?
            .map(|latest| u32_from_db("version", latest))
            .transpose()?;
            Ok(PendingPut {
                tx,
                path: path.clone(),
                path_id: next.id,
                namespace_id: next.namespace_id,
                version: u32_from_db("version", next.highest)?,
                latest,
                max_versions: self.max_versions,
                timeout: self.timeout,
            })
        })
        .await
    }

    /// `version`, or the latest if `None`; deleted versions don't count.
    pub async fn get(
        &self,
        path: &SecretPath,
        version: Option<u32>,
    ) -> Result<Option<StoredSecret>> {
        bounded(self.timeout, async move {
            let version = version.map(|v| to_db("version", v)).transpose()?;
            let row = sqlx::query!(
                "SELECT v.version, v.ciphertext, v.wrapped_dek, v.kek_version, v.created_at
                 FROM paths p JOIN secret_versions v ON v.path_id = p.id
                 WHERE p.path = $1 AND v.deleted_at IS NULL
                   AND ($2::int4 IS NULL OR v.version = $2)
                 ORDER BY v.version DESC
                 LIMIT 1",
                path.as_str(),
                version,
            )
            .fetch_optional(&self.pool)
            .await?;
            row.map(|r| {
                Ok(StoredSecret {
                    metadata: SecretMetadata {
                        path: path.clone(),
                        version: u32_from_db("version", r.version)?,
                        created_at: r.created_at,
                    },
                    ciphertext: r.ciphertext,
                    wrapped_dek: r.wrapped_dek,
                    kek_version: u32_from_db("kek_version", r.kek_version)?,
                })
            })
            .transpose()
        })
        .await
    }

    /// The versions of `path` still stored, live and deleted alike (purged
    /// ones are gone, so the numbers can have gaps), newest first: at most
    /// `limit`, only those below `before` if given. Metadata only. One index
    /// range on the primary key, however long the history.
    pub async fn versions(
        &self,
        path: &SecretPath,
        before: Option<u32>,
        limit: u32,
    ) -> Result<Vec<VersionInfo>> {
        bounded(self.timeout, async move {
            // Above every version (an int4), so the bound is never optional
            // (see `list`). int8 to hold it; int4 < int8 is in the btree
            // operator family, so the index still serves the range.
            let before = before.map_or(i64::from(i32::MAX) + 1, i64::from);
            sqlx::query!(
                "SELECT v.version, v.created_at, v.deleted_at
                 FROM paths p JOIN secret_versions v ON v.path_id = p.id
                 WHERE p.path = $1 AND v.version < $2::int8
                 ORDER BY v.version DESC
                 LIMIT $3",
                path.as_str(),
                before,
                i64::from(limit),
            )
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|r| {
                Ok(VersionInfo {
                    metadata: SecretMetadata {
                        path: path.clone(),
                        version: u32_from_db("version", r.version)?,
                        created_at: r.created_at,
                    },
                    deleted_at: r.deleted_at,
                })
            })
            .collect()
        })
        .await
    }

    /// Marks every live version of `path` deleted, uncommitted; see
    /// [`PendingDelete`]. Under the path's write lock (see `lock_path`), like
    /// a put: a put in progress finishes first and its version is deleted
    /// too, and a put that comes after sees the delete, so a check-and-set
    /// can't pass its check against a state a delete is about to change.
    pub async fn begin_delete(&self, path: &SecretPath) -> Result<PendingDelete> {
        bounded(self.timeout, async move {
            let mut tx = self.lock_path(path).await?;
            let deleted = sqlx::query!(
                "UPDATE secret_versions SET deleted_at = now()
                 WHERE path_id = (SELECT id FROM paths WHERE path = $1) AND deleted_at IS NULL",
                path.as_str(),
            )
            .execute(&mut *tx)
            .await?;
            // Nothing live is left. (After the versions, as in
            // `begin_restore`.)
            sqlx::query!(
                "UPDATE paths SET current_version = NULL
                 WHERE path = $1 AND current_version IS NOT NULL",
                path.as_str(),
            )
            .execute(&mut *tx)
            .await?;
            Ok(PendingDelete {
                tx,
                count: deleted.rows_affected(),
                timeout: self.timeout,
            })
        })
        .await
    }

    /// Removes for good up to `limit` versions deleted more than
    /// `older_than` ago, oldest deletions first; returns how many. Repeat
    /// until it returns less than `limit`. Their version numbers stay used
    /// (`paths.highest`). Rows deleted within the retention, and live rows,
    /// are never touched. A path left with no versions at all loses its
    /// labels too, in the same transaction: purging removes a deleted secret
    /// for good, its metadata included (the version numbers and times
    /// excepted).
    ///
    /// Rows another transaction holds locked are skipped, not waited for:
    /// concurrent purges take disjoint batches (otherwise two would pick the
    /// same rows, and the second, deleting fewer than its limit, would stop
    /// early), and a row being rewrapped or restored is left for the next
    /// pass. So "fewer than `limit`" means nothing is left that isn't
    /// already being handled.
    pub async fn purge_deleted(&self, older_than: Duration, limit: u32) -> Result<u64> {
        bounded(self.timeout, async move {
            // `= ANY(ARRAY(...))`, not `IN (...)`: with a generic plan (the
            // limit unknown), `IN` became a hash join over a scan of the whole
            // table; this runs the batch query once (on
            // `secret_versions_deleted`) and deletes by row address, which
            // the row lock keeps still: a TID scan (checked on 200,000
            // versions, 180,000 deleted: 0.55 ms for 1,000 rows). On a
            // nearly empty new database the cached plan may be a sequential
            // scan, which is right there and doesn't stick: ANALYZE (by
            // autovacuum) invalidates it as the table grows.
            let mut tx = self.pool.begin().await?;
            let mut path_ids = sqlx::query_scalar!(
                "DELETE FROM secret_versions WHERE ctid = ANY (ARRAY(
                     SELECT ctid FROM secret_versions
                     WHERE deleted_at < now() - make_interval(secs => $1)
                     ORDER BY deleted_at
                     LIMIT $2
                     FOR UPDATE SKIP LOCKED
                 ))
                 RETURNING path_id",
                older_than.as_secs_f64(),
                i64::from(limit),
            )
            .fetch_all(&mut *tx)
            .await?;
            let purged = u64::try_from(path_ids.len()).unwrap_or(u64::MAX);
            path_ids.sort_unstable();
            path_ids.dedup();
            // Two statements, never one. The first locks those paths' rows
            // (in id order, so concurrent purges lock alike): it waits for a
            // put or a label change holding one, and keeps them out from
            // then on (a put locks its `paths` row before it inserts a
            // version). The second, a new statement with a new snapshot taken
            // after the locks, sees every version committed before them. One
            // statement would re-check its WHERE after waiting for a lock,
            // but its NOT EXISTS would still read the old snapshot, miss a
            // version a put committed meanwhile, and clear that put's labels.
            sqlx::query!(
                "SELECT id FROM paths WHERE id = ANY ($1) ORDER BY id FOR UPDATE",
                &path_ids[..],
            )
            .fetch_all(&mut *tx)
            .await?;
            sqlx::query!(
                "UPDATE paths SET labels = '{}', labels_updated_at = NULL
                 WHERE id = ANY ($1) AND labels <> '{}'
                   AND NOT EXISTS (SELECT 1 FROM secret_versions WHERE path_id = paths.id)",
                &path_ids[..],
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(purged)
        })
        .await
    }

    /// Makes a deleted version of `path` live again, uncommitted (see
    /// [`PendingRestore`]): `version`, or if `None` the newest deleted one,
    /// but only while the path has no live version (undoing a delete):
    /// otherwise the newest deleted one is a trimmed or older version, which
    /// must be asked for by number. Older deleted versions stay deleted.
    /// Under the path's write lock (see `lock_path`), like a put: it can
    /// change the latest live version, so a check-and-set must not slip in
    /// between. Only within the retention: a purged version is gone. A put's
    /// version limit doesn't apply here; the next put trims as usual.
    pub async fn begin_restore(
        &self,
        path: &SecretPath,
        version: Option<u32>,
    ) -> Result<PendingRestore> {
        bounded(self.timeout, async move {
            let mut tx = self.lock_path(path).await?;
            // Two queries, not an optional condition (see `list`).
            let mut live = None;
            let row: Option<(i32, OffsetDateTime)> = match version {
                Some(version) => sqlx::query!(
                    "UPDATE secret_versions SET deleted_at = NULL
                     WHERE path_id = (SELECT id FROM paths WHERE path = $1)
                       AND version = $2 AND deleted_at IS NOT NULL
                     RETURNING version, created_at",
                    path.as_str(),
                    to_db("version", version)?,
                )
                .fetch_optional(&mut *tx)
                .await?
                .map(|r| (r.version, r.created_at)),
                None => {
                    // Read under the lock, so no put or delete can change it
                    // before the update.
                    live = sqlx::query_scalar!(
                        "SELECT MAX(version) FROM secret_versions
                         WHERE path_id = (SELECT id FROM paths WHERE path = $1)
                           AND deleted_at IS NULL",
                        path.as_str(),
                    )
                    .fetch_one(&mut *tx)
                    .await?
                    .map(|latest| u32_from_db("version", latest))
                    .transpose()?;
                    if live.is_some() {
                        None
                    } else {
                        sqlx::query!(
                            "WITH p AS (SELECT id FROM paths WHERE path = $1)
                             UPDATE secret_versions SET deleted_at = NULL
                             WHERE path_id = (SELECT id FROM p) AND deleted_at IS NOT NULL
                               AND version = (
                                   SELECT MAX(version) FROM secret_versions
                                   WHERE path_id = (SELECT id FROM p) AND deleted_at IS NOT NULL
                               )
                             RETURNING version, created_at",
                            path.as_str(),
                        )
                        .fetch_optional(&mut *tx)
                        .await?
                        .map(|r| (r.version, r.created_at))
                    }
                }
            };
            // The restored version is live again: the current one if it's the
            // newest (GREATEST ignores a NULL). After the version row, never
            // before: a purge holds the deleted versions it removes while it
            // waits for their paths' rows, so a restore holding the `paths`
            // row while it waits for one of those versions would deadlock
            // with it.
            if let Some((version, _)) = row {
                sqlx::query!(
                    "UPDATE paths SET current_version = GREATEST(current_version, $2)
                     WHERE path = $1",
                    path.as_str(),
                    version,
                )
                .execute(&mut *tx)
                .await?;
            }
            Ok(PendingRestore {
                tx,
                restored: row
                    .map(|(version, created_at)| {
                        Ok::<_, DatastoreError>(SecretMetadata {
                            path: path.clone(),
                            version: u32_from_db("version", version)?,
                            created_at,
                        })
                    })
                    .transpose()?,
                live,
                timeout: self.timeout,
            })
        })
        .await
    }

    /// Up to `limit` rows of `namespace` whose DEK is wrapped by its KEK
    /// `kek_version`, in key order after `after` (start with
    /// [`RowKey::FIRST`], then pass the last row's key). Deleted rows
    /// included: their DEKs block retiring a KEK too.
    pub async fn wrapped_by(
        &self,
        namespace: &Namespace,
        kek_version: u32,
        after: RowKey,
        limit: u32,
    ) -> Result<Vec<WrappedDek>> {
        bounded(self.timeout, async move {
            // Postgres eventually reuses one generic plan for a prepared
            // statement, and that plan can't know the old version is rare: it
            // pages along the primary key, filtering out nearly the whole
            // table per page. Forcing a custom plan (for this transaction
            // only) plans each page with the actual values, which uses the
            // `secret_versions_kek` index. (`.persistent(false)` would do
            // too, but isn't available on checked `query!` results.)
            let mut tx = self.pool.begin().await?;
            sqlx::query_scalar!("SELECT set_config('plan_cache_mode', 'force_custom_plan', true)")
                .fetch_one(&mut *tx)
                .await?;
            let rows = sqlx::query!(
                "SELECT v.path_id, p.path, v.version, v.wrapped_dek
                 FROM secret_versions v JOIN paths p ON p.id = v.path_id
                 WHERE v.namespace_id = (SELECT id FROM namespaces WHERE name = $1)
                   AND v.kek_version = $2 AND (v.path_id, v.version) > ($3, $4)
                 ORDER BY v.path_id, v.version
                 LIMIT $5",
                namespace.as_str(),
                to_db("kek_version", kek_version)?,
                after.path_id,
                after.version,
                i64::from(limit),
            )
            .fetch_all(&mut *tx)
            .await?;
            tx.commit().await?;
            rows.into_iter()
                .map(|r| {
                    Ok(WrappedDek {
                        key: RowKey {
                            path_id: r.path_id,
                            version: r.version,
                        },
                        path: SecretPath::parse(&r.path)
                            .map_err(DatastoreError::InvalidStoredPath)?,
                        version: u32_from_db("version", r.version)?,
                        wrapped_dek: r.wrapped_dek,
                    })
                })
                .collect()
        })
        .await
    }

    /// Stores re-wrapped DEKs, moving those rows of `namespace` from its KEK
    /// `from` to its KEK `to`, in one statement. Compare-and-set: a row no
    /// longer wrapped by `from` (another pass got there first) is left
    /// alone. Returns how many rows were updated.
    pub async fn rewrap(
        &self,
        namespace: &Namespace,
        from: u32,
        to: u32,
        rows: &[Rewrapped],
    ) -> Result<u64> {
        bounded(self.timeout, async move {
            let path_ids: Vec<Uuid> = rows.iter().map(|r| r.key.path_id).collect();
            let versions: Vec<i32> = rows.iter().map(|r| r.key.version).collect();
            let wrapped: Vec<Vec<u8>> = rows.iter().map(|r| r.wrapped_dek.clone()).collect();
            let updated = sqlx::query!(
                "UPDATE secret_versions v SET wrapped_dek = u.wrapped_dek, kek_version = $3
                 FROM UNNEST($4::uuid[], $5::int4[], $6::bytea[]) AS u(path_id, version, wrapped_dek)
                 WHERE v.path_id = u.path_id AND v.version = u.version
                   AND v.namespace_id = (SELECT id FROM namespaces WHERE name = $1)
                   AND v.kek_version = $2",
                namespace.as_str(),
                to_db("kek_version", from)?,
                to_db("kek_version", to)?,
                &path_ids[..],
                &versions[..],
                &wrapped[..],
            )
            .execute(&self.pool)
            .await
            .map_err(|e| {
                if is_below_kek_floor(&e) {
                    DatastoreError::BelowKekFloor(to)
                } else {
                    e.into()
                }
            })?;
            Ok(updated.rows_affected())
        })
        .await
    }

    /// Raises `namespace`'s KEK floor to `version` (if it's lower; a
    /// namespace this database doesn't know yet gets its row) and returns
    /// the floor now: from when this returns, no write can store a DEK of
    /// that namespace wrapped by a lower KEK version
    /// ([`DatastoreError::BelowKekFloor`]), whichever server or binary makes
    /// it. Waits for the namespace's writes in flight (they hold its floor
    /// lock shared) to commit or roll back, at most
    /// [`Datastore::with_lock_timeout`] ([`DatastoreError::KekFloorBusy`]),
    /// so every row they wrote is visible once this returns; other
    /// namespaces' writes go on. Never lowers it. The caller keeps it at or
    /// below the namespace's active KEK version, or its every write fails.
    pub async fn raise_kek_floor(&self, namespace: &Namespace, version: u32) -> Result<u32> {
        bounded(self.timeout, async move {
            let mut tx = self.pool.begin().await?;
            // As for a path's lock (`lock_path`); 0 would mean no limit.
            let lock_timeout = format!("{}ms", self.lock_timeout.as_millis().max(1));
            sqlx::query_scalar!("SELECT set_config('lock_timeout', $1, true)", lock_timeout)
                .fetch_one(&mut *tx)
                .await?;
            sqlx::query_scalar!(
                r#"SELECT 1 AS "locked!" FROM pg_advisory_xact_lock($1, hashtext($2))"#,
                KEK_FLOOR_LOCK_CLASS,
                namespace.as_str(),
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                if is_lock_timeout(&e) {
                    DatastoreError::KekFloorBusy
                } else {
                    e.into()
                }
            })?;
            let floor = sqlx::query_scalar!(
                "INSERT INTO namespaces (name, kek_floor) VALUES ($1, $2)
                 ON CONFLICT (name) DO UPDATE
                     SET kek_floor = GREATEST(namespaces.kek_floor, EXCLUDED.kek_floor)
                 RETURNING kek_floor",
                namespace.as_str(),
                to_db("kek_version", version)?,
            )
            .fetch_one(&mut *tx)
            .await?;
            let floor = u32_from_db("kek_version", floor)?;
            tx.commit().await?;
            Ok(floor)
        })
        .await
    }

    /// The highest stored-policy revision any server wrote (the policies
    /// themselves live in the keys database): a set below it was put back
    /// from an older copy, or wiped. 0 before the first policy write.
    pub async fn policy_revision_floor(&self) -> Result<u64> {
        bounded(self.timeout, async move {
            let revision = sqlx::query_scalar!("SELECT revision FROM policy_revision_floor")
                .fetch_one(&self.pool)
                .await?;
            u64::try_from(revision).map_err(|_| DatastoreError::OutOfRange {
                field: "policy revision",
                value: revision,
            })
        })
        .await
    }

    /// Raises the policy revision floor to `revision` (never lowers it).
    pub async fn raise_policy_revision_floor(&self, revision: u64) -> Result<()> {
        let revision =
            i64::try_from(revision).map_err(|_| DatastoreError::RevisionOutOfRange(revision))?;
        bounded(self.timeout, async move {
            sqlx::query!(
                "UPDATE policy_revision_floor SET revision = GREATEST(revision, $1)",
                revision
            )
            .execute(&self.pool)
            .await?;
            Ok(())
        })
        .await
    }

    /// The highest revision of the workload-identity issuing keys any server
    /// wrote or verified (the keys themselves live in the keys database): a
    /// set below it was put back from an older copy. 0 before the first.
    pub async fn issuing_revision_floor(&self) -> Result<u64> {
        bounded(self.timeout, async move {
            let revision = sqlx::query_scalar!("SELECT revision FROM issuing_revision_floor")
                .fetch_one(&self.pool)
                .await?;
            u64::try_from(revision).map_err(|_| DatastoreError::OutOfRange {
                field: "issuing revision",
                value: revision,
            })
        })
        .await
    }

    /// Raises the issuing revision floor to `revision` (never lowers it).
    pub async fn raise_issuing_revision_floor(&self, revision: u64) -> Result<()> {
        let revision =
            i64::try_from(revision).map_err(|_| DatastoreError::RevisionOutOfRange(revision))?;
        bounded(self.timeout, async move {
            sqlx::query!(
                "UPDATE issuing_revision_floor SET revision = GREATEST(revision, $1)",
                revision
            )
            .execute(&self.pool)
            .await?;
            Ok(())
        })
        .await
    }

    /// The commitments stored for root-key `generation` (see migration
    /// 0005): none, one, or several (a failed rekey attempt's, then the
    /// one that committed).
    pub async fn root_commitments(&self, generation: u32) -> Result<Vec<Vec<u8>>> {
        let generation = i32::try_from(generation).map_err(|_| DatastoreError::OutOfRange {
            field: "generation",
            value: i64::from(generation),
        })?;
        bounded(self.timeout, async move {
            Ok(sqlx::query_scalar!(
                "SELECT mac FROM root_commitments WHERE generation = $1 ORDER BY created_at",
                generation
            )
            .fetch_all(&self.pool)
            .await?)
        })
        .await
    }

    /// Stores a commitment for root-key `generation`; one already there
    /// (the same MAC) is kept. Commitments are insert-only.
    pub async fn insert_root_commitment(&self, generation: u32, mac: &[u8]) -> Result<()> {
        let generation = i32::try_from(generation).map_err(|_| DatastoreError::OutOfRange {
            field: "generation",
            value: i64::from(generation),
        })?;
        bounded(self.timeout, async move {
            sqlx::query!(
                "INSERT INTO root_commitments (generation, mac) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
                generation,
                mac
            )
            .execute(&self.pool)
            .await?;
            Ok(())
        })
        .await
    }

    /// The highest root-key generation known to have committed (0: no init
    /// ever has).
    pub async fn root_generation_floor(&self) -> Result<u32> {
        bounded(self.timeout, async move {
            let generation = sqlx::query_scalar!("SELECT generation FROM root_generation_floor")
                .fetch_one(&self.pool)
                .await?;
            u32_from_db("generation", generation)
        })
        .await
    }

    /// Raises the root-generation floor to `generation` (never lowers it).
    pub async fn raise_root_generation_floor(&self, generation: u32) -> Result<()> {
        let generation = i32::try_from(generation).map_err(|_| DatastoreError::OutOfRange {
            field: "generation",
            value: i64::from(generation),
        })?;
        bounded(self.timeout, async move {
            sqlx::query!(
                "UPDATE root_generation_floor SET generation = GREATEST(generation, $1)",
                generation
            )
            .execute(&self.pool)
            .await?;
            Ok(())
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
                u64::try_from(value).map_err(|_| DatastoreError::OutOfRange { field, value })
            };
            Ok((count("hold", row.hold)?, count("released", row.released)?))
        })
        .await
    }

    /// Raises the hold to `hold` (never lowers it).
    pub async fn raise_auto_unseal_hold(&self, hold: u64) -> Result<()> {
        let hold = i64::try_from(hold).map_err(|_| DatastoreError::RevisionOutOfRange(hold))?;
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
        let released =
            i64::try_from(released).map_err(|_| DatastoreError::RevisionOutOfRange(released))?;
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

    /// One stored secret version (deleted or not) per (namespace, KEK
    /// version) any row uses: what a root key re-committed with shares must
    /// open, to prove it's the one the data was written under. A loose
    /// index scan, as [`Datastore::kek_versions_in_use`], then one row per
    /// pair by a lateral probe.
    pub async fn version_per_kek(&self) -> Result<Vec<StoredVersion>> {
        bounded(self.timeout, async move {
            let rows = sqlx::query!(
                r#"WITH RECURSIVE used(namespace_id, version) AS (
                       (SELECT namespace_id, kek_version FROM secret_versions
                        ORDER BY namespace_id, kek_version LIMIT 1)
                       UNION ALL
                       SELECT next.namespace_id, next.kek_version
                       FROM used, LATERAL (
                           SELECT namespace_id, kek_version FROM secret_versions
                           WHERE (namespace_id, kek_version) > (used.namespace_id, used.version)
                           ORDER BY namespace_id, kek_version LIMIT 1
                       ) next
                   )
                   SELECT p.path AS "path!", one.version AS "version!",
                          one.kek_version AS "kek_version!",
                          one.ciphertext AS "ciphertext!", one.wrapped_dek AS "wrapped_dek!"
                   FROM used
                   CROSS JOIN LATERAL (
                       SELECT path_id, version, kek_version, ciphertext, wrapped_dek
                       FROM secret_versions
                       WHERE namespace_id = used.namespace_id AND kek_version = used.version
                       LIMIT 1
                   ) one
                   JOIN paths p ON p.id = one.path_id
                   ORDER BY p.path"#
            )
            .fetch_all(&self.pool)
            .await?;
            rows.into_iter()
                .map(|r| {
                    Ok(StoredVersion {
                        path: SecretPath::parse(&r.path)
                            .map_err(DatastoreError::InvalidStoredPath)?,
                        version: u32_from_db("version", r.version)?,
                        kek_version: u32_from_db("kek_version", r.kek_version)?,
                        ciphertext: r.ciphertext,
                        wrapped_dek: r.wrapped_dek,
                    })
                })
                .collect()
        })
        .await
    }

    /// The KEK floor of every namespace this database knows (written to, or
    /// a floor raised for), by name; any other's is 1.
    pub async fn kek_floors(&self) -> Result<Vec<(Namespace, u32)>> {
        bounded(self.timeout, async move {
            sqlx::query!("SELECT name, kek_floor FROM namespaces ORDER BY name")
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|row| {
                    let namespace = Namespace::parse(&row.name)
                        .map_err(|_| DatastoreError::InvalidStoredNamespace(row.name))?;
                    Ok((namespace, u32_from_db("kek_version", row.kek_floor)?))
                })
                .collect()
        })
        .await
    }

    /// `namespace`'s KEK floor now (see [`Datastore::raise_kek_floor`]): 1
    /// for a namespace this database doesn't know.
    pub async fn kek_floor(&self, namespace: &Namespace) -> Result<u32> {
        bounded(self.timeout, async move {
            let floor = sqlx::query_scalar!(
                "SELECT kek_floor FROM namespaces WHERE name = $1",
                namespace.as_str()
            )
            .fetch_optional(&self.pool)
            .await?;
            floor.map_or(Ok(1), |v| u32_from_db("kek_version", v))
        })
        .await
    }

    /// Whether any row (deleted or not) of `namespace` still has its DEK
    /// wrapped by its KEK `kek_version`. Stops at the first one, through the
    /// `secret_versions_kek` index, rather than counting.
    pub async fn any_wrapped_by(&self, namespace: &Namespace, kek_version: u32) -> Result<bool> {
        bounded(self.timeout, async move {
            let found = sqlx::query_scalar!(
                r#"SELECT EXISTS (
                       SELECT 1 FROM secret_versions
                       WHERE namespace_id = (SELECT id FROM namespaces WHERE name = $1)
                         AND kek_version = $2
                   ) AS "found!""#,
                namespace.as_str(),
                to_db("kek_version", kek_version)?,
            )
            .fetch_one(&self.pool)
            .await?;
            Ok(found)
        })
        .await
    }

    /// The highest KEK version any row (deleted or not) of `namespace` has
    /// its DEK wrapped by, if it has rows: one probe on the
    /// `secret_versions_kek` index.
    pub async fn max_kek_version(&self, namespace: &Namespace) -> Result<Option<u32>> {
        bounded(self.timeout, async move {
            sqlx::query_scalar!(
                "SELECT max(kek_version) FROM secret_versions
                 WHERE namespace_id = (SELECT id FROM namespaces WHERE name = $1)",
                namespace.as_str()
            )
            .fetch_one(&self.pool)
            .await?
            .map(|v| u32_from_db("kek_version", v))
            .transpose()
        })
        .await
    }

    /// Whether any secret version is stored at all, deleted or not.
    pub async fn any_secrets(&self) -> Result<bool> {
        bounded(self.timeout, async move {
            let any =
                sqlx::query_scalar!(r#"SELECT EXISTS (SELECT 1 FROM secret_versions) AS "any!""#)
                    .fetch_one(&self.pool)
                    .await?;
            Ok(any)
        })
        .await
    }

    /// How many rows `namespace` has, and how many of them are deleted
    /// (for deleting a namespace: it must have none, deleted included).
    pub async fn namespace_rows(&self, namespace: &Namespace) -> Result<(u64, u64)> {
        bounded(self.timeout, async move {
            let row = sqlx::query!(
                r#"SELECT count(*) AS "total!",
                          count(*) FILTER (WHERE deleted_at IS NOT NULL) AS "deleted!"
                   FROM secret_versions
                   WHERE namespace_id = (SELECT id FROM namespaces WHERE name = $1)"#,
                namespace.as_str()
            )
            .fetch_one(&self.pool)
            .await?;
            let count = |field, n: i64| {
                u64::try_from(n).map_err(|_| DatastoreError::OutOfRange { field, value: n })
            };
            Ok((count("rows", row.total)?, count("rows", row.deleted)?))
        })
        .await
    }

    /// Now, as a mark to ask for changes from (see [`Changes`]).
    pub async fn change_mark(&self) -> Result<ChangeMark> {
        bounded(self.timeout, async move {
            let mark = sqlx::query!(
                r#"SELECT pg_current_snapshot()::text AS "snapshot!",
                          pg_postmaster_start_time()::text AS "server!""#
            )
            .fetch_one(&self.pool)
            .await?;
            Ok(ChangeMark {
                snapshot: mark.snapshot,
                server: mark.server,
            })
        })
        .await
    }

    /// The changes of live versions committed since `mark`, whoever made
    /// them (migration 0004), at most `limit`: rows visible now whose
    /// change the mark's snapshot didn't see. One snapshot for the new mark
    /// and the rows, so a change is in exactly one answer; `Restarted` if
    /// the mark came from another Postgres server (or before a restart),
    /// whose transaction ids may not match these. Read-only
    /// (REPEATABLE READ is for this read's one snapshot; writes stay READ
    /// COMMITTED).
    pub async fn changes_since(&self, mark: &ChangeMark, limit: u32) -> Result<Changes> {
        bounded(self.timeout, async move {
            let mut tx = self.pool.begin().await?;
            sqlx::query!("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *tx)
                .await?;
            let now = sqlx::query!(
                r#"SELECT pg_current_snapshot()::text AS "snapshot!",
                          pg_postmaster_start_time()::text AS "server!""#
            )
            .fetch_one(&mut *tx)
            .await?;
            let now = ChangeMark {
                snapshot: now.snapshot,
                server: now.server,
            };
            if now.server != mark.server {
                tx.commit().await?;
                return Ok(Changes::Restarted(now));
            }
            let rows = sqlx::query!(
                "SELECT path, current_version FROM paths
                 WHERE changed_xid >= pg_snapshot_xmin($1::text::pg_snapshot)
                   AND NOT pg_visible_in_snapshot(changed_xid, $1::text::pg_snapshot)
                 LIMIT $2",
                mark.snapshot,
                i64::from(limit) + 1,
            )
            .fetch_all(&mut *tx)
            .await?;
            tx.commit().await?;
            if rows.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
                return Ok(Changes::TooMany(now));
            }
            let changes = rows
                .into_iter()
                .filter_map(|row| {
                    let path = SecretPath::parse(&row.path).ok()?;
                    let version = row.current_version.and_then(|v| u32::try_from(v).ok());
                    Some(Change { path, version })
                })
                .collect();
            Ok(Changes::Since(now, changes))
        })
        .await
    }

    /// Reclaims the `paths` rows of `namespace`, which is being deleted:
    /// only if it has no version at all (deleted ones included), checked
    /// under its KEK floor lock taken exclusively, so no version can be
    /// stored meanwhile, nor after (its floor is already past its every
    /// KEK). The highest version any of them reached goes into the
    /// namespace's `version_floor` first, in the same transaction, so a
    /// re-created namespace's paths number on past it: a version number is
    /// never reused. A row a put in flight holds stays (that put is
    /// refused). Returns how many rows went, or the rows still there.
    pub async fn reclaim_paths(&self, namespace: &Namespace) -> Result<Reclaimed> {
        bounded(self.timeout, async move {
            let mut tx = self.pool.begin().await?;
            // As for a path's lock (`lock_path`); 0 would mean no limit.
            let lock_timeout = format!("{}ms", self.lock_timeout.as_millis().max(1));
            sqlx::query_scalar!("SELECT set_config('lock_timeout', $1, true)", lock_timeout)
                .fetch_one(&mut *tx)
                .await?;
            sqlx::query_scalar!(
                r#"SELECT 1 AS "locked!" FROM pg_advisory_xact_lock($1, hashtext($2))"#,
                KEK_FLOOR_LOCK_CLASS,
                namespace.as_str(),
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                if is_lock_timeout(&e) {
                    DatastoreError::KekFloorBusy
                } else {
                    e.into()
                }
            })?;
            let rows = sqlx::query!(
                r#"SELECT count(*) AS "total!",
                          count(*) FILTER (WHERE deleted_at IS NOT NULL) AS "deleted!"
                   FROM secret_versions
                   WHERE namespace_id = (SELECT id FROM namespaces WHERE name = $1)"#,
                namespace.as_str()
            )
            .fetch_one(&mut *tx)
            .await?;
            let count = |n: i64| {
                u64::try_from(n).map_err(|_| DatastoreError::OutOfRange {
                    field: "rows",
                    value: n,
                })
            };
            if rows.total > 0 {
                return Ok(Reclaimed::NotEmpty {
                    rows: count(rows.total)?,
                    deleted: count(rows.deleted)?,
                });
            }
            sqlx::query!(
                "UPDATE namespaces n
                 SET version_floor = GREATEST(n.version_floor,
                     (SELECT COALESCE(MAX(p.highest), 0) FROM paths p WHERE p.namespace_id = n.id))
                 WHERE n.name = $1",
                namespace.as_str()
            )
            .execute(&mut *tx)
            .await?;
            // A row a put in flight holds is left, never waited for: that
            // put waits for the floor lock this holds (at its insert), so
            // waiting would deadlock. It can't commit (the floor refuses
            // its version), and the version floor above already counts the
            // row's committed `highest`, so numbering stays past it.
            let reclaimed = sqlx::query!(
                "DELETE FROM paths
                 WHERE id IN (
                     SELECT id FROM paths
                     WHERE namespace_id = (SELECT id FROM namespaces WHERE name = $1)
                     FOR UPDATE SKIP LOCKED)",
                namespace.as_str()
            )
            .execute(&mut *tx)
            .await?
            .rows_affected();
            tx.commit().await?;
            Ok(Reclaimed::Paths(reclaimed))
        })
        .await
    }

    /// Every (namespace, KEK version) some row (deleted or not) has its DEK
    /// wrapped by, in order. A loose index scan over `secret_versions_kek`:
    /// one index probe per pair, however many rows there are (Postgres has
    /// no skip scan for DISTINCT, which would read the whole index).
    pub async fn kek_versions_in_use(&self) -> Result<Vec<(Namespace, u32)>> {
        bounded(self.timeout, async move {
            let rows = sqlx::query!(
                r#"WITH RECURSIVE used(namespace_id, version) AS (
                       (SELECT namespace_id, kek_version FROM secret_versions
                        ORDER BY namespace_id, kek_version LIMIT 1)
                       UNION ALL
                       SELECT next.namespace_id, next.kek_version
                       FROM used, LATERAL (
                           SELECT namespace_id, kek_version FROM secret_versions
                           WHERE (namespace_id, kek_version) > (used.namespace_id, used.version)
                           ORDER BY namespace_id, kek_version LIMIT 1
                       ) next
                   )
                   SELECT n.name AS "namespace!", used.version AS "version!"
                   FROM used JOIN namespaces n ON n.id = used.namespace_id
                   ORDER BY n.name, used.version"#
            )
            .fetch_all(&self.pool)
            .await?;
            rows.into_iter()
                .map(|r| {
                    let namespace = Namespace::parse(&r.namespace)
                        .map_err(|_| DatastoreError::InvalidStoredNamespace(r.namespace.clone()))?;
                    Ok((namespace, u32_from_db("kek_version", r.version)?))
                })
                .collect()
        })
        .await
    }

    /// Changes `path`'s labels (`set` added or replaced, `remove` removed),
    /// uncommitted: [`StagedLabels::commit`] to keep it. Checked by the
    /// caller (`ferritor_core::labels::check_change`), except the total
    /// ([`DatastoreError::TooManyLabels`]). [`DatastoreError::NothingStored`]
    /// for a path with nothing stored. Holds the path's `paths` row locked,
    /// so concurrent changes to one path take turns and compose; it needs no
    /// path lock (it doesn't touch versions).
    pub async fn change_labels(
        &self,
        path: &SecretPath,
        set: &Labels,
        remove: &[String],
    ) -> Result<StagedLabels> {
        let timeout = self.timeout;
        bounded(timeout, async move {
            let mut tx = self.pool.begin().await?;
            let labels = change_labels(&mut tx, path, set, remove).await?;
            Ok(StagedLabels {
                tx,
                labels,
                timeout,
            })
        })
        .await
    }

    /// What's known about `path` as a whole: when it was first and last
    /// written, its current and oldest versions, how many are stored, its
    /// labels. `None` for a path with nothing stored (never written, or
    /// every version purged), like the history. One `paths` row and two
    /// probes and a count on the primary key.
    pub async fn path_metadata(&self, path: &SecretPath) -> Result<Option<PathMetadata>> {
        bounded(self.timeout, async move {
            let row = sqlx::query!(
                r#"SELECT p.created_at, p.updated_at, p.current_version,
                       (SELECT min(version) FROM secret_versions
                        WHERE path_id = p.id) AS oldest_version,
                       (SELECT count(*) FROM secret_versions WHERE path_id = p.id) AS "versions!",
                       p.labels AS "labels: Json<Labels>",
                       p.labels_updated_at
                   FROM paths p
                   WHERE p.path = $1"#,
                path.as_str(),
            )
            .fetch_optional(&self.pool)
            .await?;
            let Some(row) = row.filter(|row| row.versions > 0) else {
                return Ok(None);
            };
            Ok(Some(PathMetadata {
                path: path.clone(),
                created_at: row.created_at,
                updated_at: row.updated_at,
                current_version: row
                    .current_version
                    .map(|v| u32_from_db("version", v))
                    .transpose()?,
                oldest_version: row
                    .oldest_version
                    .map(|v| u32_from_db("version", v))
                    .transpose()?,
                versions: u64::try_from(row.versions).map_err(|_| DatastoreError::OutOfRange {
                    field: "versions",
                    value: row.versions,
                })?,
                labels: row.labels.0,
                labels_updated_at: row.labels_updated_at,
            }))
        })
        .await
    }

    /// The latest live version of every path, in path (byte) order: all of
    /// them, or those strictly below `prefix` by whole segments. Paths with
    /// no live version are left out.
    ///
    /// One page of it: at most `limit` paths, only those strictly after
    /// `after` if given. Paths are unique in the result, so the last one
    /// returned is a complete cursor for the next page. With `labels`, only
    /// paths whose labels include every one of them (an empty map filters
    /// nothing).
    ///
    /// A range on `paths_live` (only paths with a live version, by
    /// `paths.current_version`), in its order, and per path one primary-key
    /// probe for its version's time: a lateral probe, not a join (its
    /// `LIMIT 1` keeps the planner from flattening it into one), so the plan
    /// is always that walk, stopping at the page's limit, never a hash join
    /// over every version. Every path ever written stays in `paths`; the
    /// paths with nothing live aren't in that index, so a page never reads
    /// past them. The probe checks the version is live too (a filter after
    /// the lookup, free): were `current_version` ever wrong, a listing
    /// would leave the path out rather than show a deleted version.
    pub async fn list(
        &self,
        prefix: Option<&SecretPath>,
        after: Option<&SecretPath>,
        limit: u32,
        labels: &Labels,
    ) -> Result<Vec<SecretMetadata>> {
        bounded(self.timeout, async move {
            // Every path is non-empty, so `path > ''` is "from the start". It
            // keeps `after` an indexed bound rather than an optional one.
            let after = after.map_or("", SecretPath::as_str);
            let limit = i64::from(limit);
            // Separate queries, not one with `$1 IS NULL OR <range>`: once
            // Postgres reuses a generic plan for a prepared statement, that OR
            // can't use `paths_live` and becomes a sequential scan. The label
            // filter is a condition on the same `paths` row, in queries of
            // their own, so a listing without one is exactly what it was.
            let rows: Vec<(String, i32, OffsetDateTime)> = match (prefix, labels.is_empty()) {
                (Some(prefix), false) => {
                    let (lo, hi) = prefix.descendant_range();
                    sqlx::query!(
                        "SELECT p.path, v.version, v.created_at
                         FROM paths p
                         CROSS JOIN LATERAL (
                             SELECT version, created_at FROM secret_versions
                             WHERE path_id = p.id AND version = p.current_version AND deleted_at IS NULL
                             LIMIT 1
                         ) v
                         WHERE p.current_version IS NOT NULL AND p.path >= $1 AND p.path < $2 AND p.path > $3
                           AND p.labels @> $4 AND p.labels <> '{}'
                         ORDER BY p.path
                         LIMIT $5",
                        lo,
                        hi,
                        after,
                        Json(labels) as _,
                        limit,
                    )
                    .fetch_all(&self.pool)
                    .await?
                    .into_iter()
                    .map(|r| (r.path, r.version, r.created_at))
                    .collect()
                }
                (None, false) => sqlx::query!(
                    "SELECT p.path, v.version, v.created_at
                     FROM paths p
                     CROSS JOIN LATERAL (
                         SELECT version, created_at FROM secret_versions
                         WHERE path_id = p.id AND version = p.current_version AND deleted_at IS NULL
                         LIMIT 1
                     ) v
                     WHERE p.current_version IS NOT NULL AND p.path > $1 AND p.labels @> $2 AND p.labels <> '{}'
                     ORDER BY p.path
                     LIMIT $3",
                    after,
                    Json(labels) as _,
                    limit,
                )
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|r| (r.path, r.version, r.created_at))
                .collect(),
                (Some(prefix), true) => {
                    // Relies on `paths.path` being COLLATE "C". Both lower
                    // bounds stay: `after` alone must never widen the range.
                    let (lo, hi) = prefix.descendant_range();
                    sqlx::query!(
                        "SELECT p.path, v.version, v.created_at
                         FROM paths p
                         CROSS JOIN LATERAL (
                             SELECT version, created_at FROM secret_versions
                             WHERE path_id = p.id AND version = p.current_version AND deleted_at IS NULL
                             LIMIT 1
                         ) v
                         WHERE p.current_version IS NOT NULL AND p.path >= $1 AND p.path < $2 AND p.path > $3
                         ORDER BY p.path
                         LIMIT $4",
                        lo,
                        hi,
                        after,
                        limit,
                    )
                    .fetch_all(&self.pool)
                    .await?
                    .into_iter()
                    .map(|r| (r.path, r.version, r.created_at))
                    .collect()
                }
                (None, true) => sqlx::query!(
                    "SELECT p.path, v.version, v.created_at
                     FROM paths p
                     CROSS JOIN LATERAL (
                         SELECT version, created_at FROM secret_versions
                         WHERE path_id = p.id AND version = p.current_version AND deleted_at IS NULL
                         LIMIT 1
                     ) v
                     WHERE p.current_version IS NOT NULL AND p.path > $1
                     ORDER BY p.path
                     LIMIT $2",
                    after,
                    limit,
                )
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|r| (r.path, r.version, r.created_at))
                .collect(),
            };
            rows.into_iter()
                .map(|(path, version, created_at)| metadata(path, version, created_at))
                .collect()
        })
        .await
    }
}

/// A stored secret version, encrypted ([`Datastore::version_per_kek`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredVersion {
    pub path: SecretPath,
    pub version: u32,
    pub kek_version: u32,
    pub ciphertext: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
}

/// A path's live version changed (migration 0004): `version` is the new
/// one, `None` after a delete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub path: SecretPath,
    pub version: Option<u32>,
}

/// A point in the data database's history: the changes after it are
/// [`Datastore::changes_since`]'s. A `pg_snapshot` (as text), and when the
/// Postgres server that took it started: transaction ids mean something
/// only on that server, since a restarted or promoted one may give again
/// ids that never reached its disk (a transaction that aborted just
/// before), which the snapshot already counts as finished.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeMark {
    snapshot: String,
    server: String,
}

impl ChangeMark {
    /// The oldest transaction still running when the mark was taken (its
    /// snapshot's `xmin`, when below its `xmax`), if one was: the next
    /// poll reads every change since it, so a transaction held open (a
    /// session left inside `BEGIN`, a long migration), in any database of
    /// the Postgres server (transaction ids are the server's), makes every
    /// poll read more, until it ends.
    pub fn oldest_running(&self) -> Option<u64> {
        let mut bounds = self.snapshot.split(':');
        let xmin: u64 = bounds.next()?.parse().ok()?;
        let xmax: u64 = bounds.next()?.parse().ok()?;
        (xmin < xmax).then_some(xmin)
    }
}

/// What [`Datastore::changes_since`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Changes {
    /// Every change since the mark, each path once (its live version now),
    /// and the mark to ask from next.
    Since(ChangeMark, Vec<Change>),
    /// More than the limit: too many to tell one by one. Whoever relies on
    /// them must read again what it watches; ask from the new mark.
    TooMany(ChangeMark),
    /// The data database isn't the server the mark came from (a restart, a
    /// failover): changes may have been missed. Read again, as for
    /// `TooMany`; ask from the new mark.
    Restarted(ChangeMark),
}

/// What [`Datastore::reclaim_paths`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reclaimed {
    /// This many `paths` rows went.
    Paths(u64),
    /// Nothing: the namespace still has versions (`deleted` of them deleted).
    NotEmpty { rows: u64, deleted: u64 },
}

/// A put's `paths` row, as `upsert_path` leaves it.
struct NextVersion {
    id: Uuid,
    namespace_id: Uuid,
    /// The version the put takes.
    highest: i32,
}

/// Bumps `path`'s version counter (creating its row on its first write),
/// makes the new version its current one (a put's version is the newest:
/// rolled back with the put if it doesn't commit), and returns the row,
/// locked until `tx` ends. `None` if its namespace has no row yet (the
/// caller creates it and asks again) or the path is out of version
/// numbers. `EXCLUDED.highest - 1` is the higher of the rows' own highest
/// and the namespace's `version_floor` (the highest of the paths a deleted
/// namespace's reclaim removed: see [`Datastore::reclaim_paths`]).
async fn upsert_path(
    tx: &mut Transaction<'static, Postgres>,
    path: &SecretPath,
) -> Result<Option<NextVersion>> {
    let namespace = path.namespace();
    sqlx::query_as!(
        NextVersion,
        "WITH stored AS (
             SELECT COALESCE(MAX(version), 0) AS highest FROM secret_versions
             WHERE path_id = (SELECT id FROM paths WHERE path = $1)
         )
         INSERT INTO paths (namespace_id, path, highest, current_version)
         SELECT n.id, $1, GREATEST(stored.highest, n.version_floor) + 1,
                GREATEST(stored.highest, n.version_floor) + 1
         FROM namespaces n, stored
         WHERE n.name = $2 AND GREATEST(stored.highest, n.version_floor) < 2147483647
         ON CONFLICT (path) DO UPDATE
             SET highest = GREATEST(paths.highest, EXCLUDED.highest - 1) + 1,
                 current_version = GREATEST(paths.highest, EXCLUDED.highest - 1) + 1,
                 updated_at = now()
             WHERE GREATEST(paths.highest, EXCLUDED.highest - 1) < 2147483647
         RETURNING id, namespace_id, highest",
        path.as_str(),
        namespace.as_str(),
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| {
        // The row is locked by a label change or a purge's last step: the
        // transaction's lock_timeout (set in `lock_path`) bounds the wait.
        if is_lock_timeout(&e) {
            DatastoreError::Busy(path.clone())
        } else {
            e.into()
        }
    })
}

#[cfg(test)]
mod tests {
    use ferritor_testkit::{TestDatabase, TestResult};

    use super::*;

    /// A mark from another Postgres server (or before a restart) is never
    /// trusted: its transaction ids may not match.
    #[tokio::test]
    async fn a_mark_from_another_server_is_a_restart() -> TestResult<()> {
        let db = TestDatabase::new("DATA_DATABASE_URL", "ferritor_data_test", &MIGRATOR).await?;
        let store = Datastore::new(db.pool().clone());
        let mark = store.change_mark().await?;
        assert!(matches!(
            store.changes_since(&mark, 10).await?,
            Changes::Since(_, _)
        ));
        let running = ChangeMark {
            snapshot: "100:105:100,103".to_owned(),
            ..mark.clone()
        };
        assert_eq!(running.oldest_running(), Some(100));
        let idle = ChangeMark {
            snapshot: "105:105:".to_owned(),
            ..mark.clone()
        };
        assert_eq!(idle.oldest_running(), None);
        let elsewhere = ChangeMark {
            server: "2001-01-01 00:00:00+00".to_owned(),
            ..mark
        };
        let Changes::Restarted(next) = store.changes_since(&elsewhere, 10).await? else {
            panic!("not a restart");
        };
        assert!(matches!(
            store.changes_since(&next, 10).await?,
            Changes::Since(_, _)
        ));
        db.destroy().await?;
        Ok(())
    }
}
