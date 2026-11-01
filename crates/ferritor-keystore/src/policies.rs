//! Stored policies (migration 0004): rows, the set's state and the wrapped
//! policy key. Only storage: the MACs are computed and checked by the server
//! (`policy_store`), which this crate never second-guesses.

use std::time::Duration;

use sqlx::types::time::OffsetDateTime;
use sqlx::{PgConnection, Postgres, Transaction};

use super::{Keystore, KeystoreError, Lock, Result, bounded, lock_generation, to_db, u32_from_db};

/// One stored policy, as written (action names and paths as strings: the
/// server parses them, after checking the MAC over exactly these).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPolicy {
    pub name: String,
    pub identity: String,
    pub actions: Vec<String>,
    pub paths: Vec<String>,
    pub all_paths: bool,
    pub description: String,
    pub version: u32,
    pub mac: Vec<u8>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// The set's state: its revision, and its MAC (`None` while no policy was
/// ever written).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyState {
    pub revision: u64,
    pub mac: Option<Vec<u8>>,
}

/// Everything a server verifies, from one snapshot: the wrapped policy key,
/// the generation it's wrapped under, the state and every row (by name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySnapshot {
    pub generation: u32,
    pub wrapped_key: Option<Vec<u8>>,
    pub state: PolicyState,
    pub policies: Vec<StoredPolicy>,
}

/// A policy to store (insert or replace, by name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewPolicy {
    pub name: String,
    pub identity: String,
    pub actions: Vec<String>,
    pub paths: Vec<String>,
    pub all_paths: bool,
    pub description: String,
    pub version: u32,
    pub mac: Vec<u8>,
}

/// What one write changes, all in its transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyChanges {
    pub upsert: Vec<NewPolicy>,
    pub delete: Vec<String>,
    pub revision: u64,
    pub mac: Vec<u8>,
    /// A new wrapped policy key (the first write, or the repair).
    pub new_wrapped_key: Option<Vec<u8>>,
}

/// A policy write in progress: the set's state read under its lock. Dropped
/// without [`PolicyWrite::commit`], nothing changes.
pub struct PolicyWrite {
    tx: Transaction<'static, Postgres>,
    timeout: Duration,
    /// The set as it is now, under the lock.
    pub snapshot: PolicySnapshot,
}

fn revision_from_db(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| KeystoreError::OutOfRange {
        field: "revision",
        value,
    })
}

fn revision_to_db(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| KeystoreError::OutOfRange {
        field: "revision",
        value: i64::MAX,
    })
}

async fn snapshot_in(conn: &mut PgConnection, lock_state: bool) -> Result<PolicySnapshot> {
    let config = sqlx::query!("SELECT generation, wrapped_policy_key FROM seal_config")
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(KeystoreError::NotInitialized)?;
    // Separate literals: `query!` needs the SQL at compile time.
    let state = if lock_state {
        sqlx::query!("SELECT revision, mac FROM policy_state FOR UPDATE")
            .fetch_one(&mut *conn)
            .await
            .map(|r| (r.revision, r.mac))?
    } else {
        sqlx::query!("SELECT revision, mac FROM policy_state")
            .fetch_one(&mut *conn)
            .await
            .map(|r| (r.revision, r.mac))?
    };
    let policies = sqlx::query!(
        "SELECT name, identity, actions, paths, all_paths, description, version, mac,
                created_at, updated_at
         FROM policies ORDER BY name"
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok(StoredPolicy {
            name: row.name,
            identity: row.identity,
            actions: row.actions,
            paths: row.paths,
            all_paths: row.all_paths,
            description: row.description,
            version: u32_from_db("version", row.version)?,
            mac: row.mac,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    })
    .collect::<Result<_>>()?;
    Ok(PolicySnapshot {
        generation: u32_from_db("generation", config.generation)?,
        wrapped_key: config.wrapped_policy_key,
        state: PolicyState {
            revision: revision_from_db(state.0)?,
            mac: state.1,
        },
        policies,
    })
}

impl Keystore {
    /// The set's revision alone: what a server polls to notice a change.
    pub async fn policy_revision(&self) -> Result<u64> {
        bounded(self.timeout, async move {
            let revision = sqlx::query_scalar!("SELECT revision FROM policy_state")
                .fetch_one(&self.pool)
                .await?;
            revision_from_db(revision)
        })
        .await
    }

    /// The key, the state and every row, from one REPEATABLE READ snapshot,
    /// so they always verify together.
    pub async fn policy_snapshot(&self) -> Result<PolicySnapshot> {
        bounded(self.timeout, async move {
            let mut tx = self
                .pool
                .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .await?;
            let snapshot = snapshot_in(&mut tx, false).await?;
            tx.commit().await?;
            Ok(snapshot)
        })
        .await
    }

    /// The wrapped policy key, if there is one (a rekey checks it opens
    /// before it starts).
    pub async fn wrapped_policy_key(&self) -> Result<Option<Vec<u8>>> {
        bounded(self.timeout, async move {
            Ok(
                sqlx::query_scalar!("SELECT wrapped_policy_key FROM seal_config")
                    .fetch_optional(&self.pool)
                    .await?
                    .flatten(),
            )
        })
        .await
    }

    /// Starts a policy write: holds the seal config of `generation` `FOR
    /// SHARE` (so it can't interleave with a rekey re-wrapping the policy
    /// key, and this server's root key is the current one) and the set's
    /// state `FOR UPDATE` (so writes serialize), and reads the set under
    /// them.
    pub async fn begin_policy_write(&self, generation: u32) -> Result<PolicyWrite> {
        bounded(self.timeout, async move {
            let mut tx = self.pool.begin().await?;
            lock_generation(&mut tx, generation, Lock::Share).await?;
            let snapshot = snapshot_in(&mut tx, true).await?;
            Ok(PolicyWrite {
                tx,
                timeout: self.timeout,
                snapshot,
            })
        })
        .await
    }
}

impl PolicyWrite {
    /// Applies `changes` and commits. A timeout here leaves the outcome
    /// unknown, as for any write.
    pub async fn commit(self, changes: PolicyChanges) -> Result<()> {
        let Self {
            mut tx, timeout, ..
        } = self;
        bounded(timeout, async move {
            if let Some(wrapped) = &changes.new_wrapped_key {
                sqlx::query!("UPDATE seal_config SET wrapped_policy_key = $1", wrapped)
                    .execute(&mut *tx)
                    .await?;
            }
            if !changes.delete.is_empty() {
                sqlx::query!(
                    "DELETE FROM policies WHERE name = ANY($1)",
                    &changes.delete[..]
                )
                .execute(&mut *tx)
                .await?;
            }
            for policy in &changes.upsert {
                sqlx::query!(
                    "INSERT INTO policies
                         (name, identity, actions, paths, all_paths, description, version, mac)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                     ON CONFLICT (name) DO UPDATE SET
                         identity = EXCLUDED.identity, actions = EXCLUDED.actions,
                         paths = EXCLUDED.paths, all_paths = EXCLUDED.all_paths,
                         description = EXCLUDED.description, version = EXCLUDED.version,
                         mac = EXCLUDED.mac, updated_at = now()",
                    policy.name,
                    policy.identity,
                    &policy.actions[..],
                    &policy.paths[..],
                    policy.all_paths,
                    policy.description,
                    to_db("version", policy.version)?,
                    policy.mac,
                )
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query!(
                "UPDATE policy_state SET revision = $1, mac = $2, updated_at = now()",
                revision_to_db(changes.revision)?,
                changes.mac,
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        })
        .await
    }
}
