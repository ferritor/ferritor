//! Destroying a retired KEK: erasing its wrapped key for good, so nothing
//! wrapped by it can be decrypted any more, from this database or any
//! backup of the data database (crypto-shredding).
//!
//! Retiring ([`crate::rewrap`]) is bookkeeping: the KEK stays stored and
//! loaded, because a server whose keyring is stale (it hasn't reloaded since
//! another server rotated) keeps wrapping new DEKs with its old active KEK,
//! and a row written so after the retirement must stay readable. No timing
//! rule can rule such a write out (a paused process, an older binary during
//! a rolling deploy), so the data database does: its KEK floor
//! ([`Datastore::raise_kek_floor`]) refuses any write of a DEK wrapped by a
//! KEK below it, from any server, enforced by a trigger. Destroying version
//! v ([`Destroy::run`]):
//!
//! 1. v must be retired: rewrap moved every row off it, and no row used it.
//! 2. Raise the floor past v. It waits for the writes in flight; once it
//!    returns, no write can add a row wrapped by v. Meanwhile new writes
//!    queue behind it, so every write pauses briefly (at most
//!    `lock_timeout_ms`; a put that waits out its own lock timeout gets
//!    `Busy`, and retries).
//! 3. Check again that no row uses v (deleted rows included). One written
//!    by a stale server between the retirement and the floor makes this
//!    refuse ([`DestroyError::InUse`]): run rewrap, which moves it, and
//!    destroy again.
//! 4. Erase it in the keys database (the row stays, `destroyed`, so the
//!    version number is never reused) and drop it from this server's
//!    keyring; other servers drop it at their next refresh. Until then they
//!    hold it in memory, unused: the floor refuses it.
//!
//! A stale server that then puts a secret has its write refused by the
//! floor; it refreshes its keyring and retries once (`secrets`; at most one
//! refresh per cooldown, shared with reads, so a server that can't refresh
//! doesn't send every put to the keys database).
//!
//! Safe to retry: an already destroyed version is reported as such, not as
//! an error, and a floor raised by a call that failed later stays raised
//! (harmless: it only refuses KEKs older than the active one).
//!
//! What "erased" means to Postgres: the old row version stays in the keys
//! database's table file until vacuumed, and in WAL (full-page images) and
//! its archives, and backups of the keys database, until they age out.
//! Until then, whoever has those and a threshold of shares from that time
//! can still recover the KEK. Nothing inside Postgres can do better: a plain
//! `VACUUM` frees the space without promising to overwrite it. As a best
//! effort after a destroy, `VACUUM FULL keks` rewrites the table into a new
//! file (instant: the table is tiny), though the old file is only unlinked,
//! not shredded, and the WAL archives and backups still hold the key.
//!
//! Finish a rollout before destroying. An older binary can't start once a
//! newer server has migrated (sqlx refuses a database with migrations it
//! doesn't know), so only old servers already running are exposed, and only
//! after the first destroy: their keyring refresh fails on the erased key
//! (logged and audited), and their puts are refused by the floor. Such a
//! straggler stops writing until it's upgraded; nothing is lost, and nothing
//! is written with a destroyed KEK.

use std::sync::Arc;

use ferritor_core::messages::SEALED;
use ferritor_core::path::Namespace;
use ferritor_datastore::{Datastore, DatastoreError};
use ferritor_keystore::KekState;

use crate::seal::{Seal, SealError};

#[derive(Debug, thiserror::Error)]
pub enum DestroyError {
    #[error("{}", SEALED)]
    Sealed,
    #[error("namespace `{namespace}` has no KEK version {version}")]
    UnknownVersion { namespace: Namespace, version: u32 },
    #[error("{}", not_retired(namespace, *version, *state))]
    NotRetired {
        namespace: Namespace,
        version: u32,
        state: KekState,
    },
    #[error(
        "rows of namespace `{namespace}` still use its KEK version {version} (written by a \
         server with an out-of-date keyring after it was retired): run rewrap until it's done, \
         then destroy again"
    )]
    InUse { namespace: Namespace, version: u32 },
    #[error("timed out waiting for writes in flight before raising the KEK floor; retry")]
    Busy,
    #[error("the data database did not respond in time")]
    DataTimeout,
    #[error("data store failure")]
    Store(#[source] DatastoreError),
    #[error(transparent)]
    Keys(SealError),
}

fn not_retired(namespace: &Namespace, version: u32, state: KekState) -> String {
    match state {
        KekState::Active => format!(
            "KEK version {version} is namespace `{namespace}`'s active one: rotate, then rewrap \
             until it's retired"
        ),
        state => format!(
            "KEK version {version} of namespace `{namespace}` is {state}, not retired: rewrap \
             until it's retired (rows still use it)"
        ),
    }
}

impl From<DatastoreError> for DestroyError {
    fn from(e: DatastoreError) -> Self {
        match e {
            DatastoreError::Timeout => Self::DataTimeout,
            DatastoreError::KekFloorBusy => Self::Busy,
            other => Self::Store(other),
        }
    }
}

impl From<SealError> for DestroyError {
    fn from(e: SealError) -> Self {
        match e {
            SealError::Sealed => Self::Sealed,
            other => Self::Keys(other),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destroyed {
    pub namespace: Namespace,
    pub version: u32,
    /// `false` if it was already destroyed (an earlier call whose answer
    /// was lost, say).
    pub destroyed: bool,
    /// The namespace's KEK floor now: no write may use a KEK version of it
    /// below that.
    pub kek_floor: u32,
}

pub struct Destroy {
    seal: Arc<Seal>,
    store: Datastore,
}

impl Destroy {
    pub fn new(seal: Arc<Seal>, store: Datastore) -> Self {
        Self { seal, store }
    }

    /// Destroys retired KEK `version` of `namespace`, as described in the
    /// module docs (everything per namespace: its states, its floor, its
    /// rows).
    /// Needs the server unsealed; a seal at any point stops it before the
    /// keys database is touched (or, if it lands during that write, before
    /// this server's keyring is updated).
    pub async fn run(
        &self,
        namespace: &Namespace,
        version: u32,
    ) -> Result<Destroyed, DestroyError> {
        let epoch = self.seal.unsealed_epoch()?;
        let states: Vec<_> = self
            .seal
            .kek_states()
            .await?
            .into_iter()
            .filter(|k| &k.namespace == namespace)
            .collect();
        let state = states
            .iter()
            .find(|k| k.version == version)
            .map(|k| k.state)
            .ok_or_else(|| DestroyError::UnknownVersion {
                namespace: namespace.clone(),
                version,
            })?;
        match state {
            KekState::Retired => {}
            KekState::Destroyed => {
                return Ok(Destroyed {
                    namespace: namespace.clone(),
                    version,
                    destroyed: false,
                    kek_floor: self.store.kek_floor(namespace).await?,
                });
            }
            state => {
                return Err(DestroyError::NotRetired {
                    namespace: namespace.clone(),
                    version,
                    state,
                });
            }
        }
        // A retired version was superseded, so the namespace's active one is
        // newer and the floor stays at or below it: it never refuses the
        // active KEK.
        let above = version
            .checked_add(1)
            .filter(|above| {
                states
                    .iter()
                    .any(|k| k.state == KekState::Active && k.version >= *above)
            })
            .ok_or(SealError::Corrupt(
                "a retired KEK is not older than its namespace's active one",
            ))?;
        self.seal.ensure_unsealed_since(epoch)?;
        let kek_floor = self.store.raise_kek_floor(namespace, above).await?;
        // After the raise: every row wrapped by `version` is visible now,
        // and none can be added.
        if self.store.any_wrapped_by(namespace, version).await? {
            return Err(DestroyError::InUse {
                namespace: namespace.clone(),
                version,
            });
        }
        self.seal.ensure_unsealed_since(epoch)?;
        let destroyed = self.seal.destroy_kek(namespace, version).await?;
        Ok(Destroyed {
            namespace: namespace.clone(),
            version,
            destroyed,
            kek_floor,
        })
    }
}
