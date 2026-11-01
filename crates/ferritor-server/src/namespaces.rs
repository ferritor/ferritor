//! Namespaces: every secret belongs to the namespace named by its path's
//! first segment, and each namespace has its own KEKs (numbered from 1),
//! rotated, rewrapped and destroyed on its own. There's no default
//! namespace: nothing can be stored under a first segment that isn't one.
//!
//! The operations here span both databases (namespaces and their KEKs live
//! in the keys database, rows and floors in the data database), so they
//! live here rather than in `Seal`:
//!
//! - **Create**: refused while the data database already has rows under the
//!   name (a keys database that lost the namespace, or an older backup: its
//!   new KEK would collide with the rows' own versions). A deleted name can
//!   be created again; its numbering continues past its old versions.
//! - **Delete**, only when empty: no row at all under it, deleted rows
//!   included, so in practice delete every secret, wait out the retention
//!   (`purge_deleted_after_days`), purge, then delete. It destroys every KEK
//!   of the namespace, crypto-shredding every data-database backup of it,
//!   so it needs `destroy_kek` as well as `namespace` (checked in `grpc`).
//!   Like destroy-kek: raise the namespace's floor past its highest version
//!   (stale servers can't write there any more), check again that it has
//!   no rows and reclaim its `paths` rows (`Datastore::reclaim_paths`, one
//!   transaction under the floor lock, their highest version kept in the
//!   data database's namespace row), then destroy its KEKs and mark it
//!   deleted. The row and its destroyed KEK rows stay: a re-created
//!   namespace continues the numbering, so its first KEK lands exactly on
//!   the floor this raised, never below it, and never reuses a number for
//!   a different key; its paths number their versions on past the kept
//!   highest, so a version number never comes round again either.
//! - **Recovery** (`create_past_lost_keks`): the one way past the create
//!   guard, for a namespace the keys database lost (a failover that lost
//!   its creation, with no backup that has it) while rows under it remain,
//!   readable only on servers still holding its KEKs as vanished. It needs
//!   no live namespace by the name and rows under it. Its first KEK goes
//!   one past every version the rows use, the floor, the keys database's
//!   own numbering and what this server holds, so no number goes to a
//!   second key; and the floor is raised to it first, so a server still
//!   writing with a lost KEK is refused from then on. Rewrap against a
//!   holder then has a target: it moves the rows, and the KEK check after
//!   unseal reports the lost versions until no row uses them. Plain create
//!   keeps refusing: after a mismatched restore, restoring the right keys
//!   backup is the better fix, so skipping ahead must be a deliberate
//!   choice.
//! - **Labels**: plain metadata, as for paths (`ferritor_core::labels`).

use std::collections::BTreeMap;
use std::sync::Arc;

use ferritor_core::labels::{self, LabelError, Labels};
use ferritor_core::messages::SEALED;
use ferritor_core::path::{self, Namespace};
use ferritor_datastore::{Datastore, DatastoreError, Reclaimed};
use ferritor_keystore::{DeletedNamespace, KekState, KeystoreError, NamespaceState};
use time::OffsetDateTime;

use crate::keyring::{self, MismatchError};
use crate::seal::{Seal, SealError};

#[derive(Debug, thiserror::Error)]
pub enum NamespaceError {
    #[error("{}", SEALED)]
    Sealed,
    #[error("invalid namespace name")]
    InvalidName(#[source] path::NamespaceError),
    #[error("invalid labels")]
    InvalidLabels(#[source] LabelError),
    #[error("there is no namespace `{0}`")]
    NotFound(Namespace),
    #[error("namespace `{0}` already exists")]
    Exists(Namespace),
    #[error(
        "namespace `{namespace}` isn't empty: {rows} rows, of which {deleted} deleted. Delete \
         its secrets, and purge the deleted ones once past the retention \
         (purge_deleted_after_days), then delete the namespace"
    )]
    NotEmpty {
        namespace: Namespace,
        rows: u64,
        deleted: u64,
    },
    #[error(
        "the data database has no rows under namespace `{0}`: nothing was lost, so create it \
         without --past-lost-keks"
    )]
    NothingLost(Namespace),
    #[error(
        "a server still writes namespace `{namespace}` with a lost KEK (version {version}): \
         make every server refresh its keyring (SIGHUP), then retry"
    )]
    StillWritten { namespace: Namespace, version: u32 },
    #[error(transparent)]
    Mismatch(MismatchError),
    #[error("timed out waiting for writes in flight before raising the KEK floor; retry")]
    Busy,
    #[error("the data database did not respond in time")]
    DataTimeout,
    #[error("data store failure")]
    Store(#[source] DatastoreError),
    #[error(transparent)]
    Keys(SealError),
}

impl From<DatastoreError> for NamespaceError {
    fn from(e: DatastoreError) -> Self {
        match e {
            DatastoreError::Timeout => Self::DataTimeout,
            DatastoreError::KekFloorBusy => Self::Busy,
            other => Self::Store(other),
        }
    }
}

impl From<SealError> for NamespaceError {
    fn from(e: SealError) -> Self {
        match e {
            SealError::Sealed => Self::Sealed,
            SealError::Keystore(KeystoreError::NamespaceExists(ns)) => Self::Exists(ns),
            // Another creation took the version first: it exists now.
            SealError::Keystore(KeystoreError::CreateConflict { namespace, .. }) => {
                Self::Exists(namespace)
            }
            SealError::Keystore(KeystoreError::NoNamespace(ns)) => Self::NotFound(ns),
            SealError::Keystore(KeystoreError::TooManyLabels { count }) => {
                Self::InvalidLabels(LabelError::TooMany { count })
            }
            other => Self::Keys(other),
        }
    }
}

impl From<MismatchError> for NamespaceError {
    fn from(e: MismatchError) -> Self {
        match e {
            MismatchError::Keys(seal) => seal.into(),
            MismatchError::Data(data) => data.into(),
            other => Self::Mismatch(other),
        }
    }
}

/// A namespace as `GetNamespace` and `ListNamespaces` report it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceInfo {
    pub name: Namespace,
    pub state: NamespaceState,
    pub created_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub labels: Labels,
    pub labels_updated_at: Option<OffsetDateTime>,
    /// Its KEKs and their states, by version.
    pub keks: Vec<(u32, KekState)>,
    /// Its KEK floor in the data database.
    pub kek_floor: u32,
    /// KEK versions of it that the keys database lost and *this server*
    /// still holds, for reading only (see `seal::Keyring`).
    pub vanished_here: Vec<u32>,
}

/// What deleting a namespace did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deleted {
    pub namespace: Namespace,
    /// `false` if it was already deleted.
    pub deleted: bool,
    /// KEK versions destroyed by this call.
    pub destroyed: Vec<u32>,
    /// Its KEK floor now.
    pub kek_floor: u32,
    /// `paths` rows reclaimed by this call (every path it ever had).
    pub paths_reclaimed: u64,
}

pub struct Namespaces {
    seal: Arc<Seal>,
    store: Datastore,
}

fn parse(name: &str) -> Result<Namespace, NamespaceError> {
    Namespace::parse(name).map_err(NamespaceError::InvalidName)
}

impl Namespaces {
    pub fn new(seal: Arc<Seal>, store: Datastore) -> Self {
        Self { seal, store }
    }

    /// Creates `name` (or re-creates a deleted one) with `labels`; returns
    /// it and its first KEK's version. Needs the server unsealed.
    pub async fn create(
        &self,
        name: &str,
        labels: &Labels,
    ) -> Result<(Namespace, u32), NamespaceError> {
        let namespace = parse(name)?;
        labels::check(labels).map_err(NamespaceError::InvalidLabels)?;
        let epoch = self.seal.unsealed_epoch()?;
        // A live namespace has rows of its own: say it exists, not that the
        // keys database lost it. (The keys database checks again when it
        // stores the namespace.)
        if self.is_live(&namespace).await? {
            return Err(NamespaceError::Exists(namespace));
        }
        keyring::ensure_namespace_free(&self.store, &namespace).await?;
        self.seal.ensure_unsealed_since(epoch)?;
        let version = self.seal.create_namespace(&namespace, labels).await?;
        Ok((namespace, version))
    }

    /// Recreates `name` after the keys database lost it, past every KEK
    /// version still in use (see the module docs); returns it and its first
    /// KEK's version. Run it against a server holding the lost KEKs, after
    /// every server has refreshed. Needs the server unsealed.
    pub async fn create_past_lost_keks(
        &self,
        name: &str,
        labels: &Labels,
    ) -> Result<(Namespace, u32), NamespaceError> {
        let namespace = parse(name)?;
        labels::check(labels).map_err(NamespaceError::InvalidLabels)?;
        let epoch = self.seal.unsealed_epoch()?;
        if self.is_live(&namespace).await? {
            return Err(NamespaceError::Exists(namespace));
        }
        let (rows, _) = self.store.namespace_rows(&namespace).await?;
        if rows == 0 {
            return Err(NamespaceError::NothingLost(namespace));
        }
        let past_rows = |highest: Option<u32>| {
            highest
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(SealError::VersionExhausted)
        };
        let floor = self.store.kek_floor(&namespace).await?;
        let at_least = past_rows(self.store.max_kek_version(&namespace).await?)?.max(floor);
        // Fence off everything below it: a server still writing with a lost
        // KEK is refused from now on (it refreshes, and finds the new one).
        // Writes there pause meanwhile, as for a destroy; there are none
        // without an active KEK but such a server's.
        self.seal.ensure_unsealed_since(epoch)?;
        let floor = self.store.raise_kek_floor(&namespace, at_least).await?;
        // After the raise, every row written before it is visible.
        if let Some(highest) = self.store.max_kek_version(&namespace).await?
            && highest >= at_least
        {
            return Err(NamespaceError::StillWritten {
                namespace,
                version: highest,
            });
        }
        self.seal.ensure_unsealed_since(epoch)?;
        let version = self
            .seal
            .recreate_lost_namespace(&namespace, labels, floor)
            .await?;
        Ok((namespace, version))
    }

    async fn is_live(&self, namespace: &Namespace) -> Result<bool, NamespaceError> {
        Ok(self
            .seal
            .stored_namespaces()
            .await?
            .into_iter()
            .any(|n| &n.name == namespace && n.state == NamespaceState::Active))
    }

    /// Deletes `name`, only when empty, as described in the module docs.
    /// Already deleted: `deleted` false. Needs the server unsealed.
    pub async fn delete(&self, name: &str) -> Result<Deleted, NamespaceError> {
        let namespace = parse(name)?;
        let epoch = self.seal.unsealed_epoch()?;
        let stored = self
            .seal
            .stored_namespaces()
            .await?
            .into_iter()
            .find(|n| n.name == namespace)
            .ok_or_else(|| NamespaceError::NotFound(namespace.clone()))?;
        if stored.state == NamespaceState::Deleted {
            return Ok(Deleted {
                kek_floor: self.store.kek_floor(&namespace).await?,
                namespace,
                deleted: false,
                destroyed: Vec::new(),
                paths_reclaimed: 0,
            });
        }
        self.ensure_empty(&namespace).await?;
        let highest = self
            .seal
            .kek_states()
            .await?
            .into_iter()
            .filter(|k| k.namespace == namespace)
            .map(|k| k.version)
            .max()
            .unwrap_or(0);
        let above = highest.checked_add(1).ok_or(SealError::VersionExhausted)?;
        self.seal.ensure_unsealed_since(epoch)?;
        let kek_floor = self.store.raise_kek_floor(&namespace, above).await?;
        // After the raise: every row a stale server wrote is visible now,
        // and none can be added. Empty again, checked under its floor lock:
        // its `paths` rows go too, their highest version kept for a
        // re-created namespace to number on from (never reused).
        let paths_reclaimed = match self.store.reclaim_paths(&namespace).await? {
            Reclaimed::Paths(n) => n,
            Reclaimed::NotEmpty { rows, deleted } => {
                return Err(NamespaceError::NotEmpty {
                    namespace,
                    rows,
                    deleted,
                });
            }
        };
        self.seal.ensure_unsealed_since(epoch)?;
        let DeletedNamespace {
            destroyed, deleted, ..
        } = self.seal.delete_namespace(&namespace).await?;
        Ok(Deleted {
            namespace,
            deleted,
            destroyed,
            kek_floor,
            paths_reclaimed,
        })
    }

    async fn ensure_empty(&self, namespace: &Namespace) -> Result<(), NamespaceError> {
        let (rows, deleted) = self.store.namespace_rows(namespace).await?;
        if rows > 0 {
            return Err(NamespaceError::NotEmpty {
                namespace: namespace.clone(),
                rows,
                deleted,
            });
        }
        Ok(())
    }

    /// One namespace, live or deleted.
    pub async fn get(&self, name: &str) -> Result<NamespaceInfo, NamespaceError> {
        let namespace = parse(name)?;
        self.list()
            .await?
            .into_iter()
            .find(|info| info.name == namespace)
            .ok_or(NamespaceError::NotFound(namespace))
    }

    /// Every namespace, live and deleted, by name. Reads the keys database
    /// (no key material), so it works sealed too, as status does.
    pub async fn list(&self) -> Result<Vec<NamespaceInfo>, NamespaceError> {
        let stored = self.seal.stored_namespaces().await?;
        let keks = self.seal.kek_states().await?;
        let floors: BTreeMap<Namespace, u32> = self.store.kek_floors().await?.into_iter().collect();
        let keyring = self.seal.keyring().ok();
        let mut infos = Vec::with_capacity(stored.len());
        for ns in stored {
            infos.push(NamespaceInfo {
                keks: keks
                    .iter()
                    .filter(|k| k.namespace == ns.name)
                    .map(|k| (k.version, k.state))
                    .collect(),
                kek_floor: floors.get(&ns.name).copied().unwrap_or(1),
                vanished_here: keyring
                    .as_ref()
                    .map(|keyring| keyring.vanished(&ns.name))
                    .unwrap_or_default(),
                name: ns.name,
                state: ns.state,
                created_at: ns.created_at,
                deleted_at: ns.deleted_at,
                labels: ns.labels,
                labels_updated_at: ns.labels_updated_at,
            });
        }
        Ok(infos)
    }

    /// Changes a live namespace's labels (`set` added or replaced, `remove`
    /// removed; at least one) and returns them.
    pub async fn update_labels(
        &self,
        name: &str,
        set: &Labels,
        remove: &[String],
    ) -> Result<Labels, NamespaceError> {
        let namespace = parse(name)?;
        labels::check_change(set, remove).map_err(NamespaceError::InvalidLabels)?;
        Ok(self
            .seal
            .update_namespace_labels(&namespace, set, remove)
            .await?)
    }
}
