//! Keeping a server's keyring current without resealing: another server
//! may rotate the KEK (or a rewrap retire one), and this server then can't
//! read secrets wrapped by the new KEK and keeps wrapping new DEKs with its
//! old active one. [`refresh`] reloads the KEKs with the root key this
//! server holds ([`Seal::refresh`]); no shares needed.
//!
//! Triggered three ways: on demand, when a read meets a KEK version this
//! server doesn't have (it refreshes, then retries once; reads queued
//! behind a refresh that already fetched the version return without
//! reloading, and reads trigger at most one refresh per
//! [`ON_DEMAND_COOLDOWN`], so a row naming a KEK that truly doesn't exist
//! can't make every read reload the keyring; the cooldown starts once a
//! refresh finishes, so reads of such a row arriving together may each
//! reload once, which is accepted: starting it earlier would fail genuine
//! reads while the first refresh still runs); periodically
//! (`keyring_refresh_secs`, from `main`); and on SIGHUP, in its own task
//! so the policy reload never waits behind it (the admin lock, a slow keys
//! database).
//!
//! What it can't follow is a rekey elsewhere: the root key itself changed,
//! so this server has to be sealed and unsealed with the new shares
//! ([`SealError::RekeyedElsewhere`]).
//!
//! After every unseal, [`check_against_data`] also checks the other way:
//! that every KEK version a row in the data database uses is in the
//! keyring, since databases restored from backups that don't match leave
//! rows nothing can open (see docs/src/content/docs/operations/backup-restore.md).
//!
//! Every change and failure is logged, audited (`"event":
//! "keyring_refresh"`) and counted (`ferritor.reloads`, kind `keyring`); a
//! refresh that found nothing new is only counted, and one that returned
//! early, finding the wanted version already loaded, not even that. A
//! sealed server has no keyring to refresh: that's not reported at all.

use std::time::Duration;

use ferritor_core::path::Namespace;
use ferritor_datastore::{Datastore, DatastoreError};
use ferritor_keystore::{KekState, NamespaceState};

use crate::audit::Gate;
use crate::metrics::metrics;
use crate::seal::{Refreshed, Seal, SealError};

/// How soon after a completed refresh a read may trigger another. The
/// periodic refresh still catches up whatever this delays.
pub const ON_DEMAND_COOLDOWN: Duration = Duration::from_secs(5);

/// Refreshes `seal`'s keyring, reporting as described above; `trigger`
/// names what asked (`unknown_kek`, `periodic`, `sighup`), `wanted` the KEK
/// version a read needs (see [`Seal::refresh`]). With `audit_failure` false
/// a failure is still logged and counted, but not audited (the periodic
/// refresh audits only the first of a run of failures).
pub async fn refresh(
    seal: &Seal,
    gate: &Gate,
    trigger: &'static str,
    wanted: Option<(&Namespace, u32)>,
    audit_failure: bool,
) -> Result<Refreshed, SealError> {
    let result = seal.refresh(wanted).await;
    match &result {
        Ok(refreshed) if refreshed.changed => {
            if refreshed.vanished.is_empty() {
                tracing::info!(
                    trigger,
                    active = ?refreshed.active,
                    "refreshed the keyring: KEKs changed elsewhere"
                );
            } else {
                tracing::error!(
                    trigger,
                    active = ?refreshed.active,
                    vanished = ?refreshed.vanished,
                    "THE KEYS DATABASE WENT BACK IN TIME: it no longer has KEKs this server \
                     holds (and didn't destroy them), or a whole namespace. This server's copy \
                     is the last one: kept for reading only, new data keys are wrapped with \
                     the namespace's stored active version. Run `ferritor rewrap` against THIS \
                     server, before it's sealed or restarted, to move the rows those KEKs \
                     wrapped onto a stored one; a namespace lost entirely needs the keys \
                     database that has it restored (see https://ferritor.dev/operations/high-availability)"
                );
            }
            metrics().reload("keyring", "changed");
            gate.keyring_refreshed(trigger, Ok(refreshed));
        }
        Ok(refreshed) if refreshed.loaded => metrics().reload("keyring", "unchanged"),
        // Another refresh already loaded what was wanted: nothing to count.
        Ok(_) => {}
        Err(SealError::Sealed) => {}
        Err(e) => {
            let error = crate::error_chain(e);
            tracing::warn!(trigger, %error, "keyring refresh failed");
            metrics().reload("keyring", "failed");
            if audit_failure {
                gate.keyring_refreshed(trigger, Err(error));
            }
        }
    }
    result
}

/// KEKs that rows in the data database use but this server's keyring
/// lacks, found by [`check_against_data`], per namespace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unloaded {
    /// Rows under a namespace the keys database doesn't have at all: most
    /// likely a keys-database backup older than the data database's (or a
    /// failover that lost the namespace's creation).
    pub lost_namespaces: Vec<Namespace>,
    /// Rows under a deleted namespace: a data-database backup from before
    /// the delete, unreadable by design.
    pub deleted_namespaces: Vec<Namespace>,
    /// Within a namespace, a version the keys database doesn't have: an
    /// older keys-database backup (taken before a rotation).
    pub missing: Vec<(Namespace, u32)>,
    /// Within a namespace, a destroyed version (`destroy-kek`): a
    /// data-database backup from before the rewrap, unreadable for good, as
    /// a destroy intends.
    pub destroyed: Vec<(Namespace, u32)>,
}

#[derive(Debug, thiserror::Error)]
pub enum KekCheckError {
    #[error("the keys database or the keyring")]
    Keys(#[source] SealError),
    #[error("the data database")]
    Data(#[source] DatastoreError),
}

/// What the data database's rows need that the keyring lacks: each
/// (namespace, KEK version) some row uses (one index probe per pair)
/// checked against the keyring, and any it lacks against the keys database.
/// A KEK stored there but not loaded (created or rotated in by another
/// server since this one loaded its keyring) isn't reported: the next
/// refresh loads it.
pub async fn unloaded(seal: &Seal, store: &Datastore) -> Result<Unloaded, KekCheckError> {
    let used = store
        .kek_versions_in_use()
        .await
        .map_err(KekCheckError::Data)?;
    let absent: Vec<(Namespace, u32)> = {
        let keyring = seal.keyring().map_err(KekCheckError::Keys)?;
        used.into_iter()
            .filter(|(ns, version)| keyring.kek(ns, *version).is_none())
            .collect()
    };
    if absent.is_empty() {
        return Ok(Unloaded::default());
    }
    let catalog = seal
        .stored_namespaces()
        .await
        .map_err(KekCheckError::Keys)?;
    let states = seal.kek_states().await.map_err(KekCheckError::Keys)?;
    let mut unloaded = Unloaded::default();
    for (ns, version) in absent {
        match catalog.iter().find(|n| n.name == ns).map(|n| n.state) {
            None => {
                if !unloaded.lost_namespaces.contains(&ns) {
                    unloaded.lost_namespaces.push(ns);
                }
            }
            Some(NamespaceState::Deleted) => {
                if !unloaded.deleted_namespaces.contains(&ns) {
                    unloaded.deleted_namespaces.push(ns);
                }
            }
            Some(NamespaceState::Active) => {
                match states
                    .iter()
                    .find(|k| k.namespace == ns && k.version == version)
                    .map(|k| k.state)
                {
                    Some(KekState::Destroyed) => unloaded.destroyed.push((ns, version)),
                    Some(_) => {}
                    None => unloaded.missing.push((ns, version)),
                }
            }
        }
    }
    Ok(unloaded)
}

/// Run after every unseal (in the background: the reply doesn't wait): the
/// check for databases restored from backups that don't match. Rows that
/// use a KEK this server can't load are unreadable, and with no other copy
/// of the keys database, for good, so it's logged loudly and audited
/// (`"event": "kek_check"`); nothing at all when everything matches. A
/// failure to check is only logged.
pub async fn check_against_data(seal: &Seal, gate: &Gate, store: &Datastore) {
    match unloaded(seal, store).await {
        Ok(found) if found == Unloaded::default() => {}
        Ok(found) => {
            if !found.missing.is_empty() || !found.lost_namespaces.is_empty() {
                tracing::error!(
                    missing = ?found.missing,
                    lost_namespaces = ?found.lost_namespaces,
                    "ROWS USE KEKS THE KEYS DATABASE DOESN'T HAVE: they can't be read. Was the \
                     keys database restored from a backup older than the data database's? \
                     Restore a newer keys-database backup (KEKs are only removed by \
                     destroy-kek or a namespace delete), then seal and unseal; don't rotate, \
                     init or create those namespaces until then (all are refused meanwhile)"
                );
            }
            if !found.destroyed.is_empty() || !found.deleted_namespaces.is_empty() {
                tracing::warn!(
                    destroyed = ?found.destroyed,
                    deleted_namespaces = ?found.deleted_namespaces,
                    "rows use destroyed KEKs or deleted namespaces: they can't be read, for good \
                     (a data-database backup from before they were rewrapped and destroyed, or \
                     the namespace deleted?)"
                );
            }
            gate.kek_check(&found);
        }
        // Sealed again meanwhile: the next unseal checks.
        Err(KekCheckError::Keys(SealError::Sealed)) => {}
        Err(e) => {
            tracing::warn!(
                error = %crate::error_chain(&e),
                "couldn't check the data database's KEK versions against the keyring"
            );
        }
    }
}

/// Why a rotate, init or namespace creation was refused: the keys database
/// doesn't match the data database, and going ahead would make that
/// permanent.
#[derive(Debug, thiserror::Error)]
pub enum MismatchError {
    /// A namespace's rows use a KEK version above the keys database's
    /// highest for it: restored from a backup older than the data
    /// database's. A rotation now would create a different key under a
    /// version rows already use, and no keys database could ever open both
    /// sets.
    #[error(
        "rows of namespace `{namespace}` use KEK version {data}, but the keys database only goes \
         up to {keys} for it: it was restored from a backup older than the data database's. \
         Restore a newer keys-database backup, then seal and unseal; rotating now would reuse \
         version {next} for a different key and lose those rows for good",
        next = keys + 1
    )]
    KeysBehind {
        namespace: Namespace,
        data: u32,
        keys: u32,
    },
    /// An init with rows in the data database: their KEKs were in a keys
    /// database that's gone.
    #[error(
        "the data database holds secrets from an earlier keys database; restore that keys \
         database, or empty the data database to start over"
    )]
    DataWithoutKeys,
    /// Creating a namespace the data database already has rows under: the
    /// keys database lost it (or an older backup was restored), and its
    /// new KEK would collide with the rows' own versions.
    #[error(
        "the data database already holds {rows} rows under namespace `{namespace}`, from a keys \
         database that had it: restore that keys database rather than creating the namespace \
         anew. If no backup has it (a failover lost its creation), create it with \
         --past-lost-keks, then rewrap against a server still holding its KEKs"
    )]
    RowsWithoutNamespace { namespace: Namespace, rows: u64 },
    #[error("the keys database")]
    Keys(#[source] SealError),
    #[error("the data database")]
    Data(#[source] DatastoreError),
}

/// Refuses a rotation of `namespace` while its rows use a KEK version the
/// keys database doesn't have for it (what [`check_against_data`] reports
/// as missing after an unseal). A namespace's versions are contiguous from
/// 1, destroyed ones keeping their row (a recovery past lost KEKs only
/// skips ahead, above every version rows use), so comparing the highest of
/// each is enough: one index probe each. No false positives: every writer wraps
/// with a version the keys database has, and purged rows leave none behind.
/// A row can't gain a higher version between this check and the rotation,
/// for the same reason.
pub async fn ensure_keys_not_behind(
    seal: &Seal,
    store: &Datastore,
    namespace: &Namespace,
) -> Result<(), MismatchError> {
    let data = store
        .max_kek_version(namespace)
        .await
        .map_err(MismatchError::Data)?;
    let keys = seal
        .kek_states()
        .await
        .map_err(MismatchError::Keys)?
        .into_iter()
        .filter(|k| &k.namespace == namespace)
        .map(|k| k.version)
        .max()
        .unwrap_or(0);
    match data {
        Some(data) if data > keys => Err(MismatchError::KeysBehind {
            namespace: namespace.clone(),
            data,
            keys,
        }),
        _ => Ok(()),
    }
}

/// Refuses creating `namespace` while the data database has rows under it
/// (see [`MismatchError::RowsWithoutNamespace`]).
pub async fn ensure_namespace_free(
    store: &Datastore,
    namespace: &Namespace,
) -> Result<(), MismatchError> {
    let (rows, _) = store
        .namespace_rows(namespace)
        .await
        .map_err(MismatchError::Data)?;
    if rows > 0 {
        return Err(MismatchError::RowsWithoutNamespace {
            namespace: namespace.clone(),
            rows,
        });
    }
    Ok(())
}

/// Refuses an init while the data database holds rows: an empty keys
/// database next to stored secrets means the keys database was lost. Only
/// for an uninitialized keys database: an initialized one refuses the init
/// anyway, with its own message.
pub async fn ensure_no_orphaned_rows(seal: &Seal, store: &Datastore) -> Result<(), MismatchError> {
    if seal
        .status()
        .await
        .map_err(MismatchError::Keys)?
        .initialized
    {
        return Ok(());
    }
    if store.any_secrets().await.map_err(MismatchError::Data)? {
        return Err(MismatchError::DataWithoutKeys);
    }
    Ok(())
}
