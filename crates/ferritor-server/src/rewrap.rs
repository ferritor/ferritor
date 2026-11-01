//! Rewrap: after a rotation, move DEKs still wrapped by older KEK versions
//! to the active one, then retire the KEK versions no row uses any more.
//!
//! Operator-driven and bounded: one [`Rewrap::run`] processes at most
//! `max_rows` rows and reports whether it's done; callers repeat it until
//! then. So no single call outlives a request timeout, and an interrupted run
//! simply resumes.
//!
//! Like secret operations, a pass records the seal epoch when it starts and
//! takes the keyring only for each batch's crypto ([`Seal::keyring_at`]),
//! never across an await: a seal stops it.
//!
//! Rows are moved compare-and-set ([`Datastore::rewrap`]), so concurrent
//! passes (or servers) don't trample each other. Deleted rows are moved too:
//! their DEKs would block retiring otherwise. A row whose DEK doesn't unwrap
//! (corruption or tampering) is left as it is, logged and counted.
//!
//! A version is retired only when no row at all uses it any more, checked
//! per version once a pass has drained everything: that includes rows that
//! failed to unwrap, so a bad row blocks retiring its own version, not
//! others.
//!
//! Retiring is bookkeeping only: a retired KEK stays stored and loaded. That
//! matters because a server whose keyring is stale (it hasn't resealed since
//! another server rotated) keeps wrapping new DEKs with its old active KEK,
//! possibly one retired meanwhile. Those rows stay readable and the next pass
//! moves them. Destroying a retired KEK is a separate, deliberate step
//! (`destroy`), made safe by the data database's KEK floor rather than by
//! hoping no stale server remains.

use std::sync::Arc;

use ferritor_core::messages::SEALED;
use ferritor_core::path::Namespace;
use ferritor_datastore::{Datastore, DatastoreError, Rewrapped, RowKey};

use crate::seal::{Seal, SealError};

/// Rows per database round trip.
const BATCH: u32 = 500;
/// Used when a caller asks for 0.
pub const DEFAULT_MAX_ROWS: u32 = 5_000;
/// Keeps one call well inside a request timeout.
pub const MAX_ROWS: u32 = 50_000;

#[derive(Debug, thiserror::Error)]
pub enum RewrapError {
    #[error("{}", SEALED)]
    Sealed,
    #[error("the data database did not respond in time")]
    DataTimeout,
    /// The active KEK of this server's keyring is below the KEK floor:
    /// another server rotated and is destroying it. This server's keyring
    /// refreshes on its own (or on SIGHUP); retry then.
    #[error(
        "KEK version {0}, this server's active one, is being destroyed: its keyring is out \
         of date; retry once it's refreshed"
    )]
    StaleKeyring(u32),
    #[error("data store failure")]
    Store(#[source] DatastoreError),
    #[error(transparent)]
    Keys(SealError),
}

impl From<DatastoreError> for RewrapError {
    fn from(e: DatastoreError) -> Self {
        match e {
            DatastoreError::Timeout => Self::DataTimeout,
            DatastoreError::BelowKekFloor(version) => Self::StaleKeyring(version),
            other => Self::Store(other),
        }
    }
}

impl From<SealError> for RewrapError {
    fn from(e: SealError) -> Self {
        match e {
            SealError::Sealed => Self::Sealed,
            other => Self::Keys(other),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RewrapReport {
    /// Rows moved to the active KEK in this call.
    pub rewrapped: u64,
    /// Rows whose DEK didn't unwrap; left as they are.
    pub failed: u64,
    /// Whether every older version was drained in this call. Retiring only
    /// happens then, for each version no row uses any more.
    pub done: bool,
    /// KEKs retired in this call.
    pub retired: Vec<(Namespace, u32)>,
    /// Vanished KEKs (lost by the keys database, kept in this server's
    /// memory) dropped in this call, since no row uses them any more: their
    /// rows were rescued.
    pub released: Vec<(Namespace, u32)>,
}

pub struct Rewrap {
    seal: Arc<Seal>,
    store: Datastore,
}

impl Rewrap {
    pub fn new(seal: Arc<Seal>, store: Datastore) -> Self {
        Self { seal, store }
    }

    /// One bounded pass: up to `max_rows` rows (0 means [`DEFAULT_MAX_ROWS`],
    /// capped at [`MAX_ROWS`]), over `namespace` only, or every namespace
    /// this server holds. Each namespace's rows move onto its own active
    /// KEK; a namespace the keys database lost entirely (no active KEK) has
    /// nowhere to move them, and is skipped.
    pub async fn run(
        &self,
        namespace: Option<&Namespace>,
        max_rows: u32,
    ) -> Result<RewrapReport, RewrapError> {
        let mut budget = match max_rows {
            0 => DEFAULT_MAX_ROWS,
            n => n.min(MAX_ROWS),
        };
        let epoch = self.seal.unsealed_epoch()?;
        let namespaces: Vec<Namespace> = {
            let keyring = self.seal.keyring_at(epoch)?;
            keyring
                .namespaces()
                .filter(|ns| namespace.is_none_or(|wanted| *ns == wanted))
                .cloned()
                .collect()
        };
        let mut report = RewrapReport::default();

        for ns in &namespaces {
            let versions = self.seal.keyring_at(epoch)?.versions(ns);
            for version in versions {
                // Skipped before fetching anything: the active version's
                // rows are where they belong, and fetching them would spend
                // the budget on them, call after call.
                match self.seal.keyring_at(epoch)?.active_kek(ns) {
                    None => break,
                    Some((active, _)) if active == version => continue,
                    Some(_) => {}
                }
                let mut after = RowKey::FIRST;
                loop {
                    if budget == 0 {
                        return Ok(report);
                    }
                    let rows = self
                        .store
                        .wrapped_by(ns, version, after, budget.min(BATCH))
                        .await?;
                    let Some(last) = rows.last() else { break };
                    after = last.key;
                    budget = budget.saturating_sub(u32::try_from(rows.len()).unwrap_or(u32::MAX));

                    // Synchronous crypto only, with the keyring as of now (a
                    // rotation during the pass just moves the target).
                    let (active, rewrapped) = {
                        let keyring = self.seal.keyring_at(epoch)?;
                        let Some((active, new_kek)) = keyring.active_kek(ns) else {
                            break;
                        };
                        if version == active {
                            break;
                        }
                        let Some(old_kek) = keyring.kek(ns, version) else {
                            break;
                        };
                        let mut rewrapped = Vec::with_capacity(rows.len());
                        for row in &rows {
                            let moved = old_kek
                                .unwrap_dek(&row.path, row.version, &row.wrapped_dek)
                                .and_then(|dek| new_kek.wrap_dek(&row.path, row.version, &dek));
                            match moved {
                                Ok(wrapped_dek) => rewrapped.push(Rewrapped {
                                    key: row.key,
                                    wrapped_dek,
                                }),
                                Err(e) => {
                                    report.failed += 1;
                                    tracing::warn!(
                                        path = %row.path,
                                        version = row.version,
                                        kek_version = version,
                                        error = %crate::error_chain(&e),
                                        "DEK did not unwrap; left as it is (corrupted or tampered?)"
                                    );
                                }
                            }
                        }
                        (active, rewrapped)
                    };
                    report.rewrapped += self.store.rewrap(ns, version, active, &rewrapped).await?;
                }
            }
        }
        report.done = true;

        // The per-version check is what makes retiring safe: any row still
        // using a version (including one that failed to unwrap above) keeps
        // it from being retired.
        self.seal.ensure_unsealed_since(epoch)?;
        for (ns, version) in self.seal.decrypt_only_versions().await? {
            if !namespaces.contains(&ns) {
                continue;
            }
            if !self.store.any_wrapped_by(&ns, version).await?
                && self.seal.retire_kek(&ns, version).await?
            {
                tracing::info!(namespace = %ns, version, "retired KEK version");
                report.retired.push((ns, version));
            }
        }

        // A vanished KEK (lost by the keys database) that no row uses any
        // more has had its rows rescued above: drop it, so the keyring is
        // back to what's stored before a rotation can reuse its number.
        let vanished: Vec<(Namespace, u32)> = self
            .seal
            .keyring_at(epoch)?
            .all_vanished()
            .into_iter()
            .filter(|(ns, _)| namespaces.contains(ns))
            .collect();
        for (ns, version) in vanished {
            if !self.store.any_wrapped_by(&ns, version).await?
                && self.seal.forget_vanished(&ns, version).await?
            {
                tracing::warn!(
                    namespace = %ns,
                    version,
                    "released vanished KEK version: no row uses it any more (rescued)"
                );
                report.released.push((ns, version));
            }
        }
        Ok(report)
    }
}
