//! Purge: remove deleted secret versions for good once they're past their
//! retention (`purge_deleted_after_days`, a server setting, so a caller
//! can't purge a deletion that's still recent). Delete is soft; without
//! this, deleted rows pile up forever.
//!
//! The retention is the window in which a deletion (or a trim under
//! `max_versions`) can be undone: `Secrets::restore` (`RestoreSecret`,
//! `ferritor restore`) brings a deleted version back until it's purged.
//!
//! Operator-driven and bounded like rewrap: one [`Purge::run`] removes at
//! most `max_rows` rows and reports whether it's done; callers repeat it
//! (`ferritor purge`, from cron or a systemd timer). Each batch is one
//! statement, so an interrupted run just resumes.
//!
//! It needs no keys, but the seal freezes the data plane all the same: a
//! pass records the seal epoch when it starts and checks it before every
//! batch, so a seal stops it (one statement at most may still land).
//!
//! What it never does: touch a live version, or free a version number. The
//! highest version a path ever had stays recorded (`paths.highest`), so a
//! purged path's next put continues the numbering.

use std::sync::Arc;
use std::time::Duration;

use ferritor_core::messages::SEALED;
use ferritor_datastore::{Datastore, DatastoreError};

use crate::seal::Seal;

/// Rows per statement.
const BATCH: u32 = 1_000;
/// Used when a caller asks for 0.
pub const DEFAULT_MAX_ROWS: u32 = 10_000;
/// Keeps one call well inside a request timeout.
pub const MAX_ROWS: u32 = 100_000;

#[derive(Debug, thiserror::Error)]
pub enum PurgeError {
    #[error("{}", SEALED)]
    Sealed,
    #[error("the data database did not respond in time")]
    DataTimeout,
    #[error("data store failure")]
    Store(#[source] DatastoreError),
}

impl From<DatastoreError> for PurgeError {
    fn from(e: DatastoreError) -> Self {
        match e {
            DatastoreError::Timeout => Self::DataTimeout,
            other => Self::Store(other),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// Deleted versions removed for good in this call.
    pub purged: u64,
    /// Whether nothing past its retention is left.
    pub done: bool,
}

pub struct Purge {
    seal: Arc<Seal>,
    store: Datastore,
    retention: Duration,
}

impl Purge {
    /// Purges deletions older than `retention`.
    pub fn new(seal: Arc<Seal>, store: Datastore, retention: Duration) -> Self {
        Self {
            seal,
            store,
            retention,
        }
    }

    pub fn retention(&self) -> Duration {
        self.retention
    }

    /// One bounded pass: up to `max_rows` rows (0 means
    /// [`DEFAULT_MAX_ROWS`], capped at [`MAX_ROWS`]).
    pub async fn run(&self, max_rows: u32) -> Result<PurgeReport, PurgeError> {
        let mut budget = match max_rows {
            0 => DEFAULT_MAX_ROWS,
            n => n.min(MAX_ROWS),
        };
        let epoch = self.seal.unsealed_epoch().map_err(|_| PurgeError::Sealed)?;
        let mut report = PurgeReport::default();
        while budget > 0 {
            self.seal
                .ensure_unsealed_since(epoch)
                .map_err(|_| PurgeError::Sealed)?;
            let batch = budget.min(BATCH);
            let purged = self.store.purge_deleted(self.retention, batch).await?;
            crate::metrics::metrics().purged(purged);
            report.purged += purged;
            if purged < u64::from(batch) {
                report.done = true;
                break;
            }
            budget -= batch;
        }
        Ok(report)
    }
}
