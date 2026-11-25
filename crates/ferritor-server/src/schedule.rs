//! Scheduled tasks: purge and rewrap, run by the servers themselves, so a
//! deployment schedules nothing outside ferritor (no cron, no timer).
//!
//! The schedule is shared, in the data database (`ferritor_datastore`'s
//! `scheduled_tasks`): every server looks every [`TICK`] (plus jitter), and
//! claims a due task in one statement that moves it an interval on, so of
//! any number of servers one runs it, once per interval. A task overdue by
//! many intervals (every server down) runs once. The claim takes a lease,
//! extended between passes; a server that dies leaves a lease that runs
//! out. Every time is the database's clock.
//!
//! Correctness never depends on any of that: purge and rewrap are safe to
//! run twice and concurrently (purge deletes `FOR UPDATE SKIP LOCKED`,
//! rewrap moves rows compare-and-set), as `ferritor purge` and `ferritor
//! rewrap`, which stay for running by hand, have always been. A lease that
//! runs out early costs work, never data. Anything scheduled later must be
//! the same.
//!
//! Both need the server unsealed (a seal is the emergency stop for
//! deleting too), so a sealed server claims nothing, and a seal during a
//! run ends it. So do a pause (`ferritor schedule pause`, every server at
//! once: the row's) and shutdown. A run that fails or is cut short is due
//! again soon ([`retry`]), not an interval on.
//!
//! Audited like a request, fail closed: a run's `scheduled` entry is
//! written before its first batch, or it doesn't run; its outcome is queued
//! when it ends. Both name [`audit::SCHEDULER`] where a caller would be.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use ferritor_datastore::{Claim, Datastore, Lease, RunEnd, Task, TaskState};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::audit::{self, Gate, Outcome};
use crate::authz::Action;
use crate::purge::{Purge, PurgeError};
use crate::rewrap::{Rewrap, RewrapError};
use crate::seal::Seal;

/// How often each server looks for a due task (plus up to [`JITTER`]).
pub const TICK: Duration = Duration::from_secs(30);
const JITTER: Duration = Duration::from_secs(10);
/// How long a claim or an extension holds the task: far longer than one
/// pass, so a live run never loses it.
pub const LEASE: Duration = Duration::from_secs(300);
/// A failed or cut-short run's first retry; it doubles with each one in a
/// row, up to the task's interval.
pub const FIRST_RETRY: Duration = Duration::from_secs(60);
/// The random part of a claim's next due time: up to a tenth of the
/// interval, at most this, so tasks due together (after an outage) drift
/// apart.
const MAX_SPREAD: Duration = Duration::from_secs(600);

/// Tries at recording a run's end, a second apart.
const FINISH_ATTEMPTS: u32 = 3;

/// Purge's rows per pass: one batch, so a pause or a seal stops it within
/// one.
const PURGE_ROWS: u32 = 1_000;

/// The longest interval: 30 days.
pub const MAX_INTERVAL_MINUTES: u32 = 30 * 24 * 60;

/// How often each task is due, in minutes (`purge_interval_minutes`,
/// `rewrap_interval_minutes`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Intervals {
    pub purge_minutes: u32,
    pub rewrap_minutes: u32,
}

/// Purge daily, rewrap hourly: a pass with nothing to do is an index
/// lookup.
pub const DEFAULT: Intervals = Intervals {
    purge_minutes: 24 * 60,
    rewrap_minutes: 60,
};

impl Default for Intervals {
    fn default() -> Self {
        DEFAULT
    }
}

impl Intervals {
    /// Each from 1 minute to [`MAX_INTERVAL_MINUTES`].
    pub fn new(purge_minutes: u32, rewrap_minutes: u32) -> Result<Self, String> {
        for (name, minutes) in [
            ("purge_interval_minutes", purge_minutes),
            ("rewrap_interval_minutes", rewrap_minutes),
        ] {
            if !(1..=MAX_INTERVAL_MINUTES).contains(&minutes) {
                return Err(format!(
                    "{name} ({minutes}) must be from 1 to {MAX_INTERVAL_MINUTES}"
                ));
            }
        }
        Ok(Self {
            purge_minutes,
            rewrap_minutes,
        })
    }

    pub fn every(&self, task: Task) -> Duration {
        let minutes = match task {
            Task::Purge => self.purge_minutes,
            Task::Rewrap => self.rewrap_minutes,
        };
        Duration::from_secs(u64::from(minutes) * 60)
    }
}

/// The intervals in force: the config's, swapped on SIGHUP. With servers
/// configured differently, the one that claims a run sets the next due time
/// from its own.
#[derive(Debug, Default)]
pub struct Schedule(RwLock<Intervals>);

impl Schedule {
    pub fn new(intervals: Intervals) -> Self {
        Self(RwLock::new(intervals))
    }

    pub fn intervals(&self) -> Intervals {
        *self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn reload(&self, intervals: Intervals) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = intervals;
    }
}

/// The delay before retrying a run after `failures` failed or cut-short
/// ones in a row (this one included): [`FIRST_RETRY`], doubling, never past
/// `every`.
pub fn retry(failures: u32, every: Duration) -> Duration {
    let doubled = FIRST_RETRY.saturating_mul(
        1u32.checked_shl(failures.saturating_sub(1))
            .unwrap_or(u32::MAX),
    );
    doubled.min(every)
}

fn spread(every: Duration) -> Duration {
    (every / 10).min(MAX_SPREAD)
}

/// How a run ended, as this server saw it.
#[derive(Clone, Debug, PartialEq)]
pub struct Ran {
    pub task: Task,
    /// `ok`, `failed`, `interrupted`, or `lost` (its lease ran out and
    /// another server claimed the task: that run records its own end).
    pub result: &'static str,
    /// What it did (rows purged, moved, KEKs retired), as audited.
    pub details: serde_json::Value,
}

/// A run under way: its claim, the seal epoch it began in, the shutdown.
struct Run<'a> {
    claim: &'a Claim,
    epoch: u64,
    stop: &'a CancellationToken,
}

/// Why a run stopped before it was done.
enum Stopped {
    /// Sealed, paused, or shutting down: `interrupted`, retried soon.
    Interrupted(&'static str),
    /// An error: `failed`, retried soon.
    Failed(String),
    /// The lease isn't this run's any more.
    Lost,
}

/// The shared schedule's rows as last read, for the gauges
/// (`metrics::observe_schedule`): every server reads the same rows, so
/// every server reports the same values. Kept as they were when a read
/// fails, so a gauge never drops for want of an answer.
#[derive(Debug, Default)]
pub struct ScheduleStates(RwLock<Vec<TaskState>>);

impl ScheduleStates {
    pub fn get(&self) -> Vec<TaskState> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// For the scheduler, after each read (and the tests).
    pub fn set(&self, states: Vec<TaskState>) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = states;
    }
}

pub struct Scheduler {
    seal: Arc<Seal>,
    store: Datastore,
    purge: Arc<Purge>,
    rewrap: Arc<Rewrap>,
    gate: Arc<Gate>,
    schedule: Arc<Schedule>,
    states: Arc<ScheduleStates>,
}

impl Scheduler {
    pub fn new(
        seal: Arc<Seal>,
        store: Datastore,
        purge: Arc<Purge>,
        rewrap: Arc<Rewrap>,
        gate: Arc<Gate>,
        schedule: Arc<Schedule>,
    ) -> Self {
        Self {
            seal,
            store,
            purge,
            rewrap,
            gate,
            schedule,
            states: Arc::default(),
        }
    }

    /// The rows as each tick last read them, for the gauges.
    pub fn states(&self) -> Arc<ScheduleStates> {
        Arc::clone(&self.states)
    }

    /// Looks every [`TICK`] (plus jitter) until `stop`, running whatever
    /// is due. A run under way when `stop` fires ends at its next pass.
    pub async fn keep_running(self: Arc<Self>, stop: CancellationToken) {
        loop {
            let jitter = JITTER.mul_f64(rand_unit());
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(TICK + jitter) => {}
            }
            self.tick(&stop).await;
        }
    }

    /// One look: claims and runs each task that's due, one after the other.
    /// What ran, for the tests.
    pub async fn tick(&self, stop: &CancellationToken) -> Vec<Ran> {
        let mut ran = Vec::new();
        for task in Task::ALL {
            if stop.is_cancelled() {
                break;
            }
            // Both need the keys' side of the server: a sealed one doesn't
            // claim, so an unsealed one does.
            if self.seal.unsealed_epoch().is_err() {
                break;
            }
            let every = self.schedule.intervals().every(task);
            match self
                .store
                .claim_run(task, every, spread(every), LEASE)
                .await
            {
                Ok(Some(claim)) => ran.push(self.run(claim, every, stop).await),
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    task = task.name(),
                    error = %crate::error_chain(&e),
                    "couldn't look at the schedule; trying again at the next tick"
                ),
            }
        }
        // Sealed or not: the rows hold no key material.
        match self.store.scheduled_tasks().await {
            Ok((states, _)) => self.states.set(states),
            Err(e) => tracing::warn!(
                error = %crate::error_chain(&e),
                "couldn't read the schedule for the gauges; they keep the last values"
            ),
        }
        ran
    }

    async fn run(&self, claim: Claim, every: Duration, stop: &CancellationToken) -> Ran {
        let task = claim.task();
        let began = std::time::Instant::now();
        let action = action(task);
        // Fail closed, as a request: nothing is deleted or moved unaudited.
        let started = self.gate.scheduled(action, task.name()).await;
        let (outcome, details) = match started {
            Err(e) => (
                Err(Stopped::Failed(format!(
                    "not audited: {}",
                    crate::error_chain(&e)
                ))),
                json!({}),
            ),
            Ok(()) => match self.seal.unsealed_epoch() {
                // The run's own epoch: a seal ends it even if an unseal
                // follows before its next pass.
                Ok(epoch) => {
                    tracing::info!(task = task.name(), "scheduled run started");
                    let run = Run {
                        claim: &claim,
                        epoch,
                        stop,
                    };
                    match task {
                        Task::Purge => self.purge_pass(&run).await,
                        Task::Rewrap => self.rewrap_pass(&run).await,
                    }
                }
                Err(_) => (Err(Stopped::Interrupted("sealed")), json!({})),
            },
        };
        let failures = claim.failures().saturating_add(1);
        let (result, end, error) = match outcome {
            Ok(()) => ("ok", Some(RunEnd::Ok), None),
            Err(Stopped::Interrupted(why)) => (
                "interrupted",
                Some(RunEnd::Interrupted {
                    retry: retry(failures, every),
                }),
                Some(why.to_owned()),
            ),
            Err(Stopped::Failed(why)) => (
                "failed",
                Some(RunEnd::Failed {
                    retry: retry(failures, every),
                }),
                Some(why),
            ),
            Err(Stopped::Lost) => ("lost", None, Some("its lease ran out".to_owned())),
        };
        if let Some(end) = end {
            self.finish(&claim, end).await;
        }
        let outcome = match &error {
            None => Outcome::Succeeded(details.clone()),
            Some(error) => Outcome::Failed {
                error: format!("{result}: {error}"),
                details: Some(details.clone()),
            },
        };
        self.gate.scheduled_outcome(action, task.name(), outcome);
        match &error {
            None => tracing::info!(task = task.name(), %details, "scheduled run done"),
            Some(error) => tracing::warn!(
                task = task.name(),
                result,
                error,
                %details,
                "scheduled run ended early; due again soon"
            ),
        }
        crate::metrics::metrics().scheduled_run(task.name(), result, began.elapsed());
        Ran {
            task,
            result,
            details,
        }
    }

    /// Records how a run ended, trying a few times: unrecorded, a failed
    /// run's short retry is lost (the task stays due as its claim set it, an
    /// interval on) and its lease has to run out.
    async fn finish(&self, claim: &Claim, end: RunEnd) {
        let task = claim.task();
        for attempt in 1..=FINISH_ATTEMPTS {
            match self.store.finish_run(claim, end).await {
                Ok(true) => return,
                Ok(false) => {
                    tracing::warn!(
                        task = task.name(),
                        "a scheduled run's lease ran out before it ended: another server \
                         claimed the task"
                    );
                    return;
                }
                Err(e) if attempt < FINISH_ATTEMPTS => {
                    tracing::warn!(
                        task = task.name(),
                        error = %crate::error_chain(&e),
                        "couldn't record a scheduled run's end; trying again"
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => tracing::warn!(
                    task = task.name(),
                    error = %crate::error_chain(&e),
                    "couldn't record a scheduled run's end; its lease runs out"
                ),
            }
        }
    }

    /// Whether to go on after a pass: not sealed since the run began, not
    /// shutting down, the lease extended, not paused.
    async fn go_on(&self, run: &Run<'_>) -> Result<(), Stopped> {
        self.still_unsealed(run)?;
        if run.stop.is_cancelled() {
            return Err(Stopped::Interrupted("shutting down"));
        }
        match self.store.extend_lease(run.claim, LEASE).await {
            Ok(Lease::Held) => Ok(()),
            Ok(Lease::Paused) => Err(Stopped::Interrupted("paused")),
            Ok(Lease::Lost) => Err(Stopped::Lost),
            Err(e) => Err(Stopped::Failed(crate::error_chain(&e))),
        }
    }

    /// A seal since the run began ends it, an unseal after it included.
    fn still_unsealed(&self, run: &Run<'_>) -> Result<(), Stopped> {
        self.seal
            .ensure_unsealed_since(run.epoch)
            .map_err(|_| Stopped::Interrupted("sealed"))
    }

    async fn purge_pass(&self, run: &Run<'_>) -> (Result<(), Stopped>, serde_json::Value) {
        let mut purged = 0u64;
        let result = loop {
            if let Err(stopped) = self.still_unsealed(run) {
                break Err(stopped);
            }
            match self.purge.run(PURGE_ROWS).await {
                Ok(report) => {
                    purged += report.purged;
                    if report.done {
                        break Ok(());
                    }
                }
                Err(PurgeError::Sealed) => break Err(Stopped::Interrupted("sealed")),
                Err(PurgeError::Paused) => break Err(Stopped::Interrupted("paused")),
                Err(e) => break Err(Stopped::Failed(crate::error_chain(&e))),
            }
            if let Err(stopped) = self.go_on(run).await {
                break Err(stopped);
            }
        };
        let details = json!({
            "purged": purged,
            "retention_secs": self.purge.retention().as_secs(),
        });
        (result, details)
    }

    async fn rewrap_pass(&self, run: &Run<'_>) -> (Result<(), Stopped>, serde_json::Value) {
        // First the keyring as stored: a server that missed another's
        // rotation would take the old KEK for the active one, skip its rows
        // and call the pass done.
        match crate::keyring::refresh(&self.seal, &self.gate, "schedule", None, true).await {
            Ok(_) => {}
            Err(crate::seal::SealError::Sealed) => {
                return (Err(Stopped::Interrupted("sealed")), json!({}));
            }
            Err(e) => {
                return (
                    Err(Stopped::Failed(format!(
                        "keyring refresh: {}",
                        crate::error_chain(&e)
                    ))),
                    json!({}),
                );
            }
        }
        let (mut rewrapped, mut failed) = (0u64, 0u64);
        let (mut retired, mut released) = (Vec::new(), Vec::new());
        let result = loop {
            if let Err(stopped) = self.still_unsealed(run) {
                break Err(stopped);
            }
            // The most a call takes: rows that don't unwrap are read again
            // by every call, so a small one could spend itself on them.
            match self.rewrap.run(None, crate::rewrap::MAX_ROWS).await {
                Ok(report) => {
                    rewrapped += report.rewrapped;
                    failed = failed.max(report.failed);
                    retired.extend(report.retired);
                    released.extend(report.released);
                    if report.done && report.failed == 0 {
                        break Ok(());
                    }
                    if report.done || report.rewrapped == 0 {
                        // Only rows that don't unwrap left in its way: the
                        // next run tries again (logged per row by rewrap).
                        break Err(Stopped::Failed(format!(
                            "{} rows didn't unwrap",
                            report.failed
                        )));
                    }
                }
                Err(RewrapError::Sealed) => break Err(Stopped::Interrupted("sealed")),
                Err(RewrapError::Paused) => break Err(Stopped::Interrupted("paused")),
                Err(e) => break Err(Stopped::Failed(crate::error_chain(&e))),
            }
            if let Err(stopped) = self.go_on(run).await {
                break Err(stopped);
            }
        };
        if rewrapped > 0 {
            crate::metrics::metrics().rewrapped(rewrapped);
        }
        let details = json!({
            "rewrapped": rewrapped,
            "failed": failed,
            "retired": audit::kek_refs(&retired),
            "released": audit::kek_refs(&released),
        });
        (result, details)
    }
}

/// The admin action a task is, as audited.
pub fn action(task: Task) -> Action {
    match task {
        Task::Purge => Action::Purge,
        Task::Rewrap => Action::Rewrap,
    }
}

/// A number in [0, 1), for jitter: not for anything secret.
fn rand_unit() -> f64 {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return 0.5;
    }
    (u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_are_checked() {
        assert_eq!(Intervals::new(1440, 60), Ok(DEFAULT));
        assert!(
            Intervals::new(0, 60)
                .unwrap_err()
                .contains("purge_interval_minutes (0)")
        );
        assert!(
            Intervals::new(60, MAX_INTERVAL_MINUTES + 1)
                .unwrap_err()
                .contains("rewrap_interval_minutes (43201)")
        );
        assert_eq!(DEFAULT.every(Task::Rewrap), Duration::from_secs(3600));
    }

    /// A minute, doubling with each failure in a row, never past the
    /// interval.
    #[test]
    fn the_retry_doubles_up_to_the_interval() {
        let day = Duration::from_secs(86_400);
        let minutes = |n: u64| Duration::from_secs(60 * n);
        assert_eq!(retry(1, day), minutes(1));
        assert_eq!(retry(2, day), minutes(2));
        assert_eq!(retry(5, day), minutes(16));
        assert_eq!(retry(12, day), day);
        assert_eq!(retry(u32::MAX, day), day);
        assert_eq!(retry(3, minutes(3)), minutes(3));
    }

    #[test]
    fn the_spread_is_a_tenth_at_most_ten_minutes() {
        assert_eq!(spread(Duration::from_secs(3600)), Duration::from_secs(360));
        assert_eq!(spread(Duration::from_secs(86_400)), MAX_SPREAD);
    }
}
