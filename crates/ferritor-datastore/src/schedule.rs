//! The scheduled tasks' shared schedule (`scheduled_tasks`): which task is
//! due, who's running it, how its last run ended. Every server asks; the
//! claim, one UPDATE, lets one of them run a task once per interval. Every
//! time is the database's clock (`now()`), never a server's.
//!
//! Nothing here is a lock in Postgres's sense: a claim holds a lease, a
//! time in the row, that its run extends between batches. A server that
//! dies leaves a lease that runs out. The tasks are safe to run twice and
//! concurrently, so a lease that runs out early costs work, never data.

use std::fmt;
use std::time::Duration;

use sqlx::types::Uuid;
use sqlx::types::time::OffsetDateTime;

use crate::{Datastore, DatastoreError, Result, bounded};

/// A task the server runs on a schedule. Its row is seeded by a migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Task {
    /// Remove deleted versions past their retention.
    Purge,
    /// Move DEKs to each namespace's active KEK, retire the drained ones.
    Rewrap,
}

impl Task {
    pub const ALL: [Task; 2] = [Task::Purge, Task::Rewrap];

    /// As stored, and as the audit log, the metrics and the CLI spell it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Purge => "purge",
            Self::Rewrap => "rewrap",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|task| task.name() == name)
    }
}

impl fmt::Display for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A run this server claimed: it holds the task's lease until it
/// [`finishes`](Datastore::finish_run) or the lease runs out.
#[derive(Debug)]
pub struct Claim {
    task: Task,
    run: Uuid,
    failures: u32,
}

impl Claim {
    pub fn task(&self) -> Task {
        self.task
    }

    /// How many runs before this one failed or were cut short in a row.
    pub fn failures(&self) -> u32 {
        self.failures
    }
}

/// What extending a lease found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lease {
    /// Still this run's, extended.
    Held,
    /// Still this run's, but the task was paused meanwhile: stop.
    Paused,
    /// No longer this run's: it ran out and another server claimed the
    /// task, or the row is gone. Stop.
    Lost,
}

/// How a run ended, for [`Datastore::finish_run`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunEnd {
    /// Every row it had to handle, handled.
    Ok,
    /// It failed (a database error, say), and should be tried again
    /// `retry` from now rather than an interval on.
    Failed { retry: Duration },
    /// Cut short (a seal, a pause, a shutdown), and should be tried again
    /// `retry` from now.
    Interrupted { retry: Duration },
}

impl RunEnd {
    fn result(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed { .. } => "failed",
            Self::Interrupted { .. } => "interrupted",
        }
    }
}

/// A task's row, as `status` and the metrics show it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskState {
    pub task: Task,
    pub next_due: OffsetDateTime,
    pub paused: bool,
    /// A run holds a lease that hasn't run out.
    pub running: bool,
    pub last_started: Option<OffsetDateTime>,
    pub last_finished: Option<OffsetDateTime>,
    /// `ok`, `failed` or `interrupted`; `None` before the first run ends.
    pub last_result: Option<String>,
    pub last_success: Option<OffsetDateTime>,
}

fn seconds(d: Duration) -> f64 {
    d.as_secs_f64()
}

impl Datastore {
    /// Claims a run of `task` if it's due, not paused and no run holds a
    /// lease that hasn't run out: moves its next due time `every` (plus up
    /// to `spread`, at random, so tasks due together drift apart) from now,
    /// and takes the lease for `lease`. One statement: of any number of
    /// servers asking at once, one gets it. `None`: not this time.
    ///
    /// A task overdue by any number of intervals (every server down for a
    /// week) is claimed once, and then due an interval on: caught up once,
    /// never once per missed interval.
    pub async fn claim_run(
        &self,
        task: Task,
        every: Duration,
        spread: Duration,
        lease: Duration,
    ) -> Result<Option<Claim>> {
        bounded(self.timeout, async move {
            let row = sqlx::query!(
                r#"UPDATE scheduled_tasks
                   SET next_due = now() + make_interval(secs => $2 + random() * $3),
                       run_id = uuidv7(),
                       lease_until = now() + make_interval(secs => $4),
                       last_started = now()
                   WHERE task = $1 AND NOT paused AND next_due <= now()
                     AND (lease_until IS NULL OR lease_until < now())
                   RETURNING run_id AS "run_id!", failures"#,
                task.name(),
                seconds(every),
                seconds(spread),
                seconds(lease),
            )
            .fetch_optional(&self.pool)
            .await?;
            row.map(|row| {
                Ok(Claim {
                    task,
                    run: row.run_id,
                    failures: u32::try_from(row.failures).map_err(|_| {
                        DatastoreError::OutOfRange {
                            field: "failures",
                            value: i64::from(row.failures),
                        }
                    })?,
                })
            })
            .transpose()
        })
        .await
    }

    /// Extends `claim`'s lease to `lease` from now, if it's still the
    /// claim's, and tells whether the task was paused meanwhile.
    pub async fn extend_lease(&self, claim: &Claim, lease: Duration) -> Result<Lease> {
        bounded(self.timeout, async move {
            let row = sqlx::query!(
                r#"UPDATE scheduled_tasks
                   SET lease_until = now() + make_interval(secs => $3)
                   WHERE task = $1 AND run_id = $2
                   RETURNING paused"#,
                claim.task.name(),
                claim.run,
                seconds(lease),
            )
            .fetch_optional(&self.pool)
            .await?;
            Ok(match row {
                None => Lease::Lost,
                Some(row) if row.paused => Lease::Paused,
                Some(_) => Lease::Held,
            })
        })
        .await
    }

    /// Ends `claim`'s run: releases the lease and records how it ended. A
    /// run that failed or was cut short is due again `retry` from now (if
    /// that's sooner than the interval its claim set), so its work doesn't
    /// wait a whole interval. `false`: the lease wasn't the claim's any
    /// more (it ran out, and another server claimed the task), so nothing
    /// was recorded; that run records its own.
    pub async fn finish_run(&self, claim: &Claim, end: RunEnd) -> Result<bool> {
        bounded(self.timeout, async move {
            let finished = match end {
                RunEnd::Ok => sqlx::query!(
                    r#"UPDATE scheduled_tasks
                       SET run_id = NULL, lease_until = NULL, failures = 0,
                           last_finished = now(), last_result = $3,
                           last_success = now()
                       WHERE task = $1 AND run_id = $2"#,
                    claim.task.name(),
                    claim.run,
                    end.result(),
                )
                .execute(&self.pool)
                .await?
                .rows_affected(),
                RunEnd::Failed { retry } | RunEnd::Interrupted { retry } => sqlx::query!(
                    r#"UPDATE scheduled_tasks
                       SET run_id = NULL, lease_until = NULL,
                           failures = LEAST(failures, 1000000) + 1,
                           last_finished = now(), last_result = $3,
                           next_due = LEAST(next_due, now() + make_interval(secs => $4))
                       WHERE task = $1 AND run_id = $2"#,
                    claim.task.name(),
                    claim.run,
                    end.result(),
                    seconds(retry),
                )
                .execute(&self.pool)
                .await?
                .rows_affected(),
            };
            Ok(finished == 1)
        })
        .await
    }

    /// Pauses `task` (no server claims it, and a run under way ends at its
    /// next batch) or resumes it. Whether it was paused before.
    pub async fn set_task_paused(&self, task: Task, paused: bool) -> Result<bool> {
        bounded(self.timeout, async move {
            let row = sqlx::query!(
                r#"UPDATE scheduled_tasks SET paused = $2 WHERE task = $1
                   RETURNING old.paused AS "was_paused!""#,
                task.name(),
                paused,
            )
            .fetch_optional(&self.pool)
            .await?;
            // The row is the migration's: missing only if someone deleted it.
            Ok(row.is_some_and(|row| row.was_paused))
        })
        .await
    }

    /// Whether `task` is paused for every server: purge and rewrap ask
    /// before every batch, by hand as on the schedule. One primary-key read.
    pub async fn task_paused(&self, task: Task) -> Result<bool> {
        bounded(self.timeout, async move {
            let paused = sqlx::query_scalar!(
                "SELECT paused FROM scheduled_tasks WHERE task = $1",
                task.name(),
            )
            .fetch_optional(&self.pool)
            .await?;
            Ok(paused.unwrap_or(false))
        })
        .await
    }

    /// Every task's row, in [`Task::ALL`]'s order, and the database's time
    /// now (what `next_due` and the lease are compared with).
    pub async fn scheduled_tasks(&self) -> Result<(Vec<TaskState>, OffsetDateTime)> {
        bounded(self.timeout, async move {
            let rows = sqlx::query!(
                r#"SELECT task, next_due, paused,
                          COALESCE(lease_until >= now(), false) AS "running!",
                          last_started, last_finished, last_result, last_success,
                          now() AS "now!"
                   FROM scheduled_tasks"#,
            )
            .fetch_all(&self.pool)
            .await?;
            let now = rows
                .first()
                .map_or(OffsetDateTime::UNIX_EPOCH, |row| row.now);
            let mut states: Vec<TaskState> = rows
                .into_iter()
                // A name this server doesn't know (a newer server's task)
                // isn't this server's to show.
                .filter_map(|row| {
                    Some(TaskState {
                        task: Task::from_name(&row.task)?,
                        next_due: row.next_due,
                        paused: row.paused,
                        running: row.running,
                        last_started: row.last_started,
                        last_finished: row.last_finished,
                        last_result: row.last_result,
                        last_success: row.last_success,
                    })
                })
                .collect();
            states.sort_by_key(|state| Task::ALL.iter().position(|t| *t == state.task));
            Ok((states, now))
        })
        .await
    }
}
