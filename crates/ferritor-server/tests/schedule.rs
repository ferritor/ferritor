//! The scheduled tasks against real keys and data databases (one each per
//! test, see `ferritor-testkit`): purge and rewrap run once per interval
//! however many servers look, only on an unsealed one, never while paused,
//! and never unaudited.

use std::sync::Arc;
use std::time::Duration;

use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::Labels;
use ferritor_core::path::Namespace;
use ferritor_datastore::{Datastore, Task};
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{AllowAll, Caller};
use ferritor_server::namespaces::Namespaces;
use ferritor_server::purge::Purge;
use ferritor_server::rewrap::Rewrap;
use ferritor_server::schedule::{Ran, Schedule, Scheduler};
use ferritor_server::seal::Seal;
use ferritor_server::secrets::Secrets;
use ferritor_testkit::{Captured, TestDatabase, TestResult};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const ANON: Caller = Caller::Unauthenticated;
const RETENTION: Duration = Duration::from_secs(30 * 86_400);

struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    seal: Arc<Seal>,
    secrets: Secrets,
    shares: Vec<Vec<u8>>,
    audit: Captured,
    gate: Arc<Gate>,
}

impl Env {
    async fn new() -> TestResult<Self> {
        let keys = TestDatabase::new(
            "KEYS_DATABASE_URL",
            "ferritor_server_test",
            &ferritor_keystore::MIGRATOR,
        )
        .await?;
        let data = TestDatabase::new(
            "DATA_DATABASE_URL",
            "ferritor_server_test",
            &ferritor_datastore::MIGRATOR,
        )
        .await?;
        let seal = Arc::new(Seal::new(Keystore::new(keys.pool().clone())));
        let shares: Vec<Vec<u8>> = seal
            .init(ShareParams::new(3, 2)?)
            .await?
            .iter()
            .map(|s| s.to_bytes().to_vec())
            .collect();
        for share in &shares[..2] {
            seal.unseal(share, false).await?;
        }
        Namespaces::new(Arc::clone(&seal), Datastore::new(data.pool().clone()))
            .create("app", &Labels::new())
            .await?;
        let audit = Captured::default();
        let gate = Arc::new(Gate::new(
            Arc::new(AllowAll),
            AuditLog::new(audit.clone(), Duration::from_secs(5))?,
        ));
        let secrets = Secrets::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
            Arc::clone(&gate),
        );
        Ok(Self {
            keys,
            data,
            seal,
            secrets,
            shares,
            audit,
            gate,
        })
    }

    fn store(&self) -> Datastore {
        Datastore::new(self.data.pool().clone())
    }

    /// A server's scheduler, auditing through `gate`.
    fn scheduler(&self, gate: Arc<Gate>) -> Scheduler {
        Scheduler::new(
            Arc::clone(&self.seal),
            self.store(),
            Arc::new(Purge::new(Arc::clone(&self.seal), self.store(), RETENTION)),
            Arc::new(Rewrap::new(Arc::clone(&self.seal), self.store())),
            gate,
            Arc::new(Schedule::default()),
        )
    }

    /// `path` stored, then deleted 31 days ago: past the retention.
    async fn deleted_long_ago(&self, path: &str) -> TestResult<()> {
        self.secrets.put(&ANON, path, b"x").await?;
        self.secrets.delete(&ANON, path).await?;
        sqlx::query(
            "UPDATE secret_versions SET deleted_at = now() - interval '31 days'
             WHERE path_id = (SELECT id FROM paths WHERE path = $1)",
        )
        .bind(path)
        .execute(self.data.pool())
        .await?;
        Ok(())
    }

    async fn rows(&self, path: &str) -> TestResult<i64> {
        let count: Option<i64> = sqlx::query_scalar(
            "SELECT count(*) FROM secret_versions v JOIN paths p ON p.id = v.path_id
             WHERE p.path = $1",
        )
        .bind(path)
        .fetch_one(self.data.pool())
        .await?;
        Ok(count.unwrap_or_default())
    }

    /// Makes every task due again.
    async fn all_due(&self) -> TestResult<()> {
        sqlx::query("UPDATE scheduled_tasks SET next_due = now() - interval '1 second'")
            .execute(self.data.pool())
            .await?;
        Ok(())
    }

    /// The scheduler's audit entries, in order.
    fn scheduled_entries(&self) -> Vec<Value> {
        self.audit
            .lines()
            .iter()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|entry| entry["caller"] == "ferritor:scheduler")
            .map(|mut entry| {
                if let Some(entry) = entry.as_object_mut() {
                    entry.remove("time");
                }
                entry
            })
            .collect()
    }

    /// The scheduler's entries once there are `n`: outcomes are queued, so
    /// they reach the log after the run returns.
    async fn scheduled_entries_once(&self, n: usize) -> Vec<Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let entries = self.scheduled_entries();
            if entries.len() >= n || tokio::time::Instant::now() >= deadline {
                return entries;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn destroy(self) -> TestResult<()> {
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

fn tasks(ran: &[Ran]) -> Vec<(Task, &'static str)> {
    ran.iter().map(|ran| (ran.task, ran.result)).collect()
}

/// Two servers looking at once: purge and rewrap each run once, between
/// them, and do their work; looking again, nothing is due. Each run is
/// audited as the scheduler: its start before anything, then its outcome.
#[tokio::test]
async fn due_tasks_run_once_across_servers() {
    let env = Env::new().await.unwrap();
    env.deleted_long_ago("app/old").await.unwrap();
    env.secrets.put(&ANON, "app/live", b"x").await.unwrap();
    let app = Namespace::parse("app").unwrap();
    let rotated = env.seal.rotate(&app).await.unwrap();
    assert_eq!(rotated, 2);

    let (one, two) = (
        env.scheduler(Arc::clone(&env.gate)),
        env.scheduler(Arc::clone(&env.gate)),
    );
    let stop = CancellationToken::new();
    let (a, b) = tokio::join!(one.tick(&stop), two.tick(&stop));
    let mut ran: Vec<_> = tasks(&a).into_iter().chain(tasks(&b)).collect();
    ran.sort_by_key(|(task, _)| task.name());
    assert_eq!(ran, [(Task::Purge, "ok"), (Task::Rewrap, "ok")]);

    // Purge skips a row a rewrap holds (FOR UPDATE SKIP LOCKED), so with
    // both running at once the old row may be left for the next purge.
    let left = env.rows("app/old").await.unwrap();
    assert!(left <= 1, "{left}");
    assert_eq!(env.rows("app/live").await.unwrap(), 1);
    assert!(!env.store().any_wrapped_by(&app, 1).await.unwrap());
    assert!(one.tick(&stop).await.is_empty());
    assert!(two.tick(&stop).await.is_empty());

    let mut entries = env.scheduled_entries_once(4).await;
    assert_eq!(entries.len(), 4, "{entries:?}");
    entries.sort_by_key(|entry| entry["action"].as_str().map(str::to_owned));
    // Rewrap moves deleted rows too: the old one, unless the other
    // server's purge got to it first.
    let rewrapped = entries[3]["details"]["rewrapped"].take();
    assert!(rewrapped == 1 || rewrapped == 2, "{rewrapped}");
    assert_eq!(entries[1]["details"]["purged"].take(), 1 - left);
    assert_eq!(
        entries,
        [
            json!({"event": "scheduled", "caller": "ferritor:scheduler", "action": "purge",
                   "task": "purge"}),
            json!({"event": "outcome", "caller": "ferritor:scheduler", "action": "purge",
                   "target": {"kind": "system"}, "operation": "purge", "result": "succeeded",
                   "details": {"purged": null, "retention_secs": RETENTION.as_secs()}}),
            json!({"event": "scheduled", "caller": "ferritor:scheduler", "action": "rewrap",
                   "task": "rewrap"}),
            json!({"event": "outcome", "caller": "ferritor:scheduler", "action": "rewrap",
                   "target": {"kind": "system"}, "operation": "rewrap", "result": "succeeded",
                   "details": {"rewrapped": null, "failed": 0,
                               "retired": [{"namespace": "app", "version": 1}],
                               "released": []}}),
        ]
    );
    let (states, _) = env.store().scheduled_tasks().await.unwrap();
    assert!(
        states
            .iter()
            .all(|s| s.last_result.as_deref() == Some("ok"))
    );
    env.destroy().await.unwrap();
}

/// A rewrap that finishes its pass with rows it couldn't unwrap (corrupted,
/// tampered with) left on the old KEK isn't a success: it fails, and is due
/// again soon, while the rows it could move are moved.
#[tokio::test]
async fn a_rewrap_leaving_rows_behind_fails() {
    let env = Env::new().await.unwrap();
    env.secrets.put(&ANON, "app/good", b"x").await.unwrap();
    env.secrets.put(&ANON, "app/bad", b"x").await.unwrap();
    sqlx::query(
        "UPDATE secret_versions SET wrapped_dek = '\\x00'
         WHERE path_id = (SELECT id FROM paths WHERE path = 'app/bad')",
    )
    .execute(env.data.pool())
    .await
    .unwrap();
    let app = Namespace::parse("app").unwrap();
    env.seal.rotate(&app).await.unwrap();
    env.store()
        .set_task_paused(Task::Purge, true)
        .await
        .unwrap();

    let scheduler = env.scheduler(Arc::clone(&env.gate));
    let ran = scheduler.tick(&CancellationToken::new()).await;
    assert_eq!(tasks(&ran), [(Task::Rewrap, "failed")]);
    assert_eq!(ran[0].details["rewrapped"], 1);
    assert_eq!(ran[0].details["failed"], 1);
    assert!(env.store().any_wrapped_by(&app, 1).await.unwrap());
    let (states, now) = env.store().scheduled_tasks().await.unwrap();
    let rewrap = &states[1];
    assert_eq!(rewrap.last_result.as_deref(), Some("failed"));
    assert!(
        rewrap.next_due - now <= time::Duration::seconds(61),
        "{rewrap:?}"
    );
    env.destroy().await.unwrap();
}

/// A server that missed another's rotation refreshes its keyring before a
/// scheduled rewrap: with its stale one it would take the old KEK for the
/// active one, skip its rows, and call the pass done.
#[tokio::test]
async fn a_stale_server_rewraps_after_refreshing() {
    let env = Env::new().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"x").await.unwrap();
    let stale = Arc::new(Seal::new(Keystore::new(env.keys.pool().clone())));
    for share in &env.shares[..2] {
        stale.unseal(share, false).await.unwrap();
    }
    let app = Namespace::parse("app").unwrap();
    env.seal.rotate(&app).await.unwrap();
    env.store()
        .set_task_paused(Task::Purge, true)
        .await
        .unwrap();

    let scheduler = Scheduler::new(
        Arc::clone(&stale),
        env.store(),
        Arc::new(Purge::new(Arc::clone(&stale), env.store(), RETENTION)),
        Arc::new(Rewrap::new(Arc::clone(&stale), env.store())),
        Arc::clone(&env.gate),
        Arc::new(Schedule::default()),
    );
    let ran = scheduler.tick(&CancellationToken::new()).await;
    assert_eq!(tasks(&ran), [(Task::Rewrap, "ok")]);
    assert_eq!(ran[0].details["rewrapped"], 1);
    assert!(!env.store().any_wrapped_by(&app, 1).await.unwrap());
    env.destroy().await.unwrap();
}

/// A sealed server claims nothing, so the tasks stay due for an unsealed
/// one: a seal is the emergency stop for deleting too.
#[tokio::test]
async fn a_sealed_server_runs_nothing() {
    let env = Env::new().await.unwrap();
    env.deleted_long_ago("app/old").await.unwrap();
    env.seal.seal().await;
    let scheduler = env.scheduler(Arc::clone(&env.gate));
    let stop = CancellationToken::new();
    assert!(scheduler.tick(&stop).await.is_empty());
    assert_eq!(env.rows("app/old").await.unwrap(), 1);
    assert!(env.scheduled_entries().is_empty());

    for share in &env.shares[..2] {
        env.seal.unseal(share, false).await.unwrap();
    }
    assert_eq!(
        tasks(&scheduler.tick(&stop).await),
        [(Task::Purge, "ok"), (Task::Rewrap, "ok")]
    );
    assert_eq!(env.rows("app/old").await.unwrap(), 0);
    env.destroy().await.unwrap();
}

/// A paused task isn't run, however due, by any server; the others are.
/// Resumed, it runs at the next look.
#[tokio::test]
async fn a_paused_task_waits_for_its_resume() {
    let env = Env::new().await.unwrap();
    env.deleted_long_ago("app/old").await.unwrap();
    env.store()
        .set_task_paused(Task::Purge, true)
        .await
        .unwrap();
    let scheduler = env.scheduler(Arc::clone(&env.gate));
    let stop = CancellationToken::new();
    assert_eq!(tasks(&scheduler.tick(&stop).await), [(Task::Rewrap, "ok")]);
    assert_eq!(env.rows("app/old").await.unwrap(), 1);

    env.store()
        .set_task_paused(Task::Purge, false)
        .await
        .unwrap();
    assert_eq!(tasks(&scheduler.tick(&stop).await), [(Task::Purge, "ok")]);
    assert_eq!(env.rows("app/old").await.unwrap(), 0);
    env.destroy().await.unwrap();
}

/// A stdout that fails, like a closed pipe.
struct Broken;

impl std::io::Write for Broken {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

/// Fail closed: a run whose start can't be audited doesn't touch anything,
/// and is due again within a minute, not a day.
#[tokio::test]
async fn an_unaudited_run_never_starts() {
    let env = Env::new().await.unwrap();
    env.deleted_long_ago("app/old").await.unwrap();
    let unaudited = Arc::new(Gate::new(
        Arc::new(AllowAll),
        AuditLog::new(Broken, Duration::from_secs(1)).unwrap(),
    ));
    let scheduler = env.scheduler(unaudited);
    let stop = CancellationToken::new();
    assert_eq!(
        tasks(&scheduler.tick(&stop).await),
        [(Task::Purge, "failed"), (Task::Rewrap, "failed")]
    );
    assert_eq!(env.rows("app/old").await.unwrap(), 1);
    let (states, now) = env.store().scheduled_tasks().await.unwrap();
    for state in &states {
        assert_eq!(state.last_result.as_deref(), Some("failed"));
        assert!(
            state.next_due - now <= time::Duration::seconds(61),
            "{state:?}"
        );
    }

    // Audited again, the retry does the work.
    env.all_due().await.unwrap();
    let scheduler = env.scheduler(Arc::clone(&env.gate));
    assert_eq!(
        tasks(&scheduler.tick(&stop).await),
        [(Task::Purge, "ok"), (Task::Rewrap, "ok")]
    );
    assert_eq!(env.rows("app/old").await.unwrap(), 0);
    env.destroy().await.unwrap();
}

/// Shutting down, a server starts nothing.
#[tokio::test]
async fn nothing_starts_once_stopped() {
    let env = Env::new().await.unwrap();
    let scheduler = env.scheduler(Arc::clone(&env.gate));
    let stop = CancellationToken::new();
    stop.cancel();
    assert!(scheduler.tick(&stop).await.is_empty());
    let (states, now) = env.store().scheduled_tasks().await.unwrap();
    assert!(
        states
            .iter()
            .all(|s| s.next_due <= now && s.last_started.is_none())
    );
    env.destroy().await.unwrap();
}
