//! Test support shared by the store and server tests: a throwaway Postgres
//! database per test, created from the server named by an env var (read from
//! the workspace-root `.env`), migrated, and dropped by [`TestDatabase::destroy`].
//!
//! Not `#[sqlx::test]`: it only reads `DATABASE_URL`, which can't point at
//! both store databases in one `cargo test` run.

pub mod data;
pub mod jwt;
pub mod pki;

use std::io::{self, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sqlx::migrate::Migrator;
use sqlx::postgres::PgConnectOptions;
use sqlx::{AssertSqlSafe, PgPool};

/// Helpers return errors instead of unwrapping: `allow-unwrap-in-tests` only
/// covers `#[test]` functions, not helpers.
pub type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// A writer whose output tests can read back, like the audit log's.
#[derive(Clone, Debug, Default)]
pub struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    /// The audit entries as their callers wrote them: without the hash
    /// chain's own lines (`chain_start`, `checkpoint`, `chain_end`) and without the
    /// `seq` and `prev` the chain appends to every line (see
    /// `ferritor_core::audit_chain`). Inside a JSON string every `"` is
    /// escaped, so the last unescaped `,"seq":` is always that suffix.
    pub fn lines(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.raw())
            .lines()
            .filter(|line| {
                !["chain_start", "checkpoint", "chain_end"]
                    .iter()
                    .any(|event| line.contains(&format!(r#""event":"{event}""#)))
            })
            .map(|line| match line.rfind(r#","seq":"#) {
                Some(at) => format!("{}}}", &line[..at]),
                None => line.to_owned(),
            })
            .collect()
    }

    /// Everything written, byte for byte, chain included.
    pub fn raw(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

static NEXT_DB: AtomicU32 = AtomicU32::new(0);

pub struct TestDatabase {
    admin: PgPool,
    pool: PgPool,
    name: String,
}

impl TestDatabase {
    /// Creates `<prefix>_<pid>_<n>` on the server in `$url_var` and runs
    /// `migrator`. `prefix` must match `ferritor_%_test` so the cleanup command
    /// in docs/src/content/docs/contributing/development.md finds databases left behind by failed tests.
    pub async fn new(url_var: &str, prefix: &str, migrator: &Migrator) -> TestResult<Self> {
        // Searches parent directories, so it finds the workspace-root `.env`.
        dotenvy::dotenv().ok();
        let url = std::env::var(url_var)
            .map_err(|_| format!("{url_var} must be set (copy .env.example to .env)"))?;
        let admin = PgPool::connect(&url).await?;
        let name = format!(
            "{prefix}_{}_{}",
            std::process::id(),
            NEXT_DB.fetch_add(1, Ordering::Relaxed)
        );
        sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await?;
        let options = url.parse::<PgConnectOptions>()?.database(&name);
        let pool = PgPool::connect_with(options).await?;
        migrator.run(&pool).await?;
        Ok(Self { admin, pool, name })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Waits until `n` sessions on this database are blocked on a lock.
    pub async fn wait_for_lock_waiters(&self, n: i64) -> TestResult<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let waiting: Option<i64> = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname = $1 AND wait_event_type = 'Lock'",
            )
            .bind(&self.name)
            .fetch_one(&self.admin)
            .await?;
            if waiting == Some(n) {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(format!("expected {n} lock waiters, have {waiting:?}").into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Async, so it can't be `Drop`: a failing test leaves its database
    /// behind for inspection.
    pub async fn destroy(self) -> TestResult<()> {
        self.pool.close().await;
        sqlx::query(AssertSqlSafe(format!(
            "DROP DATABASE {} WITH (FORCE)",
            self.name
        )))
        .execute(&self.admin)
        .await?;
        Ok(())
    }
}
