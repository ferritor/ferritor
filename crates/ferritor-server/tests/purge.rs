//! Purge against real keys and data databases (one each per test, see
//! `ferritor-testkit`): deleted versions past their retention go for good,
//! nothing else does, and version numbers are never freed.

use std::sync::Arc;
use std::time::Duration;

use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::Labels;
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{AllowAll, Caller};
use ferritor_server::namespaces::Namespaces;
use ferritor_server::purge::{Purge, PurgeError, PurgeReport};
use ferritor_server::seal::Seal;
use ferritor_server::secrets::{Secrets, SecretsError};
use ferritor_testkit::{TestDatabase, TestResult};

const ANON: Caller = Caller::Unauthenticated;

/// An initialized, unsealed server with secrets wired up.
struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    seal: Arc<Seal>,
    secrets: Secrets,
    shares: Vec<Vec<u8>>,
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
        let namespaces = Namespaces::new(Arc::clone(&seal), Datastore::new(data.pool().clone()));
        for name in ["app", "a", "b", "c", "old", "recent", "live"] {
            namespaces.create(name, &Labels::new()).await?;
        }
        let gate = Arc::new(Gate::new(
            Arc::new(AllowAll),
            AuditLog::new(std::io::sink(), Duration::from_secs(5))?,
        ));
        let secrets = Secrets::new(Arc::clone(&seal), Datastore::new(data.pool().clone()), gate);
        Ok(Self {
            keys,
            data,
            seal,
            secrets,
            shares,
        })
    }

    fn purge(&self, retention: Duration) -> Purge {
        Purge::new(
            Arc::clone(&self.seal),
            Datastore::new(self.data.pool().clone()),
            retention,
        )
    }

    /// Backdates every deletion of `path` by `ago` (a Postgres interval).
    async fn deleted_ago(&self, path: &str, ago: &str) -> TestResult<()> {
        sqlx::query(
            "UPDATE secret_versions SET deleted_at = now() - $2::interval
             WHERE path_id = (SELECT id FROM paths WHERE path = $1) AND deleted_at IS NOT NULL",
        )
        .bind(path)
        .bind(ago)
        .execute(self.data.pool())
        .await?;
        Ok(())
    }

    /// Rows of `path`, deleted or not.
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

    async fn destroy(self) -> TestResult<()> {
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

#[tokio::test]
async fn purge_removes_deletions_past_retention_and_nothing_else() {
    let env = Env::new().await.unwrap();
    for path in ["old", "old", "recent", "live"] {
        env.secrets.put(&ANON, path, b"x").await.unwrap();
    }
    env.secrets.delete(&ANON, "old").await.unwrap();
    env.secrets.delete(&ANON, "recent").await.unwrap();
    env.deleted_ago("old", "31 days").await.unwrap();
    env.deleted_ago("recent", "29 days").await.unwrap();

    let purge = env.purge(Duration::from_secs(30 * 24 * 3600));
    assert_eq!(
        purge.run(0).await.unwrap(),
        PurgeReport {
            purged: 2,
            done: true
        }
    );
    assert_eq!(env.rows("old").await.unwrap(), 0);
    assert_eq!(env.rows("recent").await.unwrap(), 1);
    assert_eq!(
        env.secrets
            .get(&ANON, "live", None)
            .await
            .unwrap()
            .value
            .as_slice(),
        b"x"
    );
    // Nothing left past retention: a no-op, done.
    assert_eq!(
        purge.run(0).await.unwrap(),
        PurgeReport {
            purged: 0,
            done: true
        }
    );

    // The purged path's numbering continues, as a check-and-set expects.
    let next = env.secrets.put_if(&ANON, "old", b"y", 0).await.unwrap();
    assert_eq!(next.version, 3);
    env.destroy().await.unwrap();
}

/// Bounded per call: `max_rows` at most, `done` once nothing is left.
#[tokio::test]
async fn purge_is_bounded_and_resumes() {
    let env = Env::new().await.unwrap();
    for path in ["a", "b", "c"] {
        env.secrets.put(&ANON, path, b"x").await.unwrap();
        env.secrets.delete(&ANON, path).await.unwrap();
    }
    let purge = env.purge(Duration::ZERO);
    let first = purge.run(2).await.unwrap();
    assert_eq!(
        first,
        PurgeReport {
            purged: 2,
            done: false
        }
    );
    let rest = purge.run(2).await.unwrap();
    assert_eq!(
        rest,
        PurgeReport {
            purged: 1,
            done: true
        }
    );
    env.destroy().await.unwrap();
}

/// The seal freezes the data plane, purge included: it needs no keys, but
/// a sealed server changes nothing.
#[tokio::test]
async fn a_sealed_server_purges_nothing() {
    let env = Env::new().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"x").await.unwrap();
    env.secrets.delete(&ANON, "app/db").await.unwrap();
    env.seal.seal().await;
    assert!(matches!(
        env.purge(Duration::ZERO).run(0).await,
        Err(PurgeError::Sealed)
    ));
    assert_eq!(env.rows("app/db").await.unwrap(), 1);

    for share in &env.shares[..2] {
        env.seal.unseal(share, false).await.unwrap();
    }
    assert_eq!(env.purge(Duration::ZERO).run(0).await.unwrap().purged, 1);
    assert!(matches!(
        env.secrets.get(&ANON, "app/db", Some(1)).await,
        Err(SecretsError::VersionNotFound { .. })
    ));
    env.destroy().await.unwrap();
}
