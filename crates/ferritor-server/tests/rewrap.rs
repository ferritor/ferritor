//! Rewrap against real keys and data databases (one each per test, see
//! `ferritor-testkit`).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::Labels;
use ferritor_core::path::Namespace;
use ferritor_datastore::Datastore;
use ferritor_keystore::{KekState, Keystore};
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{AllowAll, Caller};
use ferritor_server::namespaces::Namespaces;
use ferritor_server::rewrap::{Rewrap, RewrapError, RewrapReport};
use ferritor_server::seal::Seal;
use ferritor_server::secrets::Secrets;
use ferritor_testkit::{TestDatabase, TestResult};

const ANON: Caller = Caller::Unauthenticated;

fn ns(name: &str) -> TestResult<Namespace> {
    Ok(Namespace::parse(name)?)
}

/// `(namespace, version)` pairs, as rewrap reports them.
fn keks(namespace: &str, versions: &[u32]) -> TestResult<Vec<(Namespace, u32)>> {
    let namespace = ns(namespace)?;
    Ok(versions.iter().map(|v| (namespace.clone(), *v)).collect())
}

/// An initialized, unsealed server with secrets and rewrap wired up.
struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    seal: Arc<Seal>,
    gate: Arc<Gate>,
    secrets: Secrets,
    rewrap: Rewrap,
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
            .init(ShareParams::new(5, 3)?)
            .await?
            .iter()
            .map(|s| s.to_bytes().to_vec())
            .collect();
        let gate = Arc::new(Gate::new(
            Arc::new(AllowAll),
            AuditLog::new(io::sink(), Duration::from_secs(5))?,
        ));
        let env = Self {
            secrets: Secrets::new(
                Arc::clone(&seal),
                Datastore::new(data.pool().clone()),
                Arc::clone(&gate),
            ),
            gate,
            rewrap: Rewrap::new(Arc::clone(&seal), Datastore::new(data.pool().clone())),
            keys,
            data,
            seal,
            shares,
        };
        env.unseal().await?;
        let namespaces = Namespaces::new(
            Arc::clone(&env.seal),
            Datastore::new(env.data.pool().clone()),
        );
        for name in ["app", "billing"] {
            namespaces.create(name, &Labels::new()).await?;
        }
        Ok(env)
    }

    async fn unseal(&self) -> TestResult<()> {
        for share in &self.shares[..3] {
            self.seal.unseal(share, false).await?;
        }
        Ok(())
    }

    /// `(path, version, kek_version)` of every row, deleted ones included.
    async fn rows(&self) -> TestResult<Vec<(String, i32, i32)>> {
        Ok(sqlx::query_as(
            "SELECT p.path, v.version, v.kek_version
                 FROM secret_versions v JOIN paths p ON p.id = v.path_id
                 ORDER BY p.path, v.version",
        )
        .fetch_all(self.data.pool())
        .await?)
    }

    /// `namespace`'s KEKs and their states, by version.
    async fn kek_states(&self, namespace: &str) -> TestResult<Vec<(u32, KekState)>> {
        Ok(Keystore::new(self.keys.pool().clone())
            .keks()
            .await?
            .into_iter()
            .filter(|k| k.namespace.as_str() == namespace)
            .map(|k| (k.version, k.state))
            .collect())
    }

    /// Repeats rewrap until done; returns the summed report.
    async fn rewrap_all(&self, max_rows: u32) -> TestResult<(RewrapReport, usize)> {
        let mut total = RewrapReport::default();
        for calls in 1..=100 {
            let report = self.rewrap.run(None, max_rows).await?;
            total.rewrapped += report.rewrapped;
            total.failed += report.failed;
            total.retired.extend(report.retired);
            if report.done {
                total.done = true;
                return Ok((total, calls));
            }
        }
        Err("rewrap never finished".into())
    }

    async fn destroy(self) -> TestResult<()> {
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

#[tokio::test]
async fn rotate_then_rewrap_moves_everything_and_retires_the_old_kek() {
    let env = Env::new().await.unwrap();
    for (path, value) in [("app/a", b"a"), ("app/b", b"b"), ("app/a", b"A")] {
        env.secrets.put(&ANON, path, value).await.unwrap();
    }
    assert_eq!(env.seal.rotate(&ns("app").unwrap()).await.unwrap(), 2);

    let (report, _) = env.rewrap_all(0).await.unwrap();
    assert_eq!(
        (report.rewrapped, report.failed, report.retired),
        (3, 0, keks("app", &[1]).unwrap())
    );
    assert!(
        env.rows()
            .await
            .unwrap()
            .iter()
            .all(|(_, _, kek)| *kek == 2)
    );
    assert_eq!(
        env.kek_states("app").await.unwrap(),
        [(1, KekState::Retired), (2, KekState::Active)]
    );

    // Readable now and after a reseal, every version.
    env.seal.seal().await;
    env.unseal().await.unwrap();
    let old = env.secrets.get(&ANON, "app/a", Some(1)).await.unwrap();
    assert_eq!(old.value.as_slice(), b"a");
    let latest = env.secrets.get(&ANON, "app/a", None).await.unwrap();
    assert_eq!(latest.value.as_slice(), b"A");

    // Nothing left to do: a further run is a no-op.
    let again = env.rewrap.run(None, 0).await.unwrap();
    assert_eq!(
        again,
        RewrapReport {
            done: true,
            ..RewrapReport::default()
        }
    );
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn several_rotations_are_all_drained_and_retired() {
    let env = Env::new().await.unwrap();
    env.secrets.put(&ANON, "app/v1", b"1").await.unwrap();
    env.seal.rotate(&ns("app").unwrap()).await.unwrap();
    env.secrets.put(&ANON, "app/v2", b"2").await.unwrap();
    env.seal.rotate(&ns("app").unwrap()).await.unwrap();
    env.secrets.put(&ANON, "app/v3", b"3").await.unwrap();

    let (report, _) = env.rewrap_all(0).await.unwrap();
    assert_eq!(
        (report.rewrapped, report.retired),
        (2, keks("app", &[1, 2]).unwrap())
    );
    assert!(
        env.rows()
            .await
            .unwrap()
            .iter()
            .all(|(_, _, kek)| *kek == 3)
    );
    for (path, value) in [("app/v1", b"1"), ("app/v2", b"2"), ("app/v3", b"3")] {
        let secret = env.secrets.get(&ANON, path, None).await.unwrap();
        assert_eq!(secret.value.as_slice(), value);
    }
    env.destroy().await.unwrap();
}

/// Each call is bounded; `done` only once everything is drained, and only
/// then is anything retired.
#[tokio::test]
async fn a_small_budget_takes_several_calls() {
    let env = Env::new().await.unwrap();
    for i in 0..7 {
        env.secrets
            .put(&ANON, &format!("app/s{i}"), b"x")
            .await
            .unwrap();
    }
    env.seal.rotate(&ns("app").unwrap()).await.unwrap();

    let first = env.rewrap.run(None, 3).await.unwrap();
    assert_eq!((first.rewrapped, first.done), (3, false));
    assert!(first.retired.is_empty());
    let (rest, calls) = env.rewrap_all(3).await.unwrap();
    assert_eq!(
        (rest.rewrapped, rest.retired),
        (4, keks("app", &[1]).unwrap())
    );
    assert_eq!(calls, 2);
    env.destroy().await.unwrap();
}

/// A DEK that doesn't unwrap (here: tampered with) is left alone and
/// counted. It keeps its own KEK version from being retired, but not others.
#[tokio::test]
async fn a_row_that_does_not_unwrap_blocks_retiring_only_its_version() {
    let env = Env::new().await.unwrap();
    env.secrets.put(&ANON, "app/bad", b"b").await.unwrap();
    env.seal.rotate(&ns("app").unwrap()).await.unwrap();
    env.secrets.put(&ANON, "app/good", b"g").await.unwrap();
    env.seal.rotate(&ns("app").unwrap()).await.unwrap();
    sqlx::query(
        "UPDATE secret_versions SET wrapped_dek = '\\x00'
         WHERE path_id = (SELECT id FROM paths WHERE path = 'app/bad')",
    )
    .execute(env.data.pool())
    .await
    .unwrap();

    let report = env.rewrap.run(None, 0).await.unwrap();
    assert_eq!((report.rewrapped, report.failed, report.done), (1, 1, true));
    assert_eq!(report.retired, keks("app", &[2]).unwrap());
    assert_eq!(
        env.rows().await.unwrap(),
        [("app/bad".to_owned(), 1, 1), ("app/good".to_owned(), 1, 3)]
    );
    assert_eq!(
        env.kek_states("app").await.unwrap(),
        [
            (1, KekState::DecryptOnly),
            (2, KekState::Retired),
            (3, KekState::Active)
        ]
    );
    env.destroy().await.unwrap();
}

/// Deleted rows keep their DEKs; moving them too is what lets the old KEK
/// be retired.
#[tokio::test]
async fn deleted_rows_are_rewrapped_too() {
    let env = Env::new().await.unwrap();
    env.secrets.put(&ANON, "app/gone", b"x").await.unwrap();
    env.secrets.delete(&ANON, "app/gone").await.unwrap();
    env.seal.rotate(&ns("app").unwrap()).await.unwrap();

    let (report, _) = env.rewrap_all(0).await.unwrap();
    assert_eq!(
        (report.rewrapped, report.retired),
        (1, keks("app", &[1]).unwrap())
    );
    assert_eq!(env.rows().await.unwrap(), [("app/gone".to_owned(), 1, 2)]);
    env.destroy().await.unwrap();
}

/// The stale-server case: a server that hasn't resealed since the rotation
/// keeps wrapping with its old active KEK, even after that KEK was retired.
/// Its rows stay readable (retired keys stay loaded), and the next pass moves
/// them.
#[tokio::test]
async fn rows_a_stale_server_writes_with_a_retired_kek_are_moved_next_time() {
    let env = Env::new().await.unwrap();
    // A second server, unsealed before the rotation: active KEK 1.
    let stale_seal = Arc::new(Seal::new(Keystore::new(env.keys.pool().clone())));
    for share in &env.shares[..3] {
        stale_seal.unseal(share, false).await.unwrap();
    }
    let stale = Secrets::new(
        Arc::clone(&stale_seal),
        Datastore::new(env.data.pool().clone()),
        Arc::clone(&env.gate),
    );

    env.seal.rotate(&ns("app").unwrap()).await.unwrap();
    let (report, _) = env.rewrap_all(0).await.unwrap();
    assert_eq!(report.retired, keks("app", &[1]).unwrap());

    stale.put(&ANON, "app/late", b"late").await.unwrap();
    assert_eq!(env.rows().await.unwrap(), [("app/late".to_owned(), 1, 1)]);
    let read = env.secrets.get(&ANON, "app/late", None).await.unwrap();
    assert_eq!(read.value.as_slice(), b"late");

    let (report, _) = env.rewrap_all(0).await.unwrap();
    assert_eq!((report.rewrapped, report.retired), (1, vec![]));
    assert_eq!(env.rows().await.unwrap(), [("app/late".to_owned(), 1, 2)]);
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn a_sealed_server_refuses_to_rewrap() {
    let env = Env::new().await.unwrap();
    env.seal.seal().await;
    assert!(matches!(
        env.rewrap.run(None, 0).await,
        Err(RewrapError::Sealed)
    ));
    env.destroy().await.unwrap();
}

/// A rotation is one namespace's: rewrapping moves only its rows, onto its
/// own new KEK, and retires only its old one. Another namespace's rows and
/// KEK are left as they are, and rewrapping just that one finds nothing.
#[tokio::test]
async fn rewrap_moves_only_the_rotated_namespace() {
    let env = Env::new().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"a").await.unwrap();
    env.secrets.put(&ANON, "billing/db", b"b").await.unwrap();
    assert_eq!(env.seal.rotate(&ns("app").unwrap()).await.unwrap(), 2);

    let billing_only = env
        .rewrap
        .run(Some(&ns("billing").unwrap()), 0)
        .await
        .unwrap();
    assert_eq!(
        billing_only,
        RewrapReport {
            done: true,
            ..RewrapReport::default()
        }
    );
    let (report, _) = env.rewrap_all(0).await.unwrap();
    assert_eq!(
        (report.rewrapped, report.retired),
        (1, keks("app", &[1]).unwrap())
    );
    assert_eq!(
        env.rows().await.unwrap(),
        [("app/db".to_owned(), 1, 2), ("billing/db".to_owned(), 1, 1)]
    );
    assert_eq!(
        env.kek_states("billing").await.unwrap(),
        [(1, KekState::Active)]
    );
    // Both still read: each row with its own namespace's KEK.
    for (path, value) in [("app/db", b"a"), ("billing/db", b"b")] {
        let secret = env.secrets.get(&ANON, path, None).await.unwrap();
        assert_eq!(secret.value.as_slice(), value);
    }
    env.destroy().await.unwrap();
}
