//! Secret CRUD against real keys and data databases (one each per test, see
//! `ferritor-testkit`), plus an end-to-end pass over gRPC for status codes.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ferritor_core::crypto::{CryptoError, ShareParams};
use ferritor_core::labels::Labels;
use ferritor_core::path::{Namespace, SecretPath};
use ferritor_core::proto::v1 as pb;
use ferritor_core::proto::v1::secrets_service_client::SecretsServiceClient;
use ferritor_core::proto::v1::secrets_service_server::SecretsServiceServer;
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{Action, AllowAll, Authorizer, Caller, Denied, Target};
use ferritor_server::grpc;
use ferritor_server::namespaces::{NamespaceError, Namespaces};
use ferritor_server::policy::{Policy, Rule};
use ferritor_server::seal::Seal;
use ferritor_server::secrets::{Secrets, SecretsError, VersionPage};
use ferritor_testkit::data::insert_version;
use ferritor_testkit::{Captured, TestDatabase, TestResult};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Code;

const ANON: Caller = Caller::Unauthenticated;

/// The namespaces the tests store under; created at the first unseal.
const NAMESPACES: [&str; 3] = ["app", "b", "other"];

fn app() -> TestResult<Namespace> {
    Ok(Namespace::parse("app")?)
}

/// Creates `names` (once: a later unseal finds them there).
async fn create_namespaces(
    seal: &Arc<Seal>,
    data: &TestDatabase,
    names: &[&str],
) -> TestResult<()> {
    let namespaces = Namespaces::new(Arc::clone(seal), Datastore::new(data.pool().clone()));
    for name in names {
        match namespaces.create(name, &Labels::new()).await {
            Ok(_) | Err(NamespaceError::Exists(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// An initialized server with secrets wired up; sealed until [`Env::unseal`].
struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    seal: Arc<Seal>,
    gate: Arc<Gate>,
    /// What the audit log wrote.
    audit: Captured,
    secrets: Arc<Secrets>,
    shares: Vec<Vec<u8>>,
}

impl Env {
    async fn sealed_with(authz: Arc<dyn Authorizer>) -> TestResult<Self> {
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
        let shares = seal
            .init(ShareParams::new(5, 3)?)
            .await?
            .iter()
            .map(|s| s.to_bytes().to_vec())
            .collect();
        let audit = Captured::default();
        let gate = Arc::new(Gate::new(
            authz,
            AuditLog::new(audit.clone(), Duration::from_secs(5))?,
        ));
        let secrets = Arc::new(Secrets::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
            Arc::clone(&gate),
        ));
        Ok(Self {
            keys,
            data,
            seal,
            gate,
            audit,
            secrets,
            shares,
        })
    }

    async fn sealed() -> TestResult<Self> {
        Self::sealed_with(Arc::new(AllowAll)).await
    }

    async fn unsealed() -> TestResult<Self> {
        let env = Self::sealed().await?;
        env.unseal().await?;
        Ok(env)
    }

    async fn unseal(&self) -> TestResult<()> {
        for share in &self.shares[..3] {
            self.seal.unseal(share, false).await?;
        }
        create_namespaces(&self.seal, &self.data, &NAMESPACES).await
    }

    /// Blocks every query on the paths and their versions until the
    /// transaction ends: a stand-in for a slow or hung data database. (A row
    /// lock wouldn't do: plain reads don't wait for row locks.)
    async fn stall_secrets(&self) -> TestResult<sqlx::Transaction<'static, sqlx::Postgres>> {
        let mut tx = self.data.pool().begin().await?;
        sqlx::query("LOCK TABLE paths, secret_versions IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    async fn destroy(self) -> TestResult<()> {
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

#[tokio::test]
async fn put_then_get_round_trips_every_version() {
    let env = Env::unsealed().await.unwrap();
    let first = env.secrets.put(&ANON, "app/db", b"one").await.unwrap();
    let second = env.secrets.put(&ANON, "app/db", b"two").await.unwrap();
    assert_eq!((first.version, second.version), (1, 2));

    let latest = env.secrets.get(&ANON, "app/db", None).await.unwrap();
    assert_eq!(
        (latest.metadata.version, latest.value.as_slice()),
        (2, &b"two"[..])
    );
    let old = env.secrets.get(&ANON, "app/db", Some(1)).await.unwrap();
    assert_eq!(old.value.as_slice(), b"one");

    // Empty values are values too.
    env.secrets.put(&ANON, "app/empty", b"").await.unwrap();
    assert!(
        env.secrets
            .get(&ANON, "app/empty", None)
            .await
            .unwrap()
            .value
            .is_empty()
    );
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn missing_secrets_and_versions_are_not_found() {
    let env = Env::unsealed().await.unwrap();
    assert!(matches!(
        env.secrets.get(&ANON, "app/none", None).await,
        Err(SecretsError::NotFound { .. })
    ));
    env.secrets.put(&ANON, "app/db", b"one").await.unwrap();
    assert!(matches!(
        env.secrets.get(&ANON, "app/db", Some(2)).await,
        Err(SecretsError::VersionNotFound { version: 2, .. })
    ));
    assert!(matches!(
        env.secrets.delete(&ANON, "app/none").await,
        Err(SecretsError::NotFound { .. })
    ));
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn non_canonical_paths_are_rejected() {
    let env = Env::unsealed().await.unwrap();
    for path in [
        "/app/db",
        "app//db",
        "app/db/",
        "",
        "app/../db",
        "app/caf\u{e9}",
    ] {
        assert!(
            matches!(
                env.secrets.put(&ANON, path, b"x").await,
                Err(SecretsError::InvalidPath(_))
            ),
            "{path:?}"
        );
    }
    assert!(matches!(
        env.secrets.list(&ANON, "/app", 0, "", &Labels::new()).await,
        Err(SecretsError::InvalidPath(_))
    ));
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn delete_hides_all_versions_and_numbering_continues() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"one").await.unwrap();
    env.secrets.put(&ANON, "app/db", b"two").await.unwrap();
    env.secrets.delete(&ANON, "app/db").await.unwrap();
    assert!(matches!(
        env.secrets.get(&ANON, "app/db", Some(1)).await,
        Err(SecretsError::VersionNotFound { .. })
    ));
    assert_eq!(
        env.secrets
            .put(&ANON, "app/db", b"three")
            .await
            .unwrap()
            .version,
        3
    );
    env.destroy().await.unwrap();
}

/// Check-and-set: a write lands only if the latest live version is still
/// the one expected, so a stale writer can't silently overwrite (or
/// resurrect) what someone else wrote or deleted.
#[tokio::test]
async fn put_if_stores_only_over_the_expected_version() {
    let env = Env::unsealed().await.unwrap();
    let version =
        |r: Result<ferritor_datastore::SecretMetadata, SecretsError>| r.map(|m| m.version);
    let mismatch = |r: Result<ferritor_datastore::SecretMetadata, SecretsError>| match r {
        Err(SecretsError::VersionMismatch {
            expected, latest, ..
        }) => Some((expected, latest)),
        _ => None,
    };

    // 0: create only.
    assert_eq!(
        version(env.secrets.put_if(&ANON, "app/db", b"one", 0).await).unwrap(),
        1
    );
    assert_eq!(
        mismatch(env.secrets.put_if(&ANON, "app/db", b"again", 0).await),
        Some((0, Some(1)))
    );
    // Over the version read: yes; over a stale one: no, and nothing stored.
    assert_eq!(
        version(env.secrets.put_if(&ANON, "app/db", b"two", 1).await).unwrap(),
        2
    );
    let stale = env.secrets.put_if(&ANON, "app/db", b"lost", 1).await;
    assert_eq!(
        stale.as_ref().err().map(|e| e.to_string()),
        Some("`app/db` was changed: its latest version is 2, expected 1; read it again".to_owned())
    );
    assert_eq!(mismatch(stale), Some((1, Some(2))));
    let latest = env.secrets.get(&ANON, "app/db", None).await.unwrap();
    assert_eq!(
        (latest.metadata.version, latest.value.as_slice()),
        (2, &b"two"[..])
    );

    // Deleted since it was read: a mismatch too, not a resurrection.
    env.secrets.delete(&ANON, "app/db").await.unwrap();
    assert_eq!(
        mismatch(env.secrets.put_if(&ANON, "app/db", b"back", 2).await),
        Some((2, None))
    );
    // But creating it anew is fine; numbers move on.
    assert_eq!(
        version(env.secrets.put_if(&ANON, "app/db", b"new", 0).await).unwrap(),
        3
    );
    env.destroy().await.unwrap();
}

/// Two writers who read the same version: exactly one of them wins, the
/// other is told, whatever the timing (they take turns on the path's lock).
#[tokio::test(flavor = "multi_thread")]
async fn of_two_concurrent_check_and_sets_exactly_one_lands() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"one").await.unwrap();
    for round in 1..=5 {
        let (a, b) = tokio::join!(
            env.secrets.put_if(&ANON, "app/db", b"a", round),
            env.secrets.put_if(&ANON, "app/db", b"b", round),
        );
        let landed = [&a, &b].iter().filter(|r| r.is_ok()).count();
        let refused = [&a, &b]
            .iter()
            .filter(|r| matches!(r, Err(SecretsError::VersionMismatch { .. })))
            .count();
        assert_eq!((landed, refused), (1, 1), "round {round}: {a:?} {b:?}");
    }
    env.destroy().await.unwrap();
}

/// With a version limit, a client sees only the newest versions: an older
/// one is gone (not found), the latest and a check-and-set against it are
/// unaffected.
#[tokio::test]
async fn only_the_newest_versions_are_kept() {
    let env = Env::unsealed().await.unwrap();
    let limited = Secrets::new(
        Arc::clone(&env.seal),
        Datastore::new(env.data.pool().clone()).with_max_versions(2),
        Arc::clone(&env.gate),
    );
    for value in [b"one", b"two", b"thr"] {
        limited.put(&ANON, "app/db", value).await.unwrap();
    }
    assert!(matches!(
        limited.get(&ANON, "app/db", Some(1)).await,
        Err(SecretsError::VersionNotFound { version: 1, .. })
    ));
    assert_eq!(
        limited
            .get(&ANON, "app/db", Some(2))
            .await
            .unwrap()
            .value
            .as_slice(),
        b"two"
    );
    let next = limited.put_if(&ANON, "app/db", b"fou", 3).await.unwrap();
    assert_eq!(next.version, 4);
    assert!(limited.get(&ANON, "app/db", Some(2)).await.is_err());
    env.destroy().await.unwrap();
}

/// A deleted version comes back, newest first unless one is named, and
/// is audited. Without a version only while none is live (undoing a
/// delete); nothing to restore is "not found", and a sealed server
/// restores nothing.
#[tokio::test]
async fn a_deleted_secret_can_be_restored() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"one").await.unwrap();
    env.secrets.put(&ANON, "app/db", b"two").await.unwrap();
    env.secrets.delete(&ANON, "app/db").await.unwrap();

    let restored = env.secrets.restore(&ANON, "app/db", None).await.unwrap();
    assert_eq!(restored.version, 2);
    let latest = env.secrets.get(&ANON, "app/db", None).await.unwrap();
    assert_eq!(latest.value.as_slice(), b"two");
    assert!(env.secrets.get(&ANON, "app/db", Some(1)).await.is_err());
    assert_eq!(
        env.secrets
            .restore(&ANON, "app/db", Some(1))
            .await
            .unwrap()
            .version,
        1
    );

    // Version 1 deleted again (by a trim, say): without a version, the live
    // one stops the restore.
    env.secrets.delete(&ANON, "app/db").await.unwrap();
    env.secrets.restore(&ANON, "app/db", Some(2)).await.unwrap();
    assert!(matches!(
        env.secrets.restore(&ANON, "app/db", None).await,
        Err(SecretsError::LiveVersion { latest: 2, .. })
    ));
    assert!(env.secrets.get(&ANON, "app/db", Some(1)).await.is_err());
    let nothing = env.secrets.restore(&ANON, "app/none", None).await;
    assert_eq!(
        nothing.err().map(|e| e.to_string()),
        Some("`app/none` has no deleted version to restore (none, or all purged)".to_owned())
    );
    assert!(matches!(
        env.secrets.restore(&ANON, "app/db", Some(2)).await,
        Err(SecretsError::NothingToRestore {
            version: Some(2),
            ..
        })
    ));

    env.secrets.delete(&ANON, "app/db").await.unwrap();
    env.seal.seal().await;
    assert!(matches!(
        env.secrets.restore(&ANON, "app/db", None).await,
        Err(SecretsError::Sealed)
    ));
    env.unseal().await.unwrap();
    assert!(env.secrets.get(&ANON, "app/db", None).await.is_err());

    for _ in 0..100 {
        if env
            .audit
            .lines()
            .iter()
            .filter(|l| l.contains("\"restore\""))
            .count()
            >= 7
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let restores: Vec<(String, serde_json::Value)> = env
        .audit
        .lines()
        .iter()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|e| e["operation"] == "restore")
        .map(|e| {
            (
                e["result"].as_str().unwrap_or_default().to_owned(),
                e["details"].clone(),
            )
        })
        .collect();
    assert_eq!(
        restores,
        [
            ("succeeded".to_owned(), json!({"version": 2})),
            ("succeeded".to_owned(), json!({"version": 1})),
            ("succeeded".to_owned(), json!({"version": 2})),
            ("failed".to_owned(), serde_json::Value::Null),
            ("failed".to_owned(), serde_json::Value::Null),
            ("failed".to_owned(), serde_json::Value::Null),
            ("failed".to_owned(), serde_json::Value::Null),
        ]
    );
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn list_returns_latest_versions_under_a_prefix() {
    let env = Env::unsealed().await.unwrap();
    for path in ["app/db", "app/db/a", "app/db/b", "app/db/b", "app/db0"] {
        env.secrets.put(&ANON, path, b"x").await.unwrap();
    }
    let listed: Vec<_> = env
        .secrets
        .list(&ANON, "app/db", 0, "", &Labels::new())
        .await
        .unwrap()
        .secrets
        .into_iter()
        .map(|m| (m.path.to_string(), m.version))
        .collect();
    assert_eq!(
        listed,
        [("app/db/a".to_owned(), 1), ("app/db/b".to_owned(), 2)]
    );
    assert_eq!(
        env.secrets
            .list(&ANON, "", 0, "", &Labels::new())
            .await
            .unwrap()
            .secrets
            .len(),
        4
    );
    env.destroy().await.unwrap();
}

/// Every page of a listing, following the tokens.
async fn pages(env: &Env, prefix: &str, page_size: u32) -> TestResult<Vec<Vec<String>>> {
    let mut pages = Vec::new();
    let mut token = String::new();
    loop {
        let page = env
            .secrets
            .list(&ANON, prefix, page_size, &token, &Labels::new())
            .await?;
        pages.push(page.secrets.iter().map(|m| m.path.to_string()).collect());
        if page.next_page_token.is_empty() {
            return Ok(pages);
        }
        token = page.next_page_token;
    }
}

#[tokio::test]
async fn list_pages_follow_the_token_to_the_end() {
    let env = Env::unsealed().await.unwrap();
    for path in ["app/a", "app/b", "app/c", "app/d", "app/e", "b"] {
        env.secrets.put(&ANON, path, b"x").await.unwrap();
    }
    assert_eq!(
        pages(&env, "app", 2).await.unwrap(),
        [
            vec!["app/a", "app/b"],
            vec!["app/c", "app/d"],
            vec!["app/e"]
        ]
    );
    // A full last page is the last: no empty page after it.
    env.secrets.delete(&ANON, "app/e").await.unwrap();
    assert_eq!(
        pages(&env, "app", 2).await.unwrap(),
        [vec!["app/a", "app/b"], vec!["app/c", "app/d"]]
    );
    assert_eq!(pages(&env, "", 0).await.unwrap().concat().len(), 5);

    // A secret deleted between pages just doesn't show; none repeats.
    let first = env
        .secrets
        .list(&ANON, "app", 2, "", &Labels::new())
        .await
        .unwrap();
    env.secrets.delete(&ANON, "app/c").await.unwrap();
    let second = env
        .secrets
        .list(&ANON, "app", 2, &first.next_page_token, &Labels::new())
        .await
        .unwrap();
    assert_eq!(
        second
            .secrets
            .iter()
            .map(|m| m.path.as_str())
            .collect::<Vec<_>>(),
        ["app/d"]
    );
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn a_page_token_only_resumes_the_same_prefix() {
    let env = Env::unsealed().await.unwrap();
    for path in ["app/a", "app/b", "other/a"] {
        env.secrets.put(&ANON, path, b"x").await.unwrap();
    }
    let first = env
        .secrets
        .list(&ANON, "app", 1, "", &Labels::new())
        .await
        .unwrap();
    assert!(!first.next_page_token.is_empty());
    for (prefix, token) in [
        ("other", first.next_page_token.as_str()),
        ("app/a", first.next_page_token.as_str()),
        ("app", "not a token"),
    ] {
        assert!(
            matches!(
                env.secrets
                    .list(&ANON, prefix, 1, token, &Labels::new())
                    .await,
                Err(SecretsError::InvalidPageToken)
            ),
            "{prefix} {token}"
        );
    }
    // The empty prefix covers everything, so any listing's token resumes it.
    let all = env
        .secrets
        .list(&ANON, "", 10, &first.next_page_token, &Labels::new())
        .await
        .unwrap();
    assert_eq!(all.secrets.len(), 2);
    env.destroy().await.unwrap();
}

/// 0 asks for the default size; anything above the maximum gets the maximum.
#[tokio::test]
async fn page_sizes_default_and_are_capped() {
    use ferritor_server::secrets::{DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE};

    let env = Env::unsealed().await.unwrap();
    // Listing never decrypts, so placeholder rows will do.
    sqlx::query(
        "WITH ns AS (
             INSERT INTO namespaces (name) VALUES ('app')
             ON CONFLICT (name) DO UPDATE SET kek_floor = namespaces.kek_floor
             RETURNING id
         ), p AS (
             INSERT INTO paths (namespace_id, path, highest, current_version)
             SELECT ns.id, 'app/' || lpad(g::text, 5, '0'), 1, 1
             FROM ns, generate_series(1, $1) g
             RETURNING id, namespace_id
         )
         INSERT INTO secret_versions
             (path_id, namespace_id, version, ciphertext, wrapped_dek, kek_version)
         SELECT id, namespace_id, 1, '\\x00', '\\x00', 1 FROM p",
    )
    .bind(i32::try_from(MAX_PAGE_SIZE + 1).unwrap())
    .execute(env.data.pool())
    .await
    .unwrap();
    let len = |page: &ferritor_server::secrets::Page| u32::try_from(page.secrets.len()).unwrap();

    let default = env
        .secrets
        .list(&ANON, "app", 0, "", &Labels::new())
        .await
        .unwrap();
    assert_eq!(len(&default), DEFAULT_PAGE_SIZE);
    let capped = env
        .secrets
        .list(&ANON, "app", u32::MAX, "", &Labels::new())
        .await
        .unwrap();
    assert_eq!(len(&capped), MAX_PAGE_SIZE);
    let rest = env
        .secrets
        .list(
            &ANON,
            "app",
            u32::MAX,
            &capped.next_page_token,
            &Labels::new(),
        )
        .await
        .unwrap();
    assert_eq!((len(&rest), rest.next_page_token.as_str()), (1, ""));
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn a_sealed_server_refuses_every_secret_operation() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"x").await.unwrap();
    env.seal.seal().await;

    assert!(matches!(
        env.secrets.get(&ANON, "app/db", None).await,
        Err(SecretsError::Sealed)
    ));
    assert!(matches!(
        env.secrets.put(&ANON, "app/db", b"y").await,
        Err(SecretsError::Sealed)
    ));
    assert!(matches!(
        env.secrets.delete(&ANON, "app/db").await,
        Err(SecretsError::Sealed)
    ));
    assert!(matches!(
        env.secrets.list(&ANON, "", 0, "", &Labels::new()).await,
        Err(SecretsError::Sealed)
    ));

    // Nothing was lost: unseal and it's all there.
    env.unseal().await.unwrap();
    let secret = env.secrets.get(&ANON, "app/db", None).await.unwrap();
    assert_eq!(secret.value.as_slice(), b"x");
    env.destroy().await.unwrap();
}

/// Old secrets stay readable through the KEK version they were wrapped by;
/// new ones use the new active KEK.
#[tokio::test]
async fn secrets_survive_rotation_and_reseal() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/old", b"old").await.unwrap();
    assert_eq!(env.seal.rotate(&app().unwrap()).await.unwrap(), 2);
    env.secrets.put(&ANON, "app/new", b"new").await.unwrap();

    let kek_versions: Vec<(String, i32)> = sqlx::query_as(
        "SELECT p.path, v.kek_version FROM secret_versions v JOIN paths p ON p.id = v.path_id
             ORDER BY p.path",
    )
    .fetch_all(env.data.pool())
    .await
    .unwrap();
    assert_eq!(
        kek_versions,
        [("app/new".to_owned(), 2), ("app/old".to_owned(), 1)]
    );

    env.seal.seal().await;
    env.unseal().await.unwrap();
    for (path, value) in [("app/old", &b"old"[..]), ("app/new", &b"new"[..])] {
        let secret = env.secrets.get(&ANON, path, None).await.unwrap();
        assert_eq!(secret.value.as_slice(), value);
    }
    env.destroy().await.unwrap();
}

/// The AAD binds path and version, so ciphertexts moved between rows don't
/// decrypt, and the failure is an internal error, not wrong data.
#[tokio::test]
async fn swapped_ciphertexts_do_not_decrypt() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"one").await.unwrap();
    env.secrets.put(&ANON, "app/db", b"two").await.unwrap();
    env.secrets.put(&ANON, "app/other", b"three").await.unwrap();

    // Version 1's ciphertext and DEK into version 2's row.
    sqlx::query(
        "UPDATE secret_versions AS dst
         SET ciphertext = src.ciphertext, wrapped_dek = src.wrapped_dek
         FROM secret_versions AS src
         WHERE src.path_id = (SELECT id FROM paths WHERE path = 'app/db') AND src.version = 1
           AND dst.path_id = src.path_id AND dst.version = 2",
    )
    .execute(env.data.pool())
    .await
    .unwrap();
    assert!(matches!(
        env.secrets.get(&ANON, "app/db", None).await,
        Err(SecretsError::Crypto(CryptoError::Decrypt))
    ));

    // A whole row moved to another path (renaming a path is refused by the
    // database itself, but a row can be pointed at another one).
    sqlx::query(
        "DELETE FROM secret_versions WHERE path_id = (SELECT id FROM paths WHERE path = 'app/other')",
    )
    .execute(env.data.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE secret_versions SET path_id = (SELECT id FROM paths WHERE path = 'app/other')
         WHERE path_id = (SELECT id FROM paths WHERE path = 'app/db') AND version = 1",
    )
    .execute(env.data.pool())
    .await
    .unwrap();
    assert!(matches!(
        env.secrets.get(&ANON, "app/other", None).await,
        Err(SecretsError::Crypto(CryptoError::Decrypt))
    ));
    env.destroy().await.unwrap();
}

/// Concurrent puts to one path queue on its lock: all land, numbered
/// without gaps. (No retry limit to stay under.)
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_puts_all_land_with_distinct_versions() {
    const PUTS: u32 = 20;
    let env = Env::unsealed().await.unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..PUTS {
        let secrets = Arc::clone(&env.secrets);
        tasks.spawn(async move {
            secrets
                .put(&ANON, "app/db", format!("value {i}").as_bytes())
                .await
                .map(|m| m.version)
        });
    }
    let mut versions = tasks
        .join_all()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    versions.sort_unstable();
    assert_eq!(versions, (1..=PUTS).collect::<Vec<_>>());
    env.destroy().await.unwrap();
}

/// Another server rotated: a read meeting the new KEK refreshes this
/// server's keyring (with the root key it holds) and succeeds, no reseal;
/// the refresh is audited. Reads trigger at most one per cooldown.
#[tokio::test]
async fn a_kek_rotated_elsewhere_is_picked_up_on_read() {
    let env = Env::unsealed().await.unwrap();
    let other_seal = Arc::new(Seal::new(Keystore::new(env.keys.pool().clone())));
    for share in &env.shares[..3] {
        other_seal.unseal(share, false).await.unwrap();
    }
    assert_eq!(other_seal.rotate(&app().unwrap()).await.unwrap(), 2);
    let other = Secrets::new(
        other_seal,
        Datastore::new(env.data.pool().clone()),
        Arc::clone(&env.gate),
    );
    other.put(&ANON, "app/db", b"x").await.unwrap();

    assert_eq!(
        env.secrets
            .get(&ANON, "app/db", None)
            .await
            .unwrap()
            .value
            .as_slice(),
        b"x"
    );
    // And new DEKs are wrapped by the new active KEK from now on.
    assert_eq!(env.seal.active_kek_version(&app().unwrap()), Some(2));

    // Within the cooldown a read refreshes no more: another rotation stays
    // unknown until the periodic refresh (not running here).
    let other = Secrets::new(
        {
            let seal = Arc::new(Seal::new(Keystore::new(env.keys.pool().clone())));
            for share in &env.shares[..3] {
                seal.unseal(share, false).await.unwrap();
            }
            assert_eq!(seal.rotate(&app().unwrap()).await.unwrap(), 3);
            seal
        },
        Datastore::new(env.data.pool().clone()),
        Arc::clone(&env.gate),
    );
    other.put(&ANON, "app/next", b"y").await.unwrap();
    assert!(matches!(
        env.secrets.get(&ANON, "app/next", None).await,
        Err(SecretsError::UnknownKek(3))
    ));

    for _ in 0..100 {
        if env
            .audit
            .lines()
            .iter()
            .any(|l| l.contains("keyring_refresh"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let refresh: Vec<serde_json::Value> = env
        .audit
        .lines()
        .iter()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|e| e["event"] == "keyring_refresh")
        .collect();
    assert_eq!(refresh.len(), 1);
    assert_eq!(
        (
            &refresh[0]["trigger"],
            &refresh[0]["result"],
            &refresh[0]["active"],
            &refresh[0]["vanished"]
        ),
        (
            &json!("unknown_kek"),
            &json!("succeeded"),
            &json!({"app": 2, "b": 1, "other": 1}),
            &serde_json::Value::Null
        )
    );
    env.destroy().await.unwrap();
}

/// Once seal returns, no request may use the keys: a read that was stuck on
/// the data database across the seal must not return plaintext afterwards.
#[tokio::test]
async fn a_read_stuck_across_a_seal_returns_sealed() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"secret").await.unwrap();
    let stall = env.stall_secrets().await.unwrap();

    let (read, ()) = tokio::join!(env.secrets.get(&ANON, "app/db", None), async {
        env.data.wait_for_lock_waiters(1).await.unwrap();
        env.seal.seal().await;
        stall.rollback().await.unwrap();
    });
    assert!(matches!(read, Err(SecretsError::Sealed)));
    env.destroy().await.unwrap();
}

/// Even if the server is unsealed again meanwhile: the request predates the
/// seal. (A check for "is there a keyring now?" would let this one through.)
#[tokio::test]
async fn a_read_stuck_across_a_seal_and_unseal_still_returns_sealed() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"secret").await.unwrap();
    let stall = env.stall_secrets().await.unwrap();

    let (read, ()) = tokio::join!(env.secrets.get(&ANON, "app/db", None), async {
        env.data.wait_for_lock_waiters(1).await.unwrap();
        env.seal.seal().await;
        env.unseal().await.unwrap();
        stall.rollback().await.unwrap();
    });
    assert!(matches!(read, Err(SecretsError::Sealed)));
    // A fresh request is fine.
    let secret = env.secrets.get(&ANON, "app/db", None).await.unwrap();
    assert_eq!(secret.value.as_slice(), b"secret");
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn a_write_stuck_across_a_seal_returns_sealed_and_stores_nothing() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"old").await.unwrap();
    let stall = env.stall_secrets().await.unwrap();

    let (written, ()) = tokio::join!(env.secrets.put(&ANON, "app/db", b"new"), async {
        env.data.wait_for_lock_waiters(1).await.unwrap();
        env.seal.seal().await;
        stall.rollback().await.unwrap();
    });
    assert!(matches!(written, Err(SecretsError::Sealed)));
    env.unseal().await.unwrap();
    let latest = env.secrets.get(&ANON, "app/db", None).await.unwrap();
    assert_eq!(
        (latest.metadata.version, latest.value.as_slice()),
        (1, &b"old"[..])
    );
    env.destroy().await.unwrap();
}

/// Seal freezes the data plane too: a delete stuck across a seal is rolled
/// back, not committed afterwards.
#[tokio::test]
async fn a_delete_stuck_across_a_seal_returns_sealed_and_deletes_nothing() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"kept").await.unwrap();
    let stall = env.stall_secrets().await.unwrap();

    let (deleted, ()) = tokio::join!(env.secrets.delete(&ANON, "app/db"), async {
        env.data.wait_for_lock_waiters(1).await.unwrap();
        env.seal.seal().await;
        stall.rollback().await.unwrap();
    });
    assert!(matches!(deleted, Err(SecretsError::Sealed)));
    env.unseal().await.unwrap();
    let secret = env.secrets.get(&ANON, "app/db", None).await.unwrap();
    assert_eq!(secret.value.as_slice(), b"kept");
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn a_list_stuck_across_a_seal_returns_sealed() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"x").await.unwrap();
    let stall = env.stall_secrets().await.unwrap();

    let no_labels = Labels::new();
    let (listed, ()) = tokio::join!(env.secrets.list(&ANON, "", 0, "", &no_labels), async {
        env.data.wait_for_lock_waiters(1).await.unwrap();
        env.seal.seal().await;
        stall.rollback().await.unwrap();
    });
    assert!(matches!(listed, Err(SecretsError::Sealed)));
    env.destroy().await.unwrap();
}

/// The insert itself can stall (here: on the primary key, behind another
/// transaction's uncommitted row with the same path and version). The check
/// between insert and commit must still roll the put back.
#[tokio::test]
async fn a_put_stuck_in_its_insert_across_a_seal_returns_sealed() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"old").await.unwrap();
    let mut blocker = env.data.pool().begin().await.unwrap();
    insert_version(&mut blocker, "app/db", 2, 1).await.unwrap();

    let (written, ()) = tokio::join!(env.secrets.put(&ANON, "app/db", b"new"), async {
        // The put got version 2 (the blocker's row is invisible to it) and
        // now waits on the primary key: encryption is already done.
        env.data.wait_for_lock_waiters(1).await.unwrap();
        env.seal.seal().await;
        blocker.rollback().await.unwrap();
    });
    assert!(matches!(written, Err(SecretsError::Sealed)));
    env.unseal().await.unwrap();
    let latest = env.secrets.get(&ANON, "app/db", None).await.unwrap();
    assert_eq!(
        (latest.metadata.version, latest.value.as_slice()),
        (1, &b"old"[..])
    );
    env.destroy().await.unwrap();
}

/// Secrets over the same databases, with short bounds. The call bound
/// leaves room beside the lock wait on a busy machine (a put's other
/// statements share it): at 300 ms, a slow runner could turn `Busy` into
/// `DataTimeout`.
fn impatient(env: &Env) -> Secrets {
    Secrets::new(
        Arc::clone(&env.seal),
        Datastore::new(env.data.pool().clone())
            .with_timeout(Duration::from_secs(1))
            .with_lock_timeout(Duration::from_millis(100)),
        Arc::clone(&env.gate),
    )
}

#[tokio::test]
async fn a_stalled_data_database_times_out() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"x").await.unwrap();
    let stall = env.stall_secrets().await.unwrap();

    let started = std::time::Instant::now();
    let read = impatient(&env).get(&ANON, "app/db", None).await;
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(matches!(read, Err(SecretsError::DataTimeout)));
    assert_eq!(
        tonic::Status::from(SecretsError::DataTimeout).code(),
        Code::Unavailable
    );
    stall.rollback().await.unwrap();
    env.destroy().await.unwrap();
}

/// A put stuck behind another put to the same path gives up with "busy,
/// retry" (ABORTED), not a generic timeout.
#[tokio::test]
async fn a_put_behind_a_long_put_to_the_same_path_is_busy() {
    let env = Env::unsealed().await.unwrap();
    let path = ferritor_core::path::SecretPath::parse("app/db").unwrap();
    let holder = Datastore::new(env.data.pool().clone())
        .begin_put(&path)
        .await
        .unwrap();

    let written = impatient(&env).put(&ANON, "app/db", b"x").await;
    assert!(matches!(written, Err(SecretsError::Busy(_))));
    let status = tonic::Status::from(written.err().unwrap());
    assert_eq!(
        (status.code(), status.message()),
        (
            Code::Aborted,
            "too many concurrent writes to `app/db`; retry"
        )
    );
    drop(holder);
    env.destroy().await.unwrap();
}

/// A secret's history: live and deleted versions, newest first, paged;
/// "not found" for a path with nothing stored; it takes `list` on the path
/// (metadata, not a read), and a sealed server shows none.
#[tokio::test]
async fn the_history_shows_live_and_deleted_versions() {
    let env = Env::unsealed().await.unwrap();
    for value in [b"one", b"two", b"tri"] {
        env.secrets.put(&ANON, "app/db", value).await.unwrap();
    }
    env.secrets.delete(&ANON, "app/db").await.unwrap();
    env.secrets.put(&ANON, "app/db", b"for").await.unwrap();

    let summary = |page: &VersionPage| -> Vec<(u32, bool)> {
        page.versions
            .iter()
            .map(|v| (v.metadata.version, v.deleted_at.is_some()))
            .collect()
    };
    let all = env.secrets.versions(&ANON, "app/db", 0, "").await.unwrap();
    assert_eq!(
        (summary(&all), all.next_page_token.as_str()),
        (vec![(4, false), (3, true), (2, true), (1, true)], "")
    );
    let first = env.secrets.versions(&ANON, "app/db", 3, "").await.unwrap();
    assert_eq!(summary(&first), [(4, false), (3, true), (2, true)]);
    let rest = env
        .secrets
        .versions(&ANON, "app/db", 3, &first.next_page_token)
        .await
        .unwrap();
    assert_eq!(
        (summary(&rest), rest.next_page_token.as_str()),
        (vec![(1, true)], "")
    );

    assert!(matches!(
        env.secrets.versions(&ANON, "app/db", 0, "app/db").await,
        Err(SecretsError::InvalidPageToken)
    ));
    assert!(matches!(
        env.secrets.versions(&ANON, "app/none", 0, "").await,
        Err(SecretsError::NotFound { .. })
    ));
    env.seal.seal().await;
    assert!(matches!(
        env.secrets.versions(&ANON, "app/db", 0, "").await,
        Err(SecretsError::Sealed)
    ));
    env.destroy().await.unwrap();

    let recording = Arc::new(Recording {
        deny: Some(Action::List),
        seen: Mutex::default(),
    });
    let env = Env::sealed_with(recording.clone()).await.unwrap();
    env.unseal().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"one").await.unwrap();
    assert!(matches!(
        env.secrets.versions(&ANON, "app/db", 0, "").await,
        Err(SecretsError::Denied(_))
    ));
    assert_eq!(
        recording
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last(),
        Some(&(Action::List, "`app/db`".to_owned()))
    );
    env.destroy().await.unwrap();
}

/// Records every authorization request, and denies one action.
struct Recording {
    deny: Option<Action>,
    seen: Mutex<Vec<(Action, String)>>,
}

impl Authorizer for Recording {
    fn authorize(&self, caller: &Caller, action: Action, target: Target<'_>) -> Result<(), Denied> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((action, target.to_string()));
        if self.deny == Some(action) {
            return Err(Denied::new(caller, action, target));
        }
        Ok(())
    }
}

/// Every secret operation leaves an entry naming the path, never the value;
/// writes also record what they did (version, versions trimmed or deleted),
/// failures included.
#[tokio::test]
async fn secret_operations_are_audited_without_values() {
    let env = Env::unsealed().await.unwrap();
    let limited = Secrets::new(
        Arc::clone(&env.seal),
        Datastore::new(env.data.pool().clone()).with_max_versions(2),
        Arc::clone(&env.gate),
    );
    for _ in 0..3 {
        limited.put(&ANON, "app/db", b"hunter2").await.unwrap();
    }
    assert!(limited.put_if(&ANON, "app/db", b"stale", 1).await.is_err());
    env.secrets.get(&ANON, "app/db", None).await.unwrap();
    env.secrets
        .list(&ANON, "app", 0, "", &Labels::new())
        .await
        .unwrap();
    env.secrets.delete(&ANON, "app/db").await.unwrap();

    // Outcomes are queued, not waited for: the delete's may still be.
    for _ in 0..100 {
        if env.audit.lines().len() >= 12 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let lines = env.audit.lines();
    assert!(
        lines
            .iter()
            .all(|line| !line.contains("hunter2") && !line.contains("stale"))
    );
    let audited: Vec<serde_json::Value> = lines
        .iter()
        .map(|line| {
            let mut entry: serde_json::Value = serde_json::from_str(line).unwrap();
            let entry = entry.as_object_mut().unwrap();
            for noise in ["time", "caller"] {
                entry.remove(noise);
            }
            serde_json::Value::Object(entry.clone())
        })
        .collect();
    let path = |p: &str| json!({"kind": "path", "path": p});
    let allowed = |action: &str, target: serde_json::Value| json!({"event": "authorization", "action": action, "target": target, "decision": "allowed"});
    let put = |details: serde_json::Value| {
        json!({"event": "outcome", "action": "write", "target": path("app/db"),
               "operation": "put", "result": "succeeded", "details": details})
    };
    assert_eq!(
        audited,
        [
            allowed("write", path("app/db")),
            put(json!({"version": 1, "trimmed": 0})),
            allowed("write", path("app/db")),
            put(json!({"version": 2, "trimmed": 0})),
            allowed("write", path("app/db")),
            put(json!({"version": 3, "trimmed": 1})),
            allowed("write", path("app/db")),
            json!({"event": "outcome", "action": "write", "target": path("app/db"),
                   "operation": "put", "result": "failed",
                   "error": "`app/db` was changed: its latest version is 3, expected 1; read it again"}),
            allowed("read", path("app/db")),
            allowed("list", json!({"kind": "below", "path": "app"})),
            allowed("delete", path("app/db")),
            json!({"event": "outcome", "action": "delete", "target": path("app/db"),
                   "operation": "delete", "result": "succeeded", "details": {"deleted": 2}}),
        ]
    );
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

/// Fail closed: allowed but unrecorded is refused, before touching data.
#[tokio::test]
async fn an_unaudited_request_is_refused_and_changes_nothing() {
    let env = Env::unsealed().await.unwrap();
    env.secrets.put(&ANON, "app/db", b"one").await.unwrap();
    let unaudited = Secrets::new(
        Arc::clone(&env.seal),
        Datastore::new(env.data.pool().clone()),
        Arc::new(Gate::new(
            Arc::new(AllowAll),
            AuditLog::new(Broken, Duration::from_secs(5)).unwrap(),
        )),
    );
    assert!(matches!(
        unaudited.get(&ANON, "app/db", None).await,
        Err(SecretsError::Unaudited(_))
    ));
    assert!(matches!(
        unaudited.put(&ANON, "app/db", b"two").await,
        Err(SecretsError::Unaudited(_))
    ));
    assert!(matches!(
        unaudited.delete(&ANON, "app/db").await,
        Err(SecretsError::Unaudited(_))
    ));
    assert!(matches!(
        unaudited.list(&ANON, "", 0, "", &Labels::new()).await,
        Err(SecretsError::Unaudited(_))
    ));
    let latest = env.secrets.get(&ANON, "app/db", None).await.unwrap();
    assert_eq!(latest.value.as_slice(), b"one");
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn every_operation_is_authorized_with_its_action_and_target() {
    let authz = Arc::new(Recording {
        deny: None,
        seen: Mutex::new(Vec::new()),
    });
    let env = Env::sealed_with(authz.clone()).await.unwrap();
    env.unseal().await.unwrap();

    env.secrets.put(&ANON, "app/db", b"x").await.unwrap();
    env.secrets.get(&ANON, "app/db", None).await.unwrap();
    env.secrets
        .list(&ANON, "app", 0, "", &Labels::new())
        .await
        .unwrap();
    env.secrets
        .list(&ANON, "", 0, "", &Labels::new())
        .await
        .unwrap();
    env.secrets.delete(&ANON, "app/db").await.unwrap();

    let seen = authz.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        [
            (Action::Write, "`app/db`".to_owned()),
            (Action::Read, "`app/db`".to_owned()),
            (Action::List, "secrets under `app`".to_owned()),
            (Action::List, "all secrets".to_owned()),
            (Action::Delete, "`app/db`".to_owned()),
        ]
    );
    env.destroy().await.unwrap();
}

/// A denial comes before anything else: even a sealed server answers
/// "denied", and nothing is written.
#[tokio::test]
async fn denial_comes_before_the_seal_check_and_any_data_access() {
    let authz = Arc::new(Recording {
        deny: Some(Action::Write),
        seen: Mutex::new(Vec::new()),
    });
    let env = Env::sealed_with(authz).await.unwrap();
    let denied = env.secrets.put(&ANON, "app/db", b"x").await;
    assert!(matches!(denied, Err(SecretsError::Denied(_))));
    assert_eq!(
        denied.err().map(|e| ferritor_server::error_chain(&e)),
        Some("permission denied: unauthenticated caller may not write `app/db`".to_owned())
    );

    env.unseal().await.unwrap();
    assert!(matches!(
        env.secrets.put(&ANON, "app/db", b"x").await,
        Err(SecretsError::Denied(_))
    ));
    assert!(
        env.secrets
            .list(&ANON, "", 0, "", &Labels::new())
            .await
            .unwrap()
            .secrets
            .is_empty()
    );
    env.destroy().await.unwrap();
}

/// Code and message of a failed call.
fn rejection<T>(result: Result<T, tonic::Status>) -> Option<(Code, String)> {
    result.err().map(|s| (s.code(), s.message().to_owned()))
}

fn rejected(code: Code, message: &str) -> Option<(Code, String)> {
    Some((code, message.to_owned()))
}

/// Status codes and messages as a client sees them, over a real connection.
#[tokio::test]
async fn grpc_secrets_round_trip_and_status_codes() {
    let env = Env::sealed().await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(SecretsServiceServer::new(grpc::Secrets::new(Arc::clone(
                &env.secrets,
            ))))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let mut client = SecretsServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    let put = |path: &str, value: &[u8]| pb::PutSecretRequest {
        path: path.to_owned(),
        value: value.to_vec(),
        expected_version: None,
        labels: Default::default(),
    };
    let get = |path: &str, version: u32| pb::GetSecretRequest {
        path: path.to_owned(),
        version,
    };

    assert_eq!(
        rejection(client.put_secret(put("app/db", b"x")).await),
        rejected(Code::FailedPrecondition, "the server is sealed")
    );
    env.unseal().await.unwrap();

    client.put_secret(put("app/db", b"one")).await.unwrap();
    let metadata = client
        .put_secret(put("app/db", b"two"))
        .await
        .unwrap()
        .into_inner()
        .metadata
        .unwrap();
    assert_eq!((metadata.path.as_str(), metadata.version), ("app/db", 2));
    assert!(metadata.created_at_unix > 0);

    // Version 0 means latest.
    let latest = client
        .get_secret(get("app/db", 0))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(latest.secret.map(|s| s.value), Some(b"two".to_vec()));
    let first = client
        .get_secret(get("app/db", 1))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.secret.map(|s| s.value), Some(b"one".to_vec()));

    assert_eq!(
        rejection(client.get_secret(get("app/db", 9)).await),
        rejected(Code::NotFound, "version 9 of secret `app/db` not found")
    );
    assert_eq!(
        rejection(client.get_secret(get("/app/db", 0)).await),
        rejected(
            Code::InvalidArgument,
            "invalid secret path: secret path has an empty segment (leading, trailing or doubled `/`)"
        )
    );

    let listed = client
        .list_secrets(pb::ListSecretsRequest {
            prefix: "app".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (listed.secrets.len(), listed.next_page_token.as_str()),
        (1, "")
    );
    assert_eq!(
        rejection(
            client
                .list_secrets(pb::ListSecretsRequest {
                    prefix: "app".to_owned(),
                    page_size: 1,
                    page_token: "zz".to_owned(),
                    labels: Default::default(),
                })
                .await
        ),
        rejected(
            Code::InvalidArgument,
            "invalid page token; pass back the next_page_token of the previous page of the same \
             listing (the same prefix, or the same path)"
        )
    );
    client
        .delete_secret(pb::DeleteSecretRequest {
            path: "app/db".to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(
        rejection(client.get_secret(get("app/db", 0)).await),
        rejected(Code::NotFound, "secret `app/db` not found")
    );

    serving.abort();
    env.destroy().await.unwrap();
}

fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// A path's metadata through its life: created and updated times, current
/// and oldest version, labels set with a put and changed on their own,
/// kept across a delete. Refused for a path never written, and for labels
/// that don't check out (too many, invalid keys or values), before anything
/// changes.
#[tokio::test]
async fn metadata_and_labels_follow_a_secret() {
    let env = Env::unsealed().await.unwrap();
    let stored = env
        .secrets
        .put_labeled(&ANON, "app/db", b"one", None, &labels(&[("team", "a")]))
        .await
        .unwrap();
    assert_eq!(stored.version, 1);
    let first = env.secrets.metadata(&ANON, "app/db").await.unwrap();
    assert_eq!(
        (first.current_version, first.oldest_version, first.versions),
        (Some(1), Some(1), 1)
    );
    assert_eq!(first.labels, labels(&[("team", "a")]));

    env.secrets.put(&ANON, "app/db", b"two").await.unwrap();
    let after_rotation = env.secrets.metadata(&ANON, "app/db").await.unwrap();
    assert_eq!(after_rotation.current_version, Some(2));
    assert_eq!(after_rotation.created_at, first.created_at);
    assert!(after_rotation.updated_at >= first.updated_at);
    // A put without labels leaves them.
    assert_eq!(after_rotation.labels, labels(&[("team", "a")]));

    let changed = env
        .secrets
        .update_labels(
            &ANON,
            "app/db",
            &labels(&[("project", "b"), ("team", "c")]),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(changed, labels(&[("project", "b"), ("team", "c")]));
    let changed = env
        .secrets
        .update_labels(&ANON, "app/db", &Labels::new(), &["project".to_owned()])
        .await
        .unwrap();
    assert_eq!(changed, labels(&[("team", "c")]));

    env.secrets.delete(&ANON, "app/db").await.unwrap();
    let deleted = env.secrets.metadata(&ANON, "app/db").await.unwrap();
    assert_eq!(
        (
            deleted.current_version,
            deleted.oldest_version,
            deleted.versions
        ),
        (None, Some(1), 2)
    );
    assert_eq!(deleted.labels, labels(&[("team", "c")]));

    assert!(matches!(
        env.secrets.metadata(&ANON, "app/never").await,
        Err(SecretsError::NotFound { .. })
    ));
    assert!(matches!(
        env.secrets
            .update_labels(&ANON, "app/never", &labels(&[("team", "a")]), &[])
            .await,
        Err(SecretsError::NotFound { .. })
    ));
    assert!(matches!(
        env.secrets
            .update_labels(&ANON, "app/db", &labels(&[("bad key", "a")]), &[])
            .await,
        Err(SecretsError::InvalidLabels(_))
    ));
    let many: Labels = (0..64).map(|i| (format!("k{i}"), "v".to_owned())).collect();
    assert!(matches!(
        env.secrets.update_labels(&ANON, "app/db", &many, &[]).await,
        Err(SecretsError::TooManyLabels { count: 65 })
    ));
    // An invalid label on a put stores nothing.
    assert!(matches!(
        env.secrets
            .put_labeled(&ANON, "app/db", b"x", None, &labels(&[("team", "a\nb")]))
            .await,
        Err(SecretsError::InvalidLabels(_))
    ));
    assert_eq!(
        env.secrets
            .metadata(&ANON, "app/db")
            .await
            .unwrap()
            .versions,
        2
    );
    env.destroy().await.unwrap();
}

/// Listing filters by labels: every one must match, inside the prefix.
#[tokio::test]
async fn listing_filters_by_label() {
    let env = Env::unsealed().await.unwrap();
    for (path, set) in [
        ("app/a", labels(&[("team", "a"), ("env", "prod")])),
        ("app/b", labels(&[("team", "a")])),
        ("app/c", labels(&[("team", "b")])),
    ] {
        env.secrets
            .put_labeled(&ANON, path, b"x", None, &set)
            .await
            .unwrap();
    }
    env.secrets.put(&ANON, "app/d", b"x").await.unwrap();
    let secrets = &env.secrets;
    let list = |filter: Labels| async move {
        secrets
            .list(&ANON, "app", 0, "", &filter)
            .await
            .map(|page| {
                page.secrets
                    .into_iter()
                    .map(|m| m.path.to_string())
                    .collect::<Vec<_>>()
            })
    };
    assert_eq!(
        list(labels(&[("team", "a")])).await.unwrap(),
        ["app/a", "app/b"]
    );
    assert_eq!(
        list(labels(&[("team", "a"), ("env", "prod")]))
            .await
            .unwrap(),
        ["app/a"]
    );
    assert_eq!(list(Labels::new()).await.unwrap().len(), 4);
    assert!(matches!(
        list(labels(&[("bad key", "a")])).await,
        Err(SecretsError::InvalidLabels(_))
    ));
    env.destroy().await.unwrap();
}

/// Changing labels is its own action, `label`: a writer without it can't
/// set labels (not even with a put, which then stores nothing), and a
/// labeller without `write` can tag but not store. Reading the metadata is
/// `list`, like the history.
#[tokio::test]
async fn labels_need_their_own_permission() {
    let rule = |identity: &str, actions: Vec<Action>| Rule {
        name: None,
        identity: identity.to_owned(),
        actions,
        paths: vec!["app".to_owned()],
        all_paths: false,
    };
    let policy = Policy::new(&[
        rule(
            "ops/writer",
            vec![Action::Write, Action::Read, Action::List],
        ),
        rule("ops/tagger", vec![Action::Label]),
    ])
    .unwrap();
    let env = Env::sealed_with(Arc::new(policy)).await.unwrap();
    env.unseal().await.unwrap();
    let who = |name: &str| Caller::Identity(SecretPath::parse(name).unwrap());
    let (writer, tagger) = (who("ops/writer"), who("ops/tagger"));

    assert!(matches!(
        env.secrets
            .put_labeled(&writer, "app/db", b"x", None, &labels(&[("team", "a")]))
            .await,
        Err(SecretsError::Denied(_))
    ));
    assert!(matches!(
        env.secrets.metadata(&writer, "app/db").await,
        Err(SecretsError::NotFound { .. })
    ));
    env.secrets.put(&writer, "app/db", b"x").await.unwrap();
    assert!(matches!(
        env.secrets
            .update_labels(&writer, "app/db", &labels(&[("team", "a")]), &[])
            .await,
        Err(SecretsError::Denied(_))
    ));
    env.secrets
        .update_labels(&tagger, "app/db", &labels(&[("team", "a")]), &[])
        .await
        .unwrap();
    assert!(matches!(
        env.secrets.put(&tagger, "app/db", b"y").await,
        Err(SecretsError::Denied(_))
    ));
    assert!(matches!(
        env.secrets.metadata(&tagger, "app/db").await,
        Err(SecretsError::Denied(_))
    ));
    let seen = env.secrets.metadata(&writer, "app/db").await.unwrap();
    assert_eq!((seen.versions, seen.labels), (1, labels(&[("team", "a")])));
    env.destroy().await.unwrap();
}

/// The audit log records which label keys changed, never their values;
/// a seal stops label changes and metadata reads like any data call.
#[tokio::test]
async fn label_changes_are_audited_by_key_and_stop_at_a_seal() {
    let env = Env::unsealed().await.unwrap();
    env.secrets
        .put_labeled(
            &ANON,
            "app/db",
            b"x",
            None,
            &labels(&[("owner", "value-on-put")]),
        )
        .await
        .unwrap();
    env.secrets
        .update_labels(
            &ANON,
            "app/db",
            &labels(&[("team", "value-on-update")]),
            &["owner".to_owned()],
        )
        .await
        .unwrap();
    let mut outcomes = Vec::new();
    for _ in 0..200 {
        outcomes = env
            .audit
            .lines()
            .into_iter()
            .filter(|line| line.contains(r#""event":"outcome""#))
            .collect::<Vec<_>>();
        if outcomes.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let entries: Vec<serde_json::Value> = outcomes
        .iter()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        entries[0]["details"]["labels_set"],
        serde_json::json!(["owner"])
    );
    assert_eq!(
        (&entries[1]["operation"], &entries[1]["details"]),
        (
            &serde_json::json!("label"),
            &serde_json::json!({"set": ["team"], "removed": ["owner"], "labels": 1})
        )
    );
    let log = env.audit.lines().concat();
    assert!(!log.contains("value-on-put") && !log.contains("value-on-update"));

    env.seal.seal().await;
    assert!(matches!(
        env.secrets.metadata(&ANON, "app/db").await,
        Err(SecretsError::Sealed)
    ));
    assert!(matches!(
        env.secrets
            .update_labels(&ANON, "app/db", &labels(&[("team", "b")]), &[])
            .await,
        Err(SecretsError::Sealed)
    ));
    env.destroy().await.unwrap();
}

/// There's no default namespace: a put under a first segment that isn't one
/// is refused. But only once the caller is authorized for it: a caller who
/// may not write there learns PERMISSION_DENIED either way, so the answer
/// can't be used to find out which namespaces exist.
#[tokio::test]
async fn no_namespace_is_only_told_to_an_authorized_caller() {
    let policy = Policy::new(&[
        Rule {
            name: None,
            identity: "ops/writer".to_owned(),
            actions: vec![Action::Write],
            paths: vec![],
            all_paths: true,
        },
        Rule {
            name: None,
            identity: "ops/app-only".to_owned(),
            actions: vec![Action::Write],
            paths: vec!["app".to_owned()],
            all_paths: false,
        },
    ])
    .unwrap();
    let env = Env::sealed_with(Arc::new(policy)).await.unwrap();
    env.unseal().await.unwrap();
    let who = |name: &str| Caller::Identity(SecretPath::parse(name).unwrap());
    let (writer, app_only) = (who("ops/writer"), who("ops/app-only"));

    let refused = env.secrets.put(&writer, "nope/db", b"x").await.unwrap_err();
    assert!(matches!(refused, SecretsError::NoNamespace(_)), "{refused}");
    let status = tonic::Status::from(refused);
    assert_eq!(
        (status.code(), grpc::reason_of(&status).as_deref()),
        (
            Code::FailedPrecondition,
            Some(ferritor_core::messages::reason::NO_NAMESPACE)
        )
    );
    // Not allowed there: denied, whether or not the namespace exists.
    for path in ["nope/db", "other/db"] {
        assert!(matches!(
            env.secrets.put(&app_only, path, b"x").await,
            Err(SecretsError::Denied(_))
        ));
    }
    env.secrets.put(&app_only, "app/db", b"x").await.unwrap();
    env.destroy().await.unwrap();
}
