//! Destroying retired KEKs against real keys and data databases (one each
//! per test, see `ferritor-testkit`).

use std::sync::Arc;
use std::time::Duration;

use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::Labels;
use ferritor_core::path::Namespace;
use ferritor_datastore::Datastore;
use ferritor_keystore::{KekState, Keystore};
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{AllowAll, Caller};
use ferritor_server::destroy::{Destroy, DestroyError, Destroyed};
use ferritor_server::keyring::{self, MismatchError, Unloaded};
use ferritor_server::namespaces::{NamespaceError, Namespaces};
use ferritor_server::rewrap::Rewrap;
use ferritor_server::seal::{RekeyPhase, Seal};
use ferritor_server::secrets::{Secrets, SecretsError};
use ferritor_testkit::data::insert_version;
use ferritor_testkit::{Captured, TestDatabase, TestResult};

const ANON: Caller = Caller::Unauthenticated;

fn ns(name: &str) -> TestResult<Namespace> {
    Ok(Namespace::parse(name)?)
}

fn app() -> TestResult<Namespace> {
    ns("app")
}

/// `(namespace, version)` pairs, as the reports and checks name KEKs.
fn keks(namespace: &str, versions: &[u32]) -> TestResult<Vec<(Namespace, u32)>> {
    let namespace = ns(namespace)?;
    Ok(versions.iter().map(|v| (namespace.clone(), *v)).collect())
}

/// What destroying `app`'s KEK `version` reports.
fn destroyed(version: u32, destroyed: bool, kek_floor: u32) -> TestResult<Destroyed> {
    Ok(Destroyed {
        namespace: app()?,
        version,
        destroyed,
        kek_floor,
    })
}

/// An initialized, unsealed server with secrets, rewrap and destroy.
struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    seal: Arc<Seal>,
    gate: Arc<Gate>,
    /// What the audit log wrote.
    audit: Captured,
    secrets: Secrets,
    rewrap: Rewrap,
    destroy: Destroy,
    namespaces: Namespaces,
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
        let shares = seal
            .init(ShareParams::new(5, 3)?)
            .await?
            .iter()
            .map(|s| s.to_bytes().to_vec())
            .collect();
        let audit = Captured::default();
        let gate = Arc::new(Gate::new(
            Arc::new(AllowAll),
            AuditLog::new(audit.clone(), Duration::from_secs(5))?,
        ));
        let store = || Datastore::new(data.pool().clone());
        let env = Self {
            secrets: Secrets::new(Arc::clone(&seal), store(), Arc::clone(&gate)),
            rewrap: Rewrap::new(Arc::clone(&seal), store()),
            destroy: Destroy::new(Arc::clone(&seal), store()),
            namespaces: Namespaces::new(Arc::clone(&seal), store()),
            gate,
            audit,
            keys,
            data,
            seal,
            shares,
        };
        env.unseal(&env.seal).await?;
        env.namespaces.create("app", &Labels::new()).await?;
        Ok(env)
    }

    async fn unseal(&self, seal: &Seal) -> TestResult<()> {
        for share in &self.shares[..3] {
            seal.unseal(share, false).await?;
        }
        Ok(())
    }

    /// Another server on the same databases, unsealed now: its keyring is
    /// as of now, and goes stale with the next rotation elsewhere.
    async fn second_server(&self) -> TestResult<(Arc<Seal>, Secrets)> {
        let seal = Arc::new(Seal::new(Keystore::new(self.keys.pool().clone())));
        self.unseal(&seal).await?;
        let secrets = Secrets::new(
            Arc::clone(&seal),
            Datastore::new(self.data.pool().clone()),
            Arc::clone(&self.gate),
        );
        Ok((seal, secrets))
    }

    /// `namespace`'s KEKs and their states, by version.
    async fn kek_states_of(&self, namespace: &str) -> TestResult<Vec<(u32, KekState)>> {
        Ok(Keystore::new(self.keys.pool().clone())
            .kek_states()
            .await?
            .into_iter()
            .filter(|k| k.namespace.as_str() == namespace)
            .map(|k| (k.version, k.state))
            .collect())
    }

    async fn kek_states(&self) -> TestResult<Vec<(u32, KekState)>> {
        self.kek_states_of("app").await
    }

    /// The KEK versions of every row, deleted ones included.
    async fn row_keks(&self) -> TestResult<Vec<i32>> {
        Ok(sqlx::query_scalar(
            "SELECT v.kek_version FROM secret_versions v JOIN paths p ON p.id = v.path_id
                 ORDER BY p.path, v.version",
        )
        .fetch_all(self.data.pool())
        .await?)
    }

    /// Rotates, then rewraps until done: the old active KEK ends retired.
    async fn rotate_and_retire(&self) -> TestResult<Vec<(Namespace, u32)>> {
        self.seal.rotate(&app()?).await?;
        self.rewrap_all().await
    }

    /// Rewraps until done; returns the KEKs retired.
    async fn rewrap_all(&self) -> TestResult<Vec<(Namespace, u32)>> {
        for _ in 0..100 {
            let report = self.rewrap.run(None, 0).await?;
            if report.done {
                return Ok(report.retired);
            }
        }
        Err("rewrap never finished".into())
    }

    /// Rekeys to 3 shares / threshold 2, all the way to the commit.
    async fn rekey(&self) -> TestResult<()> {
        self.rekey_on(&self.seal).await
    }

    /// [`Env::rekey`] through `seal` (another server, say).
    async fn rekey_on(&self, seal: &Seal) -> TestResult<()> {
        let nonce = seal.rekey_start(ShareParams::new(3, 2)?).await?.nonce;
        let mut progress = None;
        for share in &self.shares[..3] {
            progress = Some(seal.rekey_submit(&nonce, share).await?);
        }
        let new_shares: Vec<Vec<u8>> = progress
            .ok_or("no shares submitted")?
            .new_shares
            .iter()
            .map(|s| s.to_bytes().to_vec())
            .collect();
        let mut progress = None;
        for share in &new_shares[..2] {
            progress = Some(seal.rekey_verify(&nonce, share).await?);
        }
        match progress.map(|p| p.phase) {
            Some(RekeyPhase::Complete) => Ok(()),
            other => Err(format!("rekey ended {other:?}").into()),
        }
    }

    async fn destroy(self) -> TestResult<()> {
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

/// The whole way: rotate, rewrap (retires 1), destroy 1. The key is gone
/// from the keys database, the version stays, every secret still reads,
/// before and after a reseal, and a rekey still works with a destroyed KEK
/// in the table. Destroying again says it already was.
#[tokio::test]
async fn a_retired_kek_is_destroyed_and_every_secret_still_reads() {
    let env = Env::new().await.unwrap();
    env.secrets.put(&ANON, "app/a", b"a").await.unwrap();
    env.secrets.put(&ANON, "app/gone", b"g").await.unwrap();
    env.secrets.delete(&ANON, "app/gone").await.unwrap();
    assert_eq!(
        env.rotate_and_retire().await.unwrap(),
        keks("app", &[1]).unwrap()
    );

    let done = env.destroy.run(&app().unwrap(), 1).await.unwrap();
    assert_eq!(done, destroyed(1, true, 2).unwrap());
    assert_eq!(
        env.kek_states().await.unwrap(),
        [(1, KekState::Destroyed), (2, KekState::Active)]
    );
    let key: Option<Vec<u8>> = sqlx::query_scalar("SELECT wrapped_key FROM keks WHERE version = 1")
        .fetch_one(env.keys.pool())
        .await
        .unwrap();
    assert_eq!(key, None);
    assert_eq!(env.seal.keyring().unwrap().versions(&app().unwrap()), [2]);
    let read = env.secrets.get(&ANON, "app/a", None).await.unwrap();
    assert_eq!(read.value.as_slice(), b"a");
    env.secrets.restore(&ANON, "app/gone", None).await.unwrap();

    env.seal.seal().await;
    env.unseal(&env.seal).await.unwrap();
    assert_eq!(env.seal.keyring().unwrap().versions(&app().unwrap()), [2]);
    let read = env.secrets.get(&ANON, "app/gone", None).await.unwrap();
    assert_eq!(read.value.as_slice(), b"g");

    // A rekey re-wraps the KEKs that are left, and leaves the destroyed one.
    env.rekey().await.unwrap();
    assert_eq!(
        env.kek_states().await.unwrap(),
        [(1, KekState::Destroyed), (2, KekState::Active)]
    );

    assert_eq!(
        env.destroy.run(&app().unwrap(), 1).await.unwrap(),
        destroyed(1, false, 2).unwrap()
    );
    // And the next version number is still 3.
    assert_eq!(env.seal.rotate(&app().unwrap()).await.unwrap(), 3);
    env.destroy().await.unwrap();
}

/// Only a retired KEK: not the active one, not one rows still use, not one
/// that doesn't exist. None of them touches the floor.
#[tokio::test]
async fn only_a_retired_kek_can_be_destroyed() {
    let env = Env::new().await.unwrap();
    env.secrets.put(&ANON, "app/a", b"a").await.unwrap();
    assert!(matches!(
        env.destroy.run(&app().unwrap(), 1).await,
        Err(DestroyError::NotRetired {
            version: 1,
            state: KekState::Active,
            ..
        })
    ));
    env.seal.rotate(&app().unwrap()).await.unwrap();
    assert!(matches!(
        env.destroy.run(&app().unwrap(), 1).await,
        Err(DestroyError::NotRetired {
            version: 1,
            state: KekState::DecryptOnly,
            ..
        })
    ));
    assert!(matches!(
        env.destroy.run(&app().unwrap(), 9).await,
        Err(DestroyError::UnknownVersion { version: 9, .. })
    ));
    // No floor above 1 anywhere: no raise happened.
    let floors: i64 = sqlx::query_scalar("SELECT count(*) FROM namespaces WHERE kek_floor > 1")
        .fetch_one(env.data.pool())
        .await
        .unwrap();
    assert_eq!(floors, 0);
    env.seal.seal().await;
    assert!(matches!(
        env.destroy.run(&app().unwrap(), 1).await,
        Err(DestroyError::Sealed)
    ));
    env.destroy().await.unwrap();
}

/// The stale-server case that made destroying unsafe: a server unsealed
/// before the rotation writes with its old active KEK after it was retired.
/// Destroying then refuses (the row needs the key), the floor is raised all
/// the same, so the stale server's next put is refused by the database,
/// and it refreshes and stores with the new KEK. A rewrap moves the late
/// row, and then destroying works.
#[tokio::test]
async fn a_row_written_by_a_stale_server_blocks_destroying_until_rewrapped() {
    let env = Env::new().await.unwrap();
    let (stale_seal, stale) = env.second_server().await.unwrap();
    assert_eq!(
        env.rotate_and_retire().await.unwrap(),
        keks("app", &[1]).unwrap()
    );

    stale.put(&ANON, "app/late", b"late").await.unwrap();
    assert_eq!(env.row_keks().await.unwrap(), [1]);
    assert!(matches!(
        env.destroy.run(&app().unwrap(), 1).await,
        Err(DestroyError::InUse { version: 1, .. })
    ));
    assert_eq!(
        env.kek_states().await.unwrap(),
        [(1, KekState::Retired), (2, KekState::Active)]
    );

    // Still holding KEK 1 as active, but the floor is past it now.
    assert_eq!(stale_seal.active_kek_version(&app().unwrap()), Some(1));
    stale.put(&ANON, "app/later", b"later").await.unwrap();
    assert_eq!(stale_seal.active_kek_version(&app().unwrap()), Some(2));
    assert_eq!(env.row_keks().await.unwrap(), [1, 2]);

    assert!(env.rewrap_all().await.unwrap().is_empty());
    assert_eq!(env.row_keks().await.unwrap(), [2, 2]);
    assert!(env.destroy.run(&app().unwrap(), 1).await.unwrap().destroyed);
    for (path, value) in [("app/late", b"late".as_slice()), ("app/later", b"later")] {
        let read = env.secrets.get(&ANON, path, None).await.unwrap();
        assert_eq!(read.value.as_slice(), value);
    }
    env.destroy().await.unwrap();
}

/// Destroyed elsewhere: a stale server, whose keyring still has the
/// destroyed KEK as its active one, puts a secret. The database refuses the
/// write; the server refreshes (dropping the destroyed KEK) and stores it
/// with the active one. Nothing is lost, nothing written with the
/// destroyed KEK.
#[tokio::test]
async fn a_stale_server_catches_up_when_its_kek_was_destroyed() {
    let env = Env::new().await.unwrap();
    let (stale_seal, stale) = env.second_server().await.unwrap();
    assert_eq!(
        env.rotate_and_retire().await.unwrap(),
        keks("app", &[1]).unwrap()
    );
    assert!(env.destroy.run(&app().unwrap(), 1).await.unwrap().destroyed);
    assert_eq!(stale_seal.keyring().unwrap().versions(&app().unwrap()), [1]);

    let stored = stale.put(&ANON, "app/new", b"new").await.unwrap();
    assert_eq!(stored.version, 1);
    assert_eq!(env.row_keks().await.unwrap(), [2]);
    assert_eq!(stale_seal.keyring().unwrap().versions(&app().unwrap()), [2]);
    let read = stale.get(&ANON, "app/new", None).await.unwrap();
    assert_eq!(read.value.as_slice(), b"new");
    env.destroy().await.unwrap();
}

/// A stale server that can't refresh (here: another server destroyed its
/// KEK, then rekeyed, which no refresh can follow) doesn't send every put
/// to the admin lock and the keys database: puts share the reads' refresh
/// cooldown, so one refresh, and the rest are refused at once. The message
/// says what to do in that case.
#[tokio::test]
async fn a_stale_server_that_cannot_refresh_tries_once_per_cooldown() {
    let env = Env::new().await.unwrap();
    let (stale_seal, stale) = env.second_server().await.unwrap();
    assert_eq!(
        env.rotate_and_retire().await.unwrap(),
        keks("app", &[1]).unwrap()
    );
    assert!(env.destroy.run(&app().unwrap(), 1).await.unwrap().destroyed);
    env.rekey().await.unwrap();

    for _ in 0..3 {
        let refused = stale.put(&ANON, "app/x", b"x").await.unwrap_err();
        assert!(
            matches!(refused, SecretsError::StaleKeyring(1)),
            "{refused}"
        );
        assert!(refused.to_string().contains("seal and unseal"), "{refused}");
    }
    assert_eq!(stale_seal.active_kek_version(&app().unwrap()), Some(1));
    // Each put's own entries were written before it returned, so the
    // refresh's entry (queued before) is in.
    let refreshes = env
        .audit
        .lines()
        .iter()
        .filter(|line| line.contains(r#""event":"keyring_refresh""#))
        .filter(|line| line.contains(r#""trigger":"kek_floor""#))
        .count();
    assert_eq!(refreshes, 1);
    assert!(env.row_keks().await.unwrap().is_empty());
    env.destroy().await.unwrap();
}

/// The check after an unseal, for databases restored from backups that
/// don't match. A row whose KEK the keys database never heard of (a
/// keys-database backup older than the data database's) is `missing`; one
/// whose KEK was destroyed (a data-database backup from before the rewrap)
/// is `destroyed`; one rotated in by another server since this one loaded
/// its keyring is neither: a refresh loads it.
#[tokio::test]
async fn rows_whose_kek_is_unavailable_are_found() {
    let env = Env::new().await.unwrap();
    let (stale_seal, _) = env.second_server().await.unwrap();
    let store = Datastore::new(env.data.pool().clone());
    env.secrets.put(&ANON, "app/a", b"a").await.unwrap();
    let unloaded = || keyring::unloaded(&env.seal, &store);
    assert_eq!(unloaded().await.unwrap(), Unloaded::default());

    // Rows as an old data-database backup would bring them back, below
    // today's floor: the restored database has its own, older floor.
    let pool = env.data.pool().clone();
    let insert = |path: &'static str, kek: i32| {
        let pool = pool.clone();
        async move { insert_version(&mut *pool.acquire().await?, path, 1, kek).await }
    };
    insert("app/from-the-future", 9).await.unwrap();
    assert_eq!(
        unloaded().await.unwrap(),
        Unloaded {
            missing: keks("app", &[9]).unwrap(),
            ..Unloaded::default()
        }
    );

    assert_eq!(
        env.rotate_and_retire().await.unwrap(),
        keks("app", &[1]).unwrap()
    );
    assert!(env.destroy.run(&app().unwrap(), 1).await.unwrap().destroyed);
    sqlx::query("UPDATE namespaces SET kek_floor = 1")
        .execute(env.data.pool())
        .await
        .unwrap();
    insert("app/from-the-past", 1).await.unwrap();
    assert_eq!(
        unloaded().await.unwrap(),
        Unloaded {
            destroyed: keks("app", &[1]).unwrap(),
            missing: keks("app", &[9]).unwrap(),
            ..Unloaded::default()
        }
    );

    // The stale server never loaded KEK 2, but the keys database has it.
    let found = keyring::unloaded(&stale_seal, &store).await.unwrap();
    assert_eq!(found.missing, keks("app", &[9]).unwrap());
    env.destroy().await.unwrap();
}

/// After a mismatched restore, a rotate or init would reuse KEK versions
/// rows already use for different keys, turning a recoverable mistake
/// (restore the right keys database) into lost rows. Both are refused:
/// rotate while rows use a version above the keys database's highest, init
/// while the data database holds any row. Neither refuses a matching pair.
#[tokio::test]
async fn rotate_and_init_are_refused_while_the_databases_do_not_match() {
    let env = Env::new().await.unwrap();
    let store = Datastore::new(env.data.pool().clone());
    env.secrets.put(&ANON, "app/a", b"a").await.unwrap();
    assert_eq!(
        env.rotate_and_retire().await.unwrap(),
        keks("app", &[1]).unwrap()
    );
    assert!(env.destroy.run(&app().unwrap(), 1).await.unwrap().destroyed);
    // Destroyed versions still count as the keys database's.
    keyring::ensure_keys_not_behind(&env.seal, &store, &app().unwrap())
        .await
        .unwrap();
    // Initialized: init refuses on its own, the guard stays out of it.
    keyring::ensure_no_orphaned_rows(&env.seal, &store)
        .await
        .unwrap();

    // A row from a newer keys database (version 3, lost with it).
    insert_version(
        &mut env.data.pool().acquire().await.unwrap(),
        "app/newer",
        1,
        3,
    )
    .await
    .unwrap();
    let refused = keyring::ensure_keys_not_behind(&env.seal, &store, &app().unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(
            refused,
            MismatchError::KeysBehind {
                data: 3,
                keys: 2,
                ..
            }
        ),
        "{refused}"
    );
    assert!(refused.to_string().contains("reuse version 3"), "{refused}");

    // The keys database lost entirely: an empty one next to the rows.
    let empty_keys = TestDatabase::new(
        "KEYS_DATABASE_URL",
        "ferritor_server_test",
        &ferritor_keystore::MIGRATOR,
    )
    .await
    .unwrap();
    let fresh = Seal::new(Keystore::new(empty_keys.pool().clone()));
    assert!(matches!(
        keyring::ensure_no_orphaned_rows(&fresh, &store).await,
        Err(MismatchError::DataWithoutKeys)
    ));
    // With an empty data database too, starting over is fine.
    let empty_data = TestDatabase::new(
        "DATA_DATABASE_URL",
        "ferritor_server_test",
        &ferritor_datastore::MIGRATOR,
    )
    .await
    .unwrap();
    keyring::ensure_no_orphaned_rows(&fresh, &Datastore::new(empty_data.pool().clone()))
        .await
        .unwrap();
    empty_keys.destroy().await.unwrap();
    empty_data.destroy().await.unwrap();
    env.destroy().await.unwrap();
}

/// A failover that lost a rotation: the keys database goes back to before
/// KEK 2, while a running server still holds KEK 2, the last copy, and has
/// rows wrapped by it. Its refresh keeps KEK 2 for reading only (logged and
/// audited as vanished), wraps new data keys with the stored active KEK 1,
/// and a rewrap on it moves the rows off KEK 2, so even a freshly unsealed
/// server reads everything, then releases KEK 2 (no row uses it), so a new
/// KEK 2 rotated in elsewhere reads fine there.
#[tokio::test]
async fn a_kek_the_keys_database_lost_is_kept_for_reading_and_rewrap_rescues_its_rows() {
    let env = Env::new().await.unwrap();
    let (holder, secrets) = env.second_server().await.unwrap();
    assert_eq!(env.seal.rotate(&app().unwrap()).await.unwrap(), 2);
    keyring::refresh(&holder, &env.gate, "periodic", None, true)
        .await
        .unwrap();
    assert_eq!(holder.active_kek_version(&app().unwrap()), Some(2));
    secrets.put(&ANON, "app/at-risk", b"v2").await.unwrap();
    assert_eq!(env.row_keks().await.unwrap(), [2]);

    // The keys database fails over to a standby that never got the rotation.
    sqlx::query("DELETE FROM keks WHERE version = 2")
        .execute(env.keys.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE keks SET state = 'active' WHERE version = 1")
        .execute(env.keys.pool())
        .await
        .unwrap();

    let refreshed = keyring::refresh(&holder, &env.gate, "periodic", None, true)
        .await
        .unwrap();
    assert!(refreshed.changed);
    assert_eq!(
        (refreshed.active, refreshed.vanished),
        (keks("app", &[1]).unwrap(), keks("app", &[2]).unwrap())
    );
    let keyring = holder.keyring().unwrap();
    assert_eq!(keyring.versions(&app().unwrap()), [1, 2]);
    assert_eq!(keyring.vanished(&app().unwrap()), [2]);
    drop(keyring);
    // Queued, not waited for: poll until the writer has it.
    let audited = |line: &String| {
        line.contains(r#""event":"keyring_refresh""#)
            && line.contains(r#""active":{"app":1}"#)
            && line.contains(r#""vanished":[{"namespace":"app","version":2}]"#)
    };
    for _ in 0..200 {
        if env.audit.lines().iter().any(audited) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        env.audit.lines().iter().any(audited),
        "{:?}",
        env.audit.lines()
    );
    // Kept, not re-reported: the next refresh changes nothing.
    let again = keyring::refresh(&holder, &env.gate, "periodic", None, true)
        .await
        .unwrap();
    assert!(!again.changed);

    // Reads of its rows keep working; new rows use a stored KEK.
    let read = secrets.get(&ANON, "app/at-risk", None).await.unwrap();
    assert_eq!(read.value.as_slice(), b"v2");
    secrets.put(&ANON, "app/after", b"v1").await.unwrap();
    assert_eq!(env.row_keks().await.unwrap(), [1, 2]);

    // The rescue: a rewrap on the server holding KEK 2.
    let report = Rewrap::new(Arc::clone(&holder), Datastore::new(env.data.pool().clone()))
        .run(None, 0)
        .await
        .unwrap();
    assert_eq!((report.rewrapped, report.failed, report.done), (1, 0, true));
    assert_eq!(env.row_keks().await.unwrap(), [1, 1]);
    // No row uses KEK 2 any more: released, the keyring is what's stored.
    assert_eq!(report.released, keks("app", &[2]).unwrap());
    let keyring = holder.keyring().unwrap();
    assert_eq!(keyring.versions(&app().unwrap()), [1]);
    assert!(keyring.vanished(&app().unwrap()).is_empty());
    drop(keyring);
    assert_eq!(holder.vanished_kek_count(), Some(0));
    let (_, fresh) = env.second_server().await.unwrap();
    for (path, value) in [("app/at-risk", b"v2".as_slice()), ("app/after", b"v1")] {
        let read = fresh.get(&ANON, path, None).await.unwrap();
        assert_eq!(read.value.as_slice(), value);
    }

    // The rotate guard allows reusing number 2 now, and another server
    // does: the holder reads the new KEK 2's rows (an on-demand refresh),
    // with no old copy left under that number to fail the unwrap. That
    // server held the lost KEK 2 too (it made it); its refresh keeps it as
    // vanished, and its rotation to a new KEK 2 supersedes it.
    let other = keyring::refresh(&env.seal, &env.gate, "periodic", None, true)
        .await
        .unwrap();
    assert_eq!(
        (other.active, other.vanished),
        (keks("app", &[1]).unwrap(), keks("app", &[2]).unwrap())
    );
    assert_eq!(env.seal.rotate(&app().unwrap()).await.unwrap(), 2);
    assert_eq!(env.seal.vanished_kek_count(), Some(0));
    env.secrets.put(&ANON, "app/new-two", b"n2").await.unwrap();
    let read = secrets.get(&ANON, "app/new-two", None).await.unwrap();
    assert_eq!(read.value.as_slice(), b"n2");
    env.destroy().await.unwrap();
}

/// A rekey commit re-wraps only the stored KEKs: the keys database must
/// cover exactly its own versions, and a vanished one held in memory isn't
/// one of them.
#[tokio::test]
async fn a_rekey_works_while_a_vanished_kek_is_held() {
    let env = Env::new().await.unwrap();
    let (holder, _) = env.second_server().await.unwrap();
    assert_eq!(env.seal.rotate(&app().unwrap()).await.unwrap(), 2);
    keyring::refresh(&holder, &env.gate, "periodic", None, true)
        .await
        .unwrap();
    sqlx::query("DELETE FROM keks WHERE version = 2")
        .execute(env.keys.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE keks SET state = 'active' WHERE version = 1")
        .execute(env.keys.pool())
        .await
        .unwrap();
    keyring::refresh(&holder, &env.gate, "periodic", None, true)
        .await
        .unwrap();
    assert_eq!(holder.vanished_kek_count(), Some(1));

    env.rekey_on(&holder).await.unwrap();
    assert_eq!(env.kek_states().await.unwrap(), [(1, KekState::Active)]);
    assert_eq!(holder.vanished_kek_count(), Some(1));
    env.destroy().await.unwrap();
}

/// Rows under `namespace`, deleted ones included.
async fn rows_under(env: &Env, namespace: &str) -> TestResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM secret_versions v JOIN namespaces n ON n.id = v.namespace_id
             WHERE n.name = $1",
    )
    .bind(namespace)
    .fetch_one(env.data.pool())
    .await?)
}

/// Deleting a namespace: refused while it has any row (a deleted secret
/// counts: it can be restored until purged), then it destroys its KEKs and
/// raises its floor past them, safe to repeat, and touches no other
/// namespace. Created again, its numbering continues: the first KEK lands
/// exactly on the floor, never reusing a number for a different key.
#[tokio::test]
async fn an_empty_namespace_is_deleted_and_created_again_above_its_floor() {
    let env = Env::new().await.unwrap();
    env.namespaces.create("temp", &Labels::new()).await.unwrap();
    env.secrets.put(&ANON, "temp/a", b"a").await.unwrap();
    env.secrets.delete(&ANON, "temp/a").await.unwrap();
    let refused = env.namespaces.delete("temp").await.unwrap_err();
    assert!(
        matches!(
            refused,
            NamespaceError::NotEmpty {
                rows: 1,
                deleted: 1,
                ..
            }
        ),
        "{refused}"
    );
    assert!(refused.to_string().contains("retention"), "{refused}");

    // Purged, as once past the retention.
    sqlx::query(
        "DELETE FROM secret_versions
         WHERE namespace_id = (SELECT id FROM namespaces WHERE name = 'temp')",
    )
    .execute(env.data.pool())
    .await
    .unwrap();
    let done = env.namespaces.delete("temp").await.unwrap();
    assert_eq!(
        (done.deleted, done.destroyed, done.kek_floor),
        (true, vec![1], 2)
    );
    assert_eq!(
        env.kek_states_of("temp").await.unwrap(),
        [(1, KekState::Destroyed)]
    );
    let again = env.namespaces.delete("temp").await.unwrap();
    assert_eq!(
        (again.deleted, again.destroyed, again.kek_floor),
        (false, vec![], 2)
    );
    assert!(
        env.seal
            .keyring()
            .unwrap()
            .versions(&ns("temp").unwrap())
            .is_empty()
    );
    assert!(matches!(
        env.secrets.put(&ANON, "temp/b", b"b").await,
        Err(SecretsError::NoNamespace(_))
    ));
    assert_eq!(env.kek_states().await.unwrap(), [(1, KekState::Active)]);

    let (_, version) = env.namespaces.create("temp", &Labels::new()).await.unwrap();
    assert_eq!(version, 2);
    env.secrets.put(&ANON, "temp/b", b"b").await.unwrap();
    let read = env.secrets.get(&ANON, "temp/b", None).await.unwrap();
    assert_eq!(read.value.as_slice(), b"b");
    assert_eq!(
        env.kek_states_of("temp").await.unwrap(),
        [(1, KekState::Destroyed), (2, KekState::Active)]
    );
    env.destroy().await.unwrap();
}

/// A server that loaded a namespace before it was deleted elsewhere still
/// holds its KEK as active. Its put is refused by the raised floor; the
/// refresh finds the namespace deleted and drops it, so the put ends as
/// NoNamespace and nothing is stored.
#[tokio::test]
async fn a_stale_server_cannot_write_to_a_namespace_deleted_elsewhere() {
    let env = Env::new().await.unwrap();
    env.namespaces.create("temp", &Labels::new()).await.unwrap();
    let (stale_seal, stale) = env.second_server().await.unwrap();
    assert_eq!(stale_seal.active_kek_version(&ns("temp").unwrap()), Some(1));
    assert!(env.namespaces.delete("temp").await.unwrap().deleted);

    let refused = stale.put(&ANON, "temp/late", b"x").await.unwrap_err();
    assert!(matches!(refused, SecretsError::NoNamespace(_)), "{refused}");
    assert_eq!(stale_seal.active_kek_version(&ns("temp").unwrap()), None);
    assert_eq!(rows_under(&env, "temp").await.unwrap(), 0);
    // Its other namespaces are untouched.
    stale.put(&ANON, "app/fine", b"y").await.unwrap();
    env.destroy().await.unwrap();
}

/// A keys database that lost a whole namespace (a failover, an older
/// backup): a server holding its KEKs keeps them for reading only, as
/// vanished. New writes there are refused (no active KEK to wrap with), a
/// freshly unsealed server reports the namespace lost, and creating it anew
/// is refused while its rows exist, since its new KEK 1 would collide with
/// theirs.
#[tokio::test]
async fn a_namespace_the_keys_database_lost_is_kept_for_reading() {
    let env = Env::new().await.unwrap();
    env.namespaces.create("lost", &Labels::new()).await.unwrap();
    let (holder, secrets) = env.second_server().await.unwrap();
    secrets.put(&ANON, "lost/db", b"keep").await.unwrap();

    for statement in [
        "DELETE FROM keks WHERE namespace = 'lost'",
        "DELETE FROM namespaces WHERE name = 'lost'",
    ] {
        sqlx::query(statement)
            .execute(env.keys.pool())
            .await
            .unwrap();
    }
    let refreshed = keyring::refresh(&holder, &env.gate, "periodic", None, true)
        .await
        .unwrap();
    assert!(refreshed.changed);
    assert_eq!(
        (refreshed.active, refreshed.vanished),
        (keks("app", &[1]).unwrap(), keks("lost", &[1]).unwrap())
    );
    let read = secrets.get(&ANON, "lost/db", None).await.unwrap();
    assert_eq!(read.value.as_slice(), b"keep");
    assert!(matches!(
        secrets.put(&ANON, "lost/new", b"x").await,
        Err(SecretsError::NoNamespace(_))
    ));

    let (fresh, _) = env.second_server().await.unwrap();
    let store = Datastore::new(env.data.pool().clone());
    assert_eq!(
        keyring::unloaded(&fresh, &store).await.unwrap(),
        Unloaded {
            lost_namespaces: vec![ns("lost").unwrap()],
            ..Unloaded::default()
        }
    );
    let refused = env
        .namespaces
        .create("lost", &Labels::new())
        .await
        .unwrap_err();
    assert!(
        matches!(
            refused,
            NamespaceError::Mismatch(MismatchError::RowsWithoutNamespace { rows: 1, .. })
        ),
        "{refused}"
    );
    env.destroy().await.unwrap();
}

/// A wrapped KEK is bound to its namespace (and version): one copied into
/// another namespace's row doesn't open, so the unseal fails instead of
/// one namespace's data quietly opening under another's key.
#[tokio::test]
async fn a_kek_moved_to_another_namespace_does_not_unwrap() {
    let env = Env::new().await.unwrap();
    env.namespaces
        .create("billing", &Labels::new())
        .await
        .unwrap();
    sqlx::query(
        "UPDATE keks SET wrapped_key = (SELECT wrapped_key FROM keks WHERE namespace = 'app')
         WHERE namespace = 'billing'",
    )
    .execute(env.keys.pool())
    .await
    .unwrap();
    env.seal.seal().await;
    assert!(env.unseal(&env.seal).await.is_err());
    assert!(env.seal.is_sealed());
    env.destroy().await.unwrap();
}

/// The way out after a failover lost a namespace's creation and no backup
/// has it: plain create stays refused, `create_past_lost_keks` on a server
/// holding the lost KEKs puts the first KEK past every lost version (here
/// 1 and 2, so 3) and raises the floor to it, and a rewrap there moves the
/// rows onto it and releases the lost KEKs, after which any server reads
/// them. A server that never refreshed is fenced off by the floor: its put
/// with the lost KEK 2 is refused, it refreshes and stores with KEK 3.
#[tokio::test]
async fn a_lost_namespace_is_recovered_past_its_lost_keks() {
    let env = Env::new().await.unwrap();
    let lost = ns("lost").unwrap();
    env.namespaces.create("lost", &Labels::new()).await.unwrap();
    env.secrets.put(&ANON, "lost/one", b"1").await.unwrap();
    env.seal.rotate(&lost).await.unwrap();
    env.secrets.put(&ANON, "lost/two", b"2").await.unwrap();
    let (holder, _) = env.second_server().await.unwrap();

    for statement in [
        "DELETE FROM keks WHERE namespace = 'lost'",
        "DELETE FROM namespaces WHERE name = 'lost'",
    ] {
        sqlx::query(statement)
            .execute(env.keys.pool())
            .await
            .unwrap();
    }
    keyring::refresh(&holder, &env.gate, "periodic", None, true)
        .await
        .unwrap();
    assert_eq!(holder.keyring().unwrap().vanished(&lost), [1, 2]);

    // Nothing lost here, or still live: the recovery refuses.
    let store = || Datastore::new(env.data.pool().clone());
    let on_holder = Namespaces::new(Arc::clone(&holder), store());
    assert!(matches!(
        on_holder
            .create_past_lost_keks("ghost", &Labels::new())
            .await,
        Err(NamespaceError::NothingLost(_))
    ));
    assert!(matches!(
        on_holder.create_past_lost_keks("app", &Labels::new()).await,
        Err(NamespaceError::Exists(_))
    ));
    assert!(matches!(
        on_holder.create("lost", &Labels::new()).await,
        Err(NamespaceError::Mismatch(_))
    ));

    let (_, version) = on_holder
        .create_past_lost_keks("lost", &Labels::new())
        .await
        .unwrap();
    assert_eq!(version, 3);
    assert_eq!(
        env.kek_states_of("lost").await.unwrap(),
        [(3, KekState::Active)]
    );
    assert_eq!(store().kek_floor(&lost).await.unwrap(), 3);

    // The server that rotated never refreshed: KEK 2 is still its active
    // one, and the floor turns its put away until it has KEK 3.
    assert_eq!(env.seal.active_kek_version(&lost), Some(2));
    env.secrets.put(&ANON, "lost/late", b"l").await.unwrap();
    assert_eq!(env.seal.active_kek_version(&lost), Some(3));

    // The rescue, on the holder.
    let rewrap = Rewrap::new(Arc::clone(&holder), store());
    let report = rewrap.run(Some(&lost), 0).await.unwrap();
    assert_eq!((report.rewrapped, report.failed, report.done), (2, 0, true));
    assert_eq!(report.released, keks("lost", &[1, 2]).unwrap());
    assert!(holder.keyring().unwrap().vanished(&lost).is_empty());

    let (fresh, fresh_secrets) = env.second_server().await.unwrap();
    for (path, value) in [("lost/one", b"1"), ("lost/two", b"2"), ("lost/late", b"l")] {
        let read = fresh_secrets.get(&ANON, path, None).await.unwrap();
        assert_eq!(read.value.as_slice(), value);
    }
    assert_eq!(
        keyring::unloaded(&fresh, &store()).await.unwrap(),
        Unloaded::default()
    );
    env.destroy().await.unwrap();
}

/// A namespace deleted and created again by another server: a refresh sees
/// both changes at once (one snapshot), drops the destroyed KEK and loads
/// the new one, and the server writes with it.
#[tokio::test]
async fn a_refresh_follows_a_namespace_deleted_and_created_again_elsewhere() {
    let env = Env::new().await.unwrap();
    let temp = ns("temp").unwrap();
    env.namespaces.create("temp", &Labels::new()).await.unwrap();
    let (other, other_secrets) = env.second_server().await.unwrap();
    assert!(env.namespaces.delete("temp").await.unwrap().deleted);
    let (_, version) = env.namespaces.create("temp", &Labels::new()).await.unwrap();
    assert_eq!(version, 2);

    let refreshed = keyring::refresh(&other, &env.gate, "periodic", None, true)
        .await
        .unwrap();
    assert!(refreshed.changed && refreshed.vanished.is_empty());
    assert_eq!(other.keyring().unwrap().versions(&temp), [2]);
    other_secrets.put(&ANON, "temp/db", b"x").await.unwrap();
    assert_eq!(env.row_keks().await.unwrap(), [2]);
    env.destroy().await.unwrap();
}

/// Deleting a namespace reclaims its `paths` rows (short-lived paths don't
/// pile up forever), and keeps the highest version any of them reached:
/// created again, its paths number on past it, so `temp/a` version 3 is
/// never a different secret than it was. Other namespaces' paths stay.
#[tokio::test]
async fn deleting_a_namespace_reclaims_its_paths_and_never_reuses_a_version() {
    let env = Env::new().await.unwrap();
    env.namespaces.create("temp", &Labels::new()).await.unwrap();
    env.namespaces.create("keep", &Labels::new()).await.unwrap();
    for value in [b"1", b"2", b"3"] {
        env.secrets.put(&ANON, "temp/a", value).await.unwrap();
    }
    env.secrets.put(&ANON, "temp/b", b"b").await.unwrap();
    env.secrets.put(&ANON, "keep/x", b"x").await.unwrap();
    sqlx::query(
        "DELETE FROM secret_versions
         WHERE namespace_id = (SELECT id FROM namespaces WHERE name = 'temp')",
    )
    .execute(env.data.pool())
    .await
    .unwrap();
    let paths = |namespace: &'static str| {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM paths p JOIN namespaces n ON n.id = p.namespace_id
             WHERE n.name = $1",
        )
        .bind(namespace)
        .fetch_one(env.data.pool())
    };
    assert_eq!(paths("temp").await.unwrap(), 2);
    let done = env.namespaces.delete("temp").await.unwrap();
    assert_eq!(done.paths_reclaimed, 2);
    assert_eq!(paths("temp").await.unwrap(), 0);
    assert_eq!(paths("keep").await.unwrap(), 1);

    env.namespaces.create("temp", &Labels::new()).await.unwrap();
    let a = env.secrets.put(&ANON, "temp/a", b"new").await.unwrap();
    assert_eq!(a.version, 4);
    let fresh = env.secrets.put(&ANON, "temp/fresh", b"f").await.unwrap();
    assert_eq!(fresh.version, 4);
    let x = env.secrets.put(&ANON, "keep/x", b"x2").await.unwrap();
    assert_eq!(x.version, 2);
    env.destroy().await.unwrap();
}
