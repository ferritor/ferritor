//! Runs against the keys DB from `KEYS_DATABASE_URL` (`.env`). Each test gets
//! its own freshly migrated database (see `ferritor-testkit`).

use std::time::Duration;

use ferritor_core::crypto::{IssuingRecord, ShareParams};
use ferritor_core::labels::Labels;
use ferritor_core::path::Namespace;
use ferritor_keystore::{
    IssuingRotation, IssuingSet, IssuingTagger, KekState, Keystore, KeystoreError, MIGRATOR,
    NamespaceState, NewPolicy, Numbering, PolicyChanges, RekeyRewrap, RewrappedKek, SealConfig,
    SealWrap,
};
use ferritor_testkit::{TestDatabase, TestResult};
use sqlx::types::time::OffsetDateTime;

fn params(shares: u8, threshold: u8) -> TestResult<ShareParams> {
    Ok(ShareParams::new(shares, threshold)?)
}

struct TestDb {
    db: TestDatabase,
    store: Keystore,
}

impl TestDb {
    async fn new() -> TestResult<Self> {
        let db = TestDatabase::new("KEYS_DATABASE_URL", "ferritor_keys_test", &MIGRATOR).await?;
        let store = Keystore::new(db.pool().clone());
        Ok(Self { db, store })
    }

    /// Initialized, with namespace `app` (its KEK v1).
    async fn initialized() -> TestResult<Self> {
        let db = Self::new().await?;
        db.store.initialize(params(5, 3)?, b"check-1").await?;
        db.store
            .create_namespace(
                1,
                &ns("app")?,
                1,
                Numbering::Next,
                b"kek-1@gen1",
                &Labels::new(),
            )
            .await?;
        Ok(db)
    }

    async fn destroy(self) -> TestResult<()> {
        self.db.destroy().await
    }
}

fn ns(name: &str) -> TestResult<Namespace> {
    Ok(Namespace::parse(name)?)
}

/// `app`'s KEKs, as (version, state).
fn versions_and_states(keks: &[ferritor_keystore::StoredKek]) -> Vec<(u32, KekState)> {
    keks.iter()
        .filter(|k| k.namespace.as_str() == "app")
        .map(|k| (k.version, k.state))
        .collect()
}

/// Init stores the seal config and no KEK: there's none until a namespace
/// is created.
#[tokio::test]
async fn initialize_stores_config_and_no_kek() {
    let db = TestDb::new().await.unwrap();
    assert_eq!(db.store.seal_config().await.unwrap(), None);

    db.store
        .initialize(params(5, 3).unwrap(), b"check-1")
        .await
        .unwrap();

    assert_eq!(
        db.store.seal_config().await.unwrap(),
        Some(SealConfig {
            params: params(5, 3).unwrap(),
            root_check: b"check-1".to_vec(),
            generation: 1,
        })
    );
    assert!(db.store.keks().await.unwrap().is_empty());
    assert!(db.store.namespaces().await.unwrap().is_empty());
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn initialize_twice_fails_and_changes_nothing() {
    let db = TestDb::initialized().await.unwrap();
    assert!(matches!(
        db.store.initialize(params(3, 2).unwrap(), b"other").await,
        Err(KeystoreError::AlreadyInitialized)
    ));
    let config = db.store.seal_config().await.unwrap().unwrap();
    assert_eq!(config.params, params(5, 3).unwrap());
    assert_eq!(db.store.keks().await.unwrap().len(), 1);
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn rotate_demotes_the_active_kek() {
    let db = TestDb::initialized().await.unwrap();
    db.store
        .rotate(1, &ns("app").unwrap(), 2, b"kek-2@gen1")
        .await
        .unwrap();
    db.store
        .rotate(1, &ns("app").unwrap(), 3, b"kek-3@gen1")
        .await
        .unwrap();
    assert_eq!(
        versions_and_states(&db.store.keks().await.unwrap()),
        [
            (1, KekState::DecryptOnly),
            (2, KekState::DecryptOnly),
            (3, KekState::Active)
        ]
    );
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn rotate_rejects_wrong_version_or_generation() {
    let db = TestDb::initialized().await.unwrap();
    for new_version in [1, 3] {
        assert!(matches!(
            db.store
                .rotate(1, &ns("app").unwrap(), new_version, b"x")
                .await,
            Err(KeystoreError::RotateConflict {
                active: Some(1),
                ..
            })
        ));
    }
    assert!(matches!(
        db.store.rotate(2, &ns("app").unwrap(), 2, b"x").await,
        Err(KeystoreError::GenerationMismatch {
            expected: 2,
            found: 1
        })
    ));
    assert!(matches!(
        db.store
            .rotate(1, &ns("app").unwrap(), u32::MAX, b"x")
            .await,
        Err(KeystoreError::OutOfRange { .. })
    ));
    // Every failure rolled back: still just version 1, active.
    assert_eq!(
        versions_and_states(&db.store.keks().await.unwrap()),
        [(1, KekState::Active)]
    );
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn rotate_on_uninitialized_seal_fails() {
    let db = TestDb::new().await.unwrap();
    assert!(matches!(
        db.store.rotate(1, &ns("app").unwrap(), 2, b"x").await,
        Err(KeystoreError::NotInitialized)
    ));
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn concurrent_rotations_to_the_same_version_let_one_win() {
    let db = TestDb::initialized().await.unwrap();
    let app = ns("app").unwrap();
    let (a, b) = tokio::join!(
        db.store.rotate(1, &app, 2, b"kek-2a"),
        db.store.rotate(1, &app, 2, b"kek-2b"),
    );
    let results = [a, b];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .any(|r| matches!(r, Err(KeystoreError::RotateConflict { .. })))
    );
    assert_eq!(
        versions_and_states(&db.store.keks().await.unwrap()),
        [(1, KekState::DecryptOnly), (2, KekState::Active)]
    );
    db.destroy().await.unwrap();
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum First {
    Rotate,
    Rekey,
}

/// The guarantee in the crate docs: a rotation racing a rekey must never
/// leave a KEK wrapped under the old root key. Fake wrapped keys end in
/// `@gen<N>` for the generation they were wrapped under, so the invariant is
/// "every stored KEK ends in the current generation".
///
/// The test holds the `seal_config` row lock itself, queues the two
/// operations behind it in the order given, then releases it. Postgres grants
/// queued row locks in arrival order, so `first` decides the interleaving
/// while the real `rotate`/`rekey` code runs. (Rotate committing before rekey
/// even starts is the sequential case in
/// `rekey_rejects_incomplete_keyring_and_changes_nothing`.)
async fn race_rotate_and_rekey(first: First) -> TestResult<()> {
    let db = TestDb::initialized().await?;
    let mut gate = db.db.pool().begin().await?;
    sqlx::query("SELECT 1 FROM seal_config FOR UPDATE")
        .execute(&mut *gate)
        .await?;

    let rotate = {
        let store = db.store.clone();
        let app = ns("app")?;
        async move { store.rotate(1, &app, 2, b"kek-2@gen1").await }
    };
    let rekey = {
        let store = db.store.clone();
        let rewrapped = [RewrappedKek {
            namespace: ns("app")?,
            version: 1,
            wrapped_key: b"kek-1@gen2".to_vec(),
        }];
        let new_params = params(5, 3)?;
        async move {
            store
                .rekey(
                    1,
                    new_params,
                    b"check-2",
                    &rewrapped,
                    &Fake {
                        policy: |_| None,
                        issuing: |_, _| None,
                        tag: |_| None,
                    },
                )
                .await
        }
    };
    let (rotated, rekeyed) = match first {
        First::Rotate => {
            let rotated = tokio::spawn(rotate);
            db.db.wait_for_lock_waiters(1).await?;
            let rekeyed = tokio::spawn(rekey);
            db.db.wait_for_lock_waiters(2).await?;
            gate.rollback().await?;
            (rotated.await?, rekeyed.await?)
        }
        First::Rekey => {
            let rekeyed = tokio::spawn(rekey);
            db.db.wait_for_lock_waiters(1).await?;
            let rotated = tokio::spawn(rotate);
            db.db.wait_for_lock_waiters(2).await?;
            gate.rollback().await?;
            (rotated.await?, rekeyed.await?)
        }
    };

    let config = db.store.seal_config().await?.ok_or("seal config missing")?;
    let keks = db.store.keks().await?;
    match (first, &rotated, &rekeyed) {
        // Rotate holds its shared lock; rekey then sees v2 it wasn't given.
        (First::Rotate, Ok(()), Err(KeystoreError::KekSetMismatch)) => {
            assert_eq!(config.generation, 1);
            assert_eq!(
                versions_and_states(&keks),
                [(1, KekState::DecryptOnly), (2, KekState::Active)]
            );
        }
        // Rekey commits; rotate then reads generation 2.
        (
            First::Rekey,
            Err(KeystoreError::GenerationMismatch {
                expected: 1,
                found: 2,
            }),
            Ok(2),
        ) => {
            assert_eq!(config.generation, 2);
            assert_eq!(versions_and_states(&keks), [(1, KekState::Active)]);
        }
        other => panic!("unexpected outcome {other:?}"),
    }
    let suffix = format!("@gen{}", config.generation);
    for kek in &keks {
        assert!(
            kek.wrapped_key.ends_with(suffix.as_bytes()),
            "KEK {} is not wrapped under generation {}",
            kek.version,
            config.generation
        );
    }
    db.destroy().await
}

#[tokio::test(flavor = "multi_thread")]
async fn rotate_queued_before_rekey_makes_rekey_fail() {
    race_rotate_and_rekey(First::Rotate).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn rekey_queued_before_rotate_makes_rotate_fail() {
    race_rotate_and_rekey(First::Rekey).await.unwrap();
}

#[tokio::test]
async fn rekey_rewraps_every_kek_and_bumps_generation() {
    let db = TestDb::initialized().await.unwrap();
    db.store
        .rotate(1, &ns("app").unwrap(), 2, b"kek-2@gen1")
        .await
        .unwrap();

    let rewrapped = [
        RewrappedKek {
            namespace: ns("app").unwrap(),
            version: 2,
            wrapped_key: b"kek-2@gen2".to_vec(),
        },
        RewrappedKek {
            namespace: ns("app").unwrap(),
            version: 1,
            wrapped_key: b"kek-1@gen2".to_vec(),
        },
    ];
    let generation = db
        .store
        .rekey(
            1,
            params(7, 4).unwrap(),
            b"check-2",
            &rewrapped,
            &Fake {
                policy: |_| None,
                issuing: |_, _| None,
                tag: |_| None,
            },
        )
        .await
        .unwrap();
    assert_eq!(generation, 2);

    assert_eq!(
        db.store.seal_config().await.unwrap(),
        Some(SealConfig {
            params: params(7, 4).unwrap(),
            root_check: b"check-2".to_vec(),
            generation: 2,
        })
    );
    let keks = db.store.keks().await.unwrap();
    assert_eq!(keks[0].wrapped_key, b"kek-1@gen2");
    assert_eq!(keks[1].wrapped_key, b"kek-2@gen2");
    // States are untouched by a rekey.
    assert_eq!(
        versions_and_states(&keks),
        [(1, KekState::DecryptOnly), (2, KekState::Active)]
    );

    // Anything prepared against the old generation is now stale.
    assert!(matches!(
        db.store
            .rotate(1, &ns("app").unwrap(), 3, b"kek-3@gen1")
            .await,
        Err(KeystoreError::GenerationMismatch {
            expected: 1,
            found: 2
        })
    ));
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn rekey_rejects_incomplete_keyring_and_changes_nothing() {
    let db = TestDb::initialized().await.unwrap();
    db.store
        .rotate(1, &ns("app").unwrap(), 2, b"kek-2@gen1")
        .await
        .unwrap();
    let only_one = [RewrappedKek {
        namespace: ns("app").unwrap(),
        version: 2,
        wrapped_key: b"kek-2@gen2".to_vec(),
    }];
    assert!(matches!(
        db.store
            .rekey(
                1,
                params(5, 3).unwrap(),
                b"check-2",
                &only_one,
                &Fake {
                    policy: |_| None,
                    issuing: |_, _| None,
                    tag: |_| None
                }
            )
            .await,
        Err(KeystoreError::KekSetMismatch)
    ));
    assert!(matches!(
        db.store
            .rekey(
                9,
                params(5, 3).unwrap(),
                b"check-2",
                &only_one,
                &Fake {
                    policy: |_| None,
                    issuing: |_, _| None,
                    tag: |_| None
                }
            )
            .await,
        Err(KeystoreError::GenerationMismatch { .. })
    ));

    let config = db.store.seal_config().await.unwrap().unwrap();
    assert_eq!(
        (config.generation, config.root_check),
        (1, b"check-1".to_vec())
    );
    let keks = db.store.keks().await.unwrap();
    assert_eq!(keks[1].wrapped_key, b"kek-2@gen1");
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn retire_only_applies_to_decrypt_only_keks() {
    let db = TestDb::initialized().await.unwrap();
    db.store
        .rotate(1, &ns("app").unwrap(), 2, b"kek-2@gen1")
        .await
        .unwrap();

    for version in [2, 3] {
        assert!(matches!(
            db.store.retire(&ns("app").unwrap(), version).await,
            Err(KeystoreError::NotDecryptOnly { version: v, .. }) if v == version
        ));
    }
    db.store.retire(&ns("app").unwrap(), 1).await.unwrap();
    assert!(matches!(
        db.store.retire(&ns("app").unwrap(), 1).await,
        Err(KeystoreError::NotDecryptOnly { version: 1, .. })
    ));
    assert_eq!(
        versions_and_states(&db.store.keks().await.unwrap()),
        [(1, KekState::Retired), (2, KekState::Active)]
    );
    db.destroy().await.unwrap();
}

/// A transaction that has updated the seal config but not finished: what a
/// rekey whose COMMIT was sent but not confirmed looks like to other sessions.
async fn in_flight_rekey(db: &TestDb) -> TestResult<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = db.db.pool().begin().await?;
    sqlx::query("UPDATE seal_config SET generation = 2, root_check = 'check-2'")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn settled_read_waits_for_a_commit_in_flight() {
    let db = TestDb::initialized().await.unwrap();
    let tx = in_flight_rekey(&db).await.unwrap();

    // A plain read doesn't wait: it still sees generation 1.
    assert_eq!(db.store.seal_config().await.unwrap().unwrap().generation, 1);

    let store = db.store.clone();
    let settled =
        tokio::spawn(async move { store.settled_seal_config(Duration::from_secs(5)).await });
    db.db.wait_for_lock_waiters(1).await.unwrap();
    tx.commit().await.unwrap();
    let config = settled.await.unwrap().unwrap().unwrap();
    assert_eq!(
        (config.generation, config.root_check),
        (2, b"check-2".to_vec())
    );
    db.destroy().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn settled_read_sees_the_old_row_after_an_abort() {
    let db = TestDb::initialized().await.unwrap();
    let tx = in_flight_rekey(&db).await.unwrap();
    let store = db.store.clone();
    let settled =
        tokio::spawn(async move { store.settled_seal_config(Duration::from_secs(5)).await });
    db.db.wait_for_lock_waiters(1).await.unwrap();
    tx.rollback().await.unwrap();
    let config = settled.await.unwrap().unwrap().unwrap();
    assert_eq!(
        (config.generation, config.root_check),
        (1, b"check-1".to_vec())
    );
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn settled_read_times_out_while_the_row_is_held() {
    let db = TestDb::initialized().await.unwrap();
    let tx = in_flight_rekey(&db).await.unwrap();
    assert!(matches!(
        db.store
            .settled_seal_config(Duration::from_millis(100))
            .await,
        Err(KeystoreError::LockTimeout)
    ));
    tx.rollback().await.unwrap();
    db.destroy().await.unwrap();
}

/// A stalled database (here: the table locked by another session) costs a
/// caller at most the client-side bound, not "until it recovers".
#[tokio::test]
async fn a_stalled_database_times_out() {
    let db = TestDb::initialized().await.unwrap();
    let mut stall = db.db.pool().begin().await.unwrap();
    sqlx::query("LOCK TABLE seal_config IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *stall)
        .await
        .unwrap();

    let bounded = db.store.clone().with_timeout(Duration::from_millis(200));
    let started = std::time::Instant::now();
    assert!(matches!(
        bounded.seal_config().await,
        Err(KeystoreError::Timeout)
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    stall.rollback().await.unwrap();
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn an_exhausted_pool_is_a_timeout() {
    let db = TestDb::initialized().await.unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy_with((*db.db.pool().connect_options()).clone());
    // Opening the one connection falls under the same 100 ms, which a busy
    // machine can take longer than (CI did, for the data store's twin of
    // this test): retried until it opens. The timeout under test is the
    // next acquire's, with it held.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let only_connection = loop {
        match pool.acquire().await {
            Ok(connection) => break connection,
            Err(e) if std::time::Instant::now() > deadline => {
                panic!("no connection within 10 s: {e}")
            }
            Err(_) => {}
        }
    };
    let store = Keystore::new(pool.clone()).with_timeout(Duration::from_secs(5));
    assert!(matches!(
        store.seal_config().await,
        Err(KeystoreError::Timeout)
    ));
    drop(only_connection);
    pool.close().await;
    db.destroy().await.unwrap();
}

/// Namespaces are separate lineages: each numbered from 1, rotated on its
/// own, one active KEK each.
#[tokio::test]
async fn namespaces_have_their_own_kek_lineages() {
    let db = TestDb::initialized().await.unwrap();
    assert_eq!(
        db.store
            .next_namespace_version(&ns("billing").unwrap())
            .await
            .unwrap(),
        1
    );
    db.store
        .create_namespace(
            1,
            &ns("billing").unwrap(),
            1,
            Numbering::Next,
            b"billing-1@gen1",
            &Labels::new(),
        )
        .await
        .unwrap();
    db.store
        .rotate(1, &ns("app").unwrap(), 2, b"kek-2@gen1")
        .await
        .unwrap();
    let all: Vec<(String, u32, KekState)> = db
        .store
        .keks()
        .await
        .unwrap()
        .into_iter()
        .map(|k| (k.namespace.to_string(), k.version, k.state))
        .collect();
    assert_eq!(
        all,
        [
            ("app".to_owned(), 1, KekState::DecryptOnly),
            ("app".to_owned(), 2, KekState::Active),
            ("billing".to_owned(), 1, KekState::Active),
        ]
    );
    // A rekey must cover every namespace's KEKs.
    let only_app = [
        RewrappedKek {
            namespace: ns("app").unwrap(),
            version: 1,
            wrapped_key: b"x".to_vec(),
        },
        RewrappedKek {
            namespace: ns("app").unwrap(),
            version: 2,
            wrapped_key: b"x".to_vec(),
        },
    ];
    assert!(matches!(
        db.store
            .rekey(
                1,
                params(5, 3).unwrap(),
                b"c",
                &only_app,
                &Fake {
                    policy: |_| None,
                    issuing: |_, _| None,
                    tag: |_| None
                }
            )
            .await,
        Err(KeystoreError::KekSetMismatch)
    ));
    db.destroy().await.unwrap();
}

/// Create refuses a live namespace and a version that isn't the next;
/// delete destroys its KEKs and keeps the rows, and re-creating continues
/// the numbering past them.
#[tokio::test]
async fn deleting_and_recreating_a_namespace_continues_its_numbering() {
    let db = TestDb::initialized().await.unwrap();
    let labels = Labels::from([("team".to_owned(), "a".to_owned())]);
    assert!(matches!(
        db.store
            .create_namespace(
                1,
                &ns("app").unwrap(),
                2,
                Numbering::Next,
                b"x",
                &Labels::new()
            )
            .await,
        Err(KeystoreError::NamespaceExists(_))
    ));
    assert!(matches!(
        db.store
            .create_namespace(
                1,
                &ns("billing").unwrap(),
                2,
                Numbering::Next,
                b"x",
                &Labels::new()
            )
            .await,
        Err(KeystoreError::CreateConflict { expected: 1, .. })
    ));
    db.store
        .create_namespace(
            1,
            &ns("billing").unwrap(),
            1,
            Numbering::Next,
            b"b1@gen1",
            &labels,
        )
        .await
        .unwrap();
    db.store
        .rotate(1, &ns("billing").unwrap(), 2, b"b2@gen1")
        .await
        .unwrap();

    let deleted = db
        .store
        .delete_namespace(1, &ns("billing").unwrap())
        .await
        .unwrap();
    assert_eq!(
        (deleted.destroyed, deleted.highest, deleted.deleted),
        (vec![1, 2], 2, true)
    );
    let again = db
        .store
        .delete_namespace(1, &ns("billing").unwrap())
        .await
        .unwrap();
    assert!(!again.deleted && again.destroyed.is_empty());
    let billing = db
        .store
        .namespaces()
        .await
        .unwrap()
        .into_iter()
        .find(|n| n.name == ns("billing").unwrap())
        .unwrap();
    assert_eq!(billing.state, NamespaceState::Deleted);
    assert!(billing.labels.is_empty());
    assert!(
        db.store
            .keks()
            .await
            .unwrap()
            .iter()
            .all(|k| k.namespace != ns("billing").unwrap())
    );
    assert!(matches!(
        db.store
            .update_namespace_labels(&ns("billing").unwrap(), &labels, &[])
            .await,
        Err(KeystoreError::NoNamespace(_))
    ));

    assert_eq!(
        db.store
            .next_namespace_version(&ns("billing").unwrap())
            .await
            .unwrap(),
        3
    );
    db.store
        .create_namespace(
            1,
            &ns("billing").unwrap(),
            3,
            Numbering::Next,
            b"b3@gen1",
            &Labels::new(),
        )
        .await
        .unwrap();
    let states: Vec<(u32, KekState)> = db
        .store
        .kek_states()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.namespace == ns("billing").unwrap())
        .map(|k| (k.version, k.state))
        .collect();
    assert_eq!(
        states,
        [
            (1, KekState::Destroyed),
            (2, KekState::Destroyed),
            (3, KekState::Active)
        ]
    );
    db.destroy().await.unwrap();
}

/// A namespace's labels merge like a path's, at most 64.
#[tokio::test]
async fn namespace_labels_merge() {
    let db = TestDb::initialized().await.unwrap();
    let set = Labels::from([
        ("team".to_owned(), "a".to_owned()),
        ("env".to_owned(), "p".to_owned()),
    ]);
    assert_eq!(
        db.store
            .update_namespace_labels(&ns("app").unwrap(), &set, &[])
            .await
            .unwrap(),
        set
    );
    let left = db
        .store
        .update_namespace_labels(&ns("app").unwrap(), &Labels::new(), &["env".to_owned()])
        .await
        .unwrap();
    assert_eq!(left, Labels::from([("team".to_owned(), "a".to_owned())]));
    let many: Labels = (0..64).map(|i| (format!("k{i}"), String::new())).collect();
    assert!(matches!(
        db.store
            .update_namespace_labels(&ns("app").unwrap(), &many, &[])
            .await,
        Err(KeystoreError::TooManyLabels { count: 65 })
    ));
    assert!(matches!(
        db.store
            .update_namespace_labels(&ns("nope").unwrap(), &set, &[])
            .await,
        Err(KeystoreError::NoNamespace(_))
    ));
    db.destroy().await.unwrap();
}

/// Creating and deleting a namespace hold the seal config FOR SHARE, so a
/// rekey (FOR UPDATE) queued behind a create sees the new KEK it wasn't
/// given and refuses, rather than leaving it wrapped under the old root key.
#[tokio::test(flavor = "multi_thread")]
async fn a_namespace_created_before_a_rekey_commit_makes_it_refuse() {
    let db = TestDb::initialized().await.unwrap();
    let mut gate = db.db.pool().begin().await.unwrap();
    sqlx::query("SELECT 1 FROM seal_config FOR UPDATE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let create = tokio::spawn({
        let store = db.store.clone();
        async move {
            store
                .create_namespace(
                    1,
                    &ns("billing").unwrap(),
                    1,
                    Numbering::Next,
                    b"b1@gen1",
                    &Labels::new(),
                )
                .await
        }
    });
    db.db.wait_for_lock_waiters(1).await.unwrap();
    let rekey = tokio::spawn({
        let store = db.store.clone();
        let rewrapped = [RewrappedKek {
            namespace: ns("app").unwrap(),
            version: 1,
            wrapped_key: b"kek-1@gen2".to_vec(),
        }];
        async move {
            store
                .rekey(
                    1,
                    params(5, 3)?,
                    b"check-2",
                    &rewrapped,
                    &Fake {
                        policy: |_| None,
                        issuing: |_, _| None,
                        tag: |_| None,
                    },
                )
                .await
                .map_err(Into::into)
        }
    });
    db.db.wait_for_lock_waiters(2).await.unwrap();
    gate.rollback().await.unwrap();
    create.await.unwrap().unwrap();
    let rekeyed: TestResult<u32> = rekey.await.unwrap();
    assert!(
        matches!(
            rekeyed
                .as_ref()
                .map_err(|e| e.downcast_ref::<KeystoreError>()),
            Err(Some(KeystoreError::KekSetMismatch))
        ),
        "{rekeyed:?}"
    );
    assert_eq!(db.store.seal_config().await.unwrap().unwrap().generation, 1);
    db.destroy().await.unwrap();
}

/// Only a recovery past lost KEKs may skip numbers, and only upwards: the
/// first KEK lands above the next version, never below it.
#[tokio::test]
async fn only_a_recovery_skips_ahead() {
    let db = TestDb::initialized().await.unwrap();
    let lost = ns("lost").unwrap();
    for (version, numbering) in [(3, Numbering::Next), (0, Numbering::PastLost)] {
        assert!(matches!(
            db.store
                .create_namespace(1, &lost, version, numbering, b"x", &Labels::new())
                .await,
            Err(KeystoreError::CreateConflict { expected: 1, .. })
        ));
    }
    db.store
        .create_namespace(1, &lost, 3, Numbering::PastLost, b"l3@gen1", &Labels::new())
        .await
        .unwrap();
    let keks: Vec<(u32, KekState)> = db
        .store
        .kek_states()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.namespace == lost)
        .map(|k| (k.version, k.state))
        .collect();
    assert_eq!(keks, [(3, KekState::Active)]);
    // The numbering goes on from there.
    db.store.rotate(1, &lost, 4, b"l4@gen1").await.unwrap();
    db.destroy().await.unwrap();
}

fn app_kek() -> TestResult<RewrappedKek> {
    Ok(RewrappedKek {
        namespace: ns("app")?,
        version: 1,
        wrapped_key: b"kek-1@gen2".to_vec(),
    })
}

fn new_policy(name: &str, version: u32) -> NewPolicy {
    NewPolicy {
        name: name.to_owned(),
        identity: "apps/billing".to_owned(),
        actions: vec!["list".to_owned(), "read".to_owned()],
        paths: vec!["billing".to_owned()],
        all_paths: false,
        description: "billing, read only".to_owned(),
        version,
        mac: version.to_be_bytes().repeat(8),
    }
}

/// A policy write stores rows, the set's state and, the first time, the
/// wrapped key, all at once; a snapshot reads them back together. Nothing
/// is stored by a write that isn't committed.
#[tokio::test]
async fn policy_writes_store_rows_state_and_key_together() {
    let db = TestDb::initialized().await.unwrap();
    let empty = db.store.policy_snapshot().await.unwrap();
    assert_eq!(
        (
            empty.generation,
            empty.wrapped_key,
            empty.state.revision,
            empty.state.mac
        ),
        (1, None, 0, None)
    );
    assert!(empty.policies.is_empty());

    // Not committed: nothing.
    let dropped = db.store.begin_policy_write(1).await.unwrap();
    drop(dropped);
    assert_eq!(db.store.policy_revision().await.unwrap(), 0);

    let write = db.store.begin_policy_write(1).await.unwrap();
    write
        .commit(PolicyChanges {
            upsert: vec![
                new_policy("apps/billing-read", 1),
                new_policy("apps/other", 1),
            ],
            delete: vec![],
            revision: 1,
            mac: vec![9; 32],
            new_wrapped_key: Some(b"policy-key@gen1".to_vec()),
        })
        .await
        .unwrap();
    let write = db.store.begin_policy_write(1).await.unwrap();
    assert_eq!(write.snapshot.state.revision, 1);
    write
        .commit(PolicyChanges {
            upsert: vec![new_policy("apps/billing-read", 2)],
            delete: vec!["apps/other".to_owned()],
            revision: 2,
            mac: vec![8; 32],
            new_wrapped_key: None,
        })
        .await
        .unwrap();

    let after = db.store.policy_snapshot().await.unwrap();
    assert_eq!(after.wrapped_key.as_deref(), Some(&b"policy-key@gen1"[..]));
    assert_eq!(
        (after.state.revision, after.state.mac),
        (2, Some(vec![8; 32]))
    );
    let names: Vec<(&str, u32)> = after
        .policies
        .iter()
        .map(|p| (p.name.as_str(), p.version))
        .collect();
    assert_eq!(names, [("apps/billing-read", 2)]);
    assert_eq!(after.policies[0].actions, ["list", "read"]);
    // A write needs the current generation, like a rotation.
    assert!(matches!(
        db.store.begin_policy_write(2).await,
        Err(KeystoreError::GenerationMismatch { .. })
    ));
    db.destroy().await.unwrap();
}

/// Writes serialize on the set's state: a second waits for the first.
#[tokio::test]
async fn policy_writes_serialize() {
    let db = TestDb::initialized().await.unwrap();
    let first = db.store.begin_policy_write(1).await.unwrap();
    let second = tokio::spawn({
        let store = db.store.clone();
        async move {
            store
                .begin_policy_write(1)
                .await
                .map(|w| w.snapshot.state.revision)
        }
    });
    db.db.wait_for_lock_waiters(1).await.unwrap();
    first
        .commit(PolicyChanges {
            revision: 1,
            mac: vec![1; 32],
            ..PolicyChanges::default()
        })
        .await
        .unwrap();
    // It read the state as the first left it.
    assert_eq!(second.await.unwrap().unwrap(), 1);
    db.destroy().await.unwrap();
}

/// A rekey re-wraps the stored policy key from what it reads under its
/// lock, and refuses, committing nothing, if it can't.
#[tokio::test]
async fn a_rekey_rewraps_the_policy_key_or_refuses() {
    let db = TestDb::initialized().await.unwrap();
    db.store
        .begin_policy_write(1)
        .await
        .unwrap()
        .commit(PolicyChanges {
            revision: 1,
            mac: vec![1; 32],
            new_wrapped_key: Some(b"pk@gen1".to_vec()),
            ..PolicyChanges::default()
        })
        .await
        .unwrap();

    let refused = db
        .store
        .rekey(
            1,
            params(5, 3).unwrap(),
            b"check-2",
            &[app_kek().unwrap()],
            &Fake {
                policy: |_| None,
                issuing: |_, _| None,
                tag: |_| None,
            },
        )
        .await;
    assert!(matches!(refused, Err(KeystoreError::PolicyKeyUnusable)));
    assert_eq!(db.store.seal_config().await.unwrap().unwrap().generation, 1);

    let generation = db
        .store
        .rekey(
            1,
            params(5, 3).unwrap(),
            b"check-2",
            &[app_kek().unwrap()],
            &Fake {
                policy: |old| (old == b"pk@gen1").then(|| b"pk@gen2".to_vec()),
                issuing: |_, _| None,
                tag: |_| None,
            },
        )
        .await
        .unwrap();
    assert_eq!(generation, 2);
    assert_eq!(
        db.store.wrapped_policy_key().await.unwrap().as_deref(),
        Some(&b"pk@gen2"[..])
    );
    db.destroy().await.unwrap();
}

/// A rekey's re-wrapping, from plain functions.
struct Fake {
    policy: fn(&[u8]) -> Option<Vec<u8>>,
    issuing: fn(u32, &[u8]) -> Option<Vec<u8>>,
    tag: fn(&IssuingSet) -> Option<Vec<u8>>,
}

impl RekeyRewrap for Fake {
    fn policy_key(&self, wrapped: &[u8]) -> Option<Vec<u8>> {
        (self.policy)(wrapped)
    }

    fn issuing_key(&self, version: u32, wrapped: &[u8]) -> Option<Vec<u8>> {
        (self.issuing)(version, wrapped)
    }

    fn issuing_tag(&self, set: &IssuingSet) -> Option<Vec<u8>> {
        (self.tag)(set)
    }
}

fn issuing_states(set: &IssuingSet) -> Vec<(u32, &'static str, bool)> {
    set.keys
        .iter()
        .map(|k| (k.version, k.state.as_str(), k.wrapped_key.is_some()))
        .collect()
}

/// A stand-in for the root key's tag: the set, readable.
struct Readable;

fn readable(revision: u64, records: &[IssuingRecord<'_>]) -> Vec<u8> {
    let mut text = format!("{revision}");
    for record in records {
        text.push_str(&format!(
            ";{}|{}|{:?}|{}",
            record.version,
            record.state,
            record.retired_at,
            String::from_utf8_lossy(record.certificate)
        ));
    }
    text.into_bytes()
}

impl IssuingTagger for Readable {
    fn tag(&self, revision: u64, records: &[IssuingRecord<'_>]) -> Option<Vec<u8>> {
        Some(readable(revision, records))
    }

    fn verifies(&self, set: &IssuingSet) -> bool {
        set.tag.as_deref() == Some(readable(set.revision, &set.records()).as_slice())
    }
}

fn now() -> TestResult<OffsetDateTime> {
    Ok(OffsetDateTime::now_utc().replace_nanosecond(0)?)
}

/// A rotation to `version`, from `loaded` (the active key as the caller
/// has it), knowing `known`.
fn rotation<'a>(
    loaded: Option<(u32, &'a [u8])>,
    version: u32,
    certificate: &'a [u8],
    revoke: bool,
    known: u64,
) -> TestResult<IssuingRotation<'a>> {
    Ok(IssuingRotation {
        expected_active: loaded.map(|(v, _)| v),
        active_certificate: loaded.map(|(_, c)| c),
        version,
        certificate,
        wrapped_key: b"wrapped",
        revoke,
        at: now()?,
        known_revision: known,
    })
}

/// The issuing keys: created once, as version 1, at revision 1; a rotation
/// makes the next version active and retires (or revokes, with every
/// retired one) the old, erasing its wrapped key and keeping its
/// certificate, and raises the revision; a stale rotation conflicts, one
/// with no key says so. The set is tagged as it now is after every write;
/// the snapshot reads it too.
#[tokio::test]
async fn issuing_keys_are_created_once_and_rotated() {
    let db = TestDb::initialized().await.unwrap();
    let cert1: &[u8] = b"cert-1";
    assert_eq!(db.store.issuing_set().await.unwrap(), IssuingSet::default());
    assert_eq!(
        db.store
            .create_issuing_key(1, cert1, b"key-1@gen1", 0, &Readable)
            .await
            .unwrap(),
        1
    );
    assert!(matches!(
        db.store
            .create_issuing_key(1, b"cert-x", b"key-x", 0, &Readable)
            .await,
        Err(KeystoreError::IssuingKeyExists)
    ));
    let set = db.store.issuing_set().await.unwrap();
    assert_eq!(set.tag.as_deref(), Some(&b"1;1|active|None|cert-1"[..]));

    let first = rotation(Some((1, cert1)), 2, b"cert-2", false, 1).unwrap();
    assert_eq!(
        db.store
            .rotate_issuing_key(1, first, &Readable)
            .await
            .unwrap(),
        2
    );
    let set = db.store.issuing_set().await.unwrap();
    assert_eq!(set.keys[0].retired_at, Some(first.at));
    assert!(Readable.verifies(&set));
    assert_eq!(
        issuing_states(&set),
        [(1, "retired", false), (2, "active", true)]
    );
    // Another server rotated since this one loaded version 1.
    assert!(matches!(
        db.store
            .rotate_issuing_key(
                1,
                rotation(Some((1, cert1)), 3, b"c", false, 2).unwrap(),
                &Readable
            )
            .await,
        Err(KeystoreError::IssuingKeyConflict { .. })
    ));
    // A version that isn't the next one.
    assert!(matches!(
        db.store
            .rotate_issuing_key(
                1,
                rotation(Some((2, b"cert-2")), 2, b"c", false, 2).unwrap(),
                &Readable
            )
            .await,
        Err(KeystoreError::IssuingKeyConflict { .. })
    ));
    assert_eq!(
        db.store
            .rotate_issuing_key(
                1,
                rotation(Some((2, b"cert-2")), 3, b"cert-3", true, 2).unwrap(),
                &Readable
            )
            .await
            .unwrap(),
        3
    );
    let set = db.store.issuing_set().await.unwrap();
    assert_eq!(
        issuing_states(&set),
        // A revoking rotation cuts off the retired keys too, keeping their
        // retirement.
        [
            (1, "revoked", false),
            (2, "revoked", false),
            (3, "active", true)
        ]
    );
    assert_eq!(set.keys[0].retired_at, Some(first.at));
    assert_eq!(set.revision, 3);
    assert!(Readable.verifies(&set));
    assert_eq!(db.store.snapshot().await.unwrap().issuing, set);
    // A rotation under a stale generation (a rekey elsewhere) is refused.
    assert!(matches!(
        db.store
            .rotate_issuing_key(
                9,
                rotation(Some((3, b"cert-3")), 4, b"c", false, 3).unwrap(),
                &Readable
            )
            .await,
        Err(KeystoreError::GenerationMismatch { .. })
    ));
    // The next revision is one past the higher of the stored one and what
    // the caller knows.
    assert_eq!(
        db.store
            .rotate_issuing_key(
                1,
                rotation(Some((3, b"cert-3")), 4, b"cert-4", false, 0).unwrap(),
                &Readable
            )
            .await
            .unwrap(),
        4
    );
    db.destroy().await.unwrap();
}

/// A rotation retires (trusts on) only the certificate the caller loaded
/// with its key: one swapped into the active row, or a key that didn't
/// load, is revoked instead.
#[tokio::test]
async fn a_rotation_trusts_on_only_the_certificate_it_loaded() {
    let db = TestDb::initialized().await.unwrap();
    db.store
        .create_issuing_key(1, b"cert-1", b"key-1", 0, &Readable)
        .await
        .unwrap();
    // The certificate swapped, the set re-tagged as if by the root key: the
    // set verifies, but the caller loaded another certificate.
    sqlx::query("UPDATE issuing_keys SET certificate = '\\x666f72676564'")
        .execute(db.db.pool())
        .await
        .unwrap();
    let tag = readable(1, &db.store.issuing_set().await.unwrap().records());
    sqlx::query("UPDATE issuing_set SET tag = $1")
        .bind(tag)
        .execute(db.db.pool())
        .await
        .unwrap();
    db.store
        .rotate_issuing_key(
            1,
            rotation(Some((1, b"cert-1")), 2, b"cert-2", false, 1).unwrap(),
            &Readable,
        )
        .await
        .unwrap();
    db.store
        .rotate_issuing_key(
            1,
            rotation(None, 3, b"cert-3", false, 2).unwrap(),
            &Readable,
        )
        .await
        .unwrap();
    let set = db.store.issuing_set().await.unwrap();
    assert_eq!(
        issuing_states(&set),
        [
            (1, "revoked", false),
            (2, "revoked", false),
            (3, "active", true)
        ]
    );
    db.destroy().await.unwrap();
}

/// A set that doesn't verify, or is below what the caller knows (rolled
/// back), is replaced only by a revoking rotation, which revokes every key
/// in it and takes its revision from what the caller knows, never from
/// the set.
#[tokio::test]
async fn an_unverified_set_is_only_replaced_by_revoking_everything() {
    let db = TestDb::initialized().await.unwrap();
    db.store
        .create_issuing_key(1, b"cert-1", b"key-1", 0, &Readable)
        .await
        .unwrap();
    db.store
        .rotate_issuing_key(
            1,
            rotation(Some((1, b"cert-1")), 2, b"cert-2", false, 1).unwrap(),
            &Readable,
        )
        .await
        .unwrap();
    // Rolled back: the caller knows revision 5.
    assert!(matches!(
        db.store
            .rotate_issuing_key(
                1,
                rotation(Some((2, b"cert-2")), 3, b"cert-3", false, 5).unwrap(),
                &Readable
            )
            .await,
        Err(KeystoreError::IssuingKeysUnverified)
    ));
    // Tampered: a revision far ahead, with a tag that doesn't verify.
    sqlx::query("UPDATE issuing_set SET revision = 9000000000000000000")
        .execute(db.db.pool())
        .await
        .unwrap();
    assert!(matches!(
        db.store
            .rotate_issuing_key(
                1,
                rotation(Some((2, b"cert-2")), 3, b"cert-3", false, 5).unwrap(),
                &Readable
            )
            .await,
        Err(KeystoreError::IssuingKeysUnverified)
    ));
    assert_eq!(
        db.store
            .rotate_issuing_key(1, rotation(None, 3, b"cert-3", true, 5).unwrap(), &Readable)
            .await
            .unwrap(),
        6
    );
    let set = db.store.issuing_set().await.unwrap();
    assert_eq!(
        issuing_states(&set),
        [
            (1, "revoked", false),
            (2, "revoked", false),
            (3, "active", true)
        ]
    );
    assert!(Readable.verifies(&set));
    db.destroy().await.unwrap();
}

/// A rekey re-wraps the active issuing key (re-read under its lock) and
/// re-tags the set if the callback vouches for it (if not, the set keeps
/// its tag), and refuses, changing nothing, if it can't re-wrap.
#[tokio::test]
async fn a_rekey_rewraps_the_issuing_key() {
    let db = TestDb::initialized().await.unwrap();
    db.store
        .create_issuing_key(1, b"cert-1", b"key-1@gen1", 0, &Readable)
        .await
        .unwrap();
    db.store
        .rotate_issuing_key(
            1,
            rotation(Some((1, b"cert-1")), 2, b"cert-2", false, 1).unwrap(),
            &Readable,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE issuing_keys SET wrapped_key = 'key-2@gen1' WHERE version = 2")
        .execute(db.db.pool())
        .await
        .unwrap();
    let before = db.store.issuing_set().await.unwrap();
    let refused = db
        .store
        .rekey(
            1,
            params(5, 3).unwrap(),
            b"check-2",
            &[app_kek().unwrap()],
            &Fake {
                policy: |_| None,
                issuing: |_, _| None,
                tag: |_| Some(b"retagged".to_vec()),
            },
        )
        .await;
    assert!(matches!(refused, Err(KeystoreError::IssuingKeyUnusable)));
    assert_eq!(db.store.seal_config().await.unwrap().unwrap().generation, 1);
    assert_eq!(db.store.issuing_set().await.unwrap(), before);

    let generation = db
        .store
        .rekey(
            1,
            params(5, 3).unwrap(),
            b"check-2",
            &[app_kek().unwrap()],
            &Fake {
                policy: |_| None,
                issuing: |version, old| {
                    (version == 2 && old == b"key-2@gen1").then(|| b"key-2@gen2".to_vec())
                },
                tag: |set| (set.revision == 2).then(|| b"tag@gen2".to_vec()),
            },
        )
        .await
        .unwrap();
    assert_eq!(generation, 2);
    let set = db.store.issuing_set().await.unwrap();
    assert_eq!(set.keys[1].wrapped_key.as_deref(), Some(&b"key-2@gen2"[..]));
    assert_eq!(set.keys[0].wrapped_key, None);
    assert_eq!(set.tag.as_deref(), Some(&b"tag@gen2"[..]));
    assert_eq!(set.revision, 2);
    db.destroy().await.unwrap();
}

/// The schema holds the rule: only the active key has a wrapped key, and
/// there's one active key at most.
#[tokio::test]
async fn only_the_active_issuing_key_has_a_wrapped_key() {
    let db = TestDb::initialized().await.unwrap();
    db.store
        .create_issuing_key(1, b"cert-1", b"key-1", 0, &Readable)
        .await
        .unwrap();
    for statement in [
        "INSERT INTO issuing_keys (version, certificate, state, wrapped_key, retired_at)
         VALUES (2, '\\x00', 'retired', '\\x01', now())",
        "INSERT INTO issuing_keys (version, certificate, state, wrapped_key)
         VALUES (2, '\\x00', 'active', '\\x01')",
        "UPDATE issuing_keys SET state = 'retired', retired_at = now()",
    ] {
        assert!(
            sqlx::query(statement).execute(db.db.pool()).await.is_err(),
            "{statement}"
        );
    }
    db.destroy().await.unwrap();
}

/// What a rekey stores as the new root key's KMS wrap.
struct Wrapping(Option<SealWrap>);

impl RekeyRewrap for Wrapping {
    fn policy_key(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn issuing_key(&self, _: u32, _: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn issuing_tag(&self, _: &IssuingSet) -> Option<Vec<u8>> {
        None
    }

    fn seal_wrap(&self) -> Option<&SealWrap> {
        self.0.as_ref()
    }
}

fn wrap(key_id: &str, generation: u32) -> SealWrap {
    SealWrap {
        provider: "awskms".to_owned(),
        key_id: key_id.to_owned(),
        generation,
        ciphertext: format!("{key_id}@{generation}").into_bytes(),
    }
}

/// Init stores the wrap with the seal config; a rekey replaces every wrap
/// with the new generation's, or, from a server with none, removes them.
#[tokio::test]
async fn a_rekey_replaces_the_seal_wraps() {
    let db = TestDb::new().await.unwrap();
    db.store
        .initialize_wrapped(params(5, 3).unwrap(), b"check", Some(&wrap("key-a", 1)))
        .await
        .unwrap();
    let (config, wraps) = db.store.seal_config_and_wraps("awskms").await.unwrap();
    assert_eq!(config.unwrap().generation, 1);
    assert_eq!(wraps, [wrap("key-a", 1)]);

    db.store
        .rekey(
            1,
            params(5, 3).unwrap(),
            b"check-2",
            &[],
            &Wrapping(Some(wrap("key-b", 2))),
        )
        .await
        .unwrap();
    let (config, wraps) = db.store.seal_config_and_wraps("awskms").await.unwrap();
    assert_eq!(config.unwrap().generation, 2);
    assert_eq!(wraps, [wrap("key-b", 2)]);

    // To another provider: its wrap replaces the other provider's, and a
    // read of every wrap sees exactly it.
    let gcp = SealWrap {
        provider: "gcpkms".to_owned(),
        ..wrap("projects/p/locations/l/keyRings/r/cryptoKeys/k", 3)
    };
    db.store
        .rekey(
            2,
            params(5, 3).unwrap(),
            b"check-3",
            &[],
            &Wrapping(Some(gcp.clone())),
        )
        .await
        .unwrap();
    assert!(
        db.store
            .seal_config_and_wraps("awskms")
            .await
            .unwrap()
            .1
            .is_empty()
    );
    assert_eq!(db.store.seal_wraps().await.unwrap(), [gcp]);

    db.store
        .rekey(3, params(5, 3).unwrap(), b"check-4", &[], &Wrapping(None))
        .await
        .unwrap();
    assert!(db.store.seal_wraps().await.unwrap().is_empty());
    db.destroy().await.unwrap();
}
