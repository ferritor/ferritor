//! Runs against the data DB from `DATA_DATABASE_URL` (`.env`). Each test gets
//! its own freshly migrated database (see `ferritor-testkit`).

use std::time::Duration;

use ferritor_core::labels::Labels;
use ferritor_core::path::{Namespace, SecretPath};
use ferritor_datastore::{
    Change, ChangeMark, Changes, Datastore, DatastoreError, MIGRATOR, Reclaimed, Rewrapped, RowKey,
};
use ferritor_testkit::data::insert_version;
use ferritor_testkit::{TestDatabase, TestResult};

struct TestDb {
    db: TestDatabase,
    store: Datastore,
}

impl TestDb {
    async fn new() -> TestResult<Self> {
        let db = TestDatabase::new("DATA_DATABASE_URL", "ferritor_data_test", &MIGRATOR).await?;
        let store = Datastore::new(db.pool().clone());
        Ok(Self { db, store })
    }

    /// Stores the next version of `path` with recognisable fake bytes.
    async fn put(&self, path: &str) -> TestResult<u32> {
        let pending = self.store.begin_put(&SecretPath::parse(path)?).await?;
        let version = pending.version();
        let ciphertext = format!("ct:{path}@{version}");
        pending
            .insert(ciphertext.as_bytes(), b"dek", 1)
            .await?
            .commit()
            .await?;
        Ok(version)
    }

    /// Deletes and commits; returns how many versions were marked.
    async fn delete(&self, path: &str) -> TestResult<u64> {
        let pending = self.store.begin_delete(&SecretPath::parse(path)?).await?;
        let count = pending.count();
        pending.commit().await?;
        Ok(count)
    }

    async fn destroy(self) -> TestResult<()> {
        self.db.destroy().await
    }
}

type TestError = Box<dyn std::error::Error + Send + Sync>;

fn ns(name: &str) -> TestResult<Namespace> {
    Ok(Namespace::parse(name)?)
}

fn p(path: &str) -> TestResult<SecretPath> {
    Ok(SecretPath::parse(path)?)
}

#[tokio::test]
async fn puts_create_increasing_versions() {
    let db = TestDb::new().await.unwrap();
    assert_eq!(db.put("app/db").await.unwrap(), 1);
    assert_eq!(db.put("app/db").await.unwrap(), 2);
    assert_eq!(db.put("app/other").await.unwrap(), 1);
    db.destroy().await.unwrap();
}

/// Puts to one path queue on its lock instead of racing for a number.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_put_to_a_path_waits_and_gets_the_next_version() {
    let db = TestDb::new().await.unwrap();
    let path = p("app/db").unwrap();
    let first = db.store.begin_put(&path).await.unwrap();
    assert_eq!(first.version(), 1);

    let store = db.store.clone();
    let second = tokio::spawn({
        let path = path.clone();
        async move { store.begin_put(&path).await.map(|p| p.version()) }
    });
    db.db.wait_for_lock_waiters(1).await.unwrap();
    first
        .insert(b"a", b"dek", 1)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert_eq!(second.await.unwrap().unwrap(), 2);
    db.destroy().await.unwrap();
}

/// A put sees the latest live version under the path's lock: what a
/// check-and-set compares against.
#[tokio::test]
async fn a_put_sees_the_latest_live_version() {
    let db = TestDb::new().await.unwrap();
    let path = p("app/db").unwrap();
    let latest = |db: &TestDb| {
        let (store, path) = (db.store.clone(), path.clone());
        async move {
            let pending = store.begin_put(&path).await.unwrap();
            (pending.latest(), pending.version())
        }
    };
    assert_eq!(latest(&db).await, (None, 1));
    db.put("app/db").await.unwrap();
    db.put("app/db").await.unwrap();
    assert_eq!(latest(&db).await, (Some(2), 3));
    // Deleted: no live version, but the numbers still move on.
    db.delete("app/db").await.unwrap();
    assert_eq!(latest(&db).await, (None, 3));
    db.destroy().await.unwrap();
}

/// A delete takes the path's write lock too: it waits for a put in
/// progress and then deletes that version as well, so no put can pass a
/// check-and-set against a state a delete is about to change (or survive a
/// delete it raced).
#[tokio::test(flavor = "multi_thread")]
async fn a_delete_waits_for_a_put_in_progress_and_deletes_it_too() {
    let db = TestDb::new().await.unwrap();
    let path = p("app/db").unwrap();
    db.put("app/db").await.unwrap();
    let put = db.store.begin_put(&path).await.unwrap();
    assert_eq!(put.latest(), Some(1));

    let store = db.store.clone();
    let delete = tokio::spawn({
        let path = path.clone();
        async move {
            let pending = store.begin_delete(&path).await?;
            let count = pending.count();
            pending.commit().await?;
            Ok::<_, ferritor_datastore::DatastoreError>(count)
        }
    });
    db.db.wait_for_lock_waiters(1).await.unwrap();
    put.insert(b"a", b"dek", 1)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert_eq!(delete.await.unwrap().unwrap(), 2);
    assert!(db.store.get(&path, None).await.unwrap().is_none());
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn puts_to_different_paths_do_not_wait_for_each_other() {
    let db = TestDb::new().await.unwrap();
    let a = db.store.begin_put(&p("app/a").unwrap()).await.unwrap();
    // Would block (and time the test out) if it shared app/a's lock.
    let b = db.store.begin_put(&p("app/b").unwrap()).await.unwrap();
    b.insert(b"b", b"dek", 1)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    a.insert(b"a", b"dek", 1)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn a_dropped_put_stores_nothing_and_releases_the_lock() {
    let db = TestDb::new().await.unwrap();
    let path = p("app/db").unwrap();
    drop(db.store.begin_put(&path).await.unwrap());
    let again = db.store.begin_put(&path).await.unwrap();
    assert_eq!(again.version(), 1);
    drop(again);
    assert!(db.store.get(&path, None).await.unwrap().is_none());
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn a_staged_put_dropped_before_commit_stores_nothing() {
    let db = TestDb::new().await.unwrap();
    let path = p("app/db").unwrap();
    let pending = db.store.begin_put(&path).await.unwrap();
    drop(pending.insert(b"a", b"dek", 1).await.unwrap());
    assert!(db.store.get(&path, None).await.unwrap().is_none());
    // The lock went with it, and the number wasn't used up.
    assert_eq!(db.store.begin_put(&path).await.unwrap().version(), 1);
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn a_delete_dropped_before_commit_deletes_nothing() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    let pending = db.store.begin_delete(&p("app/db").unwrap()).await.unwrap();
    assert_eq!(pending.count(), 1);
    drop(pending);
    assert!(
        db.store
            .get(&p("app/db").unwrap(), None)
            .await
            .unwrap()
            .is_some()
    );
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn get_returns_latest_or_a_given_version() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    db.put("app/db").await.unwrap();

    let latest = db
        .store
        .get(&p("app/db").unwrap(), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest.metadata.version, 2);
    assert_eq!(latest.ciphertext, b"ct:app/db@2");
    assert_eq!(
        (latest.wrapped_dek.as_slice(), latest.kek_version),
        (&b"dek"[..], 1)
    );

    let first = db
        .store
        .get(&p("app/db").unwrap(), Some(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.ciphertext, b"ct:app/db@1");
    assert!(
        db.store
            .get(&p("app/db").unwrap(), Some(3))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.store
            .get(&p("app/none").unwrap(), None)
            .await
            .unwrap()
            .is_none()
    );
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn delete_hides_every_version_and_numbers_are_never_reused() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    db.put("app/db").await.unwrap();

    assert_eq!(db.delete("app/db").await.unwrap(), 2);
    assert!(
        db.store
            .get(&p("app/db").unwrap(), None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.store
            .get(&p("app/db").unwrap(), Some(1))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.store
            .list(None, None, 100, &Labels::new())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(db.delete("app/db").await.unwrap(), 0);

    // A new put continues the numbering: version 1 stays a deleted row.
    assert_eq!(db.put("app/db").await.unwrap(), 3);
    let latest = db
        .store
        .get(&p("app/db").unwrap(), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest.metadata.version, 3);
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn list_matches_whole_segments_and_returns_latest_versions() {
    let db = TestDb::new().await.unwrap();
    // Near misses around `app/db`: `0` sorts right after `/`, `.` before it.
    for path in [
        "app/db",
        "app/db/a",
        "app/db/b",
        "app/db/b",
        "app/db0",
        "app/db.old",
        "apps/x",
    ] {
        db.put(path).await.unwrap();
    }
    let listed = |prefix: Option<&str>| {
        let store = db.store.clone();
        let prefix = prefix.map(|s| p(s).unwrap());
        async move {
            store
                .list(prefix.as_ref(), None, 100, &Labels::new())
                .await
                .unwrap()
                .into_iter()
                .map(|m| (m.path.to_string(), m.version))
                .collect::<Vec<_>>()
        }
    };

    assert_eq!(
        listed(Some("app/db")).await,
        [("app/db/a".to_owned(), 1), ("app/db/b".to_owned(), 2)]
    );
    assert_eq!(listed(Some("app")).await.len(), 5);
    assert_eq!(listed(None).await.len(), 6);
    assert!(listed(Some("nothing")).await.is_empty());
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn list_pages_by_the_last_path_without_leaving_the_prefix() {
    let db = TestDb::new().await.unwrap();
    // `app` itself sorts between a cursor `a` and `app`'s descendants.
    for path in ["app", "app/a", "app/b", "app/b", "app/c", "apps/x", "b"] {
        db.put(path).await.unwrap();
    }
    let page = |prefix: Option<&str>, after: Option<&str>, limit: u32| {
        let store = db.store.clone();
        let prefix = prefix.map(|s| p(s).unwrap());
        let after = after.map(|s| p(s).unwrap());
        async move {
            store
                .list(prefix.as_ref(), after.as_ref(), limit, &Labels::new())
                .await
                .unwrap()
                .into_iter()
                .map(|m| m.path.to_string())
                .collect::<Vec<_>>()
        }
    };

    assert_eq!(page(None, None, 2).await, ["app", "app/a"]);
    // One row per path even though `app/b` has two versions.
    assert_eq!(page(None, Some("app/a"), 2).await, ["app/b", "app/c"]);
    assert_eq!(page(None, Some("app/c"), 2).await, ["apps/x", "b"]);
    assert!(page(None, Some("b"), 2).await.is_empty());
    assert_eq!(
        page(Some("app"), Some("app/a"), 10).await,
        ["app/b", "app/c"]
    );
    // A cursor outside the prefix never widens it: before it, the range's
    // own lower bound still holds; past it, nothing.
    assert_eq!(
        page(Some("app"), Some("a"), 10).await,
        ["app/a", "app/b", "app/c"]
    );
    assert!(page(Some("app"), Some("apps/x"), 10).await.is_empty());
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn a_stalled_database_times_out() {
    let db = TestDb::new().await.unwrap();
    let mut stall = db.db.pool().begin().await.unwrap();
    sqlx::query("LOCK TABLE secret_versions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *stall)
        .await
        .unwrap();

    let bounded = db.store.clone().with_timeout(Duration::from_millis(200));
    let started = std::time::Instant::now();
    assert!(matches!(
        bounded.get(&p("app/db").unwrap(), None).await,
        Err(DatastoreError::Timeout)
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    stall.rollback().await.unwrap();
    db.destroy().await.unwrap();
}

/// A put stuck behind another put to the same path gives up on its own,
/// with a "busy, retry" error rather than a generic timeout.
#[tokio::test]
async fn a_put_waiting_too_long_for_the_path_lock_is_busy() {
    let db = TestDb::new().await.unwrap();
    let path = p("app/db").unwrap();
    let holder = db.store.begin_put(&path).await.unwrap();

    let impatient = db
        .store
        .clone()
        .with_lock_timeout(Duration::from_millis(100));
    assert!(matches!(
        impatient.begin_put(&path).await,
        Err(DatastoreError::Busy(_))
    ));
    drop(holder);
    db.destroy().await.unwrap();
}

/// The put transaction's lock_timeout also bounds the insert's wait on the
/// primary key. That wait needs a row written outside `begin_put`'s lock;
/// it must still come back as "busy", not an internal error.
#[tokio::test]
async fn an_insert_stuck_on_a_foreign_row_is_busy() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    let mut foreign = db.db.pool().begin().await.unwrap();
    insert_version(&mut foreign, "app/db", 2, 1).await.unwrap();

    let impatient = db
        .store
        .clone()
        .with_lock_timeout(Duration::from_millis(100));
    // The foreign row is uncommitted, so this put also picks version 2.
    let pending = impatient.begin_put(&p("app/db").unwrap()).await.unwrap();
    assert_eq!(pending.version(), 2);
    assert!(matches!(
        pending.insert(b"a", b"dek", 1).await,
        Err(DatastoreError::Busy(_))
    ));
    foreign.rollback().await.unwrap();
    db.destroy().await.unwrap();
}

/// No connection free within the pool's acquire timeout is an overloaded
/// database: `Timeout`, like the client-side bound, not an internal error.
#[tokio::test]
async fn an_exhausted_pool_is_a_timeout() {
    let db = TestDb::new().await.unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy_with((*db.db.pool().connect_options()).clone());
    // Opening the one connection falls under the same 100 ms, which a busy
    // machine can take longer than (CI did): retried until it opens. The
    // timeout under test is the next acquire's, with it held.
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
    // The client-side bound is far away: the pool's timeout fires first.
    let store = Datastore::new(pool.clone()).with_timeout(Duration::from_secs(5));
    assert!(matches!(
        store.get(&p("app/db").unwrap(), None).await,
        Err(DatastoreError::Timeout)
    ));
    drop(only_connection);
    pool.close().await;
    db.destroy().await.unwrap();
}

/// Stores `path` with its DEK wrapped by `kek_version`.
async fn put_with_kek(db: &TestDb, path: &str, kek_version: u32) -> TestResult<()> {
    let pending = db.store.begin_put(&SecretPath::parse(path)?).await?;
    pending
        .insert(b"ct", b"old-wrap", kek_version)
        .await?
        .commit()
        .await?;
    Ok(())
}

#[tokio::test]
async fn wrapped_by_pages_through_one_kek_version_in_key_order() {
    let db = TestDb::new().await.unwrap();
    for path in ["app/a", "app/b", "app/c", "app/d", "app/e"] {
        put_with_kek(&db, path, 1).await.unwrap();
    }
    put_with_kek(&db, "app/other", 2).await.unwrap();
    // Another namespace's version 1 isn't app's.
    put_with_kek(&db, "billing/x", 1).await.unwrap();
    // Deleted rows still count: their DEKs are wrapped too.
    db.delete("app/e").await.unwrap();
    let app = ns("app").unwrap();

    let mut seen = Vec::new();
    let mut after = RowKey::FIRST;
    loop {
        let page = db.store.wrapped_by(&app, 1, after, 2).await.unwrap();
        let Some(last) = page.last() else { break };
        after = last.key;
        assert!(page.len() <= 2);
        seen.extend(page.into_iter().map(|w| w.path.to_string()));
    }
    // uuidv7 path ids are time-ordered, so key order is the order the paths
    // were first written here.
    assert_eq!(seen, ["app/a", "app/b", "app/c", "app/d", "app/e"]);
    assert!(db.store.any_wrapped_by(&app, 1).await.unwrap());
    assert!(!db.store.any_wrapped_by(&app, 3).await.unwrap());
    assert!(
        !db.store
            .any_wrapped_by(&ns("other").unwrap(), 1)
            .await
            .unwrap()
    );
    db.destroy().await.unwrap();
}

/// Rewrap is compare-and-set: rows that already moved on are left alone.
#[tokio::test]
async fn rewrap_only_moves_rows_still_on_the_old_kek() {
    let db = TestDb::new().await.unwrap();
    put_with_kek(&db, "app/a", 1).await.unwrap();
    put_with_kek(&db, "app/b", 1).await.unwrap();
    let app = ns("app").unwrap();
    let rows = db
        .store
        .wrapped_by(&app, 1, RowKey::FIRST, 10)
        .await
        .unwrap();
    let rewrapped: Vec<Rewrapped> = rows
        .iter()
        .map(|w| Rewrapped {
            key: w.key,
            wrapped_dek: b"new-wrap".to_vec(),
        })
        .collect();

    assert_eq!(db.store.rewrap(&app, 1, 3, &rewrapped).await.unwrap(), 2);
    // A second, late pass with the same rows changes nothing.
    assert_eq!(db.store.rewrap(&app, 1, 3, &rewrapped).await.unwrap(), 0);
    assert!(!db.store.any_wrapped_by(&app, 1).await.unwrap());
    assert!(db.store.any_wrapped_by(&app, 3).await.unwrap());
    let a = db
        .store
        .get(&p("app/a").unwrap(), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (a.kek_version, a.wrapped_dek.as_slice()),
        (3, &b"new-wrap"[..])
    );
    assert_current_versions_agree(&db).await.unwrap();
    db.destroy().await.unwrap();
}

/// How many rows `path` has, deleted or not.
async fn rows(db: &TestDb, path: &str) -> TestResult<i64> {
    let count: Option<i64> = sqlx::query_scalar(
        "SELECT count(*) FROM secret_versions v JOIN paths p ON p.id = v.path_id
         WHERE p.path = $1",
    )
    .bind(path)
    .fetch_one(db.db.pool())
    .await?;
    Ok(count.unwrap_or_default())
}

/// Backdates every deletion of `path` by `ago`.
async fn deleted_ago(db: &TestDb, path: &str, ago: &str) -> TestResult<()> {
    sqlx::query(
        "UPDATE secret_versions SET deleted_at = now() - $2::interval
         WHERE path_id = (SELECT id FROM paths WHERE path = $1) AND deleted_at IS NOT NULL",
    )
    .bind(path)
    .bind(ago)
    .execute(db.db.pool())
    .await?;
    Ok(())
}

/// Only rows deleted longer ago than the retention go, oldest first, at
/// most `limit` per call; live rows and recent deletions stay.
#[tokio::test]
async fn purge_removes_only_deletions_past_their_retention() {
    let db = TestDb::new().await.unwrap();
    for path in ["old", "old", "old", "recent", "live"] {
        db.put(path).await.unwrap();
    }
    db.delete("old").await.unwrap();
    db.delete("recent").await.unwrap();
    deleted_ago(&db, "old", "2 hours").await.unwrap();
    deleted_ago(&db, "recent", "10 minutes").await.unwrap();
    let hour = Duration::from_secs(3600);

    assert_eq!(db.store.purge_deleted(hour, 2).await.unwrap(), 2);
    assert_eq!(db.store.purge_deleted(hour, 2).await.unwrap(), 1);
    assert_eq!(db.store.purge_deleted(hour, 2).await.unwrap(), 0);
    assert_eq!(
        (
            rows(&db, "old").await.unwrap(),
            rows(&db, "recent").await.unwrap(),
            rows(&db, "live").await.unwrap()
        ),
        (0, 1, 1)
    );
    // No retention: every deletion goes, still never a live row.
    assert_eq!(db.store.purge_deleted(Duration::ZERO, 10).await.unwrap(), 1);
    assert_eq!(rows(&db, "live").await.unwrap(), 1);
    assert_current_versions_agree(&db).await.unwrap();
    db.destroy().await.unwrap();
}

/// Purging every row of a path doesn't make its numbers come round again:
/// AAD binds path and version, and a check-and-set's expected version
/// must never match a different secret.
#[tokio::test]
async fn versions_are_never_reused_even_after_a_purge() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    db.put("app/db").await.unwrap();
    db.delete("app/db").await.unwrap();
    db.store.purge_deleted(Duration::ZERO, 10).await.unwrap();
    assert_eq!(rows(&db, "app/db").await.unwrap(), 0);

    let pending = db.store.begin_put(&p("app/db").unwrap()).await.unwrap();
    assert_eq!((pending.version(), pending.latest()), (3, None));
    // Dropped before committing: the number isn't spent either.
    drop(pending);
    assert_eq!(db.put("app/db").await.unwrap(), 3);
    assert_current_versions_agree(&db).await.unwrap();
    db.destroy().await.unwrap();
}

#[tokio::test]
async fn a_path_at_the_last_version_number_is_exhausted() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    sqlx::query("UPDATE paths SET highest = 2147483647 WHERE path = 'app/db'")
        .execute(db.db.pool())
        .await
        .unwrap();
    assert!(matches!(
        db.store.begin_put(&p("app/db").unwrap()).await,
        Err(DatastoreError::VersionsExhausted(_))
    ));
    db.destroy().await.unwrap();
}

/// Writes a row the way a hand repair (or a restored backup) might: without
/// bumping its path's `highest`.
async fn insert_behind_its_back(db: &TestDb, path: &str, version: i32) -> TestResult<()> {
    insert_version(&mut *db.db.pool().acquire().await?, path, version, 1).await
}

/// `paths.highest` falling behind the rows must not make puts collide on
/// the primary key: the next version clears both records, and the put
/// repairs `highest`.
#[tokio::test]
async fn a_row_written_behind_the_counters_back_is_skipped_past() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    insert_behind_its_back(&db, "app/db", 5).await.unwrap();
    assert_eq!(db.put("app/db").await.unwrap(), 6);
    assert_eq!(db.put("app/db").await.unwrap(), 7);

    // A new path, its counter written at the row's version.
    insert_behind_its_back(&db, "app/new", 3).await.unwrap();
    assert_eq!(db.put("app/new").await.unwrap(), 4);
    db.destroy().await.unwrap();
}

/// Rows at the last version number exhaust the path too, rather than
/// overflowing.
#[tokio::test]
async fn rows_at_the_last_version_number_exhaust_the_path() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    insert_behind_its_back(&db, "app/db", i32::MAX)
        .await
        .unwrap();
    assert!(matches!(
        db.store.begin_put(&p("app/db").unwrap()).await,
        Err(DatastoreError::VersionsExhausted(_))
    ));
    db.destroy().await.unwrap();
}

/// A row another transaction holds (a concurrent purge's batch, a rewrap)
/// is skipped, not waited for: concurrent purges take disjoint batches
/// instead of picking the same rows, the slower one then stopping early.
#[tokio::test]
async fn purge_skips_rows_another_transaction_holds() {
    let db = TestDb::new().await.unwrap();
    for path in ["a", "b", "c"] {
        db.put(path).await.unwrap();
        db.delete(path).await.unwrap();
    }
    let mut held = db.db.pool().begin().await.unwrap();
    sqlx::query(
        "SELECT 1 FROM secret_versions WHERE path_id = (SELECT id FROM paths WHERE path = 'b')
         FOR UPDATE",
    )
    .execute(&mut *held)
    .await
    .unwrap();

    // Bounded, so waiting on the held row would fail the test, not hang it.
    let store = Datastore::new(db.db.pool().clone()).with_timeout(Duration::from_secs(2));
    assert_eq!(store.purge_deleted(Duration::ZERO, 10).await.unwrap(), 2);
    assert_eq!(rows(&db, "b").await.unwrap(), 1);
    held.rollback().await.unwrap();
    assert_eq!(store.purge_deleted(Duration::ZERO, 10).await.unwrap(), 1);
    assert_current_versions_agree(&db).await.unwrap();
    db.destroy().await.unwrap();
}

/// Puts `path` through `store` (with its own version limit); returns the
/// version and how many older ones the put trimmed.
async fn put_with(store: &Datastore, path: &str) -> TestResult<(u32, u64)> {
    let staged = store
        .begin_put(&p(path)?)
        .await?
        .insert(b"ct", b"dek", 1)
        .await?;
    let trimmed = staged.trimmed();
    Ok((staged.commit().await?.version, trimmed))
}

/// Live version numbers of `path`, oldest first.
async fn live(db: &TestDb, path: &str) -> TestResult<Vec<i32>> {
    Ok(sqlx::query_scalar(
        "SELECT version FROM secret_versions
         WHERE path_id = (SELECT id FROM paths WHERE path = $1) AND deleted_at IS NULL
         ORDER BY version",
    )
    .bind(path)
    .fetch_all(db.db.pool())
    .await?)
}

/// With a limit, each put keeps only the newest N live versions: older
/// ones become deleted (hidden, purged later), numbering carries on.
#[tokio::test]
async fn a_put_keeps_only_the_newest_versions() {
    let db = TestDb::new().await.unwrap();
    let two = Datastore::new(db.db.pool().clone()).with_max_versions(2);
    assert_eq!(put_with(&two, "app/db").await.unwrap(), (1, 0));
    assert_eq!(put_with(&two, "app/db").await.unwrap(), (2, 0));
    assert_eq!(put_with(&two, "app/db").await.unwrap(), (3, 1));
    assert_eq!(put_with(&two, "app/db").await.unwrap(), (4, 1));
    assert_eq!(live(&db, "app/db").await.unwrap(), [3, 4]);
    let path = p("app/db").unwrap();
    assert!(two.get(&path, Some(2)).await.unwrap().is_none());
    assert_eq!(rows(&db, "app/db").await.unwrap(), 4);

    // Trimmed versions are deleted ones: purged like any other.
    assert_eq!(two.purge_deleted(Duration::ZERO, 10).await.unwrap(), 2);
    assert_eq!(put_with(&two, "app/db").await.unwrap(), (5, 1));
    assert_eq!(live(&db, "app/db").await.unwrap(), [4, 5]);
    assert_current_versions_agree(&db).await.unwrap();
    db.destroy().await.unwrap();
}

/// Lowering the limit trims a path's excess on its next put; without a
/// limit, every version stays.
#[tokio::test]
async fn a_lowered_limit_applies_on_the_next_put() {
    let db = TestDb::new().await.unwrap();
    let unlimited = Datastore::new(db.db.pool().clone());
    for _ in 0..5 {
        put_with(&unlimited, "app/db").await.unwrap();
    }
    assert_eq!(live(&db, "app/db").await.unwrap(), [1, 2, 3, 4, 5]);

    let one = Datastore::new(db.db.pool().clone()).with_max_versions(1);
    assert_eq!(put_with(&one, "app/db").await.unwrap(), (6, 5));
    assert_eq!(live(&db, "app/db").await.unwrap(), [6]);
    // Other paths are untouched until written.
    put_with(&unlimited, "app/other").await.unwrap();
    put_with(&unlimited, "app/other").await.unwrap();
    assert_eq!(live(&db, "app/other").await.unwrap(), [1, 2]);
    assert_current_versions_agree(&db).await.unwrap();
    db.destroy().await.unwrap();
}

/// Restores and commits `version` of `path` (the newest deleted if `None`);
/// returns the version restored, if any.
async fn restore(db: &TestDb, path: &str, version: Option<u32>) -> TestResult<Option<u32>> {
    let pending = db.store.begin_restore(&p(path)?, version).await?;
    let restored = pending.restored().map(|m| m.version);
    pending.commit().await?;
    Ok(restored)
}

/// A deleted version comes back: the newest by default (only while none is
/// live; older ones stay deleted), or a given one, and the latest live
/// version moves with it. Nothing comes back that's live, purged, or never
/// was.
#[tokio::test]
async fn a_deleted_version_can_be_restored_until_purged() {
    let db = TestDb::new().await.unwrap();
    for _ in 0..3 {
        db.put("app/db").await.unwrap();
    }
    db.delete("app/db").await.unwrap();
    assert_eq!(restore(&db, "app/db", None).await.unwrap(), Some(3));
    assert_eq!(live(&db, "app/db").await.unwrap(), [3]);
    assert_eq!(restore(&db, "app/db", Some(1)).await.unwrap(), Some(1));
    assert_eq!(live(&db, "app/db").await.unwrap(), [1, 3]);
    let pending = db.store.begin_put(&p("app/db").unwrap()).await.unwrap();
    assert_eq!((pending.latest(), pending.version()), (Some(3), 4));
    drop(pending);

    // Live already, never stored, or purged: nothing to restore.
    assert_eq!(restore(&db, "app/db", Some(3)).await.unwrap(), None);
    assert_eq!(restore(&db, "app/db", Some(9)).await.unwrap(), None);
    assert_eq!(restore(&db, "nothing/here", None).await.unwrap(), None);
    // No version while one is live: nothing, even with version 2 deleted,
    // and the live one reported.
    let pending = db
        .store
        .begin_restore(&p("app/db").unwrap(), None)
        .await
        .unwrap();
    assert_eq!((pending.restored(), pending.live()), (None, Some(3)));
    drop(pending);
    assert_eq!(live(&db, "app/db").await.unwrap(), [1, 3]);
    db.store.purge_deleted(Duration::ZERO, 10).await.unwrap();
    assert_eq!(restore(&db, "app/db", Some(2)).await.unwrap(), None);
    assert_eq!(live(&db, "app/db").await.unwrap(), [1, 3]);
    assert_current_versions_agree(&db).await.unwrap();
    db.destroy().await.unwrap();
}

/// A path's history: live and deleted versions, newest first, without the
/// purged ones (so with gaps) and without other paths, a page at a time.
#[tokio::test]
async fn the_history_lists_live_and_deleted_versions_newest_first() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    db.put("app/db").await.unwrap();
    db.delete("app/db").await.unwrap();
    db.store.purge_deleted(Duration::ZERO, 10).await.unwrap();
    db.put("app/db").await.unwrap();
    db.delete("app/db").await.unwrap();
    db.put("app/db").await.unwrap();
    db.put("app/db").await.unwrap();
    // Neighbours by prefix, by whole segment or not: not part of it.
    db.put("app/db2").await.unwrap();
    db.put("app/db/x").await.unwrap();

    let path = p("app/db").unwrap();
    let all = db.store.versions(&path, None, 10).await.unwrap();
    let summary: Vec<(u32, bool)> = all
        .iter()
        .map(|v| (v.metadata.version, v.deleted_at.is_some()))
        .collect();
    assert_eq!(summary, [(5, false), (4, false), (3, true)]);
    assert!(all.iter().all(|v| v.metadata.path == path));

    let first = db.store.versions(&path, None, 2).await.unwrap();
    assert_eq!(
        first.iter().map(|v| v.metadata.version).collect::<Vec<_>>(),
        [5, 4]
    );
    let rest = db.store.versions(&path, Some(4), 2).await.unwrap();
    assert_eq!(
        rest.iter().map(|v| v.metadata.version).collect::<Vec<_>>(),
        [3]
    );
    assert!(
        db.store
            .versions(&path, Some(3), 2)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db.store
            .versions(&p("nothing/here").unwrap(), None, 10)
            .await
            .unwrap()
            .is_empty()
    );
    db.destroy().await.unwrap();
}

/// The KEK floor refuses a DEK wrapped by an older KEK, on a put's insert
/// and on a rewrap's update, and only ever goes up.
#[tokio::test]
async fn the_kek_floor_refuses_older_keks_and_never_goes_down() {
    let db = TestDb::new().await.unwrap();
    let app = ns("app").unwrap();
    assert_eq!(db.store.kek_floor(&app).await.unwrap(), 1);
    db.put("app/old").await.unwrap();
    assert_eq!(db.store.raise_kek_floor(&app, 3).await.unwrap(), 3);
    assert_eq!(db.store.raise_kek_floor(&app, 2).await.unwrap(), 3);
    assert_eq!(db.store.kek_floor(&app).await.unwrap(), 3);
    // Another namespace has no floor: its version 1 is fine.
    assert_eq!(
        db.store.kek_floor(&ns("billing").unwrap()).await.unwrap(),
        1
    );
    put_with_kek(&db, "billing/x", 1).await.unwrap();

    let below = db.store.begin_put(&p("app/new").unwrap()).await.unwrap();
    assert!(matches!(
        below.insert(b"a", b"dek", 2).await,
        Err(DatastoreError::BelowKekFloor(2))
    ));
    let at = db.store.begin_put(&p("app/new").unwrap()).await.unwrap();
    // Version 1 again: the refused put stored nothing, its number neither.
    assert_eq!(at.version(), 1);
    at.insert(b"a", b"dek", 3)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();

    // A row already below the floor stays (readable), and may move up, but
    // not to another version below it.
    let row = db
        .store
        .wrapped_by(&app, 1, RowKey::FIRST, 10)
        .await
        .unwrap();
    assert_eq!(row.len(), 1);
    let moved = [Rewrapped {
        key: row[0].key,
        wrapped_dek: b"dek2".to_vec(),
    }];
    assert!(matches!(
        db.store.rewrap(&app, 1, 2, &moved).await,
        Err(DatastoreError::BelowKekFloor(2))
    ));
    assert_eq!(db.store.rewrap(&app, 1, 3, &moved).await.unwrap(), 1);
    assert!(!db.store.any_wrapped_by(&app, 1).await.unwrap());
    assert_current_versions_agree(&db).await.unwrap();
    db.destroy().await.unwrap();
}

/// What makes destroying safe: raising the floor waits for the writes in
/// flight, so once it returns, a row they wrote is visible to the
/// any-left check, and no later write can add one.
#[tokio::test(flavor = "multi_thread")]
async fn raising_the_kek_floor_waits_for_writes_in_flight() {
    let db = TestDb::new().await.unwrap();
    let in_flight = db
        .store
        .begin_put(&p("app/late").unwrap())
        .await
        .unwrap()
        .insert(b"a", b"dek", 1)
        .await
        .unwrap();

    let raise = tokio::spawn({
        let store = db.store.clone();
        async move {
            store
                .raise_kek_floor(&Namespace::parse("app")?, 2)
                .await
                .map_err(TestError::from)
        }
    });
    db.db.wait_for_lock_waiters(1).await.unwrap();
    assert!(!raise.is_finished());
    in_flight.commit().await.unwrap();
    assert_eq!(raise.await.unwrap().unwrap(), 2);
    assert!(
        db.store
            .any_wrapped_by(&ns("app").unwrap(), 1)
            .await
            .unwrap()
    );

    // A write that waits for a raise sees the raised floor.
    let mut raising = db.db.pool().begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(2, hashtext('app'))")
        .execute(&mut *raising)
        .await
        .unwrap();
    sqlx::query("UPDATE namespaces SET kek_floor = 3 WHERE name = 'app'")
        .execute(&mut *raising)
        .await
        .unwrap();
    let writer = tokio::spawn({
        let store = db.store.clone();
        async move {
            store
                .begin_put(&SecretPath::parse("app/next")?)
                .await?
                .insert(b"a", b"dek", 2)
                .await
                .map(drop)
                .map_err(Into::into)
        }
    });
    db.db.wait_for_lock_waiters(1).await.unwrap();
    raising.commit().await.unwrap();
    let refused: TestResult<()> = writer.await.unwrap();
    assert!(
        matches!(
            refused
                .as_ref()
                .map_err(|e| e.downcast_ref::<DatastoreError>()),
            Err(Some(DatastoreError::BelowKekFloor(2)))
        ),
        "{refused:?}"
    );
    db.destroy().await.unwrap();
}

/// A raise stuck behind a write in flight gives up on its own: "busy,
/// retry", not a generic timeout.
#[tokio::test]
async fn a_kek_floor_raise_waiting_too_long_is_busy() {
    let db = TestDb::new().await.unwrap();
    let in_flight = db
        .store
        .begin_put(&p("app/slow").unwrap())
        .await
        .unwrap()
        .insert(b"a", b"dek", 1)
        .await
        .unwrap();
    let impatient = db
        .store
        .clone()
        .with_lock_timeout(Duration::from_millis(100));
    assert!(matches!(
        impatient.raise_kek_floor(&ns("app").unwrap(), 2).await,
        Err(DatastoreError::KekFloorBusy)
    ));
    drop(in_flight);
    assert_eq!(db.store.kek_floor(&ns("app").unwrap()).await.unwrap(), 1);
    db.destroy().await.unwrap();
}

/// The floor is only sound in READ COMMITTED (a later snapshot could miss
/// a raise), so the trigger refuses writes in any other isolation level,
/// whoever makes them.
#[tokio::test]
async fn a_kek_version_write_outside_read_committed_is_refused() {
    let db = TestDb::new().await.unwrap();
    for level in [
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
    ] {
        let mut tx = db.db.pool().begin().await.unwrap();
        sqlx::query(level).execute(&mut *tx).await.unwrap();
        let refused = insert_version(&mut tx, "app/db", 1, 1).await.unwrap_err();
        let code = refused
            .downcast_ref::<sqlx::Error>()
            .and_then(|e| e.as_database_error())
            .and_then(|e| e.code())
            .map(|code| code.into_owned());
        assert_eq!(code.as_deref(), Some("FR002"), "{level}: {refused}");
    }
    // And in READ COMMITTED it's fine.
    db.put("app/db").await.unwrap();
    db.destroy().await.unwrap();
}

fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// Labels merge: set adds or replaces, remove removes, and the last one
/// removed leaves none (and no time they changed). Only for a path that was
/// written, at most 64.
#[tokio::test]
async fn labels_merge_and_are_only_for_written_paths() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    let path = p("app/db").unwrap();
    let change = |set: Labels, remove: &'static [&'static str]| {
        let (store, path) = (db.store.clone(), path.clone());
        async move {
            let remove: Vec<String> = remove.iter().map(|k| (*k).to_owned()).collect();
            store
                .change_labels(&path, &set, &remove)
                .await?
                .commit()
                .await
        }
    };
    assert_eq!(
        change(labels(&[("team", "a"), ("project", "b")]), &[])
            .await
            .unwrap(),
        labels(&[("project", "b"), ("team", "a")])
    );
    assert_eq!(
        change(labels(&[("team", "c")]), &["project"])
            .await
            .unwrap(),
        labels(&[("team", "c")])
    );
    assert_eq!(
        change(Labels::new(), &["team"]).await.unwrap(),
        Labels::new()
    );
    let left = db.store.path_metadata(&path).await.unwrap().unwrap();
    assert_eq!((left.labels.len(), left.labels_updated_at), (0, None));

    assert!(matches!(
        db.store
            .change_labels(&p("app/never").unwrap(), &labels(&[("team", "a")]), &[])
            .await,
        Err(DatastoreError::NothingStored(_))
    ));
    let many: Labels = (0..65).map(|i| (format!("k{i}"), String::new())).collect();
    assert!(matches!(
        db.store.change_labels(&path, &many, &[]).await,
        Err(DatastoreError::TooManyLabels { count: 65 })
    ));
    // A dropped change keeps nothing.
    drop(
        db.store
            .change_labels(&path, &labels(&[("x", "y")]), &[])
            .await
            .unwrap(),
    );
    assert!(
        db.store
            .path_metadata(&path)
            .await
            .unwrap()
            .unwrap()
            .labels
            .is_empty()
    );
    db.destroy().await.unwrap();
}

/// A path's metadata: first and last write, current and oldest version,
/// how many are stored, labels. A put's labels land in its transaction.
#[tokio::test]
async fn path_metadata_follows_puts_deletes_and_labels() {
    let db = TestDb::new().await.unwrap();
    let path = p("app/db").unwrap();
    assert_eq!(db.store.path_metadata(&path).await.unwrap(), None);
    db.put("app/db").await.unwrap();
    let first = db.store.path_metadata(&path).await.unwrap().unwrap();
    assert_eq!(
        (first.current_version, first.oldest_version, first.versions),
        (Some(1), Some(1), 1)
    );
    assert_eq!(first.created_at, first.updated_at);
    assert_eq!((first.labels.len(), first.labels_updated_at), (0, None));

    let pending = db.store.begin_put(&path).await.unwrap();
    let mut staged = pending.insert(b"ct", b"dek", 1).await.unwrap();
    assert_eq!(
        staged.set_labels(&labels(&[("team", "a")])).await.unwrap(),
        labels(&[("team", "a")])
    );
    staged.commit().await.unwrap();
    let second = db.store.path_metadata(&path).await.unwrap().unwrap();
    assert_eq!((second.current_version, second.versions), (Some(2), 2));
    assert_eq!(second.created_at, first.created_at);
    assert!(second.updated_at >= first.updated_at);
    assert_eq!(second.labels, labels(&[("team", "a")]));
    assert!(second.labels_updated_at.is_some());

    db.delete("app/db").await.unwrap();
    let deleted = db.store.path_metadata(&path).await.unwrap().unwrap();
    assert_eq!(
        (
            deleted.current_version,
            deleted.oldest_version,
            deleted.versions
        ),
        (None, Some(1), 2)
    );
    assert_eq!(deleted.labels, labels(&[("team", "a")]));
    db.destroy().await.unwrap();
}

/// Listing by label: only paths whose labels include every one asked for,
/// within the prefix, paged as usual.
#[tokio::test]
async fn listing_filters_by_labels() {
    let db = TestDb::new().await.unwrap();
    for (path, set) in [
        ("app/a", labels(&[("team", "a"), ("env", "prod")])),
        ("app/b", labels(&[("team", "a")])),
        ("app/c", labels(&[("team", "b")])),
        ("other/d", labels(&[("team", "a"), ("env", "prod")])),
    ] {
        db.put(path).await.unwrap();
        db.store
            .change_labels(&p(path).unwrap(), &set, &[])
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
    }
    db.put("app/e").await.unwrap();
    let list = |prefix: Option<&str>, filter: Labels, after: Option<&str>, limit: u32| {
        let store = db.store.clone();
        let prefix = prefix.map(|s| SecretPath::parse(s).unwrap());
        let after = after.map(|s| SecretPath::parse(s).unwrap());
        async move {
            store
                .list(prefix.as_ref(), after.as_ref(), limit, &filter)
                .await
                .map(|rows| {
                    rows.into_iter()
                        .map(|m| m.path.to_string())
                        .collect::<Vec<_>>()
                })
        }
    };
    let team_a = labels(&[("team", "a")]);
    assert_eq!(
        list(None, team_a.clone(), None, 100).await.unwrap(),
        ["app/a", "app/b", "other/d"]
    );
    assert_eq!(
        list(Some("app"), team_a.clone(), None, 100).await.unwrap(),
        ["app/a", "app/b"]
    );
    assert_eq!(
        list(
            Some("app"),
            labels(&[("team", "a"), ("env", "prod")]),
            None,
            100
        )
        .await
        .unwrap(),
        ["app/a"]
    );
    assert_eq!(
        list(None, team_a.clone(), None, 1).await.unwrap(),
        ["app/a"]
    );
    assert_eq!(
        list(None, team_a, Some("app/a"), 1).await.unwrap(),
        ["app/b"]
    );
    assert!(
        list(None, labels(&[("team", "z")]), None, 100)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        list(Some("app"), Labels::new(), None, 100)
            .await
            .unwrap()
            .len(),
        4
    );
    db.destroy().await.unwrap();
}

/// The labels of `path`, straight from its row (`None` without one).
async fn stored_labels(db: &TestDb, path: &str) -> TestResult<Option<Labels>> {
    let labels: Option<sqlx::types::Json<Labels>> =
        sqlx::query_scalar("SELECT labels FROM paths WHERE path = $1")
            .bind(path)
            .fetch_optional(db.db.pool())
            .await?;
    Ok(labels.map(|labels| labels.0))
}

/// Purging a path's last rows removes its labels too, and its metadata is
/// then gone like its history; the version numbers stay.
#[tokio::test]
async fn purging_a_paths_last_rows_removes_its_labels() {
    let db = TestDb::new().await.unwrap();
    let path = p("app/db").unwrap();
    db.put("app/db").await.unwrap();
    db.put("app/keep").await.unwrap();
    for target in ["app/db", "app/keep"] {
        db.store
            .change_labels(&p(target).unwrap(), &labels(&[("team", "a")]), &[])
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
    }
    db.delete("app/db").await.unwrap();

    assert_eq!(
        db.store.purge_deleted(Duration::ZERO, 100).await.unwrap(),
        1
    );
    assert_eq!(db.store.path_metadata(&path).await.unwrap(), None);
    assert_eq!(
        stored_labels(&db, "app/db").await.unwrap(),
        Some(Labels::new())
    );
    // Purged first, then the change: nothing stored to label.
    assert!(matches!(
        db.store
            .change_labels(&path, &labels(&[("team", "a")]), &[])
            .await,
        Err(DatastoreError::NothingStored(_))
    ));
    assert_eq!(
        stored_labels(&db, "app/keep").await.unwrap(),
        Some(labels(&[("team", "a")]))
    );
    // The numbering goes on.
    assert_eq!(db.put("app/db").await.unwrap(), 2);
    assert_current_versions_agree(&db).await.unwrap();
    db.destroy().await.unwrap();
}

/// A label change in flight on a path whose last version purge removes:
/// the purge waits for it, then clears the labels it set, since the path
/// has nothing stored any more. Never labels on a path with nothing stored.
#[tokio::test(flavor = "multi_thread")]
async fn a_purge_clears_the_labels_of_a_change_it_waited_for() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    db.delete("app/db").await.unwrap();
    let in_flight = db
        .store
        .change_labels(&p("app/db").unwrap(), &labels(&[("team", "a")]), &[])
        .await
        .unwrap();
    let purge = tokio::spawn({
        let store = db.store.clone();
        async move { store.purge_deleted(Duration::ZERO, 100).await }
    });
    db.db.wait_for_lock_waiters(1).await.unwrap();
    in_flight.commit().await.unwrap();
    assert_eq!(purge.await.unwrap().unwrap(), 1);
    assert_eq!(
        stored_labels(&db, "app/db").await.unwrap(),
        Some(Labels::new())
    );
    db.destroy().await.unwrap();
}

/// A put with labels to a path whose last versions purge is removing: the
/// put holds its `paths` row, the purge waits for it, and then sees the new
/// version (its check is a statement of its own, after the lock), so the
/// put's labels stay. One statement would read a snapshot from before the
/// wait and clear them.
#[tokio::test(flavor = "multi_thread")]
async fn a_put_with_labels_keeps_them_through_a_purge_of_older_versions() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    db.delete("app/db").await.unwrap();
    let path = p("app/db").unwrap();
    let mut staged = db
        .store
        .begin_put(&path)
        .await
        .unwrap()
        .insert(b"ct", b"dek", 1)
        .await
        .unwrap();
    staged.set_labels(&labels(&[("team", "a")])).await.unwrap();
    let purge = tokio::spawn({
        let store = db.store.clone();
        async move { store.purge_deleted(Duration::ZERO, 100).await }
    });
    db.db.wait_for_lock_waiters(1).await.unwrap();
    staged.commit().await.unwrap();
    assert_eq!(purge.await.unwrap().unwrap(), 1);
    let after = db.store.path_metadata(&path).await.unwrap().unwrap();
    assert_eq!(
        (after.versions, after.labels),
        (1, labels(&[("team", "a")]))
    );
    assert_current_versions_agree(&db).await.unwrap();
    db.destroy().await.unwrap();
}

/// A label change doesn't wait for a purge holding the path's version rows
/// (deleting one, uncommitted): it locks only the `paths` row, and the
/// versions it checks for are still there until the purge commits.
#[tokio::test(flavor = "multi_thread")]
async fn a_label_change_does_not_wait_for_a_purge_of_versions() {
    let db = TestDb::new().await.unwrap();
    let path = p("app/db").unwrap();
    db.put("app/db").await.unwrap();
    db.put("app/db").await.unwrap();
    let mut purge = db.db.pool().begin().await.unwrap();
    sqlx::query(
        "DELETE FROM secret_versions
         WHERE path_id = (SELECT id FROM paths WHERE path = 'app/db') AND version = 2",
    )
    .execute(&mut *purge)
    .await
    .unwrap();

    let changed = tokio::time::timeout(
        Duration::from_secs(2),
        db.store
            .change_labels(&path, &labels(&[("team", "a")]), &[]),
    )
    .await
    .expect("waited for the purge")
    .unwrap()
    .commit()
    .await
    .unwrap();
    assert_eq!(changed, labels(&[("team", "a")]));
    purge.commit().await.unwrap();
    // Version 1 is still there, and so are the labels.
    let after = db.store.path_metadata(&path).await.unwrap().unwrap();
    assert_eq!(
        (after.versions, after.labels),
        (1, labels(&[("team", "a")]))
    );
    db.destroy().await.unwrap();
}

/// Listing leaves out paths with no live version (deleted, or purged), with
/// a label filter or without, however many of them come first.
#[tokio::test]
async fn listing_skips_paths_with_no_live_version() {
    let db = TestDb::new().await.unwrap();
    for path in ["app/a", "app/b", "app/c", "app/d"] {
        db.put(path).await.unwrap();
        db.store
            .change_labels(&p(path).unwrap(), &labels(&[("team", "a")]), &[])
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
    }
    db.delete("app/a").await.unwrap();
    db.delete("app/b").await.unwrap();
    db.store.purge_deleted(Duration::ZERO, 100).await.unwrap();
    db.delete("app/c").await.unwrap();
    for filter in [Labels::new(), labels(&[("team", "a")])] {
        for prefix in [None, Some(p("app").unwrap())] {
            let listed: Vec<String> = db
                .store
                .list(prefix.as_ref(), None, 1, &filter)
                .await
                .unwrap()
                .into_iter()
                .map(|m| m.path.to_string())
                .collect();
            assert_eq!(listed, ["app/d"], "{filter:?} {prefix:?}");
        }
    }
    db.destroy().await.unwrap();
}

/// The SQLSTATE of a refused write.
fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|e| e.code())
        .map(|code| code.into_owned())
}

/// A path's text and a namespace's name never change: the AAD binds the
/// path's text, and a version's namespace must stay its path's.
#[tokio::test]
async fn paths_and_namespace_names_are_immutable() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    for statement in [
        "UPDATE paths SET path = 'app/other' WHERE path = 'app/db'",
        "UPDATE namespaces SET name = 'other' WHERE name = 'app'",
        "UPDATE paths SET namespace_id = uuidv7()",
    ] {
        let refused = sqlx::query(statement)
            .execute(db.db.pool())
            .await
            .unwrap_err();
        assert_eq!(sqlstate(&refused).as_deref(), Some("FR003"), "{statement}");
    }
    db.destroy().await.unwrap();
}

/// A path is in the namespace its text names: a row filed under another
/// namespace (and so under its KEK floor) is refused by the composite
/// foreign key on the path's derived first segment.
#[tokio::test]
async fn a_path_is_in_the_namespace_its_text_names() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    db.put("billing/db").await.unwrap();
    let refused = sqlx::query(
        "INSERT INTO paths (namespace_id, path, highest)
         SELECT id, 'app/other', 1 FROM namespaces WHERE name = 'billing'",
    )
    .execute(db.db.pool())
    .await
    .unwrap_err();
    assert_eq!(sqlstate(&refused).as_deref(), Some("23503"));
    // The derived segment can't be set by hand either.
    let refused = sqlx::query(
        "INSERT INTO paths (namespace_id, path, namespace, highest)
         SELECT id, 'app/other', 'billing', 1 FROM namespaces WHERE name = 'billing'",
    )
    .execute(db.db.pool())
    .await
    .unwrap_err();
    assert!(refused.as_database_error().is_some(), "{refused}");
    db.destroy().await.unwrap();
}

/// A version is in its path's namespace: a row claiming another one is
/// refused by the composite foreign key, so the per-namespace KEK queries
/// and the floor can't be steered past it.
#[tokio::test]
async fn a_version_is_in_its_paths_namespace() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    db.put("billing/db").await.unwrap();
    let refused = sqlx::query(
        "INSERT INTO secret_versions
             (path_id, namespace_id, version, ciphertext, wrapped_dek, kek_version)
         SELECT p.id, n.id, 5, '\\x00', '\\x00', 1
         FROM paths p, namespaces n WHERE p.path = 'app/db' AND n.name = 'billing'",
    )
    .execute(db.db.pool())
    .await
    .unwrap_err();
    assert_eq!(sqlstate(&refused).as_deref(), Some("23503"));
    let moved = sqlx::query(
        "UPDATE secret_versions SET namespace_id = (SELECT id FROM namespaces WHERE name = 'billing')
         WHERE path_id = (SELECT id FROM paths WHERE path = 'app/db')",
    )
    .execute(db.db.pool())
    .await
    .unwrap_err();
    assert_eq!(sqlstate(&moved).as_deref(), Some("23503"));
    db.destroy().await.unwrap();
}

/// A floor raise in one namespace waits for that namespace's writes only:
/// a write in flight elsewhere doesn't hold it up.
#[tokio::test]
async fn a_floor_raise_waits_only_for_its_own_namespace() {
    let db = TestDb::new().await.unwrap();
    let in_flight = db
        .store
        .begin_put(&p("billing/slow").unwrap())
        .await
        .unwrap()
        .insert(b"a", b"dek", 1)
        .await
        .unwrap();
    let impatient = db
        .store
        .clone()
        .with_lock_timeout(Duration::from_millis(200));
    assert_eq!(
        impatient
            .raise_kek_floor(&ns("app").unwrap(), 2)
            .await
            .unwrap(),
        2
    );
    assert!(matches!(
        impatient.raise_kek_floor(&ns("billing").unwrap(), 2).await,
        Err(DatastoreError::KekFloorBusy)
    ));
    drop(in_flight);
    db.destroy().await.unwrap();
}

/// The per-namespace queries: versions in use, highest version, rows.
#[tokio::test]
async fn kek_queries_are_per_namespace() {
    let db = TestDb::new().await.unwrap();
    put_with_kek(&db, "app/a", 1).await.unwrap();
    put_with_kek(&db, "app/b", 3).await.unwrap();
    put_with_kek(&db, "billing/x", 2).await.unwrap();
    db.delete("app/b").await.unwrap();
    let used: Vec<(String, u32)> = db
        .store
        .kek_versions_in_use()
        .await
        .unwrap()
        .into_iter()
        .map(|(n, v)| (n.to_string(), v))
        .collect();
    assert_eq!(
        used,
        [
            ("app".to_owned(), 1),
            ("app".to_owned(), 3),
            ("billing".to_owned(), 2)
        ]
    );
    assert_eq!(
        db.store.max_kek_version(&ns("app").unwrap()).await.unwrap(),
        Some(3)
    );
    assert_eq!(
        db.store
            .max_kek_version(&ns("none").unwrap())
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        db.store.namespace_rows(&ns("app").unwrap()).await.unwrap(),
        (2, 1)
    );
    assert_eq!(
        db.store.namespace_rows(&ns("none").unwrap()).await.unwrap(),
        (0, 0)
    );
    db.destroy().await.unwrap();
}

/// Every path whose `current_version` isn't its latest live version (or
/// NULL without one), as `(path, stored, actual)`.
async fn current_versions_astray(
    db: &TestDb,
) -> TestResult<Vec<(String, Option<i32>, Option<i32>)>> {
    Ok(sqlx::query_as(
        "SELECT p.path, p.current_version, live.version
         FROM paths p
         LEFT JOIN LATERAL (
             SELECT max(version) AS version FROM secret_versions
             WHERE path_id = p.id AND deleted_at IS NULL
         ) live ON true
         WHERE p.current_version IS DISTINCT FROM live.version",
    )
    .fetch_all(db.db.pool())
    .await?)
}

/// Fails unless every path's `current_version` is its latest live version
/// (the invariant listings rely on).
async fn assert_current_versions_agree(db: &TestDb) -> TestResult<()> {
    let astray = current_versions_astray(db).await?;
    if astray.is_empty() {
        Ok(())
    } else {
        Err(format!("current_version astray (path, stored, actual): {astray:?}").into())
    }
}

/// `path`'s current version, once every path's is checked against its
/// versions.
async fn current(db: &TestDb, path: &SecretPath) -> TestResult<Option<u32>> {
    assert_current_versions_agree(db).await?;
    let metadata = db.store.path_metadata(path).await?;
    Ok(metadata.and_then(|m| m.current_version))
}

/// `paths.current_version`, what listings read, follows every write that
/// changes a path's latest live version: puts, trims, deletes, restores of
/// older and newer versions, purges; a dropped put leaves it as it was.
#[tokio::test]
async fn the_current_version_follows_every_write() {
    let db = TestDb::new().await.unwrap();
    let two = Datastore::new(db.db.pool().clone()).with_max_versions(2);
    let path = p("app/db").unwrap();
    for _ in 0..4 {
        put_with(&two, "app/db").await.unwrap();
    }
    assert_eq!(current(&db, &path).await.unwrap(), Some(4));
    drop(db.store.begin_put(&path).await.unwrap());
    assert_eq!(current(&db, &path).await.unwrap(), Some(4));
    db.delete("app/db").await.unwrap();
    assert_eq!(current(&db, &path).await.unwrap(), None);
    // An older version back while none is live: it's the current one.
    assert_eq!(restore(&db, "app/db", Some(2)).await.unwrap(), Some(2));
    assert_eq!(current(&db, &path).await.unwrap(), Some(2));
    // A newer one back: it is.
    assert_eq!(restore(&db, "app/db", Some(4)).await.unwrap(), Some(4));
    assert_eq!(current(&db, &path).await.unwrap(), Some(4));
    // An older one back next to it: it stays.
    assert_eq!(restore(&db, "app/db", Some(3)).await.unwrap(), Some(3));
    assert_eq!(current(&db, &path).await.unwrap(), Some(4));
    db.delete("app/db").await.unwrap();
    db.store.purge_deleted(Duration::ZERO, 100).await.unwrap();
    assert_eq!(current(&db, &path).await.unwrap(), None);
    assert_eq!(put_with(&two, "app/db").await.unwrap(), (5, 0));
    assert_eq!(current(&db, &path).await.unwrap(), Some(5));
    db.destroy().await.unwrap();
}

/// A write in a random sequence ([`the_store_matches_a_model_through_any_writes`]),
/// on one of its case's paths.
#[derive(Clone, Debug)]
enum Op {
    Put(usize),
    /// A put through a store keeping 2 live versions: it trims.
    PutTrimming(usize),
    Delete(usize),
    /// A version by number (some never stored), or the newest deleted.
    Restore(usize, Option<u32>),
    /// Every deleted version, of every case so far.
    Purge,
}

fn op() -> impl proptest::strategy::Strategy<Value = Op> {
    use proptest::prelude::*;
    let path = 0..2_usize;
    prop_oneof![
        3 => path.clone().prop_map(Op::Put),
        2 => path.clone().prop_map(Op::PutTrimming),
        2 => path.clone().prop_map(Op::Delete),
        // Low numbers, which a short sequence has stored: restoring an
        // older and a newer deleted version, in either order, is the case
        // that tests a restore's current version.
        4 => (path, proptest::option::of(1..5_u32)).prop_map(|(p, v)| Op::Restore(p, v)),
        1 => Just(Op::Purge),
    ]
}

/// What one path should hold: its counter and each stored version's
/// liveness.
#[derive(Default)]
struct ModelPath {
    highest: u32,
    stored: std::collections::BTreeMap<u32, bool>,
}

impl ModelPath {
    fn current(&self) -> Option<u32> {
        self.stored
            .iter()
            .rev()
            .find_map(|(v, live)| live.then_some(*v))
    }
}

/// Runs `ops` on the paths of namespace `ns` (each case its own) and checks
/// after every step: the invariant, each path's metadata, and the listing,
/// against the model.
async fn run_against_model(db: &TestDb, ns: &str, ops: &[Op]) -> TestResult<()> {
    let trimming = Datastore::new(db.db.pool().clone()).with_max_versions(2);
    let paths: Vec<SecretPath> = (0..2)
        .map(|i| SecretPath::parse(&format!("{ns}/p{i}")))
        .collect::<Result<_, _>>()?;
    let mut model: Vec<ModelPath> = (0..2).map(|_| ModelPath::default()).collect();
    for op in ops {
        match *op {
            Op::Put(i) | Op::PutTrimming(i) => {
                let store = if matches!(op, Op::Put(_)) {
                    &db.store
                } else {
                    &trimming
                };
                let pending = store.begin_put(&paths[i]).await?;
                let m = &mut model[i];
                m.highest += 1;
                if pending.version() != m.highest {
                    return Err(format!(
                        "{op:?}: version {}, expected {}",
                        pending.version(),
                        m.highest
                    )
                    .into());
                }
                pending.insert(b"ct", b"dek", 1).await?.commit().await?;
                m.stored.insert(m.highest, true);
                if matches!(op, Op::PutTrimming(_)) {
                    let live: Vec<u32> = m
                        .stored
                        .iter()
                        .filter(|(_, l)| **l)
                        .map(|(v, _)| *v)
                        .collect();
                    for v in live.iter().rev().skip(2) {
                        m.stored.insert(*v, false);
                    }
                }
            }
            Op::Delete(i) => {
                db.store.begin_delete(&paths[i]).await?.commit().await?;
                model[i].stored.values_mut().for_each(|live| *live = false);
            }
            Op::Restore(i, version) => {
                let pending = db.store.begin_restore(&paths[i], version).await?;
                let restored = pending.restored().map(|m| m.version);
                pending.commit().await?;
                let m = &mut model[i];
                let expected = match version {
                    Some(v) => m.stored.get(&v).is_some_and(|live| !live).then_some(v),
                    None if m.current().is_some() => None,
                    None => m
                        .stored
                        .iter()
                        .rev()
                        .find_map(|(v, live)| (!live).then_some(*v)),
                };
                if restored != expected {
                    return Err(
                        format!("{op:?}: restored {restored:?}, expected {expected:?}").into(),
                    );
                }
                if let Some(v) = expected {
                    m.stored.insert(v, true);
                }
            }
            Op::Purge => {
                db.store.purge_deleted(Duration::ZERO, 10_000).await?;
                for m in &mut model {
                    m.stored.retain(|_, live| *live);
                }
            }
        }
        assert_current_versions_agree(db).await?;
        for (path, m) in paths.iter().zip(&model) {
            let metadata = db.store.path_metadata(path).await?;
            let found = metadata.map(|m| (m.current_version, m.versions));
            let expected = (!m.stored.is_empty()).then(|| {
                (
                    m.current(),
                    u64::try_from(m.stored.len()).unwrap_or(u64::MAX),
                )
            });
            if found != expected {
                return Err(
                    format!("after {op:?}, {path}: {found:?}, expected {expected:?}").into(),
                );
            }
        }
        let listed: Vec<(String, u32)> = db
            .store
            .list(Some(&SecretPath::parse(ns)?), None, 100, &Labels::new())
            .await?
            .into_iter()
            .map(|m| (m.path.to_string(), m.version))
            .collect();
        let expected: Vec<(String, u32)> = paths
            .iter()
            .zip(&model)
            .filter_map(|(path, m)| m.current().map(|v| (path.to_string(), v)))
            .collect();
        if listed != expected {
            return Err(format!("after {op:?}: listed {listed:?}, expected {expected:?}").into());
        }
    }
    Ok(())
}

/// Random sequences of puts (trimming or not), deletes, restores and purges
/// keep the store where a model of it says: version numbers, each path's
/// current version (`paths.current_version`, checked against the versions
/// themselves) and version count, and the listing. One database for every
/// case, a namespace per case (shrinking runs more of them).
#[test]
fn the_store_matches_a_model_through_any_writes() {
    use proptest::test_runner::{Config, TestCaseError, TestRunner};

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let db = runtime.block_on(TestDb::new()).unwrap();
    let case = std::sync::atomic::AtomicU32::new(0);
    let mut runner = TestRunner::new(Config {
        cases: 256,
        failure_persistence: None,
        ..Config::default()
    });
    let result = runner.run(&proptest::collection::vec(op(), 1..32), |ops| {
        let ns = format!(
            "c{}",
            case.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        runtime
            .block_on(run_against_model(&db, &ns, &ops))
            .map_err(|e| TestCaseError::fail(e.to_string()))
    });
    runtime.block_on(db.destroy()).unwrap();
    result.unwrap();
}

/// A namespace's `paths` rows are reclaimed only when it has no version at
/// all (a deleted one counts), its labels with them; the highest version
/// they reached stays, and its paths number on past it afterwards. Other
/// namespaces are untouched.
#[tokio::test]
async fn reclaimed_paths_never_give_a_version_number_twice() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    db.put("app/db").await.unwrap();
    db.put("app/other").await.unwrap();
    db.put("keep/x").await.unwrap();
    db.delete("app/db").await.unwrap();
    assert_eq!(
        db.store.reclaim_paths(&ns("app").unwrap()).await.unwrap(),
        Reclaimed::NotEmpty {
            rows: 3,
            deleted: 2
        }
    );
    sqlx::query(
        "DELETE FROM secret_versions
         WHERE namespace_id = (SELECT id FROM namespaces WHERE name = 'app')",
    )
    .execute(db.db.pool())
    .await
    .unwrap();
    assert_eq!(
        db.store.reclaim_paths(&ns("app").unwrap()).await.unwrap(),
        Reclaimed::Paths(2)
    );
    assert!(
        db.store
            .path_metadata(&p("app/db").unwrap())
            .await
            .unwrap()
            .is_none()
    );
    // Past the highest any of them reached (app/db's 2), every path.
    assert_eq!(db.put("app/db").await.unwrap(), 3);
    assert_eq!(db.put("app/new").await.unwrap(), 3);
    assert_eq!(db.put("keep/x").await.unwrap(), 2);
    assert_current_versions_agree(&db).await.unwrap();
    db.destroy().await.unwrap();
}

/// A put in flight while its namespace is deleted: it holds its `paths` row
/// and waits for the floor lock at its insert, while the reclaim holds that
/// lock. The reclaim leaves the row alone rather than wait for it (which
/// would deadlock), and the put, once it gets the lock, is refused by the
/// raised floor; numbering stays past the reclaimed paths.
#[tokio::test]
async fn a_put_in_flight_never_deadlocks_its_namespaces_reclaim() {
    let db = TestDb::new().await.unwrap();
    let app = ns("app").unwrap();
    db.put("app/db").await.unwrap();
    db.put("app/other").await.unwrap();
    db.put("app/other").await.unwrap();
    sqlx::query(
        "DELETE FROM secret_versions
         WHERE namespace_id = (SELECT id FROM namespaces WHERE name = 'app')",
    )
    .execute(db.db.pool())
    .await
    .unwrap();
    // As `Namespaces::delete` does first: no write with KEK 1 any more.
    db.store.raise_kek_floor(&app, 2).await.unwrap();
    let pending = db.store.begin_put(&p("app/db").unwrap()).await.unwrap();
    let reclaim = tokio::spawn({
        let store = db.store.clone();
        let app = app.clone();
        async move { store.reclaim_paths(&app).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(matches!(
        pending.insert(b"ct", b"dek", 1).await,
        Err(DatastoreError::BelowKekFloor(1))
    ));
    // app/other went; app/db, held by the put, stayed.
    assert_eq!(reclaim.await.unwrap().unwrap(), Reclaimed::Paths(1));
    // Past every version either path reached (app/other's 2).
    for path in ["app/db", "app/new"] {
        let pending = db.store.begin_put(&p(path).unwrap()).await.unwrap();
        assert_eq!(pending.version(), 3);
        pending
            .insert(b"ct", b"dek", 2)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
    }
    db.destroy().await.unwrap();
}

/// The changes since a mark: each path whose live version moved, once, at
/// its live version now (a delete: none), whichever connection made them;
/// a rolled-back put, a restore of an older version and a label change
/// aren't changes. The next mark starts where this one ended. Over the
/// limit, too many to tell.
#[tokio::test]
async fn changes_since_a_mark_are_each_path_once() {
    let db = TestDb::new().await.unwrap();
    db.put("app/db").await.unwrap();
    let mark = db.store.change_mark().await.unwrap();
    let change = |path: &str, version: Option<u32>| Change {
        path: p(path).unwrap(),
        version,
    };
    let since = |mark: ChangeMark| {
        let store = db.store.clone();
        async move {
            match store.changes_since(&mark, 100).await.unwrap() {
                Changes::Since(next, mut changes) => {
                    changes.sort_by(|a, b| a.path.cmp(&b.path));
                    (next, changes)
                }
                other => panic!("{other:?}"),
            }
        }
    };
    let (mark, nothing) = since(mark).await;
    assert_eq!(nothing, []);
    db.put("app/db").await.unwrap();
    db.put("app/db").await.unwrap();
    db.put("other/x").await.unwrap();
    drop(db.store.begin_put(&p("app/y").unwrap()).await.unwrap());
    let (mark, changes) = since(mark).await;
    assert_eq!(
        changes,
        [change("app/db", Some(3)), change("other/x", Some(1))]
    );

    db.delete("app/db").await.unwrap();
    let (mark, changes) = since(mark).await;
    assert_eq!(changes, [change("app/db", None)]);
    restore(&db, "app/db", Some(3)).await.unwrap();
    let (mark, changes) = since(mark).await;
    assert_eq!(changes, [change("app/db", Some(3))]);
    // Version 2 below the live 3: the live version stays, no change.
    restore(&db, "app/db", Some(2)).await.unwrap();
    db.store
        .change_labels(&p("other/x").unwrap(), &labels(&[("team", "a")]), &[])
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let (mark, changes) = since(mark).await;
    assert_eq!(changes, []);

    // A transaction that began before a poll and commits after it: in
    // the poll after its commit, not lost between the two.
    let staged = db
        .store
        .begin_put(&p("app/late").unwrap())
        .await
        .unwrap()
        .insert(b"ct", b"dek", 1)
        .await
        .unwrap();
    let (mark, changes) = since(mark).await;
    assert_eq!(changes, []);
    staged.commit().await.unwrap();
    let (mark, changes) = since(mark).await;
    assert_eq!(changes, [change("app/late", Some(1))]);

    for n in 0..3 {
        db.put(&format!("app/many{n}")).await.unwrap();
    }
    assert!(matches!(
        db.store.changes_since(&mark, 2).await.unwrap(),
        Changes::TooMany(_)
    ));
    db.destroy().await.unwrap();
}

/// Root commitments: several per generation, insert-only (an update, a
/// delete or a truncate is refused), the same one stored once; the floor
/// only rises.
#[tokio::test]
async fn root_commitments_are_insert_only_and_the_floor_only_rises() {
    let db = TestDb::new().await.unwrap();
    assert_eq!(
        db.store.root_commitments(1).await.unwrap(),
        Vec::<Vec<u8>>::new()
    );
    db.store.insert_root_commitment(1, &[1; 32]).await.unwrap();
    db.store.insert_root_commitment(1, &[2; 32]).await.unwrap();
    db.store.insert_root_commitment(1, &[1; 32]).await.unwrap();
    db.store.insert_root_commitment(2, &[3; 32]).await.unwrap();
    assert_eq!(
        db.store.root_commitments(1).await.unwrap(),
        [vec![1; 32], vec![2; 32]]
    );
    for statement in [
        "UPDATE root_commitments SET mac = '\\x00'",
        "DELETE FROM root_commitments",
        "TRUNCATE root_commitments",
    ] {
        let refused = sqlx::query(statement)
            .execute(db.db.pool())
            .await
            .unwrap_err();
        assert!(
            refused.to_string().contains("insert-only"),
            "{statement}: {refused}"
        );
    }
    assert_eq!(db.store.root_commitments(2).await.unwrap(), [vec![3; 32]]);

    assert_eq!(db.store.root_generation_floor().await.unwrap(), 0);
    db.store.raise_root_generation_floor(2).await.unwrap();
    db.store.raise_root_generation_floor(1).await.unwrap();
    assert_eq!(db.store.root_generation_floor().await.unwrap(), 2);
    db.destroy().await.unwrap();
}

/// One stored version per (namespace, KEK version) any row uses, deleted
/// rows included.
#[tokio::test]
async fn a_version_per_kek_covers_every_kek_in_use() {
    let db = TestDb::new().await.unwrap();
    assert!(db.store.version_per_kek().await.unwrap().is_empty());
    {
        let mut conn = db.db.pool().acquire().await.unwrap();
        insert_version(&mut conn, "app/a", 1, 1).await.unwrap();
        insert_version(&mut conn, "app/a", 2, 2).await.unwrap();
        insert_version(&mut conn, "app/b", 1, 2).await.unwrap();
        insert_version(&mut conn, "other/x", 1, 1).await.unwrap();
    }
    db.delete("other/x").await.unwrap();
    let mut pairs: Vec<(String, u32)> = db
        .store
        .version_per_kek()
        .await
        .unwrap()
        .into_iter()
        .map(|v| (v.path.namespace().as_str().to_owned(), v.kek_version))
        .collect();
    pairs.sort();
    assert_eq!(
        pairs,
        [
            ("app".to_owned(), 1),
            ("app".to_owned(), 2),
            ("other".to_owned(), 1)
        ]
    );
    db.destroy().await.unwrap();
}
