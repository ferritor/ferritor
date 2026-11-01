//! The root commitments against real keys and data databases (one each per
//! test, see `ferritor-testkit`): an unseal accepts a root key only if the data
//! database holds a commitment to it, at a generation not below the floor;
//! the shares re-commit one that's lost, once a stored secret proves
//! continuity.

use std::sync::Arc;
use std::time::Duration;

use ferritor_core::crypto::{self, Kek, RootKey, ShareParams};
use ferritor_core::labels::Labels;
use ferritor_core::path::Namespace;
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{AllowAll, Caller};
use ferritor_server::namespaces::Namespaces;
use ferritor_server::seal::{RekeyPhase, Seal, SealError};
use ferritor_server::secrets::Secrets;
use ferritor_testkit::{Captured, TestDatabase, TestResult};

const ANON: Caller = Caller::Unauthenticated;

struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    gate: Arc<Gate>,
    shares: Vec<Vec<u8>>,
}

impl Env {
    /// Initialized (5 shares, threshold 3) by a server with the ledger;
    /// `app` created; with `secret`, `app/db` stored.
    async fn new(secret: bool) -> TestResult<Self> {
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
        let gate = Arc::new(Gate::new(
            Arc::new(AllowAll),
            AuditLog::new(Captured::default(), Duration::from_secs(5))?,
        ));
        let mut env = Self {
            keys,
            data,
            gate,
            shares: Vec::new(),
        };
        let seal = env.seal();
        env.shares = seal
            .init(ShareParams::new(5, 3)?)
            .await?
            .iter()
            .map(|s| s.to_bytes().to_vec())
            .collect();
        env.unseal(&seal, &env.shares[..3]).await?;
        Namespaces::new(Arc::clone(&seal), env.store())
            .create("app", &Labels::new())
            .await?;
        if secret {
            env.secrets(&seal).put(&ANON, "app/db", b"one").await?;
        }
        Ok(env)
    }

    fn store(&self) -> Datastore {
        Datastore::new(self.data.pool().clone())
    }

    /// A server (a fresh process: nothing remembered) with the ledger.
    fn seal(&self) -> Arc<Seal> {
        Arc::new(
            Seal::new(Keystore::new(self.keys.pool().clone()))
                .with_root_ledger(Arc::new(self.store())),
        )
    }

    fn secrets(&self, seal: &Arc<Seal>) -> Secrets {
        Secrets::new(Arc::clone(seal), self.store(), Arc::clone(&self.gate))
    }

    async fn unseal(&self, seal: &Seal, shares: &[Vec<u8>]) -> Result<(), SealError> {
        for share in shares {
            seal.unseal(share, false).await?;
        }
        Ok(())
    }

    async fn recommit(&self, seal: &Seal, shares: &[Vec<u8>]) -> Result<bool, SealError> {
        let mut recommitted = false;
        for share in shares {
            recommitted = seal.unseal_recommit(share, false).await?.recommitted;
        }
        Ok(recommitted)
    }

    /// The floor, once it's at least `expected` (raised in the background).
    async fn floor_reaches(&self, expected: u32) -> TestResult<u32> {
        for _ in 0..100 {
            let floor = self.store().root_generation_floor().await?;
            if floor >= expected {
                return Ok(floor);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Err(format!("the floor never reached {expected}").into())
    }

    /// What a restore of the data database from before `generation`'s
    /// commitment leaves: its commitments gone (insert-only, so only by
    /// hand), the floor `floor`.
    async fn lose_commitments(&self, generation: i32, floor: i32) -> TestResult<()> {
        let pool = self.data.pool();
        sqlx::query("ALTER TABLE root_commitments DISABLE TRIGGER USER")
            .execute(pool)
            .await?;
        sqlx::query("DELETE FROM root_commitments WHERE generation = $1")
            .bind(generation)
            .execute(pool)
            .await?;
        sqlx::query("ALTER TABLE root_commitments ENABLE TRIGGER USER")
            .execute(pool)
            .await?;
        sqlx::query("UPDATE root_generation_floor SET generation = $1")
            .bind(floor)
            .execute(pool)
            .await?;
        Ok(())
    }

    async fn destroy(self) -> TestResult<()> {
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

/// Init commits generation 1 and raises the floor; once it has, an init is
/// refused even with the keys database wiped.
#[tokio::test]
async fn init_commits_the_root_key_and_gates_another_init() {
    let env = Env::new(false).await.unwrap();
    assert_eq!(env.floor_reaches(1).await.unwrap(), 1);
    assert_eq!(env.store().root_commitments(1).await.unwrap().len(), 1);

    sqlx::query("DELETE FROM seal_config")
        .execute(env.keys.pool())
        .await
        .unwrap();
    let refused = env.seal().init(ShareParams::new(5, 3).unwrap()).await;
    assert!(
        matches!(refused, Err(SealError::InitAfterCommit { floor: 1 })),
        "{refused:?}"
    );
    env.destroy().await.unwrap();
}

/// A root key substituted in the keys database (its own root_check and
/// KEKs, a generation of its own): its shares are refused, and can't
/// re-commit it, since no stored secret opens under it.
#[tokio::test]
async fn a_substituted_root_key_is_refused_and_cant_be_recommitted() {
    let env = Env::new(true).await.unwrap();
    let forged = RootKey::generate().unwrap();
    let app = Namespace::parse("app").unwrap();
    let kek = Kek::generate().unwrap();
    sqlx::query("UPDATE seal_config SET root_check = $1, generation = 2")
        .bind(forged.root_check().unwrap())
        .execute(env.keys.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE keks SET wrapped_key = $1 WHERE namespace = 'app' AND version = 1")
        .bind(forged.wrap_kek(&app, 1, &kek).unwrap())
        .execute(env.keys.pool())
        .await
        .unwrap();
    let shares: Vec<Vec<u8>> = crypto::split(&forged, ShareParams::new(5, 3).unwrap(), 2)
        .unwrap()
        .iter()
        .map(|s| s.to_bytes().to_vec())
        .collect();

    let seal = env.seal();
    let refused = env.unseal(&seal, &shares[..3]).await;
    assert!(
        matches!(refused, Err(SealError::RootUncommitted { generation: 2 })),
        "{refused:?}"
    );
    let refused = env.recommit(&seal, &shares[..3]).await;
    assert!(
        matches!(refused, Err(SealError::RecommitDiscontinuous)),
        "{refused:?}"
    );
    assert!(seal.is_sealed());
    assert!(env.store().root_commitments(2).await.unwrap().is_empty());
    env.destroy().await.unwrap();
}

/// A data database restored from before a rekey has no commitment to the
/// new root key: every unseal is refused, shares included, until the
/// shares re-commit it (a stored secret opens), and then it serves.
#[tokio::test]
async fn a_data_database_restored_from_before_a_rekey_is_recommitted() {
    let env = Env::new(true).await.unwrap();
    let seal = env.seal();
    env.unseal(&seal, &env.shares[..3]).await.unwrap();
    let nonce = seal
        .rekey_start(ShareParams::new(3, 2).unwrap())
        .await
        .unwrap()
        .nonce;
    let mut progress = None;
    for share in &env.shares[..3] {
        progress = Some(seal.rekey_submit(&nonce, share).await.unwrap());
    }
    let progress = progress.unwrap();
    assert_eq!(progress.phase, RekeyPhase::Verifying);
    let new: Vec<Vec<u8>> = progress
        .new_shares
        .iter()
        .map(|s| s.to_bytes().to_vec())
        .collect();
    for share in &new[..2] {
        seal.rekey_verify(&nonce, share).await.unwrap();
    }
    assert_eq!(env.floor_reaches(2).await.unwrap(), 2);
    assert_eq!(env.store().root_commitments(2).await.unwrap().len(), 1);

    env.lose_commitments(2, 1).await.unwrap();
    let restarted = env.seal();
    let refused = env.unseal(&restarted, &new[..2]).await;
    assert!(
        matches!(refused, Err(SealError::RootUncommitted { generation: 2 })),
        "{refused:?}"
    );
    assert!(env.recommit(&restarted, &new[..2]).await.unwrap());
    assert!(!restarted.is_sealed());
    assert_eq!(env.floor_reaches(2).await.unwrap(), 2);
    let read = env
        .secrets(&restarted)
        .get(&ANON, "app/db", None)
        .await
        .unwrap();
    assert_eq!(read.value.as_slice(), b"one");

    // From then on, a plain unseal is enough.
    let again = env.seal();
    env.unseal(&again, &new[..2]).await.unwrap();
    assert!(!again.is_sealed());
    env.destroy().await.unwrap();
}

/// A restore between two attempts leaves only a failed attempt's
/// commitment for the generation, which doesn't verify: refused, then
/// re-committed.
#[tokio::test]
async fn only_a_commitment_that_doesnt_verify_is_recommitted() {
    let env = Env::new(true).await.unwrap();
    env.floor_reaches(1).await.unwrap();
    env.lose_commitments(1, 1).await.unwrap();
    env.store()
        .insert_root_commitment(1, &[7; 32])
        .await
        .unwrap();
    let seal = env.seal();
    let refused = env.unseal(&seal, &env.shares[..3]).await;
    assert!(
        matches!(refused, Err(SealError::RootUncommitted { generation: 1 })),
        "{refused:?}"
    );
    assert!(env.recommit(&seal, &env.shares[..3]).await.unwrap());
    assert_eq!(env.store().root_commitments(1).await.unwrap().len(), 2);
    env.destroy().await.unwrap();
}

/// A keys database behind the floor is refused, naming both generations,
/// and a re-commit never lowers the floor; lowered by hand, it unseals.
#[tokio::test]
async fn a_keys_database_behind_the_floor_is_refused_naming_both() {
    let env = Env::new(true).await.unwrap();
    env.floor_reaches(1).await.unwrap();
    sqlx::query("UPDATE root_generation_floor SET generation = 2")
        .execute(env.data.pool())
        .await
        .unwrap();
    let seal = env.seal();
    let refused = env.unseal(&seal, &env.shares[..3]).await.unwrap_err();
    assert!(
        matches!(
            refused,
            SealError::RootBelowFloor {
                generation: 1,
                floor: 2
            }
        ),
        "{refused:?}"
    );
    let message = refused.to_string();
    assert!(
        message.contains("generation 1") && message.contains("floor 2"),
        "{message}"
    );
    assert!(
        message.contains("https://ferritor.dev/operations/high-availability"),
        "{message}"
    );
    assert!(matches!(
        env.recommit(&seal, &env.shares[..3]).await,
        Err(SealError::RootBelowFloor { .. })
    ));
    assert_eq!(env.store().root_generation_floor().await.unwrap(), 2);

    sqlx::query("UPDATE root_generation_floor SET generation = 1")
        .execute(env.data.pool())
        .await
        .unwrap();
    env.unseal(&seal, &env.shares[..3]).await.unwrap();
    assert!(!seal.is_sealed());
    env.destroy().await.unwrap();
}

/// With no secret stored there's nothing to prove continuity with: a
/// re-commit is refused, and says so.
#[tokio::test]
async fn a_recommit_with_nothing_stored_is_refused() {
    let env = Env::new(false).await.unwrap();
    env.floor_reaches(1).await.unwrap();
    env.lose_commitments(1, 1).await.unwrap();
    let refused = env.recommit(&env.seal(), &env.shares[..3]).await;
    assert!(
        matches!(refused, Err(SealError::RecommitNothingStored)),
        "{refused:?}"
    );
    env.destroy().await.unwrap();
}

/// Continuity needs one row that opens, whichever (namespace, KEK
/// version) it's under: one namespace's rows unreadable doesn't refuse an
/// honest re-commit.
#[tokio::test]
async fn continuity_needs_one_row_that_opens_anywhere() {
    let env = Env::new(true).await.unwrap();
    {
        let seal = env.seal();
        env.unseal(&seal, &env.shares[..3]).await.unwrap();
        Namespaces::new(Arc::clone(&seal), env.store())
            .create("other", &Labels::new())
            .await
            .unwrap();
        env.secrets(&seal)
            .put(&ANON, "other/x", b"two")
            .await
            .unwrap();
    }
    sqlx::query(
        "UPDATE secret_versions SET ciphertext = '\\x00'
         WHERE namespace_id = (SELECT id FROM namespaces WHERE name = 'app')",
    )
    .execute(env.data.pool())
    .await
    .unwrap();
    env.floor_reaches(1).await.unwrap();
    env.lose_commitments(1, 1).await.unwrap();
    assert!(env.recommit(&env.seal(), &env.shares[..3]).await.unwrap());
    env.destroy().await.unwrap();
}
