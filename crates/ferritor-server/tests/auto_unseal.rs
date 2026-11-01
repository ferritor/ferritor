//! Auto-unseal against real keys and data databases, with a key management
//! service kept in memory (`MemoryKms`): init in KMS mode stores a wrap and
//! unseals; a restart unwraps it and unseals, after the same checks a shares
//! unseal makes; the shares stay the recovery path; a rekey replaces the
//! wrap, and is how a deployment moves between Shamir and KMS.

use std::sync::Arc;
use std::time::Duration;

use ferritor_core::crypto::{self, Kek, RootKey, ShareParams};
use ferritor_core::labels::Labels;
use ferritor_core::path::Namespace;
use ferritor_datastore::Datastore;
use ferritor_keystore::{Keystore, SealWrap};
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{AllowAll, Caller};
use ferritor_server::auto_unseal::{AutoUnseal, MemoryKms};
use ferritor_server::namespaces::Namespaces;
use ferritor_server::seal::{AutoOutcome, RekeyPhase, Seal, SealError, SealMode};
use ferritor_server::secrets::Secrets;
use ferritor_testkit::{Captured, TestDatabase, TestResult};

const ANON: Caller = Caller::Unauthenticated;
const KEY: &str = "arn:aws:kms:ap-southeast-1:111122223333:key/test";

struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    gate: Arc<Gate>,
    kms: Arc<MemoryKms>,
    shares: Vec<Vec<u8>>,
}

impl Env {
    /// Databases, and a key management service; nothing initialized.
    async fn empty() -> TestResult<Self> {
        Ok(Self {
            keys: TestDatabase::new(
                "KEYS_DATABASE_URL",
                "ferritor_server_test",
                &ferritor_keystore::MIGRATOR,
            )
            .await?,
            data: TestDatabase::new(
                "DATA_DATABASE_URL",
                "ferritor_server_test",
                &ferritor_datastore::MIGRATOR,
            )
            .await?,
            gate: Arc::new(Gate::new(
                Arc::new(AllowAll),
                AuditLog::new(Captured::default(), Duration::from_secs(5))?,
            )),
            kms: Arc::new(MemoryKms::new(KEY)),
            shares: Vec::new(),
        })
    }

    /// Initialized by a server in KMS mode (unsealed at once), `app`
    /// created and `app/db` stored.
    async fn new() -> TestResult<Self> {
        let mut env = Self::empty().await?;
        let seal = env.kms_seal();
        env.shares = shares_of(seal.init(ShareParams::new(5, 3)?).await?);
        assert!(!seal.is_sealed(), "init in KMS mode unseals");
        env.store_secret(&seal).await?;
        Ok(env)
    }

    fn store(&self) -> Datastore {
        Datastore::new(self.data.pool().clone())
    }

    fn keystore(&self) -> Keystore {
        Keystore::new(self.keys.pool().clone())
    }

    /// A server (a fresh process) configured for Shamir alone.
    fn shamir_seal(&self) -> Arc<Seal> {
        Arc::new(Seal::new(self.keystore()).with_root_ledger(Arc::new(self.store())))
    }

    /// A server configured for auto-unseal with this service.
    fn kms_seal(&self) -> Arc<Seal> {
        self.seal_with(Arc::clone(&self.kms) as Arc<dyn AutoUnseal>)
    }

    fn seal_with(&self, kms: Arc<dyn AutoUnseal>) -> Arc<Seal> {
        Arc::new(
            Seal::new(self.keystore())
                .with_root_ledger(Arc::new(self.store()))
                .with_auto_unseal(kms),
        )
    }

    async fn store_secret(&self, seal: &Arc<Seal>) -> TestResult<()> {
        Namespaces::new(Arc::clone(seal), self.store())
            .create("app", &Labels::new())
            .await?;
        self.secrets(seal).put(&ANON, "app/db", b"one").await?;
        Ok(())
    }

    fn secrets(&self, seal: &Arc<Seal>) -> Secrets {
        Secrets::new(Arc::clone(seal), self.store(), Arc::clone(&self.gate))
    }

    async fn read(&self, seal: &Arc<Seal>) -> TestResult<Vec<u8>> {
        Ok(self
            .secrets(seal)
            .get(&ANON, "app/db", None)
            .await?
            .value
            .to_vec())
    }

    async fn unseal(&self, seal: &Seal, shares: &[Vec<u8>]) -> Result<(), SealError> {
        for share in shares {
            seal.unseal(share, false).await?;
        }
        Ok(())
    }

    /// Rekeys on `seal` (unsealed) from `current` to 3 shares, threshold 2,
    /// changing the protection to `change` if given; returns the new shares.
    async fn rekey(
        &self,
        seal: &Seal,
        current: &[Vec<u8>],
        change: Option<SealMode>,
    ) -> TestResult<Vec<Vec<u8>>> {
        let nonce = seal
            .rekey_start_changing(ShareParams::new(3, 2)?, change)
            .await?
            .nonce;
        let mut progress = None;
        for share in current {
            progress = Some(seal.rekey_submit(&nonce, share).await?);
        }
        let progress = progress.ok_or("no shares")?;
        assert_eq!(progress.phase, RekeyPhase::Verifying);
        let new = shares_of(progress.new_shares);
        for share in &new[..2] {
            seal.rekey_verify(&nonce, share).await?;
        }
        Ok(new)
    }

    async fn wraps(&self) -> TestResult<Vec<SealWrap>> {
        Ok(self.keystore().seal_config_and_wraps("awskms").await?.1)
    }

    async fn destroy(self) -> TestResult<()> {
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

fn shares_of(shares: Vec<crypto::Share>) -> Vec<Vec<u8>> {
    shares.iter().map(|s| s.to_bytes().to_vec()).collect()
}

/// Init in KMS mode stores a wrap for generation 1 under the configured
/// key and unseals at once; a restarted server unwraps it and serves.
#[tokio::test]
async fn a_server_unseals_itself_at_start() {
    let env = Env::new().await.unwrap();
    let wraps = env.wraps().await.unwrap();
    assert_eq!(wraps.len(), 1);
    assert_eq!((wraps[0].key_id.as_str(), wraps[0].generation), (KEY, 1));
    assert_eq!(env.store().root_commitments(1).await.unwrap().len(), 1);

    let restarted = env.kms_seal();
    assert!(matches!(
        restarted.auto_unseal().await,
        AutoOutcome::Unsealed
    ));
    assert_eq!(env.read(&restarted).await.unwrap(), b"one");
    assert_eq!(restarted.auto_report().result, Some("ok"));
    // Unsealed: nothing more to do, and no call to the service.
    let unwraps = env.kms.unwraps();
    assert!(matches!(
        restarted.auto_unseal().await,
        AutoOutcome::NotNeeded
    ));
    assert_eq!(env.kms.unwraps(), unwraps);
    env.destroy().await.unwrap();
}

/// A server whose config names another key finds no wrap for it, and waits;
/// one whose service is down retries. The shares unseal either.
#[tokio::test]
async fn the_shares_unseal_when_the_service_cant() {
    let env = Env::new().await.unwrap();
    let other = env.seal_with(Arc::new(MemoryKms::new("another-key")));
    assert!(matches!(other.auto_unseal().await, AutoOutcome::Waiting(_)));
    assert_eq!(other.auto_report().result, Some("no_wrap"));
    env.unseal(&other, &env.shares[..3]).await.unwrap();
    assert_eq!(env.read(&other).await.unwrap(), b"one");

    env.kms.set_available(false);
    let down = env.kms_seal();
    assert!(matches!(
        down.auto_unseal().await,
        AutoOutcome::Retry(SealError::AutoUnseal(_))
    ));
    assert_eq!(down.auto_report().result, Some("kms_unavailable"));
    env.unseal(&down, &env.shares[..3]).await.unwrap();
    assert!(!down.is_sealed());
    env.destroy().await.unwrap();
}

/// The attack the root commitment stops: a keys-database writer who may
/// also use the KMS key (it has Encrypt) substitutes a root key of their
/// own, wrapped under the configured key, with its root_check and KEKs.
/// The server unwraps it, root_check passes, and the commitment refuses it.
#[tokio::test]
async fn a_root_key_substituted_with_the_kms_key_is_refused() {
    let env = Env::new().await.unwrap();
    let forged = RootKey::generate().unwrap();
    let ciphertext = env.kms.wrap(&forged, 2).await.unwrap().ciphertext;
    let keys = env.keys.pool();
    sqlx::query("UPDATE seal_config SET root_check = $1, generation = 2")
        .bind(forged.root_check().unwrap())
        .execute(keys)
        .await
        .unwrap();
    sqlx::query("UPDATE seal_wraps SET generation = 2, ciphertext = $1")
        .bind(ciphertext)
        .execute(keys)
        .await
        .unwrap();
    let app = Namespace::parse("app").unwrap();
    sqlx::query("UPDATE keks SET wrapped_key = $1 WHERE namespace = 'app'")
        .bind(forged.wrap_kek(&app, 1, &Kek::generate().unwrap()).unwrap())
        .execute(keys)
        .await
        .unwrap();

    let seal = env.kms_seal();
    assert!(matches!(
        seal.auto_unseal().await,
        AutoOutcome::Refused(SealError::RootUncommitted { generation: 2 })
    ));
    assert!(seal.is_sealed());
    assert_eq!(seal.auto_report().result, Some("root_commitment"));
    env.destroy().await.unwrap();
}

/// A wrap of another generation than the seal config's is refused, never
/// unwrapped.
#[tokio::test]
async fn a_wrap_of_another_generation_is_never_unwrapped() {
    let env = Env::new().await.unwrap();
    sqlx::query("UPDATE seal_wraps SET generation = 7")
        .execute(env.keys.pool())
        .await
        .unwrap();
    let seal = env.kms_seal();
    let unwraps = env.kms.unwraps();
    assert!(matches!(
        seal.auto_unseal().await,
        AutoOutcome::Refused(SealError::WrapMismatch)
    ));
    assert_eq!(env.kms.unwraps(), unwraps);
    env.destroy().await.unwrap();
}

/// A rekey in KMS mode replaces the wrap with the new generation's; a
/// rekey on a server configured for Shamir removes it (KMS → Shamir), and
/// one on a server configured for KMS adds it back (Shamir → KMS).
#[tokio::test]
async fn a_rekey_moves_between_kms_and_shamir() {
    let env = Env::new().await.unwrap();
    let seal = env.kms_seal();
    assert!(matches!(seal.auto_unseal().await, AutoOutcome::Unsealed));
    let new = env.rekey(&seal, &env.shares[..3], None).await.unwrap();
    let wraps = env.wraps().await.unwrap();
    assert_eq!(wraps.len(), 1);
    assert_eq!(wraps[0].generation, 2);
    let restarted = env.kms_seal();
    assert!(matches!(
        restarted.auto_unseal().await,
        AutoOutcome::Unsealed
    ));

    // To Shamir: rekeyed by a server configured for it.
    let shamir = env.shamir_seal();
    env.unseal(&shamir, &new[..2]).await.unwrap();
    let newer = env
        .rekey(&shamir, &new[..2], Some(SealMode::Shamir))
        .await
        .unwrap();
    assert!(env.wraps().await.unwrap().is_empty());
    assert!(matches!(
        env.kms_seal().auto_unseal().await,
        AutoOutcome::Waiting(_)
    ));

    // And back: unsealed with the shares, rekeyed in KMS mode.
    let back = env.kms_seal();
    env.unseal(&back, &newer[..2]).await.unwrap();
    env.rekey(&back, &newer[..2], Some(SealMode::AwsKms))
        .await
        .unwrap();
    let wraps = env.wraps().await.unwrap();
    assert_eq!((wraps.len(), wraps[0].generation), (1, 4));
    let last = env.kms_seal();
    assert!(matches!(last.auto_unseal().await, AutoOutcome::Unsealed));
    assert_eq!(env.read(&last).await.unwrap(), b"one");
    env.destroy().await.unwrap();
}

/// Init in KMS mode with the service down stores nothing anywhere.
#[tokio::test]
async fn an_init_the_service_refuses_stores_nothing() {
    let env = Env::empty().await.unwrap();
    env.kms.set_available(false);
    let refused = env.kms_seal().init(ShareParams::new(5, 3).unwrap()).await;
    assert!(
        matches!(refused, Err(SealError::AutoUnseal(_))),
        "{refused:?}"
    );
    assert!(env.keystore().seal_config().await.unwrap().is_none());
    assert!(env.store().root_commitments(1).await.unwrap().is_empty());
    assert_eq!(env.store().root_generation_floor().await.unwrap(), 0);
    env.destroy().await.unwrap();
}

/// An explicit seal holds every server's next auto-unseal (no call to the
/// service), on a server that's already sealed too; an explicit release
/// lets them unseal again.
#[tokio::test]
async fn a_seal_holds_every_server_until_released() {
    let env = Env::new().await.unwrap();
    let first = env.kms_seal();
    assert!(matches!(first.auto_unseal().await, AutoOutcome::Unsealed));
    let outcome = first.seal().await;
    assert!(outcome.hold_set);
    assert!(first.hold().await.held());

    let unwraps = env.kms.unwraps();
    let restarted = env.kms_seal();
    assert!(matches!(restarted.auto_unseal().await, AutoOutcome::Held));
    assert_eq!(restarted.auto_report().result, Some("held"));
    assert_eq!(env.kms.unwraps(), unwraps, "held: no call to the service");

    // Sealing a sealed server raises the hold again.
    let before = restarted.hold().await.keys.hold;
    assert!(restarted.seal().await.hold_set);
    assert_eq!(restarted.hold().await.keys.hold, before + 1);

    // A plain shares unseal doesn't release it.
    env.unseal(&restarted, &env.shares[..3]).await.unwrap();
    assert!(restarted.hold().await.held());

    assert!(restarted.release_hold().await);
    assert!(!restarted.hold().await.held());
    assert!(matches!(
        env.kms_seal().auto_unseal().await,
        AutoOutcome::Unsealed
    ));
    env.destroy().await.unwrap();
}

/// Releasing takes both databases: one side cleared by hand leaves the
/// other holding.
#[tokio::test]
async fn one_database_alone_never_releases_the_hold() {
    let env = Env::new().await.unwrap();
    assert!(env.kms_seal().seal().await.hold_set);
    sqlx::query("UPDATE auto_unseal_hold SET released = hold")
        .execute(env.keys.pool())
        .await
        .unwrap();
    assert!(matches!(
        env.kms_seal().auto_unseal().await,
        AutoOutcome::Held
    ));
    sqlx::query("UPDATE auto_unseal_hold SET released = 0")
        .execute(env.keys.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE auto_unseal_hold SET released = hold")
        .execute(env.data.pool())
        .await
        .unwrap();
    assert!(matches!(
        env.kms_seal().auto_unseal().await,
        AutoOutcome::Held
    ));
    // An explicit unseal --auto goes past it.
    assert!(matches!(
        env.kms_seal().auto_unseal_released().await,
        AutoOutcome::Unsealed
    ));
    env.destroy().await.unwrap();
}

/// A seal landing elsewhere while an attempt waits on the service wins:
/// the hold is read again right before publishing.
#[tokio::test]
async fn a_seal_during_an_attempt_wins() {
    let env = Env::new().await.unwrap();
    env.kms.set_delay(Duration::from_millis(500));
    let starting = env.kms_seal();
    let attempt = tokio::spawn({
        let starting = Arc::clone(&starting);
        async move { starting.auto_unseal().await }
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(env.shamir_seal().seal().await.hold_set);
    assert!(matches!(attempt.await.unwrap(), AutoOutcome::Held));
    assert!(starting.is_sealed());
    env.destroy().await.unwrap();
}

type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The data database's ledger, with hold writes refused while `down`.
struct Flaky {
    store: Datastore,
    down: std::sync::atomic::AtomicBool,
}

impl ferritor_server::root_ledger::RootLedger for Flaky {
    fn floor(&self) -> BoxFuture<'_, Result<u32, String>> {
        self.store.floor()
    }
    fn raise_floor(&self, generation: u32) -> BoxFuture<'_, Result<(), String>> {
        self.store.raise_floor(generation)
    }
    fn commitments(&self, generation: u32) -> BoxFuture<'_, Result<Vec<Vec<u8>>, String>> {
        self.store.commitments(generation)
    }
    fn insert(&self, generation: u32, mac: Vec<u8>) -> BoxFuture<'_, Result<(), String>> {
        self.store.insert(generation, mac)
    }
    fn version_per_kek(
        &self,
    ) -> BoxFuture<'_, Result<Vec<ferritor_datastore::StoredVersion>, String>> {
        ferritor_server::root_ledger::RootLedger::version_per_kek(&self.store)
    }
    fn hold(&self) -> BoxFuture<'_, Result<(u64, u64), String>> {
        self.store.hold()
    }
    fn raise_hold(&self, hold: u64) -> BoxFuture<'_, Result<(), String>> {
        if self.down.load(std::sync::atomic::Ordering::SeqCst) {
            return Box::pin(async { Err("unreachable".to_owned()) });
        }
        self.store.raise_hold(hold)
    }
    fn release_hold(&self, released: u64) -> BoxFuture<'_, Result<(), String>> {
        self.store.release_hold(released)
    }
}

/// A seal whose hold can't be written to a database says so (the server
/// is sealed, but a restart could auto-unseal it), keeps the half it did
/// write in force, and retries the rest until it lands.
#[tokio::test]
async fn a_hold_that_cant_be_written_is_reported_and_retried() {
    use ferritor_server::root_ledger::RootLedger as _;
    let env = Env::new().await.unwrap();
    let flaky = Arc::new(Flaky {
        store: env.store(),
        down: std::sync::atomic::AtomicBool::new(true),
    });
    let seal = Arc::new(
        Seal::new(env.keystore())
            .with_root_ledger(
                Arc::clone(&flaky) as Arc<dyn ferritor_server::root_ledger::RootLedger>
            )
            .with_auto_unseal(Arc::clone(&env.kms) as Arc<dyn AutoUnseal>),
    );
    let outcome = seal.seal().await;
    assert!(seal.is_sealed());
    assert!(!outcome.hold_set);
    assert_eq!(seal.hold_pending(), 1);
    // The keys database's half is in force meanwhile.
    assert!(matches!(
        env.kms_seal().auto_unseal().await,
        AutoOutcome::Held
    ));
    assert_eq!(env.store().hold().await.unwrap().0, 0);

    flaky.down.store(false, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..50 {
        if seal.hold_pending() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(seal.hold_pending(), 0);
    assert_eq!(env.store().hold().await.unwrap().0, 1);
    env.destroy().await.unwrap();
}

/// The server's own loop: retries while the service is down, unseals once
/// it's back; after an explicit seal it waits on the hold, without calling
/// the service. A release elsewhere brings up a server the databases' hold
/// held, not the one sealed explicitly, until it's unsealed itself.
#[tokio::test]
async fn the_loop_keeps_the_server_unsealed_and_heeds_the_hold() {
    let env = Env::new().await.unwrap();
    env.kms.set_available(false);
    let seal = env.kms_seal();
    let looping = tokio::spawn(ferritor_server::auto_unseal::keep_unsealed_with(
        Arc::clone(&seal),
        Arc::clone(&env.gate),
        env.store(),
        Duration::from_millis(50),
        Duration::from_millis(200),
    ));
    let unsealed_within = |seal: Arc<Seal>, expected: bool| async move {
        for _ in 0..60 {
            if seal.is_sealed() != expected {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(seal.is_sealed());
    env.kms.set_available(true);
    assert!(
        unsealed_within(Arc::clone(&seal), true).await,
        "never unsealed"
    );

    assert!(seal.seal().await.hold_set);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(seal.is_sealed());
    let unwraps = env.kms.unwraps();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(env.kms.unwraps(), unwraps, "held: no call to the service");

    // A release elsewhere lifts the databases' hold: a server held by it
    // (restarted since) comes up. The one sealed explicitly stays sealed:
    // its own hold ends only with an unseal on it.
    let restarted = env.kms_seal();
    let restarted_loop = tokio::spawn(ferritor_server::auto_unseal::keep_unsealed_with(
        Arc::clone(&restarted),
        Arc::clone(&env.gate),
        env.store(),
        Duration::from_millis(50),
        Duration::from_millis(200),
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(restarted.is_sealed());
    assert!(env.shamir_seal().release_hold().await);
    assert!(
        unsealed_within(Arc::clone(&restarted), true).await,
        "the release didn't bring the held server up"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        seal.is_sealed(),
        "the sealed server unsealed without being asked"
    );
    assert!(matches!(
        seal.auto_unseal_released().await,
        AutoOutcome::Unsealed
    ));
    looping.abort();
    restarted_loop.abort();
    env.destroy().await.unwrap();
}

/// The server's own loop never undoes its explicit seal, even with the
/// databases' hold unwritten: the keys database's half is stuck behind a
/// lock until the write times out, the data database's half refused. The
/// loop wakes the moment the keyring drops; this server's own hold, set in
/// the same critical section, stops it. An explicit `--auto` then unseals.
#[tokio::test]
async fn the_loop_never_undoes_its_own_seal() {
    let env = Env::new().await.unwrap();
    let flaky = Arc::new(Flaky {
        store: env.store(),
        down: std::sync::atomic::AtomicBool::new(true),
    });
    let seal = Arc::new(
        Seal::new(env.keystore().with_timeout(Duration::from_millis(300)))
            .with_root_ledger(
                Arc::clone(&flaky) as Arc<dyn ferritor_server::root_ledger::RootLedger>
            )
            .with_auto_unseal(Arc::clone(&env.kms) as Arc<dyn AutoUnseal>),
    );
    let looping = tokio::spawn(ferritor_server::auto_unseal::keep_unsealed_with(
        Arc::clone(&seal),
        Arc::clone(&env.gate),
        env.store(),
        Duration::from_millis(20),
        Duration::from_millis(100),
    ));
    for _ in 0..100 {
        if !seal.is_sealed() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!seal.is_sealed(), "the loop never unsealed");

    let mut locked = env.keys.pool().begin().await.unwrap();
    sqlx::query("SELECT hold FROM auto_unseal_hold FOR UPDATE")
        .execute(&mut *locked)
        .await
        .unwrap();
    let outcome = seal.seal().await;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(seal.is_sealed(), "the loop undid the seal");
    }
    assert!(!outcome.hold_set);
    assert!(seal.hold().await.here);
    locked.rollback().await.unwrap();

    assert!(matches!(
        seal.auto_unseal_released().await,
        AutoOutcome::Unsealed
    ));
    assert!(!seal.hold().await.here);
    looping.abort();
    env.destroy().await.unwrap();
}

/// A server refused for a missing root commitment keeps looking (a
/// `Decrypt` every `MAX_WAIT`), so a re-commit with the shares on another
/// server brings it up too, without a restart.
#[tokio::test]
async fn a_recommit_elsewhere_brings_a_refused_server_up() {
    let env = Env::new().await.unwrap();
    for _ in 0..100 {
        if env.store().root_generation_floor().await.unwrap() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let data = env.data.pool();
    for statement in [
        "ALTER TABLE root_commitments DISABLE TRIGGER USER",
        "DELETE FROM root_commitments",
        "ALTER TABLE root_commitments ENABLE TRIGGER USER",
    ] {
        sqlx::query(statement).execute(data).await.unwrap();
    }
    let refused = env.kms_seal();
    let looping = tokio::spawn(ferritor_server::auto_unseal::keep_unsealed_with(
        Arc::clone(&refused),
        Arc::clone(&env.gate),
        env.store(),
        Duration::from_millis(20),
        Duration::from_millis(100),
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(refused.is_sealed());
    assert_eq!(refused.auto_report().result, Some("root_commitment"));

    let other = env.shamir_seal();
    for share in &env.shares[..3] {
        other.unseal_recommit(share, false).await.unwrap();
    }
    for _ in 0..50 {
        if !refused.is_sealed() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!refused.is_sealed(), "never looked again");
    looping.abort();
    env.destroy().await.unwrap();
}

/// A rekey keeps how the root key is protected unless asked: through a
/// server configured for the shares alone, or for another key, it's refused
/// before any share is asked for; asked for a mode this server isn't
/// configured for, too.
#[tokio::test]
async fn a_rekey_changes_the_protection_only_when_asked() {
    let env = Env::new().await.unwrap();
    let params = ShareParams::new(3, 2).unwrap();

    let shamir = env.shamir_seal();
    env.unseal(&shamir, &env.shares[..3]).await.unwrap();
    let refused = shamir.rekey_start(params).await.unwrap_err();
    assert!(
        matches!(
            refused,
            SealError::RekeyWouldChangeSeal {
                suggest: "shamir",
                ..
            }
        ),
        "{refused:?}"
    );
    assert!(refused.to_string().contains("--seal shamir"), "{refused}");
    assert!(matches!(
        shamir
            .rekey_start_changing(params, Some(SealMode::AwsKms))
            .await,
        Err(SealError::SealChangeUnconfigured {
            asked: "awskms",
            ..
        })
    ));

    let other = env.seal_with(Arc::new(MemoryKms::new("another-key")));
    env.unseal(&other, &env.shares[..3]).await.unwrap();
    assert!(matches!(
        other.rekey_start(params).await,
        Err(SealError::RekeyWouldChangeSeal {
            suggest: "awskms",
            ..
        })
    ));
    assert!(
        other
            .rekey_start_changing(params, Some(SealMode::AwsKms))
            .await
            .is_ok()
    );

    // Configured like the deployment: no question.
    let same = env.kms_seal();
    assert!(matches!(same.auto_unseal().await, AutoOutcome::Unsealed));
    assert!(same.rekey_start(params).await.is_ok());
    env.destroy().await.unwrap();
}
