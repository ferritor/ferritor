//! The seal state machine against a real keys database (one per test, see
//! `ferritor-testkit`), plus an end-to-end pass over gRPC for status codes.

use std::sync::Arc;
use std::time::Duration;

use ferritor_core::crypto::{self, CryptoError, Dek, Share, ShareParams};
use ferritor_core::labels::Labels;
use ferritor_core::messages::reason;
use ferritor_core::path::{Namespace, SecretPath};
use ferritor_core::proto::v1 as pb;
use ferritor_core::proto::v1::system_service_client::SystemServiceClient;
use ferritor_core::proto::v1::system_service_server::SystemServiceServer;
use ferritor_datastore::Datastore;
use ferritor_keystore::{Keystore, MIGRATOR, RewrappedKek};
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::destroy::Destroy;
use ferritor_server::grpc::{self, System};
use ferritor_server::namespaces::Namespaces;
use ferritor_server::purge::Purge;
use ferritor_server::rewrap::Rewrap;
use ferritor_server::seal::{
    PendingRekey, RekeyPhase, RekeyProgress, RekeyStatus, Seal, SealError, Status,
};
use ferritor_testkit::{TestDatabase, TestResult};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Code;

fn app() -> TestResult<Namespace> {
    Ok(Namespace::parse("app")?)
}

/// `app`'s active KEK version (the namespace these tests use).
fn active(keyring: &ferritor_server::seal::Keyring) -> TestResult<u32> {
    let (version, _) = keyring.active_kek(&app()?).ok_or("no active KEK")?;
    Ok(version)
}

fn params(shares: u8, threshold: u8) -> TestResult<ShareParams> {
    Ok(ShareParams::new(shares, threshold)?)
}

struct Server {
    db: TestDatabase,
    seal: Seal,
    /// The namespace the tests store under, created at the first unseal.
    app: Namespace,
}

impl Server {
    async fn new() -> TestResult<Self> {
        Self::with_commit_check_timeout(Duration::from_secs(5)).await
    }

    async fn with_commit_check_timeout(timeout: Duration) -> TestResult<Self> {
        let db = TestDatabase::new("KEYS_DATABASE_URL", "ferritor_server_test", &MIGRATOR).await?;
        let seal = Seal::new(Keystore::new(db.pool().clone())).with_commit_check_timeout(timeout);
        Ok(Self {
            db,
            seal,
            app: app()?,
        })
    }

    /// Initialized with 5 shares, threshold 3; returns the encoded shares.
    async fn initialized() -> TestResult<(Self, Vec<Vec<u8>>)> {
        Self::init(Self::new().await?).await
    }

    async fn init(server: Self) -> TestResult<(Self, Vec<Vec<u8>>)> {
        let shares = server.seal.init(params(5, 3)?).await?;
        let shares = shares.iter().map(|s| s.to_bytes().to_vec()).collect();
        Ok((server, shares))
    }

    /// Unseals with `shares`; at the first unseal, creates the namespace
    /// `app` (no data database here, so straight through the seal).
    async fn unseal_with(&self, shares: &[Vec<u8>]) -> Result<Status, SealError> {
        let mut status = self.seal.unseal(&[], false).await?;
        for share in shares {
            status = self.seal.unseal(share, false).await?;
        }
        if !status.sealed && self.seal.active_kek_version(&self.app).is_none() {
            self.seal
                .create_namespace(&self.app, &Labels::new())
                .await?;
        }
        Ok(status)
    }

    /// Starts a rekey to 3 shares / threshold 2 and authorizes it with
    /// `current`; returns the nonce and the (uncommitted) new shares.
    async fn authorize_rekey(&self, current: &[Vec<u8>]) -> TestResult<(String, Vec<Vec<u8>>)> {
        let nonce = self.seal.rekey_start(params(3, 2)?).await?.nonce;
        self.authorize_rekey_from(&nonce, current).await
    }

    /// Submits `current` to the rekey `nonce`; returns it with the new shares.
    async fn authorize_rekey_from(
        &self,
        nonce: &str,
        current: &[Vec<u8>],
    ) -> TestResult<(String, Vec<Vec<u8>>)> {
        let mut progress = None;
        for share in current {
            progress = Some(self.seal.rekey_submit(nonce, share).await?);
        }
        let progress = progress.ok_or("no shares submitted")?;
        if progress.phase != RekeyPhase::Verifying {
            return Err(format!("expected verifying, got {:?}", progress.phase).into());
        }
        let new_shares = progress
            .new_shares
            .iter()
            .map(|s| s.to_bytes().to_vec())
            .collect();
        Ok((nonce.to_owned(), new_shares))
    }

    /// Submits `new` back to finish the rekey; returns the last progress.
    async fn verify_rekey(&self, nonce: &str, new: &[Vec<u8>]) -> Result<RekeyProgress, SealError> {
        let mut progress = None;
        for share in new {
            progress = Some(self.seal.rekey_verify(nonce, share).await?);
        }
        progress.ok_or(SealError::NoRekey)
    }

    /// Stores the pending rekey (3 shares / threshold 2, from generation 1)
    /// through the keystore directly: the database state a commit leaves when
    /// it succeeds but reports an error to `rekey_verify`.
    async fn commit_behind_the_seal(&self, new_shares: &[Vec<u8>]) -> TestResult<()> {
        let (root_check, rewrapped) = self.rekey_rows(new_shares)?;
        Keystore::new(self.db.pool().clone())
            .rekey(1, params(3, 2)?, &root_check, &rewrapped, &Nothing)
            .await?;
        Ok(())
    }

    /// The same writes, left uncommitted: a rekey whose COMMIT was sent but
    /// not confirmed, still holding the seal config row.
    async fn rekey_in_flight(
        &self,
        new_shares: &[Vec<u8>],
    ) -> TestResult<sqlx::Transaction<'static, sqlx::Postgres>> {
        let (root_check, rewrapped) = self.rekey_rows(new_shares)?;
        let mut tx = self.db.pool().begin().await?;
        sqlx::query(
            "UPDATE seal_config SET shares = 3, threshold = 2, root_check = $1, generation = 2",
        )
        .bind(root_check)
        .execute(&mut *tx)
        .await?;
        for kek in rewrapped {
            sqlx::query("UPDATE keks SET wrapped_key = $2 WHERE version = $1")
                .bind(i32::try_from(kek.version)?)
                .bind(kek.wrapped_key)
                .execute(&mut *tx)
                .await?;
        }
        Ok(tx)
    }

    /// Root check and re-wrapped KEKs for the root key `new_shares` rebuild.
    fn rekey_rows(&self, new_shares: &[Vec<u8>]) -> TestResult<(Vec<u8>, Vec<RewrappedKek>)> {
        let shares = new_shares
            .iter()
            .map(|b| Share::from_bytes(b))
            .collect::<Result<Vec<_>, _>>()?;
        let root = crypto::combine(&shares, 2)?;
        let keyring = self.seal.keyring()?;
        let rewrapped = (1..=active(&keyring)?)
            .map(|version| {
                let kek = keyring.kek(&app()?, version).ok_or("missing KEK")?;
                Ok(RewrappedKek {
                    namespace: app()?,
                    version,
                    wrapped_key: root.wrap_kek(&app()?, version, kek)?,
                })
            })
            .collect::<TestResult<Vec<_>>>()?;
        Ok((root.root_check()?, rewrapped))
    }

    /// Holds the seal config row exclusively, so rotate and rekey (which
    /// lock it) get stuck on the database while holding the admin lock.
    async fn block_seal_config(&self) -> TestResult<sqlx::Transaction<'static, sqlx::Postgres>> {
        let mut tx = self.db.pool().begin().await?;
        sqlx::query("SELECT 1 FROM seal_config FOR UPDATE")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// Waits (up to 5 s) until the keyring is gone.
    async fn wait_until_sealed(&self) -> TestResult<()> {
        for _ in 0..500 {
            if self.seal.keyring().is_err() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err("still unsealed".into())
    }

    async fn destroy(self) -> TestResult<()> {
        self.db.destroy().await
    }
}

#[tokio::test]
async fn init_returns_shares_and_stays_sealed() {
    let server = Server::new().await.unwrap();
    assert!(matches!(
        server.seal.unseal(&[], false).await,
        Err(SealError::NotInitialized)
    ));
    let status = server.seal.status().await.unwrap();
    assert!(!status.initialized && status.sealed);

    let shares = server.seal.init(params(5, 3).unwrap()).await.unwrap();
    assert_eq!(shares.len(), 5);
    assert!(shares.iter().all(|s| s.generation() == 1));
    let status = server.seal.status().await.unwrap();
    assert_eq!(
        status,
        Status {
            initialized: true,
            sealed: true,
            shares: 5,
            threshold: 3,
            generation: 1,
            progress: 0,
            rekey: None,
            recommitted: false,
            // Configured for the shares alone; no hold yet (no data
            // database here, so only the keys database's half).
            auto_unseal: Some(ferritor_server::seal::AutoUnsealStatus {
                hold: ferritor_server::seal::Hold {
                    keys: ferritor_server::seal::HoldHalf {
                        hold: 0,
                        released: 0,
                        readable: true,
                    },
                    data: None,
                    here: false,
                },
                ..Default::default()
            }),
        }
    );
    assert!(matches!(server.seal.keyring(), Err(SealError::Sealed)));
    assert!(matches!(
        server.seal.init(params(5, 3).unwrap()).await,
        Err(SealError::AlreadyInitialized)
    ));
    server.destroy().await.unwrap();
}

#[tokio::test]
async fn threshold_shares_unseal_and_seal_drops_the_keyring() {
    let (server, shares) = Server::initialized().await.unwrap();
    // Any 3 of the 5, in any order.
    let status = server.unseal_with(&shares[2..4]).await.unwrap();
    assert_eq!((status.sealed, status.progress), (true, 2));
    let status = server.seal.unseal(&shares[0], false).await.unwrap();
    assert_eq!((status.sealed, status.progress), (false, 0));

    let keyring = server.seal.keyring().unwrap();
    assert_eq!(keyring.generation(), 1);
    // Init creates no KEK: there's no default namespace.
    assert_eq!(keyring.namespaces().count(), 0);

    // Further shares while unsealed are ignored.
    let status = server.seal.unseal(&shares[1], false).await.unwrap();
    assert_eq!((status.sealed, status.progress), (false, 0));

    let status = server.seal.seal().await.status.unwrap();
    assert!(status.sealed);
    assert!(matches!(server.seal.keyring(), Err(SealError::Sealed)));
    server.destroy().await.unwrap();
}

#[tokio::test]
async fn bad_submissions_are_rejected_without_losing_progress() {
    let (server, shares) = Server::initialized().await.unwrap();
    server.seal.unseal(&shares[0], false).await.unwrap();

    assert!(matches!(
        server.seal.unseal(&shares[0], false).await,
        Err(SealError::DuplicateShare(_))
    ));
    assert!(matches!(
        server.seal.unseal(b"garbage", false).await,
        Err(SealError::InvalidShare(CryptoError::MalformedShare))
    ));
    assert_eq!(server.seal.status().await.unwrap().progress, 1);

    let status = server.seal.unseal(&[], true).await.unwrap();
    assert_eq!(status.progress, 0);
    server.destroy().await.unwrap();
}

#[tokio::test]
async fn shares_of_another_seal_are_wrong_and_reset_progress() {
    let (server, _) = Server::initialized().await.unwrap();
    let (other, other_shares) = Server::initialized().await.unwrap();

    assert!(matches!(
        server.unseal_with(&other_shares[..3]).await,
        Err(SealError::WrongShares)
    ));
    let status = server.seal.status().await.unwrap();
    assert_eq!((status.sealed, status.progress), (true, 0));
    server.destroy().await.unwrap();
    other.destroy().await.unwrap();
}

#[tokio::test]
async fn rotate_needs_unseal_and_survives_reseal() {
    let (server, shares) = Server::initialized().await.unwrap();
    assert!(matches!(
        server.seal.rotate(&app().unwrap()).await,
        Err(SealError::Sealed)
    ));

    server.unseal_with(&shares[..3]).await.unwrap();
    assert_eq!(server.seal.rotate(&app().unwrap()).await.unwrap(), 2);
    assert_eq!(server.seal.rotate(&app().unwrap()).await.unwrap(), 3);
    assert_eq!(active(&server.seal.keyring().unwrap()).unwrap(), 3);

    // Reloaded from the keystore: every version unwraps, 3 is active.
    server.seal.seal().await;
    server.unseal_with(&shares[..3]).await.unwrap();
    let keyring = server.seal.keyring().unwrap();
    assert_eq!(active(&keyring).unwrap(), 3);
    assert!((1..=3).all(|v| keyring.kek(&app().unwrap(), v).is_some()));
    server.destroy().await.unwrap();
}

/// The failure this two-phase design exists for: the response carrying the
/// new shares is lost. Nothing was committed, so abandoning the rekey (by
/// cancelling or sealing) leaves the current shares working.
#[tokio::test]
async fn lost_new_shares_leave_the_old_shares_working() {
    let (server, shares) = Server::initialized().await.unwrap();
    server.unseal_with(&shares[..3]).await.unwrap();

    let (nonce, _lost) = server.authorize_rekey(&shares[..3]).await.unwrap();
    assert_eq!(server.seal.keyring().unwrap().generation(), 1);
    let config = server.seal.status().await.unwrap();
    assert_eq!((config.shares, config.threshold), (5, 3));
    let cancelled = server.seal.rekey_cancel(&nonce).await.unwrap();
    assert_eq!(cancelled.phase, RekeyPhase::Cancelled);

    assert_eq!(server.seal.seal().await.pending_rekey, PendingRekey::None);
    assert!(!server.unseal_with(&shares[2..]).await.unwrap().sealed);

    // Sealing mid-verification abandons it the same way, and says so.
    server.authorize_rekey(&shares[..3]).await.unwrap();
    assert_eq!(
        server.seal.seal().await.pending_rekey,
        PendingRekey::Discarded
    );
    assert!(!server.unseal_with(&shares[..3]).await.unwrap().sealed);
    assert!(matches!(
        server.seal.rekey_verify(&nonce, &shares[0]).await,
        Err(SealError::NoRekey)
    ));
    server.destroy().await.unwrap();
}

#[tokio::test]
async fn verified_rekey_replaces_shares_and_keeps_the_keks() {
    let (server, old_shares) = Server::initialized().await.unwrap();
    server.unseal_with(&old_shares[..3]).await.unwrap();
    server.seal.rotate(&app().unwrap()).await.unwrap();

    // A DEK wrapped by each KEK before the rekey must unwrap after it.
    let path = SecretPath::parse("app/db").unwrap();
    let dek = Dek::generate().unwrap();
    let keyring = server.seal.keyring().unwrap();
    let wrapped: Vec<_> = [1, 2]
        .iter()
        .map(|&v| {
            keyring
                .kek(&app().unwrap(), v)
                .unwrap()
                .wrap_dek(&path, 1, &dek)
                .unwrap()
        })
        .collect();

    let started = server
        .seal
        .rekey_start(params(3, 2).unwrap())
        .await
        .unwrap();
    assert_eq!(
        (started.phase, started.progress, started.required),
        (RekeyPhase::Authorizing, 0, 3)
    );
    let (nonce, new_shares) = server
        .authorize_rekey_from(&started.nonce, &old_shares[1..4])
        .await
        .unwrap();
    assert_eq!(new_shares.len(), 3);

    let progress = server
        .seal
        .rekey_verify(&nonce, &new_shares[2])
        .await
        .unwrap();
    assert_eq!(
        (
            progress.phase,
            progress.progress,
            progress.required,
            progress.generation
        ),
        (RekeyPhase::Verifying, 1, 2, Some(2))
    );
    assert_eq!(server.seal.keyring().unwrap().generation(), 1);
    let done = server
        .seal
        .rekey_verify(&nonce, &new_shares[0])
        .await
        .unwrap();
    assert_eq!(
        (done.phase, done.generation),
        (RekeyPhase::Complete, Some(2))
    );
    assert_eq!(server.seal.keyring().unwrap().generation(), 2);

    server.seal.seal().await;
    assert!(matches!(
        server.seal.unseal(&old_shares[0], false).await,
        Err(SealError::InvalidShare(CryptoError::StaleShare {
            expected: 2,
            found: 1
        }))
    ));
    let status = server.unseal_with(&new_shares[1..]).await.unwrap();
    assert!(!status.sealed);
    assert_eq!(
        (status.shares, status.threshold, status.generation),
        (3, 2, 2)
    );

    let keyring = server.seal.keyring().unwrap();
    assert_eq!(active(&keyring).unwrap(), 2);
    for (v, wrapped) in [1, 2].iter().zip(&wrapped) {
        keyring
            .kek(&app().unwrap(), *v)
            .unwrap()
            .unwrap_dek(&path, 1, wrapped)
            .unwrap();
    }
    server.destroy().await.unwrap();
}

/// KEKs are re-wrapped at commit, so a KEK rotated in between survives.
#[tokio::test]
async fn rotation_between_authorize_and_verify_is_kept() {
    let (server, shares) = Server::initialized().await.unwrap();
    server.unseal_with(&shares[..3]).await.unwrap();
    let (nonce, new_shares) = server.authorize_rekey(&shares[..3]).await.unwrap();
    assert_eq!(server.seal.rotate(&app().unwrap()).await.unwrap(), 2);
    server.verify_rekey(&nonce, &new_shares[..2]).await.unwrap();

    server.seal.seal().await;
    server.unseal_with(&new_shares[..2]).await.unwrap();
    let keyring = server.seal.keyring().unwrap();
    assert_eq!(active(&keyring).unwrap(), 2);
    assert!(keyring.kek(&app().unwrap(), 1).is_some());
    server.destroy().await.unwrap();
}

#[tokio::test]
async fn verification_rejects_anything_but_the_new_shares() {
    let (server, shares) = Server::initialized().await.unwrap();
    server.unseal_with(&shares[..3]).await.unwrap();
    let (nonce, new_shares) = server.authorize_rekey(&shares[..3]).await.unwrap();

    // Phases don't mix.
    assert!(matches!(
        server.seal.rekey_submit(&nonce, &shares[3]).await,
        Err(SealError::RekeyVerifying)
    ));
    // Old shares are from the old generation.
    assert!(matches!(
        server.seal.rekey_verify(&nonce, &shares[0]).await,
        Err(SealError::InvalidShare(CryptoError::StaleShare {
            expected: 2,
            found: 1
        }))
    ));
    // Shares of another rekey carry the right generation but the wrong key:
    // progress resets, the attempt stays in verification.
    let (other, other_shares) = Server::initialized().await.unwrap();
    other.unseal_with(&other_shares[..3]).await.unwrap();
    let (_, other_new) = other.authorize_rekey(&other_shares[..3]).await.unwrap();
    assert!(matches!(
        server.verify_rekey(&nonce, &other_new[..2]).await,
        Err(SealError::WrongShares)
    ));
    assert_eq!(server.seal.keyring().unwrap().generation(), 1);

    let done = server.verify_rekey(&nonce, &new_shares[..2]).await.unwrap();
    assert_eq!(
        (done.phase, done.generation),
        (RekeyPhase::Complete, Some(2))
    );
    server.destroy().await.unwrap();
    other.destroy().await.unwrap();
}

/// Status reports the rekey collecting shares, so a nonce lost with
/// RekeyStart's reply can be recovered, and stops once it ends.
#[tokio::test]
async fn status_shows_a_rekey_in_progress() {
    let (server, old) = Server::initialized().await.unwrap();
    server.unseal_with(&old[..3]).await.unwrap();
    let rekey = || async { server.seal.status().await.unwrap().rekey };
    assert_eq!(rekey().await, None);

    let nonce = server
        .seal
        .rekey_start(params(3, 2).unwrap())
        .await
        .unwrap()
        .nonce;
    let expect = |phase, progress, required, generation| {
        Some(RekeyStatus {
            nonce: nonce.clone(),
            phase,
            progress,
            required,
            generation,
        })
    };
    assert_eq!(rekey().await, expect(RekeyPhase::Authorizing, 0, 3, None));
    server.seal.rekey_submit(&nonce, &old[0]).await.unwrap();
    assert_eq!(rekey().await, expect(RekeyPhase::Authorizing, 1, 3, None));
    // Unseal's status (here: a no-op while unsealed) carries it too.
    let unseal_status = server.seal.unseal(&[], false).await.unwrap();
    assert_eq!(
        unseal_status.rekey,
        expect(RekeyPhase::Authorizing, 1, 3, None)
    );

    server
        .authorize_rekey_from(&nonce, &old[1..3])
        .await
        .unwrap();
    assert_eq!(rekey().await, expect(RekeyPhase::Verifying, 0, 2, Some(2)));
    server.seal.rekey_cancel(&nonce).await.unwrap();
    assert_eq!(rekey().await, None);

    // Gone after completing, and after a seal.
    let (nonce, new_shares) = server.authorize_rekey(&old[..3]).await.unwrap();
    server.verify_rekey(&nonce, &new_shares[..2]).await.unwrap();
    assert_eq!(rekey().await, None);
    server
        .seal
        .rekey_start(params(3, 2).unwrap())
        .await
        .unwrap();
    assert_eq!(server.seal.seal().await.status.unwrap().rekey, None);
    server.destroy().await.unwrap();
}

/// The most confusing state a rekey can be in: the commit landed but wasn't
/// confirmed, so the attempt is still verifying. Status alone resolves it:
/// its generation already equals the one the new shares carry.
#[tokio::test]
async fn status_shows_an_unconfirmed_commit_that_landed() {
    let (server, old) = Server::initialized().await.unwrap();
    server.unseal_with(&old[..3]).await.unwrap();
    let (nonce, new) = server.authorize_rekey(&old[..3]).await.unwrap();
    let before = server.seal.status().await.unwrap();
    let rekey = before.rekey.unwrap();
    assert_eq!((before.generation, rekey.generation), (1, Some(2)));

    server.commit_behind_the_seal(&new[..2]).await.unwrap();
    let after = server.seal.status().await.unwrap();
    let rekey = after.rekey.unwrap();
    assert_eq!(rekey.phase, RekeyPhase::Verifying);
    assert_eq!(Some(after.generation), rekey.generation);

    // And a further verify finishes it.
    let done = server.verify_rekey(&nonce, &new[..2]).await.unwrap();
    assert_eq!(done.phase, RekeyPhase::Complete);
    assert_eq!(server.seal.status().await.unwrap().rekey, None);
    server.destroy().await.unwrap();
}

/// Replies carry a generation exactly when the proto says: the submit that
/// ends authorizing (VERIFYING, with the target generation), not a cancel.
#[tokio::test]
async fn rekey_replies_carry_the_generation_while_verifying() {
    let (server, old) = Server::initialized().await.unwrap();
    server.unseal_with(&old[..3]).await.unwrap();
    let nonce = server
        .seal
        .rekey_start(params(3, 2).unwrap())
        .await
        .unwrap()
        .nonce;
    let partial = server.seal.rekey_submit(&nonce, &old[0]).await.unwrap();
    assert_eq!(
        (partial.phase, partial.generation),
        (RekeyPhase::Authorizing, None)
    );
    server.seal.rekey_submit(&nonce, &old[1]).await.unwrap();
    let authorized = server.seal.rekey_submit(&nonce, &old[2]).await.unwrap();
    assert_eq!(
        (authorized.phase, authorized.generation),
        (RekeyPhase::Verifying, Some(2))
    );
    let cancelled = server.seal.rekey_cancel(&nonce).await.unwrap();
    assert_eq!(
        (cancelled.phase, cancelled.generation),
        (RekeyPhase::Cancelled, None)
    );
    server.destroy().await.unwrap();
}

#[tokio::test]
async fn rekey_attempt_lifecycle() {
    let (server, shares) = Server::initialized().await.unwrap();
    assert!(matches!(
        server.seal.rekey_start(params(3, 2).unwrap()).await,
        Err(SealError::Sealed)
    ));
    server.unseal_with(&shares[..3]).await.unwrap();

    let started = server
        .seal
        .rekey_start(params(3, 2).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        server.seal.rekey_start(params(3, 2).unwrap()).await,
        Err(SealError::RekeyInProgress)
    ));
    assert!(matches!(
        server.seal.rekey_verify(&started.nonce, &shares[0]).await,
        Err(SealError::RekeyAuthorizing)
    ));
    assert!(matches!(
        server.seal.rekey_submit("not-the-nonce", &shares[0]).await,
        Err(SealError::NonceMismatch)
    ));

    // Wrong shares reset progress but keep the attempt.
    let (other, other_shares) = Server::initialized().await.unwrap();
    for share in &other_shares[..2] {
        server
            .seal
            .rekey_submit(&started.nonce, share)
            .await
            .unwrap();
    }
    assert!(matches!(
        server
            .seal
            .rekey_submit(&started.nonce, &other_shares[2])
            .await,
        Err(SealError::WrongShares)
    ));
    let progress = server
        .seal
        .rekey_submit(&started.nonce, &shares[0])
        .await
        .unwrap();
    assert_eq!(progress.progress, 1);

    assert!(matches!(
        server.seal.rekey_cancel("not-the-nonce").await,
        Err(SealError::NonceMismatch)
    ));
    let cancelled = server.seal.rekey_cancel(&started.nonce).await.unwrap();
    assert_eq!(cancelled.phase, RekeyPhase::Cancelled);
    assert!(matches!(
        server.seal.rekey_submit(&started.nonce, &shares[1]).await,
        Err(SealError::NoRekey)
    ));
    assert_eq!(server.seal.keyring().unwrap().generation(), 1);
    server.destroy().await.unwrap();
    other.destroy().await.unwrap();
}

/// A commit that succeeded but reported an error: retrying verification
/// must recognise the stored key and complete, not leave it pending.
#[tokio::test]
async fn verify_after_an_ambiguous_commit_completes() {
    let (server, old_shares) = Server::initialized().await.unwrap();
    server.unseal_with(&old_shares[..3]).await.unwrap();
    let (nonce, new_shares) = server.authorize_rekey(&old_shares[..3]).await.unwrap();
    server
        .commit_behind_the_seal(&new_shares[..2])
        .await
        .unwrap();

    // keystore.rekey now fails (generation 2 != 1), but the key is stored.
    let done = server.verify_rekey(&nonce, &new_shares[1..]).await.unwrap();
    assert_eq!(
        (done.phase, done.generation),
        (RekeyPhase::Complete, Some(2))
    );
    assert_eq!(server.seal.keyring().unwrap().generation(), 2);

    server.seal.seal().await;
    assert!(matches!(
        server.seal.unseal(&old_shares[0], false).await,
        Err(SealError::InvalidShare(CryptoError::StaleShare { .. }))
    ));
    assert!(!server.unseal_with(&new_shares[..2]).await.unwrap().sealed);
    server.destroy().await.unwrap();
}

/// Cancelling must not discard a key the database already holds: that would
/// tell operators the old shares still work when only the new ones do.
#[tokio::test]
async fn cancel_refuses_once_the_new_key_is_stored() {
    let (server, old_shares) = Server::initialized().await.unwrap();
    server.unseal_with(&old_shares[..3]).await.unwrap();
    let (nonce, new_shares) = server.authorize_rekey(&old_shares[..3]).await.unwrap();
    server
        .commit_behind_the_seal(&new_shares[..2])
        .await
        .unwrap();

    assert!(matches!(
        server.seal.rekey_cancel(&nonce).await,
        Err(SealError::RekeyCommitted { generation: 2 })
    ));
    // Adopted rather than dropped.
    assert_eq!(server.seal.keyring().unwrap().generation(), 2);
    assert!(matches!(
        server.seal.rekey_verify(&nonce, &new_shares[0]).await,
        Err(SealError::NoRekey)
    ));
    server.seal.seal().await;
    assert!(!server.unseal_with(&new_shares[1..]).await.unwrap().sealed);
    server.destroy().await.unwrap();
}

/// The window a plain read leaves open: the commit was sent, the database is
/// still finishing it. The check must wait for it rather than answer "not
/// committed" just before it lands.
#[tokio::test]
async fn cancel_waits_for_an_unconfirmed_commit_and_refuses() {
    let (server, old_shares) = Server::initialized().await.unwrap();
    server.unseal_with(&old_shares[..3]).await.unwrap();
    let (nonce, new_shares) = server.authorize_rekey(&old_shares[..3]).await.unwrap();
    let in_flight = server.rekey_in_flight(&new_shares[..2]).await.unwrap();

    let (cancelled, ()) = tokio::join!(server.seal.rekey_cancel(&nonce), async {
        server.db.wait_for_lock_waiters(1).await.unwrap();
        in_flight.commit().await.unwrap();
    });
    assert!(matches!(
        cancelled,
        Err(SealError::RekeyCommitted { generation: 2 })
    ));
    assert_eq!(server.seal.keyring().unwrap().generation(), 2);
    assert_eq!(server.seal.status().await.unwrap().generation, 2);
    server.seal.seal().await;
    assert!(!server.unseal_with(&new_shares[1..]).await.unwrap().sealed);
    server.destroy().await.unwrap();
}

#[tokio::test]
async fn cancel_after_an_unconfirmed_commit_aborts_keeps_the_old_shares() {
    let (server, old_shares) = Server::initialized().await.unwrap();
    server.unseal_with(&old_shares[..3]).await.unwrap();
    let (nonce, new_shares) = server.authorize_rekey(&old_shares[..3]).await.unwrap();
    let in_flight = server.rekey_in_flight(&new_shares[..2]).await.unwrap();

    let (cancelled, ()) = tokio::join!(server.seal.rekey_cancel(&nonce), async {
        server.db.wait_for_lock_waiters(1).await.unwrap();
        in_flight.rollback().await.unwrap();
    });
    assert_eq!(cancelled.unwrap().phase, RekeyPhase::Cancelled);
    server.seal.seal().await;
    let status = server.unseal_with(&old_shares[2..]).await.unwrap();
    assert_eq!((status.sealed, status.generation), (false, 1));
    server.destroy().await.unwrap();
}

/// Still unresolved when the timeout hits: the honest answer is "unknown",
/// and the pending key must be kept.
#[tokio::test]
async fn unresolved_commit_is_reported_unknown_and_keeps_the_attempt() {
    let server = Server::with_commit_check_timeout(Duration::from_millis(200))
        .await
        .unwrap();
    let (server, old_shares) = Server::init(server).await.unwrap();
    server.unseal_with(&old_shares[..3]).await.unwrap();
    let (nonce, new_shares) = server.authorize_rekey(&old_shares[..3]).await.unwrap();
    let in_flight = server.rekey_in_flight(&new_shares[..2]).await.unwrap();

    assert!(matches!(
        server.seal.rekey_cancel(&nonce).await,
        Err(SealError::RekeyOutcomeUnknown)
    ));
    in_flight.rollback().await.unwrap();
    // Resolved now (aborted): the kept attempt can be cancelled.
    let cancelled = server.seal.rekey_cancel(&nonce).await.unwrap();
    assert_eq!(cancelled.phase, RekeyPhase::Cancelled);
    server.destroy().await.unwrap();
}

/// The person sealing must hear that only the new shares work now, from the
/// response itself, and the status backs it up with the new generation.
#[tokio::test]
async fn seal_reports_a_rekey_that_was_already_stored() {
    let (server, old_shares) = Server::initialized().await.unwrap();
    server.unseal_with(&old_shares[..3]).await.unwrap();
    let (_, new_shares) = server.authorize_rekey(&old_shares[..3]).await.unwrap();
    server
        .commit_behind_the_seal(&new_shares[..2])
        .await
        .unwrap();

    let outcome = server.seal.seal().await;
    assert_eq!(outcome.pending_rekey, PendingRekey::Committed);
    assert_eq!(
        outcome.status.map(|s| (s.sealed, s.generation)),
        Some((true, 2))
    );
    assert!(!server.unseal_with(&new_shares[1..]).await.unwrap().sealed);
    server.destroy().await.unwrap();
}

/// Sealing must not wait on an unresolved rekey commit: the keyring is gone
/// before the check starts. Here the check is still blocked when we look.
#[tokio::test]
async fn seal_takes_effect_before_resolving_a_pending_rekey() {
    let (server, old_shares) = Server::initialized().await.unwrap();
    server.unseal_with(&old_shares[..3]).await.unwrap();
    let (_, new_shares) = server.authorize_rekey(&old_shares[..3]).await.unwrap();
    let in_flight = server.rekey_in_flight(&new_shares[..2]).await.unwrap();

    let (outcome, ()) = tokio::join!(server.seal.seal(), async {
        server.db.wait_for_lock_waiters(1).await.unwrap();
        assert!(matches!(server.seal.keyring(), Err(SealError::Sealed)));
        in_flight.rollback().await.unwrap();
    });
    assert_eq!(outcome.pending_rekey, PendingRekey::Discarded);
    assert!(!server.unseal_with(&old_shares[..3]).await.unwrap().sealed);
    server.destroy().await.unwrap();
}

/// While seal resolves a pending rekey, no unseal may run. Otherwise one
/// with the old shares could slip in (its plain read doesn't wait for the
/// unfinished commit), unseal with the old root key just as the new one
/// lands, and make the seal response report "unsealed".
#[tokio::test]
async fn unseal_waits_while_seal_resolves_a_pending_rekey() {
    let (server, old_shares) = Server::initialized().await.unwrap();
    server.unseal_with(&old_shares[..3]).await.unwrap();
    let (_, new_shares) = server.authorize_rekey(&old_shares[..3]).await.unwrap();
    let in_flight = server.rekey_in_flight(&new_shares[..2]).await.unwrap();

    let (outcome, unsealed, ()) = tokio::join!(
        server.seal.seal(),
        async {
            // Starts once seal's check is blocked on the unfinished commit.
            server.db.wait_for_lock_waiters(1).await.unwrap();
            server.unseal_with(&old_shares[..3]).await
        },
        async {
            server.db.wait_for_lock_waiters(1).await.unwrap();
            // Time for the unseal to get through, if nothing holds it back.
            tokio::time::sleep(Duration::from_millis(200)).await;
            in_flight.commit().await.unwrap();
        },
    );
    assert_eq!(outcome.pending_rekey, PendingRekey::Committed);
    assert_eq!(
        outcome.status.map(|s| (s.sealed, s.generation)),
        Some((true, 2))
    );
    assert!(matches!(
        unsealed,
        Err(SealError::InvalidShare(CryptoError::StaleShare {
            expected: 2,
            found: 1
        }))
    ));
    assert!(matches!(server.seal.keyring(), Err(SealError::Sealed)));
    assert!(!server.unseal_with(&new_shares[1..]).await.unwrap().sealed);
    server.destroy().await.unwrap();
}

#[tokio::test]
async fn seal_reports_an_unresolved_rekey_as_unknown() {
    let server = Server::with_commit_check_timeout(Duration::from_millis(200))
        .await
        .unwrap();
    let (server, old_shares) = Server::init(server).await.unwrap();
    server.unseal_with(&old_shares[..3]).await.unwrap();
    let (_, new_shares) = server.authorize_rekey(&old_shares[..3]).await.unwrap();
    let in_flight = server.rekey_in_flight(&new_shares[..2]).await.unwrap();

    let outcome = server.seal.seal().await;
    assert_eq!(outcome.pending_rekey, PendingRekey::Unknown);
    assert!(matches!(server.seal.keyring(), Err(SealError::Sealed)));
    in_flight.rollback().await.unwrap();
    server.destroy().await.unwrap();
}

#[tokio::test]
async fn seal_discards_a_rekey_still_authorizing() {
    let (server, shares) = Server::initialized().await.unwrap();
    server.unseal_with(&shares[..3]).await.unwrap();
    server
        .seal
        .rekey_start(params(3, 2).unwrap())
        .await
        .unwrap();
    assert_eq!(
        server.seal.seal().await.pending_rekey,
        PendingRekey::Discarded
    );
    server.destroy().await.unwrap();
}

/// The lockdown must not wait for an admin call stuck on the database, and
/// the stuck call must not unseal the server again when it finishes.
#[tokio::test]
async fn seal_is_immediate_while_rotate_is_stuck() {
    let (server, shares) = Server::initialized().await.unwrap();
    server.unseal_with(&shares[..3]).await.unwrap();
    let blocker = server.block_seal_config().await.unwrap();

    let app = app().unwrap();
    let (rotated, outcome, ()) = tokio::join!(
        server.seal.rotate(&app),
        async {
            server.db.wait_for_lock_waiters(1).await.unwrap();
            server.seal.seal().await
        },
        async {
            server.db.wait_for_lock_waiters(1).await.unwrap();
            // Sealed while rotate still holds the admin lock, stuck.
            server.wait_until_sealed().await.unwrap();
            // ...and rotate is in fact still stuck on the database.
            server.db.wait_for_lock_waiters(1).await.unwrap();
            blocker.rollback().await.unwrap();
        },
    );
    // The KEK was stored, but its keyring was not published.
    assert_eq!(rotated.unwrap(), 2);
    assert_eq!(outcome.status.map(|s| s.sealed), Some(true));
    assert!(matches!(server.seal.keyring(), Err(SealError::Sealed)));

    server.unseal_with(&shares[..3]).await.unwrap();
    assert_eq!(active(&server.seal.keyring().unwrap()).unwrap(), 2);
    server.destroy().await.unwrap();
}

/// Same for a rekey commit: it's stored, so verify reports it complete, but
/// the seal wins and the new shares are what unseal next.
#[tokio::test]
async fn seal_is_immediate_while_rekey_verify_is_stuck() {
    let (server, old_shares) = Server::initialized().await.unwrap();
    server.unseal_with(&old_shares[..3]).await.unwrap();
    let (nonce, new_shares) = server.authorize_rekey(&old_shares[..3]).await.unwrap();
    server
        .seal
        .rekey_verify(&nonce, &new_shares[0])
        .await
        .unwrap();
    let blocker = server.block_seal_config().await.unwrap();

    let (verified, outcome, ()) = tokio::join!(
        server.seal.rekey_verify(&nonce, &new_shares[1]),
        async {
            server.db.wait_for_lock_waiters(1).await.unwrap();
            server.seal.seal().await
        },
        async {
            server.db.wait_for_lock_waiters(1).await.unwrap();
            server.wait_until_sealed().await.unwrap();
            blocker.rollback().await.unwrap();
        },
    );
    assert_eq!(verified.unwrap().phase, RekeyPhase::Complete);
    // Verify took the attempt before the seal got the admin lock.
    assert_eq!(outcome.pending_rekey, PendingRekey::None);
    assert_eq!(
        outcome.status.map(|s| (s.sealed, s.generation)),
        Some((true, 2))
    );
    assert!(matches!(server.seal.keyring(), Err(SealError::Sealed)));
    assert!(!server.unseal_with(&new_shares[1..]).await.unwrap().sealed);
    server.destroy().await.unwrap();
}

/// Code and message of a failed call: the code alone is ambiguous (several
/// errors share `FAILED_PRECONDITION` or `INVALID_ARGUMENT`), and the message
/// is part of what the client sees.
fn rejection<T>(result: Result<T, tonic::Status>) -> Option<(Code, String)> {
    result.err().map(|s| (s.code(), s.message().to_owned()))
}

fn rejected(code: Code, message: &str) -> Option<(Code, String)> {
    Some((code, message.to_owned()))
}

/// Status codes and messages as a client sees them, over a real gRPC connection.
#[tokio::test]
async fn grpc_maps_errors_to_status_codes() {
    let server = Server::new().await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let Server { db, seal, .. } = server;
    let data = TestDatabase::new(
        "DATA_DATABASE_URL",
        "ferritor_server_test",
        &ferritor_datastore::MIGRATOR,
    )
    .await
    .unwrap();
    let seal = Arc::new(seal);
    let rewrap = Arc::new(Rewrap::new(
        Arc::clone(&seal),
        Datastore::new(data.pool().clone()),
    ));
    // Deletions purgeable at once.
    let purge = Arc::new(Purge::new(
        Arc::clone(&seal),
        Datastore::new(data.pool().clone()),
        Duration::ZERO,
    ));
    let destroy = Arc::new(Destroy::new(
        Arc::clone(&seal),
        Datastore::new(data.pool().clone()),
    ));
    let namespaces = Arc::new(Namespaces::new(
        Arc::clone(&seal),
        Datastore::new(data.pool().clone()),
    ));
    let serving = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(SystemServiceServer::new(System::new(
                seal,
                rewrap,
                purge,
                destroy,
                namespaces,
                Datastore::new(data.pool().clone()),
                Arc::new(Gate::new(
                    Arc::new(ferritor_server::authz::AllowAll),
                    AuditLog::new(std::io::sink(), Duration::from_secs(5)).unwrap(),
                )),
            )))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let mut client = SystemServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    let init = pb::InitRequest {
        shares: 5,
        threshold: 3,
    };
    let too_many = pb::InitRequest {
        shares: 300,
        threshold: 3,
    };
    let swapped = pb::InitRequest {
        shares: 3,
        threshold: 5,
    };
    let garbage = pb::UnsealRequest {
        share: b"garbage".to_vec(),
        reset: false,
        recommit: false,
        ..Default::default()
    };

    assert_eq!(
        rejection(client.unseal(pb::UnsealRequest::default()).await),
        rejected(Code::FailedPrecondition, "the seal is not initialized")
    );
    assert_eq!(
        rejection(client.init(too_many).await),
        rejected(Code::InvalidArgument, "shares must be at most 255")
    );
    assert_eq!(
        rejection(client.init(swapped).await),
        rejected(
            Code::InvalidArgument,
            "threshold must be between 2 and the share count, got 5 of 3"
        )
    );
    let shares = client.init(init).await.unwrap().into_inner().shares;
    assert_eq!(shares.len(), 5);
    assert_eq!(
        rejection(client.init(init).await),
        rejected(Code::AlreadyExists, "the seal is already initialized")
    );
    assert_eq!(
        rejection(
            client
                .rotate_kek(pb::RotateKekRequest {
                    namespace: "app".to_owned()
                })
                .await
        ),
        rejected(Code::FailedPrecondition, "the server is sealed")
    );
    assert_eq!(
        rejection(client.unseal(garbage).await),
        rejected(Code::InvalidArgument, "invalid share: malformed share")
    );

    let mut status = None;
    for share in &shares[..3] {
        status = client
            .unseal(pb::UnsealRequest {
                share: share.clone(),
                reset: false,
                recommit: false,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .status;
    }
    assert_eq!(status.map(|s| s.sealed), Some(false));
    // No namespace yet: nothing to rotate (nor to store under).
    let rotate_app = || pb::RotateKekRequest {
        namespace: "app".to_owned(),
    };
    let refused = client.rotate_kek(rotate_app()).await.unwrap_err();
    assert_eq!(
        (refused.code(), grpc::reason_of(&refused).as_deref()),
        (Code::FailedPrecondition, Some(reason::NO_NAMESPACE))
    );
    let created = client
        .create_namespace(pb::CreateNamespaceRequest {
            name: "app".to_owned(),
            labels: [("team".to_owned(), "core".to_owned())].into(),
            past_lost_keks: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.kek_version, 1);
    assert_eq!(
        rejection(
            client
                .create_namespace(pb::CreateNamespaceRequest {
                    name: "app".to_owned(),
                    labels: Default::default(),
                    past_lost_keks: false,
                })
                .await
        ),
        rejected(Code::AlreadyExists, "namespace `app` already exists")
    );
    assert_eq!(
        rejection(
            client
                .create_namespace(pb::CreateNamespaceRequest {
                    name: "a/b".to_owned(),
                    labels: Default::default(),
                    past_lost_keks: false,
                })
                .await
        )
        .map(|(code, _)| code),
        Some(Code::InvalidArgument)
    );
    let version = client
        .rotate_kek(rotate_app())
        .await
        .unwrap()
        .into_inner()
        .version;
    assert_eq!(version, 2);

    // While a rekey is verifying, status shows it, with the new generation,
    // but never share material.
    let nonce = client
        .rekey_start(pb::RekeyStartRequest {
            shares: 3,
            threshold: 2,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .progress
        .unwrap()
        .nonce;
    for share in &shares[..3] {
        client
            .rekey_submit(pb::RekeySubmitRequest {
                nonce: nonce.clone(),
                share: share.clone(),
            })
            .await
            .unwrap();
    }
    let rekey = client
        .status(pb::StatusRequest {})
        .await
        .unwrap()
        .into_inner()
        .status
        .and_then(|s| s.rekey)
        .unwrap();
    assert_eq!(rekey.phase(), pb::RekeyPhase::Verifying);
    assert_eq!(rekey.generation, 2);
    assert!(rekey.new_shares.is_empty());

    serving.abort();
    db.destroy().await.unwrap();
    data.destroy().await.unwrap();
}

/// With the keys database stalled, seal still returns at once (sealed, the
/// status left out), and admin calls fail within the bound instead of
/// hanging. The bound covers the setup's calls too (init, the unseals),
/// so it leaves them room on a busy machine: at 200 ms, `init` alone timed
/// out in CI.
#[tokio::test]
async fn a_stalled_keys_database_never_blocks_seal_and_bounds_unseal() {
    let db = TestDatabase::new("KEYS_DATABASE_URL", "ferritor_server_test", &MIGRATOR)
        .await
        .unwrap();
    let seal = Seal::new(Keystore::new(db.pool().clone()).with_timeout(Duration::from_secs(1)))
        .with_commit_check_timeout(Duration::from_millis(100));
    let shares: Vec<Vec<u8>> = seal
        .init(params(5, 3).unwrap())
        .await
        .unwrap()
        .iter()
        .map(|s| s.to_bytes().to_vec())
        .collect();
    for share in &shares[..3] {
        seal.unseal(share, false).await.unwrap();
    }

    let mut stall = db.pool().begin().await.unwrap();
    sqlx::query("LOCK TABLE seal_config IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *stall)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let outcome = seal.seal().await;
    // The seal config's read runs out its bound; nothing waits for the lock.
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(outcome.status, None);
    assert!(seal.is_sealed());
    assert!(matches!(
        seal.unseal(&shares[0], false).await,
        Err(SealError::KeysTimeout)
    ));
    assert_eq!(
        tonic::Status::from(SealError::KeysTimeout).code(),
        Code::Unavailable
    );

    stall.rollback().await.unwrap();
    for share in &shares[..3] {
        seal.unseal(share, false).await.unwrap();
    }
    assert!(!seal.is_sealed());
    db.destroy().await.unwrap();
}

/// A server picks up another server's rotation by refreshing with the root
/// key it holds, no shares needed, but can't follow a rekey (the root key
/// itself changed); a sealed server has nothing to refresh. Asked for a
/// version it already has, a refresh returns without reloading.
#[tokio::test]
async fn a_refresh_follows_a_rotation_elsewhere_but_not_a_rekey() {
    let (server, shares) = Server::initialized().await.unwrap();
    server.unseal_with(&shares[..3]).await.unwrap();
    let other = Seal::new(Keystore::new(server.db.pool().clone()));
    for share in &shares[..3] {
        other.unseal(share, false).await.unwrap();
    }

    let app_at = |version| vec![(app().unwrap(), version)];
    let versions = || server.seal.keyring().unwrap().versions(&app().unwrap());
    let nothing_new = server.seal.refresh(None).await.unwrap();
    assert_eq!(
        (nothing_new.active, nothing_new.changed),
        (app_at(1), false)
    );
    assert_eq!(versions(), [1]);
    assert_eq!(other.rotate(&app().unwrap()).await.unwrap(), 2);
    let rotated = server.seal.refresh(None).await.unwrap();
    assert_eq!((rotated.active, rotated.changed), (app_at(2), true));
    assert_eq!(versions(), [1, 2]);
    assert_eq!(server.seal.active_kek_version(&app().unwrap()), Some(2));

    // Version 3 isn't picked up by a refresh wanting 2, which is there.
    assert_eq!(other.rotate(&app().unwrap()).await.unwrap(), 3);
    let had_it = server
        .seal
        .refresh(Some((&app().unwrap(), 2)))
        .await
        .unwrap();
    assert_eq!(
        (had_it.active, had_it.changed, had_it.loaded),
        (app_at(2), false, false)
    );
    assert_eq!(versions(), [1, 2]);
    let wanted = server
        .seal
        .refresh(Some((&app().unwrap(), 3)))
        .await
        .unwrap();
    assert_eq!(
        (wanted.active, wanted.changed, wanted.loaded),
        (app_at(3), true, true)
    );
    assert_eq!(versions(), [1, 2, 3]);

    let (_, new_shares) = server.authorize_rekey(&shares[..3]).await.unwrap();
    server
        .commit_behind_the_seal(&new_shares[..2])
        .await
        .unwrap();
    assert!(matches!(
        server.seal.refresh(None).await,
        Err(SealError::RekeyedElsewhere {
            running: 1,
            stored: 2
        })
    ));
    // Still running on what it had.
    assert_eq!(server.seal.active_kek_version(&app().unwrap()), Some(3));

    server.seal.seal().await;
    assert!(matches!(
        server.seal.refresh(None).await,
        Err(SealError::Sealed)
    ));
    server.destroy().await.unwrap();
}

/// The active issuing key's version in `seal`'s keyring, if it holds one.
fn issuing(seal: &Seal) -> TestResult<Option<u32>> {
    Ok(seal
        .keyring()?
        .issuing()
        .active
        .as_ref()
        .map(|ca| ca.version()))
}

/// Issues a certificate with `seal`'s active issuing key, for a fresh key.
fn issue(seal: &Seal) -> TestResult<Vec<u8>> {
    let keyring = seal.keyring()?;
    let ca = keyring.issuing().active.as_ref().ok_or("no issuing key")?;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())?
        .serialize_request(&key)?
        .der()
        .to_vec();
    let now = time::OffsetDateTime::now_utc();
    let identity = SecretPath::parse("k8s/billing/api")?;
    Ok(ca
        .issue(&csr, &identity, now, now + time::Duration::hours(1))?
        .certificate)
}

/// The issuing CA: created once, while unsealed only; rotated, the old key
/// retired (or revoked) with its certificate kept; the keyring holds the
/// active one, which signs; a seal drops it, an unseal loads it again.
#[tokio::test]
async fn the_issuing_ca_lives_with_the_keyring() {
    let (server, shares) = Server::initialized().await.unwrap();
    assert!(matches!(
        server.seal.identity_init().await,
        Err(SealError::Sealed)
    ));
    server.unseal_with(&shares[..3]).await.unwrap();
    assert_eq!(issuing(&server.seal).unwrap(), None);
    assert!(matches!(
        server.seal.identity_rotate(false).await,
        Err(SealError::NoIssuingKey)
    ));

    let first = server.seal.identity_init().await.unwrap();
    assert_eq!(first.version, 1);
    assert_eq!(issuing(&server.seal).unwrap(), Some(1));
    issue(&server.seal).unwrap();
    assert!(matches!(
        server.seal.identity_init().await,
        Err(SealError::IssuingKeyExists)
    ));

    assert_eq!(server.seal.identity_rotate(false).await.unwrap().version, 2);
    assert_eq!(server.seal.identity_rotate(true).await.unwrap().version, 3);
    assert_eq!(issuing(&server.seal).unwrap(), Some(3));
    let states: Vec<_> = server
        .seal
        .issuing_keys()
        .unwrap()
        .into_iter()
        .map(|k| (k.version, k.state.as_str()))
        .collect();
    assert_eq!(states, [(1, "revoked"), (2, "revoked"), (3, "active")]);
    // The keyring has every certificate, for trusting what each signed.
    assert_eq!(server.seal.keyring().unwrap().issuing().stored.len(), 3);

    server.seal.seal().await;
    assert!(server.seal.keyring().is_err());
    server.unseal_with(&shares[..3]).await.unwrap();
    assert_eq!(issuing(&server.seal).unwrap(), Some(3));
    issue(&server.seal).unwrap();
    server.db.destroy().await.unwrap();
}

/// Another server's rotation reaches this one at its next refresh, like a
/// KEK rotation.
#[tokio::test]
async fn a_refresh_picks_up_another_servers_issuing_key() {
    let (server, shares) = Server::initialized().await.unwrap();
    server.unseal_with(&shares[..3]).await.unwrap();
    let other = Seal::new(Keystore::new(server.db.pool().clone()));
    for share in &shares[..3] {
        other.unseal(share, false).await.unwrap();
    }
    other.identity_init().await.unwrap();
    assert_eq!(issuing(&server.seal).unwrap(), None);
    let refreshed = server.seal.refresh(None).await.unwrap();
    assert!(refreshed.changed, "{refreshed:?}");
    assert_eq!(issuing(&server.seal).unwrap(), Some(1));
    issue(&server.seal).unwrap();
    // Nothing new: nothing published.
    assert!(!server.seal.refresh(None).await.unwrap().changed);
    server.db.destroy().await.unwrap();
}

/// A rekey re-wraps the active issuing key under the new root key: after
/// it, and after a seal and an unseal with the new shares, the key loads
/// and signs.
#[tokio::test]
async fn a_rekey_keeps_the_issuing_key() {
    let (server, shares) = Server::initialized().await.unwrap();
    server.unseal_with(&shares[..3]).await.unwrap();
    server.seal.identity_init().await.unwrap();
    let (nonce, new_shares) = server.authorize_rekey(&shares[..3]).await.unwrap();
    server.verify_rekey(&nonce, &new_shares[..2]).await.unwrap();
    assert_eq!(issuing(&server.seal).unwrap(), Some(1));
    server.seal.seal().await;
    server.unseal_with(&new_shares[..2]).await.unwrap();
    assert_eq!(issuing(&server.seal).unwrap(), Some(1));
    issue(&server.seal).unwrap();
    server.db.destroy().await.unwrap();
}

/// An issuing key that doesn't open (its wrapped key changed in the
/// database) leaves the server unsealing and working, without one: no
/// certificate is issued until it's rotated. A rekey refuses before anyone
/// hands in shares, as for the policy key.
#[tokio::test]
async fn an_unusable_issuing_key_never_stops_an_unseal() {
    let (server, shares) = Server::initialized().await.unwrap();
    server.unseal_with(&shares[..3]).await.unwrap();
    server.seal.identity_init().await.unwrap();
    sqlx::query("UPDATE issuing_keys SET wrapped_key = '\\x00' WHERE state = 'active'")
        .execute(server.db.pool())
        .await
        .unwrap();
    server.seal.seal().await;
    let status = server.unseal_with(&shares[..3]).await.unwrap();
    assert!(!status.sealed);
    assert_eq!(issuing(&server.seal).unwrap(), None);
    assert!(matches!(
        server.seal.rekey_start(params(3, 2).unwrap()).await,
        Err(SealError::IssuingKeyUnusable)
    ));
    // The way out: a rotation, with a new key.
    server.seal.identity_rotate(true).await.unwrap();
    assert_eq!(issuing(&server.seal).unwrap(), Some(2));
    server.db.destroy().await.unwrap();
}

/// A rekey with no policy or issuing key to re-wrap.
struct Nothing;

impl ferritor_keystore::RekeyRewrap for Nothing {
    fn policy_key(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn issuing_key(&self, _: u32, _: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn issuing_tag(&self, _: &ferritor_keystore::IssuingSet) -> Option<Vec<u8>> {
        None
    }
}
