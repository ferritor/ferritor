//! Authorization of `SystemService` calls, over a real gRPC connection: every
//! call asks the authorizer first, nonces are hidden from callers who may
//! not rekey, and a refused caller never waits behind admin work.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use ferritor_core::proto::v1 as pb;
use ferritor_core::proto::v1::system_service_client::SystemServiceClient;
use ferritor_core::proto::v1::system_service_server::SystemServiceServer;
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{Action, Authorizer, Caller, Denied, Target};
use ferritor_server::destroy::Destroy;
use ferritor_server::grpc::System;
use ferritor_server::namespaces::Namespaces;
use ferritor_server::purge::Purge;
use ferritor_server::rewrap::Rewrap;
use ferritor_server::seal::Seal;
use ferritor_testkit::data::insert_version;
use ferritor_testkit::{Captured, TestDatabase, TestResult};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Code;
use tonic::transport::Channel;

/// Allows everything except the actions in `deny` (changeable mid-test),
/// and records what it was asked.
#[derive(Default)]
struct Switchable {
    deny: Mutex<Vec<Action>>,
    asked: Mutex<Vec<(Action, String)>>,
}

impl Switchable {
    fn deny(&self, actions: &[Action]) {
        *self.deny.lock().unwrap_or_else(PoisonError::into_inner) = actions.to_vec();
    }

    fn forget(&self) {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    fn asked(&self) -> Vec<(Action, String)> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Authorizer for Switchable {
    fn authorize(&self, caller: &Caller, action: Action, target: Target<'_>) -> Result<(), Denied> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((action, target.to_string()));
        if self
            .deny
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&action)
        {
            return Err(Denied::new(caller, action, target));
        }
        Ok(())
    }
}

struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    authz: Arc<Switchable>,
    /// What the audit log wrote.
    audit: Captured,
    client: SystemServiceClient<Channel>,
    /// The init shares (5, threshold 3).
    shares: Vec<Vec<u8>>,
    serving: JoinHandle<()>,
}

impl Env {
    /// Initialized (5 shares, threshold 3) and unsealed, everything allowed.
    async fn unsealed() -> TestResult<Self> {
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
        let authz = Arc::new(Switchable::default());
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let audit = Captured::default();
        let gate = Arc::new(Gate::new(
            authz.clone(),
            AuditLog::new(audit.clone(), Duration::from_secs(5))?,
        ));
        let destroy = Arc::new(Destroy::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
        ));
        let namespaces = Arc::new(Namespaces::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
        ));
        let system = System::new(
            seal,
            rewrap,
            purge,
            destroy,
            namespaces,
            Datastore::new(data.pool().clone()),
            gate,
        );
        let serving = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(SystemServiceServer::new(system))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .ok();
        });
        let mut client = SystemServiceClient::connect(format!("http://{addr}")).await?;
        let shares = client
            .init(pb::InitRequest {
                shares: 5,
                threshold: 3,
            })
            .await?
            .into_inner()
            .shares;
        for share in &shares[..3] {
            client
                .unseal(pb::UnsealRequest {
                    share: share.clone(),
                    reset: false,
                    recommit: false,
                    ..Default::default()
                })
                .await?;
        }
        client
            .create_namespace(pb::CreateNamespaceRequest {
                name: "app".to_owned(),
                labels: Default::default(),
                past_lost_keks: false,
            })
            .await?;
        // Each unseal reply also asks Rekey (whether to show a nonce); tests
        // only look at their own calls.
        authz.forget();
        Ok(Self {
            keys,
            data,
            authz,
            audit,
            client,
            shares,
            serving,
        })
    }

    async fn rekey(&mut self) -> TestResult<Option<pb::RekeyProgress>> {
        let status = self.client.status(pb::StatusRequest {}).await?.into_inner();
        Ok(status.status.and_then(|s| s.rekey))
    }

    async fn destroy(self) -> TestResult<()> {
        self.serving.abort();
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

/// `(action, decision)` of every audit entry, once there are `n` (a seal's
/// entry is queued without waiting, so it may land just after the reply).
async fn audited(audit: &Captured, n: usize) -> TestResult<Vec<(String, String)>> {
    let field = |entry: &Value, name: &str| entry[name].as_str().unwrap_or_default().to_owned();
    Ok(entries(audit, "authorization", n)
        .await?
        .iter()
        .map(|entry| (field(entry, "action"), field(entry, "decision")))
        .collect())
}

/// The audit entries of one `event` kind, once there are `n` (outcome
/// entries, like a seal's authorization, are queued without waiting).
async fn entries(audit: &Captured, event: &str, n: usize) -> TestResult<Vec<Value>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let found = audit
            .lines()
            .iter()
            .map(|line| serde_json::from_str::<Value>(line))
            .filter(|entry| entry.as_ref().map_or(true, |e| e["event"] == event))
            .collect::<Result<Vec<_>, _>>()?;
        if found.len() >= n || Instant::now() > deadline {
            return Ok(found);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn rotate_app() -> pb::RotateKekRequest {
    pb::RotateKekRequest {
        namespace: "app".to_owned(),
    }
}

fn denied<T>(result: Result<T, tonic::Status>) -> Option<(Code, String)> {
    result.err().map(|s| (s.code(), s.message().to_owned()))
}

#[tokio::test]
async fn every_system_call_asks_for_its_action_on_the_server() {
    let mut env = Env::unsealed().await.unwrap();
    let c = &mut env.client;
    c.status(pb::StatusRequest {}).await.unwrap();
    c.rotate_kek(rotate_app()).await.unwrap();
    c.rewrap(pb::RewrapRequest::default()).await.unwrap();
    let nonce = c
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
    c.rekey_cancel(pb::RekeyCancelRequest { nonce })
        .await
        .unwrap();
    c.seal(pb::SealRequest {}).await.unwrap();

    let server = "the server".to_owned();
    let asked = env.authz.asked();
    let actions: Vec<Action> = asked.iter().map(|(a, _)| *a).collect();
    // Replies carrying a status also ask Rekey (whether to show the nonce)
    // and Unseal (whether to show the auto-unseal key and errors).
    assert_eq!(
        actions,
        [
            Action::Status,
            Action::Rekey,
            Action::Unseal,
            Action::Rotate,
            Action::Rewrap,
            Action::Rekey,
            Action::Rekey,
            Action::Seal,
            Action::Rekey,
            Action::Unseal,
        ]
    );
    assert!(asked.iter().all(|(_, target)| *target == server));

    // The audit log has every call (setup's too), but not the nonce checks.
    let allowed = |action: &str| (action.to_owned(), "allowed".to_owned());
    assert_eq!(
        audited(&env.audit, 11).await.unwrap(),
        [
            allowed("init"),
            allowed("unseal"),
            allowed("unseal"),
            allowed("unseal"),
            allowed("namespace"),
            allowed("status"),
            allowed("rotate"),
            allowed("rewrap"),
            allowed("rekey"),
            allowed("rekey"),
            allowed("seal"),
        ]
    );
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn a_refused_admin_call_is_audited_as_denied() {
    let mut env = Env::unsealed().await.unwrap();
    env.authz.deny(&[Action::Rotate]);
    assert_eq!(
        denied(env.client.rotate_kek(rotate_app()).await).map(|(code, _)| code),
        Some(Code::PermissionDenied)
    );
    assert_eq!(
        audited(&env.audit, 6).await.unwrap().last(),
        Some(&("rotate".to_owned(), "denied".to_owned()))
    );
    env.destroy().await.unwrap();
}

/// Every admin call that changes state also records what it did: details
/// on success (never a nonce or share), the error on failure. `status`
/// records nothing beyond its authorization.
#[tokio::test]
async fn admin_outcomes_are_audited() {
    let mut env = Env::unsealed().await.unwrap();
    let c = &mut env.client;
    c.status(pb::StatusRequest {}).await.unwrap();
    c.rotate_kek(rotate_app()).await.unwrap();
    c.rewrap(pb::RewrapRequest::default()).await.unwrap();
    let nonce = c
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
    let wrong = c
        .rekey_submit(pb::RekeySubmitRequest {
            nonce: "not-the-nonce".to_owned(),
            share: vec![1; 33],
        })
        .await;
    assert!(wrong.is_err());
    c.rekey_cancel(pb::RekeyCancelRequest {
        nonce: nonce.clone(),
    })
    .await
    .unwrap();
    let bad_params = c
        .rekey_start(pb::RekeyStartRequest {
            shares: 2,
            threshold: 3,
            ..Default::default()
        })
        .await;
    assert!(bad_params.is_err());
    c.seal(pb::SealRequest {}).await.unwrap();

    let outcomes = entries(&env.audit, "outcome", 12).await.unwrap();
    let summary: Vec<(String, String, Value)> = outcomes
        .iter()
        .map(|e| {
            let s = |name: &str| e[name].as_str().unwrap_or_default().to_owned();
            let rest = if e["result"] == "succeeded" {
                e["details"].clone()
            } else {
                e["error"].clone()
            };
            (s("operation"), s("result"), rest)
        })
        .collect();
    let ok = |op: &str, details: Value| (op.to_owned(), "succeeded".to_owned(), details);
    let failed = |op: &str, error: &str| (op.to_owned(), "failed".to_owned(), json!(error));
    assert_eq!(
        summary,
        [
            ok("init", json!({"shares": 5, "threshold": 3})),
            ok(
                "unseal",
                json!({"sealed": true, "progress": 1, "threshold": 3, "generation": 1})
            ),
            ok(
                "unseal",
                json!({"sealed": true, "progress": 2, "threshold": 3, "generation": 1})
            ),
            ok(
                "unseal",
                json!({"sealed": false, "progress": 0, "threshold": 3, "generation": 1})
            ),
            ok(
                "create_namespace",
                json!({"namespace": "app", "kek_version": 1, "labels": []})
            ),
            ok("rotate_kek", json!({"namespace": "app", "kek_version": 2})),
            ok(
                "rewrap",
                json!({"namespace": null, "rewrapped": 0, "failed": 0, "done": true,
                       "retired": [{"namespace": "app", "version": 1}], "released": []})
            ),
            ok(
                "rekey_start",
                json!({"phase": "authorizing", "progress": 0, "required": 3,
                       "shares": 3, "threshold": 2, "seal": "kept"})
            ),
            failed("rekey_submit", "nonce does not match the rekey in progress"),
            ok(
                "rekey_cancel",
                json!({"phase": "cancelled", "progress": 0, "required": 3})
            ),
            failed(
                "rekey_start",
                "threshold must be between 2 and the share count, got 3 of 2"
            ),
            ok("seal", json!({"pending_rekey": "none", "hold_set": true})),
        ]
    );
    // Every outcome names its caller and action; none carries the nonce.
    assert!(
        outcomes
            .iter()
            .all(|e| e.get("caller").is_some() && e["action"].is_string())
    );
    assert!(env.audit.lines().iter().all(|line| !line.contains(&nonce)));
    env.destroy().await.unwrap();
}

/// The one thing the audit log must never hold: share material. A full
/// rekey over gRPC (the old shares in, the new shares out and back in for
/// verification), and no share appears anywhere in the log, in any of the
/// forms it could leak in: hex (as the CLI shows them), base64, or a JSON
/// byte array. Nor does the nonce.
#[tokio::test]
async fn a_full_rekey_leaves_no_share_or_nonce_in_the_log() {
    let mut env = Env::unsealed().await.unwrap();
    let old = env.shares.clone();
    let started = env
        .client
        .rekey_start(pb::RekeyStartRequest {
            shares: 3,
            threshold: 2,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .progress
        .unwrap();
    let nonce = started.nonce;
    let mut new = Vec::new();
    for share in &old[..3] {
        let progress = env
            .client
            .rekey_submit(pb::RekeySubmitRequest {
                nonce: nonce.clone(),
                share: share.clone(),
            })
            .await
            .unwrap()
            .into_inner()
            .progress
            .unwrap();
        new = progress.new_shares;
    }
    assert_eq!(new.len(), 3);
    for share in &new[..2] {
        env.client
            .rekey_verify(pb::RekeyVerifyRequest {
                nonce: nonce.clone(),
                share: share.clone(),
            })
            .await
            .unwrap();
    }
    let outcomes = entries(&env.audit, "outcome", 4 + 1 + 1 + 3 + 2)
        .await
        .unwrap();
    let last = outcomes.last().unwrap();
    assert_eq!(
        (
            &last["operation"],
            &last["details"]["phase"],
            &last["details"]["generation"]
        ),
        (&json!("rekey_verify"), &json!("complete"), &json!(2))
    );

    let log = env.audit.lines().concat();
    assert!(!log.contains(&nonce));
    for share in old.iter().chain(&new) {
        let hex: String = share.iter().map(|b| format!("{b:02x}")).collect();
        let base64 = STANDARD.encode(share);
        let array = serde_json::to_string(share).unwrap();
        for form in [hex.as_str(), base64.as_str(), &array[1..array.len() - 1]] {
            assert!(!log.contains(form), "a share leaked as {form}");
        }
    }
    env.destroy().await.unwrap();
}

/// Purge asks for its own action on the server, and records what it did.
#[tokio::test]
async fn purge_is_authorized_and_audited() {
    let mut env = Env::unsealed().await.unwrap();
    let reply = env
        .client
        .purge(pb::PurgeRequest { max_rows: 0 })
        .await
        .unwrap()
        .into_inner();
    assert_eq!((reply.purged, reply.done), (0, true));
    assert_eq!(
        env.authz.asked(),
        [(Action::Purge, "the server".to_owned())]
    );
    let outcomes = entries(&env.audit, "outcome", 6).await.unwrap();
    let last = outcomes.last().unwrap();
    assert_eq!(
        (&last["operation"], &last["result"], &last["details"]),
        (
            &json!("purge"),
            &json!("succeeded"),
            &json!({"purged": 0, "done": true, "retention_secs": 0})
        )
    );

    env.authz.deny(&[Action::Purge]);
    let refused = env.client.purge(pb::PurgeRequest { max_rows: 0 }).await;
    assert_eq!(
        denied(refused).map(|(code, _)| code),
        Some(Code::PermissionDenied)
    );
    env.destroy().await.unwrap();
}

/// DestroyKek asks for its own action on the server, and records what it
/// did, a refusal included: here the active KEK, which isn't retired
/// (FAILED_PRECONDITION with reason NOT_RETIRED and the state).
#[tokio::test]
async fn destroy_kek_is_authorized_and_audited() {
    let mut env = Env::unsealed().await.unwrap();
    let refused = env
        .client
        .destroy_kek(pb::DestroyKekRequest {
            namespace: "app".to_owned(),
            version: 1,
        })
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::FailedPrecondition);
    assert_eq!(
        ferritor_server::grpc::reason_of(&refused).as_deref(),
        Some(ferritor_core::messages::reason::NOT_RETIRED)
    );
    assert_eq!(
        tonic_types::StatusExt::get_error_details(&refused)
            .error_info()
            .unwrap()
            .metadata["state"],
        "active"
    );
    assert_eq!(
        env.authz.asked(),
        [(Action::DestroyKek, "the server".to_owned())]
    );
    let outcomes = entries(&env.audit, "outcome", 6).await.unwrap();
    let last = outcomes.last().unwrap();
    assert_eq!(
        (&last["operation"], &last["result"], &last["details"]),
        (
            &json!("destroy_kek"),
            &json!("failed"),
            &json!({"namespace": "app", "version": 1})
        )
    );

    env.authz.deny(&[Action::DestroyKek]);
    let refused = env
        .client
        .destroy_kek(pb::DestroyKekRequest {
            namespace: "app".to_owned(),
            version: 1,
        })
        .await;
    assert_eq!(
        denied(refused).map(|(code, _)| code),
        Some(Code::PermissionDenied)
    );
    env.destroy().await.unwrap();
}

/// Every unseal checks the data database's rows against the keyring and
/// audits KEK versions the keys database doesn't have (here: a row as a
/// keys-database backup older than the data database's would leave it).
/// Nothing is audited when everything matches, as at the first unseal.
#[tokio::test]
async fn an_unseal_reports_rows_whose_kek_is_missing() {
    let mut env = Env::unsealed().await.unwrap();
    // The first unseal's check (in the background) found nothing.
    assert!(
        entries(&env.audit, "kek_check", 1)
            .await
            .unwrap()
            .is_empty()
    );
    insert_version(
        &mut env.data.pool().acquire().await.unwrap(),
        "app/db",
        1,
        9,
    )
    .await
    .unwrap();
    env.client.seal(pb::SealRequest {}).await.unwrap();
    for share in &env.shares[..3] {
        env.client
            .unseal(pb::UnsealRequest {
                share: share.clone(),
                reset: false,
                recommit: false,
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let found = entries(&env.audit, "kek_check", 1).await.unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        (&found[0]["missing"], &found[0]["destroyed"]),
        (&json!([{"namespace": "app", "version": 9}]), &json!([]))
    );
    env.destroy().await.unwrap();
}

/// A rotation while rows use a KEK version the keys database doesn't have
/// (restored from an older backup) would reuse that version for another
/// key: refused with FAILED_PRECONDITION and reason KEYS_DATABASE_MISMATCH,
/// recorded as the call's outcome, and nothing rotated.
#[tokio::test]
async fn a_rotation_is_refused_while_the_keys_database_is_behind() {
    let mut env = Env::unsealed().await.unwrap();
    insert_version(
        &mut env.data.pool().acquire().await.unwrap(),
        "app/db",
        1,
        2,
    )
    .await
    .unwrap();
    let refused = env.client.rotate_kek(rotate_app()).await.unwrap_err();
    assert_eq!(refused.code(), Code::FailedPrecondition);
    assert_eq!(
        ferritor_server::grpc::reason_of(&refused).as_deref(),
        Some(ferritor_core::messages::reason::KEYS_DATABASE_MISMATCH)
    );
    assert!(
        refused
            .message()
            .contains("Restore a newer keys-database backup"),
        "{}",
        refused.message()
    );
    // Init, three unseals and the namespace, then this refusal (queued,
    // not waited for).
    let outcomes = entries(&env.audit, "outcome", 6).await.unwrap();
    assert_eq!(outcomes.len(), 6);
    let last = outcomes.last().unwrap();
    assert_eq!(
        (&last["operation"], &last["result"]),
        (&json!("rotate_kek"), &json!("failed"))
    );
    let app = env
        .client
        .get_namespace(pb::GetNamespaceRequest {
            name: "app".to_owned(),
        })
        .await
        .unwrap()
        .into_inner()
        .namespace
        .unwrap();
    assert_eq!(app.keks.len(), 1);
    env.destroy().await.unwrap();
}

/// Cancel needs nothing but the nonce, so a caller who may not rekey must
/// see neither the nonce (in any reply carrying a status) nor be able to
/// cancel. Phase and progress stay visible.
#[tokio::test]
async fn without_rekey_the_nonce_is_hidden_and_cancel_refused() {
    let mut env = Env::unsealed().await.unwrap();
    let nonce = env
        .client
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
    assert_eq!(env.rekey().await.unwrap().unwrap().nonce, nonce);

    env.authz.deny(&[Action::Rekey]);
    let hidden = env.rekey().await.unwrap().unwrap();
    assert_eq!(hidden.nonce, "");
    assert_eq!(hidden.phase(), pb::RekeyPhase::Authorizing);
    assert_eq!((hidden.progress, hidden.required), (0, 3));
    // Unseal's reply (a no-op while unsealed) carries a status too.
    let via_unseal = env
        .client
        .unseal(pb::UnsealRequest::default())
        .await
        .unwrap()
        .into_inner()
        .status
        .and_then(|s| s.rekey)
        .unwrap();
    assert_eq!(via_unseal.nonce, "");

    assert_eq!(
        denied(
            env.client
                .rekey_cancel(pb::RekeyCancelRequest {
                    nonce: nonce.clone()
                })
                .await
        ),
        Some((
            Code::PermissionDenied,
            "permission denied: unauthenticated caller may not rekey the server".to_owned()
        ))
    );
    // Still running.
    env.authz.deny(&[]);
    assert_eq!(env.rekey().await.unwrap().unwrap().nonce, nonce);
    env.destroy().await.unwrap();
}

/// Seal can be refused now; a refused seal must leave everything as it was.
#[tokio::test]
async fn a_refused_seal_leaves_the_server_unsealed() {
    let mut env = Env::unsealed().await.unwrap();
    env.authz.deny(&[Action::Seal]);
    assert_eq!(
        denied(env.client.seal(pb::SealRequest {}).await),
        Some((
            Code::PermissionDenied,
            "permission denied: unauthenticated caller may not seal the server".to_owned()
        ))
    );
    let status = env
        .client
        .status(pb::StatusRequest {})
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert!(!status.sealed);
    env.destroy().await.unwrap();
}

/// Authorization comes before the admin lock: with an admin call stuck on
/// the database (holding the lock), a refused caller is told so at once
/// instead of queueing behind it.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_caller_never_waits_behind_admin_work() {
    let env = Env::unsealed().await.unwrap();
    let mut blocker = env.keys.pool().begin().await.unwrap();
    sqlx::query("SELECT 1 FROM seal_config FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let mut stuck_client = env.client.clone();
    let stuck = tokio::spawn(async move { stuck_client.rotate_kek(rotate_app()).await });
    env.keys.wait_for_lock_waiters(1).await.unwrap();

    env.authz.deny(&[Action::Status]);
    let started = Instant::now();
    let refused = env.client.clone().status(pb::StatusRequest {}).await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        denied(refused).map(|(code, _)| code),
        Some(Code::PermissionDenied)
    );

    blocker.rollback().await.unwrap();
    stuck.await.unwrap().unwrap();
    env.destroy().await.unwrap();
}

/// Every namespace call asks for the namespace action; deleting one also
/// asks for destroy_kek (it destroys the namespace's KEKs, crypto-shredding
/// every backup of its rows), and without it nothing is deleted.
#[tokio::test]
async fn namespace_calls_are_authorized_and_delete_needs_destroy_kek() {
    let mut env = Env::unsealed().await.unwrap();
    let name = |name: &str| name.to_owned();
    let c = &mut env.client;
    c.create_namespace(pb::CreateNamespaceRequest {
        name: name("billing"),
        labels: [(name("team"), name("payments"))].into(),
        past_lost_keks: false,
    })
    .await
    .unwrap();
    let listed = c
        .list_namespaces(pb::ListNamespacesRequest {})
        .await
        .unwrap()
        .into_inner()
        .namespaces;
    assert_eq!(
        listed.iter().map(|ns| ns.name.as_str()).collect::<Vec<_>>(),
        ["app", "billing"]
    );
    let labels = c
        .update_namespace_labels(pb::UpdateNamespaceLabelsRequest {
            name: name("billing"),
            set: [(name("tier"), name("1"))].into(),
            remove: vec![name("team")],
        })
        .await
        .unwrap()
        .into_inner()
        .labels;
    assert_eq!(labels, [(name("tier"), name("1"))].into());
    let billing = c
        .get_namespace(pb::GetNamespaceRequest {
            name: name("billing"),
        })
        .await
        .unwrap()
        .into_inner()
        .namespace
        .unwrap();
    assert_eq!(
        (billing.deleted, billing.keks.len(), billing.kek_floor),
        (false, 1, 1)
    );
    assert!(
        env.authz
            .asked()
            .iter()
            .all(|(action, _)| *action == Action::Namespace)
    );

    env.authz.forget();
    env.authz.deny(&[Action::DestroyKek]);
    let delete = || pb::DeleteNamespaceRequest {
        name: name("billing"),
    };
    let refused = env.client.delete_namespace(delete()).await;
    assert_eq!(
        denied(refused).map(|(code, _)| code),
        Some(Code::PermissionDenied)
    );
    assert_eq!(
        env.authz
            .asked()
            .iter()
            .map(|(action, _)| *action)
            .collect::<Vec<_>>(),
        [Action::Namespace, Action::DestroyKek]
    );
    let still = env
        .client
        .get_namespace(pb::GetNamespaceRequest {
            name: name("billing"),
        })
        .await
        .unwrap()
        .into_inner()
        .namespace
        .unwrap();
    assert!(!still.deleted);

    env.authz.deny(&[]);
    let done = env
        .client
        .delete_namespace(delete())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (done.deleted, done.destroyed, done.kek_floor),
        (true, vec![1], 2)
    );

    env.authz.deny(&[Action::Namespace]);
    assert_eq!(
        denied(
            env.client
                .list_namespaces(pb::ListNamespacesRequest {})
                .await
        )
        .map(|(code, _)| code),
        Some(Code::PermissionDenied)
    );
    env.destroy().await.unwrap();
}

/// Status gives totals only: how many namespaces, how many vanished KEKs.
/// Namespace names are behind the namespace action.
#[tokio::test]
async fn status_counts_namespaces_without_naming_them() {
    let mut env = Env::unsealed().await.unwrap();
    env.client
        .create_namespace(pb::CreateNamespaceRequest {
            name: "billing".to_owned(),
            labels: Default::default(),
            past_lost_keks: false,
        })
        .await
        .unwrap();
    env.authz.deny(&[Action::Namespace]);
    let status = env
        .client
        .status(pb::StatusRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!((status.namespaces, status.vanished_keks), (2, 0));
    let shown = format!("{status:?}");
    assert!(
        !shown.contains("billing") && !shown.contains("\"app\""),
        "{shown}"
    );
    env.destroy().await.unwrap();
}

/// The issuing CA's calls ask for `identity` on the server, are refused
/// without it, and init and rotate record their outcome (the version and
/// the certificate's fingerprint, never key material).
#[tokio::test]
async fn identity_calls_are_authorized_and_audited() {
    let mut env = Env::unsealed().await.unwrap();
    env.authz.forget();
    let c = &mut env.client;
    let created = c
        .identity_init(pb::IdentityInitRequest {})
        .await
        .unwrap()
        .into_inner()
        .key
        .unwrap();
    assert_eq!(created.version, 1);
    assert_eq!(created.state(), pb::IssuingKeyState::Active);
    c.identity_rotate(pb::IdentityRotateRequest { revoke: true })
        .await
        .unwrap();
    let keys = c
        .identity_status(pb::IdentityStatusRequest {})
        .await
        .unwrap()
        .into_inner()
        .keys;
    assert_eq!(
        keys.iter()
            .map(|k| (k.version, k.state()))
            .collect::<Vec<_>>(),
        [
            (1, pb::IssuingKeyState::Revoked),
            (2, pb::IssuingKeyState::Active)
        ]
    );
    assert!(keys[0].retired_at_unix.is_some() && keys[1].retired_at_unix.is_none());
    assert!(
        env.authz
            .asked()
            .iter()
            .all(|(action, target)| *action == Action::Identity && target == "the server")
    );
    let outcomes = entries(&env.audit, "outcome", 0).await.unwrap();
    let identity: Vec<&Value> = outcomes
        .iter()
        .filter(|e| {
            e["operation"]
                .as_str()
                .is_some_and(|o| o.starts_with("identity"))
        })
        .collect();
    assert_eq!(identity.len(), 2, "{identity:?}");
    assert_eq!(identity[1]["details"]["version"], 2);
    assert_eq!(identity[1]["details"]["revoked_previous"], true);
    assert_eq!(
        identity[0]["details"]["fingerprint"].as_str().map(str::len),
        Some(64)
    );

    env.authz.deny(&[Action::Identity]);
    for refused in [
        env.client
            .identity_init(pb::IdentityInitRequest {})
            .await
            .map(drop),
        env.client
            .identity_rotate(pb::IdentityRotateRequest { revoke: false })
            .await
            .map(drop),
        env.client
            .identity_status(pb::IdentityStatusRequest {})
            .await
            .map(drop),
    ] {
        assert_eq!(
            denied(refused).map(|(code, _)| code),
            Some(Code::PermissionDenied)
        );
    }
    env.destroy().await.unwrap();
}

/// On a server configured for the shares alone, `unseal --auto` is refused
/// (it can't unseal there) and releases nothing; a seal sets the hold, and
/// an unseal with shares releases it only with `release_hold`.
#[tokio::test]
async fn the_hold_is_released_explicitly_and_auto_needs_a_provider() {
    let mut env = Env::unsealed().await.unwrap();
    let keys = Keystore::new(env.keys.pool().clone());
    let sealed = env
        .client
        .seal(pb::SealRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(sealed.hold_set);
    assert_eq!(keys.auto_unseal_hold().await.unwrap(), (1, 0));

    let refused = env
        .client
        .unseal(pb::UnsealRequest {
            auto: true,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(refused.message().contains("--release-hold"), "{refused:?}");
    assert_eq!(keys.auto_unseal_hold().await.unwrap(), (1, 0));

    // A plain unseal with shares leaves the hold...
    for share in &env.shares[..3] {
        env.client
            .unseal(pb::UnsealRequest {
                share: share.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    assert_eq!(keys.auto_unseal_hold().await.unwrap(), (1, 0));
    // ...and one asking for it releases it.
    env.client.seal(pb::SealRequest {}).await.unwrap();
    for (i, share) in env.shares[..3].iter().enumerate() {
        env.client
            .unseal(pb::UnsealRequest {
                share: share.clone(),
                release_hold: i == 2,
                ..Default::default()
            })
            .await
            .unwrap();
    }
    assert_eq!(keys.auto_unseal_hold().await.unwrap(), (2, 2));
    env.serving.abort();
    env.keys.destroy().await.unwrap();
    env.data.destroy().await.unwrap();
}
