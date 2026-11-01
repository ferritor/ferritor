//! `WatchSecrets` over real connections: a TLS server with its change feed,
//! an authorizer whose grants a test can change, and a second server on the
//! same databases, whose writes the stream reports too.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::Labels;
use ferritor_core::path::SecretPath;
use ferritor_core::proto::v1 as pb;
use ferritor_core::proto::v1::secrets_service_client::SecretsServiceClient;
use ferritor_core::proto::v1::watch_secrets_response::Event;
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{Action, Authorizer, Caller, Denied, Target};
use ferritor_server::namespaces::Namespaces;
use ferritor_server::ratelimit::{Limits, Quota};
use ferritor_server::seal::Seal;
use ferritor_server::secrets::Secrets;
use ferritor_server::watch::Watch;
use ferritor_server::{grpc, tls};
use ferritor_testkit::pki::{Ca, Pem, uri};
use ferritor_testkit::{Captured, TestDatabase, TestResult};
use rcgen::ExtendedKeyUsagePurpose;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tonic::service::Routes;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::{Code, Streaming};
use tonic_types::StatusExt;

const APP: &str = "apps/web";
const WRITER: &str = "ops/writer";

/// Grants: (identity, action, path prefix), changeable while serving.
#[derive(Default)]
struct Grants(Mutex<Vec<(String, Action, String)>>);

impl Grants {
    fn allow(&self, identity: &str, action: Action, prefix: &str) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).push((
            identity.to_owned(),
            action,
            prefix.to_owned(),
        ));
    }

    fn revoke(&self, identity: &str, action: Action, prefix: &str) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(i, a, p)| !(i == identity && *a == action && p == prefix));
    }
}

impl Authorizer for Grants {
    fn authorize(&self, caller: &Caller, action: Action, target: Target<'_>) -> Result<(), Denied> {
        let path = match target {
            Target::Path(path) | Target::Below(path) => Some(path),
            Target::All | Target::System => None,
        };
        let allowed = match (caller, path) {
            (Caller::Identity(identity), Some(path)) => self
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|(i, a, prefix)| {
                    i == identity.as_str()
                        && *a == action
                        && SecretPath::parse(prefix)
                            .is_ok_and(|prefix| *path == prefix || path.is_under(&prefix))
                }),
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(Denied::new(caller, action, target))
        }
    }
}

struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    seal: Arc<Seal>,
    watch: Arc<Watch>,
    gate: Arc<Gate>,
    grants: Arc<Grants>,
    /// Another server's, on the same databases (no feed of its own needed).
    elsewhere: Arc<Secrets>,
    ca: Ca,
    addr: String,
    serving: Vec<JoinHandle<()>>,
}

impl Env {
    async fn new() -> TestResult<Self> {
        let keys = TestDatabase::new(
            "KEYS_DATABASE_URL",
            "ferritor_watch_test",
            &ferritor_keystore::MIGRATOR,
        )
        .await?;
        let data = TestDatabase::new(
            "DATA_DATABASE_URL",
            "ferritor_watch_test",
            &ferritor_datastore::MIGRATOR,
        )
        .await?;
        let seal = Arc::new(Seal::new(Keystore::new(keys.pool().clone())));
        let shares: Vec<Vec<u8>> = seal
            .init(ShareParams::new(3, 2)?)
            .await?
            .iter()
            .map(|share| share.to_bytes().to_vec())
            .collect();
        for share in &shares[..2] {
            seal.unseal(share, false).await?;
        }
        Namespaces::new(Arc::clone(&seal), Datastore::new(data.pool().clone()))
            .create("app", &Labels::new())
            .await?;
        let grants = Arc::new(Grants::default());
        grants.allow(WRITER, Action::Write, "app");
        grants.allow(WRITER, Action::Delete, "app");
        let gate = Arc::new(Gate::new(
            Arc::clone(&grants) as Arc<dyn Authorizer>,
            AuditLog::new(Captured::default(), Duration::from_secs(5))?,
        ));
        let watch = Watch::new();
        let mut serving = vec![tokio::spawn(
            Arc::clone(&watch).run(Datastore::new(data.pool().clone())),
        )];
        let secrets = Arc::new(
            Secrets::new(
                Arc::clone(&seal),
                Datastore::new(data.pool().clone()),
                Arc::clone(&gate),
            )
            .with_watch(Arc::clone(&watch)),
        );
        let elsewhere = Arc::new(Secrets::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
            Arc::clone(&gate),
        ));
        let ca = Ca::new()?;
        let pem = ca.server()?;
        let tls_config = tls::server_tls(
            pem.cert.as_bytes(),
            pem.key.as_bytes(),
            ca.cert.as_bytes(),
            None,
        )?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = format!("https://localhost:{}", listener.local_addr()?.port());
        let routes = Routes::new(grpc::secrets_service(secrets));
        let age = Duration::from_secs(600);
        serving.push(tokio::spawn(async move {
            tls::serve(
                tls::server(age, age),
                routes,
                listener,
                Some(tls_config),
                std::future::pending(),
            )
            .await
            .ok();
        }));
        Ok(Self {
            keys,
            data,
            seal,
            watch,
            gate,
            grants,
            elsewhere,
            ca,
            addr,
            serving,
        })
    }

    async fn client(&self, pem: &Pem) -> TestResult<SecretsServiceClient<Channel>> {
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(&self.ca.cert))
            .identity(Identity::from_pem(&pem.cert, &pem.key));
        let channel = Endpoint::from_shared(self.addr.clone())?
            .tls_config(tls)?
            .connect()
            .await?;
        Ok(SecretsServiceClient::new(channel))
    }

    /// A watch as `pem`, past its `ready`.
    async fn watch(
        &self,
        pem: &Pem,
        paths: &[&str],
        prefixes: &[&str],
    ) -> TestResult<Result<Streaming<pb::WatchSecretsResponse>, tonic::Status>> {
        let request = pb::WatchSecretsRequest {
            paths: paths.iter().map(|p| (*p).to_owned()).collect(),
            prefixes: prefixes.iter().map(|p| (*p).to_owned()).collect(),
        };
        let mut stream = match self.client(pem).await?.watch_secrets(request).await {
            Ok(response) => response.into_inner(),
            Err(status) => return Ok(Err(status)),
        };
        match next(&mut stream).await? {
            Ok(Event::Ready(_)) => Ok(Ok(stream)),
            Ok(other) => Err(format!("first event {other:?}, not ready").into()),
            Err(status) => Ok(Err(status)),
        }
    }

    /// A write as another server would make it.
    async fn put(&self, path: &str, value: &str) -> TestResult<u32> {
        let caller = Caller::Identity(SecretPath::parse(WRITER)?);
        Ok(self
            .elsewhere
            .put(&caller, path, value.as_bytes())
            .await?
            .version)
    }

    async fn destroy(self) -> TestResult<()> {
        self.watch.close();
        for serving in &self.serving {
            serving.abort();
        }
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

/// The next event, or the status the stream ended with.
async fn next(
    stream: &mut Streaming<pb::WatchSecretsResponse>,
) -> TestResult<Result<Event, tonic::Status>> {
    match tokio::time::timeout(Duration::from_secs(10), stream.message()).await? {
        Ok(Some(message)) => Ok(Ok(message.event.ok_or("an empty event")?)),
        Ok(None) => Err("the stream ended without a status".into()),
        Err(status) => Ok(Err(status)),
    }
}

fn changed(path: &str, version: u32) -> Event {
    Event::Changed(pb::SecretChanged {
        path: path.to_owned(),
        version,
    })
}

/// Paths and prefixes: every change of a live version they cover, from
/// another server's writes too; a delete is version 0; nothing outside
/// what's watched.
#[tokio::test]
async fn a_watch_sends_every_change_it_covers() {
    let env = Env::new().await.unwrap();
    env.grants.allow(APP, Action::Read, "app/db");
    env.grants.allow(APP, Action::List, "app/web");
    let app = env.ca.client(APP).unwrap();
    let mut stream = env
        .watch(&app, &["app/db"], &["app/web"])
        .await
        .unwrap()
        .unwrap();
    env.put("app/other", "x").await.unwrap();
    env.put("app/db", "1").await.unwrap();
    assert_eq!(
        next(&mut stream).await.unwrap().unwrap(),
        changed("app/db", 1)
    );
    env.put("app/web/tls/cert", "pem").await.unwrap();
    assert_eq!(
        next(&mut stream).await.unwrap().unwrap(),
        changed("app/web/tls/cert", 1)
    );
    let writer = Caller::Identity(SecretPath::parse(WRITER).unwrap());
    env.elsewhere.delete(&writer, "app/db").await.unwrap();
    assert_eq!(
        next(&mut stream).await.unwrap().unwrap(),
        changed("app/db", 0)
    );
    env.destroy().await.unwrap();
}

/// A watch needs read on each path and list on each prefix; without, it's
/// refused as it opens. A permission withdrawn later ends the stream, at
/// the next change it covers.
#[tokio::test]
async fn a_watch_needs_and_keeps_needing_its_permissions() {
    let env = Env::new().await.unwrap();
    let app = env.ca.client(APP).unwrap();
    let refused = env
        .watch(&app, &["app/db"], &[])
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code(), Code::PermissionDenied, "{refused:?}");
    env.grants.allow(APP, Action::Read, "app/db");
    let refused = env.watch(&app, &[], &["app"]).await.unwrap().unwrap_err();
    assert_eq!(refused.code(), Code::PermissionDenied, "{refused:?}");
    let refused = env.watch(&app, &[], &[]).await.unwrap().unwrap_err();
    assert_eq!(refused.code(), Code::InvalidArgument, "{refused:?}");

    let mut stream = env.watch(&app, &["app/db"], &[]).await.unwrap().unwrap();
    env.grants.revoke(APP, Action::Read, "app/db");
    env.put("app/db", "1").await.unwrap();
    let ended = next(&mut stream).await.unwrap().unwrap_err();
    assert_eq!(ended.code(), Code::PermissionDenied, "{ended:?}");
    env.destroy().await.unwrap();
}

/// An identity has at most its `max_watch_streams` open (`WATCH_FULL`,
/// `limit: identity`), whatever other identities have, and a stream its
/// client closed frees its place.
#[tokio::test]
async fn an_identity_has_at_most_its_watch_streams() {
    let env = Env::new().await.unwrap();
    env.gate.use_limits(
        Limits::new(
            std::num::NonZeroU32::new(100).unwrap(),
            Quota {
                rate: None,
                max_in_flight: None,
                max_watch_streams: std::num::NonZeroU32::new(2),
            },
            Vec::new(),
        ),
        Duration::from_secs(5),
    );
    env.grants.allow(APP, Action::Read, "app");
    env.grants.allow(WRITER, Action::Read, "app");
    let app = env.ca.client(APP).unwrap();
    let first = env.watch(&app, &["app/db"], &[]).await.unwrap().unwrap();
    let _second = env.watch(&app, &["app/db"], &[]).await.unwrap().unwrap();
    let full = env
        .watch(&app, &["app/db"], &[])
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(full.code(), Code::ResourceExhausted, "{full:?}");
    assert_eq!(grpc::reason_of(&full).as_deref(), Some("WATCH_FULL"));
    let limit = full
        .get_error_details()
        .error_info()
        .and_then(|info| info.metadata.get("limit").cloned());
    assert_eq!(limit.as_deref(), Some("identity"));
    let writer = env.ca.client(WRITER).unwrap();
    let _other = env.watch(&writer, &["app/db"], &[]).await.unwrap().unwrap();

    drop(first);
    let mut reopened = None;
    for _ in 0..50 {
        if let Ok(stream) = env.watch(&app, &["app/db"], &[]).await.unwrap() {
            reopened = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(reopened.is_some(), "a closed stream's place wasn't freed");
    env.destroy().await.unwrap();
}

/// A seal ends every stream (SEALED), as does the server shutting down
/// (UNAVAILABLE), so none holds the drain open.
#[tokio::test]
async fn a_seal_or_a_shutdown_ends_the_streams() {
    let env = Env::new().await.unwrap();
    env.grants.allow(APP, Action::Read, "app/db");
    let app = env.ca.client(APP).unwrap();
    let mut stream = env.watch(&app, &["app/db"], &[]).await.unwrap().unwrap();
    env.seal.seal().await;
    let ended = next(&mut stream).await.unwrap().unwrap_err();
    assert_eq!(ended.code(), Code::FailedPrecondition, "{ended:?}");
    let refused = env
        .watch(&app, &["app/db"], &[])
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code(), Code::FailedPrecondition, "{refused:?}");
    env.destroy().await.unwrap();

    let env = Env::new().await.unwrap();
    env.grants.allow(APP, Action::Read, "app/db");
    let app = env.ca.client(APP).unwrap();
    let mut stream = env.watch(&app, &["app/db"], &[]).await.unwrap().unwrap();
    env.watch.close();
    let ended = next(&mut stream).await.unwrap().unwrap_err();
    assert_eq!(ended.code(), Code::Unavailable, "{ended:?}");
    env.destroy().await.unwrap();
}

/// A stream outlives no client certificate: it ends when it expires.
#[tokio::test]
async fn a_watch_ends_when_its_certificate_expires() {
    let env = Env::new().await.unwrap();
    env.grants.allow(APP, Action::Read, "app/db");
    let short = env
        .ca
        .issue(
            vec![uri(&format!("ferritor://{APP}")).unwrap()],
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            Some(OffsetDateTime::now_utc() + time::Duration::seconds(3)),
        )
        .unwrap();
    let mut stream = env.watch(&short, &["app/db"], &[]).await.unwrap().unwrap();
    let ended = next(&mut stream).await.unwrap().unwrap_err();
    assert_eq!(ended.code(), Code::Unauthenticated, "{ended:?}");
    assert!(ended.message().contains("expired"), "{ended:?}");
    env.destroy().await.unwrap();
}
