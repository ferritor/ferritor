//! The CSI provider against a real server in process (TLS, the token
//! exchange, an authorizer whose grants a test can change), with
//! `MountRequest`s as the Secrets Store CSI Driver sends them: the
//! `SecretProviderClass`'s parameters merged with the kubelet's attributes,
//! the pod's token among them. `mount_at(now)` decides by the `now` it's
//! given, so backoffs run without waiting.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ferritor_agent::csi::config::ProviderConfig;
use ferritor_agent::csi::proto::csi_driver_provider_client::CsiDriverProviderClient;
use ferritor_agent::csi::proto::csi_driver_provider_server::CsiDriverProviderServer;
use ferritor_agent::csi::proto::{MountRequest, MountResponse, VersionRequest};
use ferritor_agent::csi::provider::Provider;
use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::Labels;
use ferritor_core::path::SecretPath;
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{Action, Authorizer, Caller, Denied, Target};
use ferritor_server::identity::exchange::Exchange;
use ferritor_server::identity::mapping::{Mapping, Template};
use ferritor_server::identity::{
    DEFAULT_EXCHANGE_BURST, DEFAULT_MAX_TOKEN_AGE, Identity, Issuer, JwksSource,
};
use ferritor_server::namespaces::Namespaces;
use ferritor_server::seal::Seal;
use ferritor_server::secrets::Secrets;
use ferritor_server::watch::{self, Watch};
use ferritor_server::{grpc, tls};
use ferritor_testkit::jwt::{AUDIENCE, ISS, TokenIssuer};
use ferritor_testkit::pki::Ca;
use ferritor_testkit::{Captured, TestDatabase, TestResult};
use serde_json::json;
use tokio::net::{TcpListener, UnixListener};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::Code;
use tonic::service::Routes;

const WRITER: &str = "ops/writer";
const API: &str = "k8s/billing/api";
const WORKER: &str = "k8s/billing/worker";

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
    secrets: Arc<Secrets>,
    grants: Arc<Grants>,
    audit: Captured,
    issuer: TokenIssuer,
    dir: std::path::PathBuf,
    provider: Arc<Provider>,
    config: ProviderConfig,
    serving: Vec<JoinHandle<()>>,
    gate: Arc<Gate>,
}

impl Env {
    async fn new() -> TestResult<Self> {
        let keys = TestDatabase::new(
            "KEYS_DATABASE_URL",
            "ferritor_csi_test",
            &ferritor_keystore::MIGRATOR,
        )
        .await?;
        let data = TestDatabase::new(
            "DATA_DATABASE_URL",
            "ferritor_csi_test",
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
        seal.identity_init().await?;
        Namespaces::new(Arc::clone(&seal), Datastore::new(data.pool().clone()))
            .create("billing", &Labels::new())
            .await?;
        let grants = Arc::new(Grants::default());
        grants.allow(WRITER, Action::Write, "billing");
        let audit = Captured::default();
        let gate = Arc::new(Gate::new(
            Arc::clone(&grants) as Arc<dyn Authorizer>,
            AuditLog::new(audit.clone(), Duration::from_secs(5))?,
        ));
        let watch = Watch::new();
        let feed = tokio::spawn(Arc::clone(&watch).run(Datastore::new(data.pool().clone())));
        let secrets = Arc::new(
            Secrets::new(
                Arc::clone(&seal),
                Datastore::new(data.pool().clone()),
                Arc::clone(&gate),
            )
            .with_watch(Arc::clone(&watch)),
        );
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ferritor-csi-e2e-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir)?;
        let ca = Ca::new()?;
        std::fs::write(dir.join("ca.pem"), &ca.cert)?;
        let pem = ca.server()?;
        let tls_config = tls::server_tls(
            pem.cert.as_bytes(),
            pem.key.as_bytes(),
            ca.cert.as_bytes(),
            None,
        )?;
        let issuer = TokenIssuer::new(&dir)?;
        let exchange_listener = TcpListener::bind("127.0.0.1:0").await?;
        let exchange_addr = exchange_listener.local_addr()?;
        let exchange = Arc::new(
            Exchange::new(
                Arc::clone(&seal),
                Arc::clone(&gate),
                Identity {
                    listen_addr: exchange_addr,
                    lifetime: Duration::from_secs(3600),
                    issuers: vec![Issuer {
                        name: "k8s".to_owned(),
                        iss: ISS.to_owned(),
                        audience: AUDIENCE.to_owned(),
                        max_token_age: DEFAULT_MAX_TOKEN_AGE,
                        exchange_burst: DEFAULT_EXCHANGE_BURST,
                        jwks: JwksSource::File(issuer.jwks.clone()),
                        mappings: vec![Mapping {
                            template: Template::parse(
                                "k8s/{kubernetes.io.namespace}/{kubernetes.io.serviceaccount.name}",
                                "k8s",
                            )?,
                            require: vec![(
                                "kubernetes.io.namespace".to_owned(),
                                vec!["billing".to_owned()],
                            )],
                        }],
                        not_before: None,
                    }],
                    revoked: Vec::new(),
                },
            )
            .await?,
        );
        tls_config.use_workload_trust(exchange.trust());
        let exchange_tls = tls_config.without_client_auth()?;
        let age = Duration::from_secs(600);
        let mut serving = vec![feed];
        let routes = Routes::new(grpc::identity_service(exchange));
        serving.push(tokio::spawn(async move {
            tls::serve(
                tls::server(age, age),
                routes,
                exchange_listener,
                Some(exchange_tls),
                std::future::pending(),
            )
            .await
            .ok();
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let routes = Routes::new(grpc::secrets_service(Arc::clone(&secrets)));
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
        let config = ProviderConfig::parse(&format!(
            "server = \"https://localhost:{}\"\nca = \"{}\"\nexchange = \"https://localhost:{}\"\n\
             socket = \"{}\"\nrefusal_backoff_secs = 60\nwatch = false\n",
            addr.port(),
            dir.join("ca.pem").display(),
            exchange_addr.port(),
            dir.join("ferritor.sock").display(),
        ))?;
        Ok(Self {
            keys,
            data,
            seal,
            secrets,
            grants,
            audit,
            issuer,
            dir,
            provider: Arc::new(Provider::new(config.clone())),
            config,
            serving,
            gate,
        })
    }

    async fn put(&self, path: &str, value: &str) -> TestResult<u32> {
        let caller = Caller::Identity(SecretPath::parse(WRITER)?);
        Ok(self
            .secrets
            .put(&caller, path, value.as_bytes())
            .await?
            .version)
    }

    /// A service account token for `namespace/account`, as the kubelet
    /// hands it over.
    fn token(&self, namespace: &str, account: &str) -> TestResult<String> {
        self.issuer.token(&json!({
            "sub": format!("system:serviceaccount:{namespace}:{account}"),
            "kubernetes.io": {"namespace": namespace, "serviceaccount": {"name": account}},
        }))
    }

    /// A `MountRequest` as the driver builds it for pod `pod` of
    /// `namespace/account`, with the class's `parameters`.
    fn request(
        &self,
        pod: &str,
        token: &str,
        parameters: &[(&str, &str)],
    ) -> TestResult<MountRequest> {
        let mut attributes: BTreeMap<String, String> = parameters
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        attributes.insert("secretProviderClass".to_owned(), "billing".to_owned());
        attributes.insert("csi.storage.k8s.io/pod.name".to_owned(), pod.to_owned());
        attributes.insert(
            "csi.storage.k8s.io/pod.namespace".to_owned(),
            "billing".to_owned(),
        );
        attributes.insert(
            "csi.storage.k8s.io/serviceAccount.tokens".to_owned(),
            json!({"ferritor": {"token": token, "expirationTimestamp": "2099-01-01T00:00:00Z"}})
                .to_string(),
        );
        Ok(MountRequest {
            attributes: serde_json::to_string(&attributes)?,
            secrets: "{}".to_owned(),
            target_path: format!("/var/lib/kubelet/pods/{pod}/volumes/secrets"),
            permission: "420".to_owned(),
            current_object_version: Vec::new(),
        })
    }

    /// Calls of `action` by `caller` the server decided on.
    fn decisions(&self, caller: &str, action: &str) -> usize {
        self.audit
            .lines()
            .iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|e| {
                e["event"] == "authorization" && e["action"] == action && e["caller"] == caller
            })
            .count()
    }

    /// The exchanges audited. Their entries are queued, not waited for, so
    /// it first waits for one decision that is (a check no test makes): the
    /// writer takes entries in order, so every exchange audited before it
    /// is written too, however slow the machine.
    async fn exchanges(&self) -> usize {
        if let Ok(barrier) = SecretPath::parse("test/audit-barrier") {
            let caller = Caller::Identity(barrier.clone());
            // Allowed or not, the decision is recorded before this returns.
            self.gate
                .check(&caller, Action::Read, Target::Path(&barrier))
                .await
                .ok();
        }
        self.audit
            .lines()
            .iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|e| e["event"] == "exchange")
            .count()
    }

    async fn destroy(self) -> TestResult<()> {
        for serving in &self.serving {
            serving.abort();
        }
        std::fs::remove_dir_all(&self.dir).ok();
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

/// The response's files, by path, as text, with their modes.
fn files(response: &MountResponse) -> Vec<(String, String, i32)> {
    response
        .files
        .iter()
        .map(|f| {
            (
                f.path.clone(),
                String::from_utf8_lossy(&f.contents).into_owned(),
                f.mode,
            )
        })
        .collect()
}

fn versions(response: &MountResponse) -> Vec<(String, String)> {
    response
        .object_version
        .iter()
        .map(|v| (v.id.clone(), v.version.clone()))
        .collect()
}

/// A prefix volume: every secret below it, a file each (deeper paths in
/// subdirectories), with the ferritor versions; read with the pod's identity,
/// from its own token. A refresh with nothing changed reads nothing again;
/// a new version comes with the next refresh after the shared window.
#[tokio::test]
async fn a_prefix_volume_holds_every_secret_below_it() {
    let env = Env::new().await.unwrap();
    env.grants.allow(API, Action::Read, "billing/api");
    env.grants.allow(API, Action::List, "billing/api");
    env.put("billing/api/db-password", "foo").await.unwrap();
    env.put("billing/api/tls/cert", "pem").await.unwrap();
    env.put("billing/other/x", "not this").await.unwrap();
    let token = env.token("billing", "api").unwrap();
    let request = env
        .request("api-1", &token, &[("prefix", "billing/api")])
        .unwrap();
    let t0 = Instant::now();
    let mounted = env.provider.mount_at(&request, t0).await.unwrap();
    assert_eq!(
        files(&mounted),
        [
            ("db-password".to_owned(), "foo".to_owned(), 0o644),
            ("tls/cert".to_owned(), "pem".to_owned(), 0o644)
        ]
    );
    assert_eq!(
        versions(&mounted),
        [
            ("billing/api/db-password".to_owned(), "1".to_owned()),
            ("billing/api/tls/cert".to_owned(), "1".to_owned())
        ]
    );
    assert_eq!(env.decisions(API, "read"), 2);
    assert_eq!(env.exchanges().await, 1);

    // A refresh past the shared window, nothing changed: one listing, no
    // read, no new exchange (the token's mapping is remembered).
    let later = t0 + Duration::from_secs(120);
    env.provider.mount_at(&request, later).await.unwrap();
    assert_eq!(env.decisions(API, "read"), 2);
    assert_eq!(env.decisions(API, "list"), 2);
    assert_eq!(env.exchanges().await, 1);

    env.put("billing/api/db-password", "bar").await.unwrap();
    let refreshed = env
        .provider
        .mount_at(&request, later + Duration::from_secs(120))
        .await
        .unwrap();
    assert_eq!(files(&refreshed)[0].1, "bar");
    assert_eq!(versions(&refreshed)[0].1, "2");
    assert_eq!(env.decisions(API, "read"), 3);
    env.destroy().await.unwrap();
}

/// Objects: exactly those paths, to the files named, with `read` alone;
/// the class's `filePermission` sets the mode.
#[tokio::test]
async fn an_objects_volume_needs_read_only() {
    let env = Env::new().await.unwrap();
    env.grants
        .allow(API, Action::Read, "billing/api/db-password");
    env.grants.allow(API, Action::Read, "billing/shared");
    env.put("billing/api/db-password", "foo").await.unwrap();
    env.put("billing/shared/redis-password", "bar")
        .await
        .unwrap();
    let token = env.token("billing", "api").unwrap();
    let objects = r#"[{"path": "billing/api/db-password"},
                      {"path": "billing/shared/redis-password", "file": "redis"}]"#;
    let request = env
        .request(
            "api-1",
            &token,
            &[("objects", objects), ("filePermission", "0440")],
        )
        .unwrap();
    let mounted = env
        .provider
        .mount_at(&request, Instant::now())
        .await
        .unwrap();
    assert_eq!(
        files(&mounted),
        [
            ("db-password".to_owned(), "foo".to_owned(), 0o440),
            ("redis".to_owned(), "bar".to_owned(), 0o440)
        ]
    );
    assert_eq!(env.decisions(API, "list"), 0);
    env.destroy().await.unwrap();
}

/// Each pod reads as its own identity: reads are shared between the pods
/// of one identity on the node (one read for many replicas), never with
/// another identity, which is refused what it may not read even while the
/// first identity's read is fresh.
#[tokio::test]
async fn reads_are_shared_within_an_identity_only() {
    let env = Env::new().await.unwrap();
    env.grants.allow(API, Action::Read, "billing/api");
    env.put("billing/api/db-password", "foo").await.unwrap();
    let objects = r#"[{"path": "billing/api/db-password"}]"#;
    let api = env.token("billing", "api").unwrap();
    let now = Instant::now();
    for pod in ["api-1", "api-2", "api-3"] {
        let request = env.request(pod, &api, &[("objects", objects)]).unwrap();
        env.provider.mount_at(&request, now).await.unwrap();
    }
    assert_eq!(env.decisions(API, "read"), 1);

    let worker = env.token("billing", "worker").unwrap();
    let request = env
        .request("worker-1", &worker, &[("objects", objects)])
        .unwrap();
    let refused = env.provider.mount_at(&request, now).await.unwrap_err();
    assert_eq!(refused.code(), Code::PermissionDenied, "{refused:?}");
    assert_eq!(env.decisions(WORKER, "read"), 1);
    env.destroy().await.unwrap();
}

/// A token the issuer's mappings refuse fails the mount for good, and is
/// remembered: the kubelet's retries don't reach the exchange again until
/// the backoff passes.
#[tokio::test]
async fn a_refused_token_is_remembered() {
    let env = Env::new().await.unwrap();
    let token = env.token("shop", "api").unwrap();
    let request = env
        .request("shop-1", &token, &[("prefix", "billing/api")])
        .unwrap();
    let t0 = Instant::now();
    for retry in 0..10 {
        let refused = env
            .provider
            .mount_at(&request, t0 + Duration::from_millis(500 * retry))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Code::PermissionDenied, "{refused:?}");
        assert!(
            refused.message().contains("token was refused"),
            "{refused:?}"
        );
    }
    let refusals = env.exchanges().await;
    assert_eq!(refusals, 1);
    env.provider
        .mount_at(&request, t0 + Duration::from_secs(61))
        .await
        .unwrap_err();
    assert_eq!(env.exchanges().await, 2);
    env.destroy().await.unwrap();
}

/// A rollout's pods retrying a path their identity may not read reach the
/// server once per backoff step, however many pods and retries, so the
/// identity's shared denial budget holds and its allowed reads go on.
#[tokio::test]
async fn retries_of_a_denied_path_reach_the_server_once_per_step() {
    let env = Env::new().await.unwrap();
    env.grants.allow(API, Action::Read, "billing/api");
    env.put("billing/api/db-password", "foo").await.unwrap();
    env.put("billing/secret/x", "no").await.unwrap();
    let token = env.token("billing", "api").unwrap();
    let denied = r#"[{"path": "billing/secret/x"}]"#;
    let allowed = r#"[{"path": "billing/api/db-password"}]"#;
    let t0 = Instant::now();
    for pod in 0..20 {
        for retry in 0..5 {
            let request = env
                .request(&format!("api-{pod}"), &token, &[("objects", denied)])
                .unwrap();
            let at = t0 + Duration::from_millis(100 * (pod * 5 + retry));
            let refused = env.provider.mount_at(&request, at).await.unwrap_err();
            assert_eq!(refused.code(), Code::PermissionDenied);
        }
    }
    let denials = || {
        env.audit
            .lines()
            .iter()
            .filter(|line| line.contains("\"denied\"") && line.contains("billing/secret/x"))
            .count()
    };
    assert_eq!(denials(), 1);
    let request = env
        .request("api-0", &token, &[("objects", allowed)])
        .unwrap();
    env.provider.mount_at(&request, t0).await.unwrap();
    // The next step: one more try, then twice the backoff.
    let request = env
        .request("api-0", &token, &[("objects", denied)])
        .unwrap();
    env.provider
        .mount_at(&request, t0 + Duration::from_secs(61))
        .await
        .unwrap_err();
    env.provider
        .mount_at(&request, t0 + Duration::from_secs(150))
        .await
        .unwrap_err();
    assert_eq!(denials(), 2);
    env.provider
        .mount_at(&request, t0 + Duration::from_secs(182))
        .await
        .unwrap_err();
    assert_eq!(denials(), 3);
    env.destroy().await.unwrap();
}

/// Access revoked after a volume was mounted: `keep` returns the value
/// delivered; `remove` leaves its file out (the others stay); a volume
/// whose every secret is refused stays as it is (the driver can't empty
/// one).
#[tokio::test]
async fn a_revoked_secret_follows_on_revoked() {
    let env = Env::new().await.unwrap();
    env.grants.allow(API, Action::Read, "billing/api");
    env.grants.allow(API, Action::Read, "billing/shared");
    env.put("billing/api/db-password", "foo").await.unwrap();
    env.put("billing/shared/redis-password", "bar")
        .await
        .unwrap();
    let token = env.token("billing", "api").unwrap();
    let objects = r#"[{"path": "billing/api/db-password"},
                      {"path": "billing/shared/redis-password"}]"#;
    let keep = env
        .request("keep", &token, &[("objects", objects)])
        .unwrap();
    let remove = env
        .request(
            "remove",
            &token,
            &[("objects", objects), ("onRevoked", "remove")],
        )
        .unwrap();
    let t0 = Instant::now();
    env.provider.mount_at(&keep, t0).await.unwrap();
    env.provider.mount_at(&remove, t0).await.unwrap();
    env.grants.revoke(API, Action::Read, "billing/shared");
    let later = t0 + Duration::from_secs(120);
    let kept = env.provider.mount_at(&keep, later).await.unwrap();
    assert_eq!(files(&kept).len(), 2);
    let removed = env.provider.mount_at(&remove, later).await.unwrap();
    assert_eq!(
        files(&removed),
        [("db-password".to_owned(), "foo".to_owned(), 0o644)]
    );
    env.grants.revoke(API, Action::Read, "billing/api");
    let none = env
        .provider
        .mount_at(&remove, later + Duration::from_secs(120))
        .await
        .unwrap_err();
    assert_eq!(none.code(), Code::PermissionDenied);
    env.destroy().await.unwrap();
}

/// Nobody decided anything (sealed): the mount fails for now, so the driver
/// leaves the volume as it is; as `FAILED_PRECONDITION`, never
/// `UNAVAILABLE`, which the driver retries within the call, letting a first
/// mount's error be masked and the pod start with an empty volume.
#[tokio::test]
async fn a_sealed_server_leaves_the_volume_as_it_is() {
    let env = Env::new().await.unwrap();
    env.grants.allow(API, Action::Read, "billing/api");
    env.put("billing/api/db-password", "foo").await.unwrap();
    let token = env.token("billing", "api").unwrap();
    let request = env
        .request(
            "api-1",
            &token,
            &[("objects", r#"[{"path": "billing/api/db-password"}]"#)],
        )
        .unwrap();
    let t0 = Instant::now();
    env.provider.mount_at(&request, t0).await.unwrap();
    env.seal.seal().await;
    let failed = env
        .provider
        .mount_at(&request, t0 + Duration::from_secs(120))
        .await
        .unwrap_err();
    assert_eq!(failed.code(), Code::FailedPrecondition, "{failed:?}");
    env.destroy().await.unwrap();
}

/// Over the wire, as the driver calls it: `Version` and `Mount` on the
/// node-local socket.
#[tokio::test]
async fn the_driver_reaches_it_on_its_socket() {
    let env = Env::new().await.unwrap();
    env.grants.allow(API, Action::Read, "billing/api");
    env.put("billing/api/db-password", "foo").await.unwrap();
    let socket = env.dir.join("ferritor.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let provider = Arc::clone(&env.provider);
    let serving = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(CsiDriverProviderServer::new(provider))
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await
            .ok();
    });
    let path = socket.clone();
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                    tokio::net::UnixStream::connect(path).await?,
                ))
            }
        }))
        .await
        .unwrap();
    let mut client = CsiDriverProviderClient::new(channel);
    let version = client
        .version(VersionRequest {
            version: "v1alpha1".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(version.runtime_name, "ferritor-csi-provider");
    let token = env.token("billing", "api").unwrap();
    let request = env
        .request(
            "api-1",
            &token,
            &[("objects", r#"[{"path": "billing/api/db-password"}]"#)],
        )
        .unwrap();
    let mounted = client.mount(request).await.unwrap().into_inner();
    assert_eq!(files(&mounted)[0].1, "foo");
    serving.abort();
    env.destroy().await.unwrap();
}

/// A secret below the prefix the volume can't hold (a name the driver
/// keeps for itself, or a file that would also be a directory) is skipped,
/// never the volume: one put mustn't stop every pod mounting the prefix.
/// Of a file and a directory, the one the volume already has stays.
#[tokio::test]
async fn a_bad_name_below_a_prefix_skips_that_secret_only() {
    let env = Env::new().await.unwrap();
    env.grants.allow(API, Action::Read, "billing/api");
    env.grants.allow(API, Action::List, "billing/api");
    env.put("billing/api/db-password", "foo").await.unwrap();
    env.put("billing/api/tls/cert", "pem").await.unwrap();
    let token = env.token("billing", "api").unwrap();
    let request = env
        .request("api-1", &token, &[("prefix", "billing/api")])
        .unwrap();
    let t0 = Instant::now();
    env.provider.mount_at(&request, t0).await.unwrap();

    env.put("billing/api/..data", "planted").await.unwrap();
    // `tls` as a file, next to the `tls/` the volume has.
    env.put("billing/api/tls", "flat").await.unwrap();
    let refreshed = env
        .provider
        .mount_at(&request, t0 + Duration::from_secs(120))
        .await
        .unwrap();
    let names: Vec<String> = files(&refreshed).into_iter().map(|(n, _, _)| n).collect();
    assert_eq!(names, ["db-password", "tls/cert"]);

    // A new volume has nothing yet: the shallower stays.
    let fresh = env
        .request("api-2", &token, &[("prefix", "billing/api")])
        .unwrap();
    let mounted = env
        .provider
        .mount_at(&fresh, t0 + Duration::from_secs(240))
        .await
        .unwrap();
    let names: Vec<String> = files(&mounted).into_iter().map(|(n, _, _)| n).collect();
    assert_eq!(names, ["db-password", "tls"]);
    env.destroy().await.unwrap();
}

/// A pod's volumes mount together, with one token: it's exchanged once.
#[tokio::test]
async fn concurrent_mounts_with_one_token_exchange_it_once() {
    let env = Env::new().await.unwrap();
    env.grants.allow(API, Action::Read, "billing/api");
    env.put("billing/api/db-password", "foo").await.unwrap();
    let token = env.token("billing", "api").unwrap();
    let objects = r#"[{"path": "billing/api/db-password"}]"#;
    let first = env
        .request("api-1", &token, &[("objects", objects)])
        .unwrap();
    let mut second = first.clone();
    second.target_path.push_str("-2");
    let now = Instant::now();
    let (a, b) = tokio::join!(
        env.provider.mount_at(&first, now),
        env.provider.mount_at(&second, now)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(env.exchanges().await, 1);
    env.destroy().await.unwrap();
}

/// With a watch stream per identity, a refresh with nothing changed asks
/// the server nothing, however long since the last (the shared window is
/// 30 s); a change drops what it makes stale, and the next refresh reads
/// just that.
#[tokio::test]
async fn a_watch_lets_refreshes_skip_the_server_until_something_changes() {
    let env = Env::new().await.unwrap();
    env.grants.allow(API, Action::Read, "billing/api");
    env.grants.allow(API, Action::List, "billing/api");
    env.put("billing/api/db-password", "foo").await.unwrap();
    env.put("billing/api/other", "o").await.unwrap();
    let mut config = env.config.clone();
    config.watch = true;
    let provider = Provider::new(config);
    let token = env.token("billing", "api").unwrap();
    let request = env
        .request("api-1", &token, &[("prefix", "billing/api")])
        .unwrap();
    let t0 = Instant::now();
    provider.mount_at(&request, t0).await.unwrap();
    for _ in 0..100 {
        if provider.watch_ready(API) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(provider.watch_ready(API));
    // The setup's puts reach the stream at the feed's next poll: let them
    // pass, so they drop nothing read after.
    tokio::time::sleep(2 * watch::POLL).await;
    // Read again once the watch was ready: from then on it vouches.
    provider
        .mount_at(&request, t0 + Duration::from_secs(60))
        .await
        .unwrap();
    let calls = |env: &Env| (env.decisions(API, "read"), env.decisions(API, "list"));
    let before = calls(&env);
    for minutes in [3, 5, 7] {
        provider
            .mount_at(&request, t0 + Duration::from_secs(60 * minutes))
            .await
            .unwrap();
    }
    assert_eq!(
        calls(&env),
        before,
        "a refresh with nothing changed asked the server"
    );

    env.put("billing/api/db-password", "bar").await.unwrap();
    // The feed polls every 250 ms; then the stream tells the provider.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let refreshed = provider
        .mount_at(&request, t0 + Duration::from_secs(600))
        .await
        .unwrap();
    assert_eq!(files(&refreshed)[0].1, "bar");
    // The listing and db-password's read; not other's.
    assert_eq!(calls(&env), (before.0 + 1, before.1 + 1));
    env.destroy().await.unwrap();
}

/// The same for an objects volume, which has no listing: a change of one
/// of its paths drops that path's read alone.
#[tokio::test]
async fn a_watch_drops_the_read_a_change_makes_stale() {
    let env = Env::new().await.unwrap();
    env.grants.allow(API, Action::Read, "billing/api");
    env.put("billing/api/db-password", "foo").await.unwrap();
    env.put("billing/api/other", "o").await.unwrap();
    let mut config = env.config.clone();
    config.watch = true;
    let provider = Provider::new(config);
    let token = env.token("billing", "api").unwrap();
    let objects = r#"[{"path": "billing/api/db-password"}, {"path": "billing/api/other"}]"#;
    let request = env
        .request("api-1", &token, &[("objects", objects)])
        .unwrap();
    let t0 = Instant::now();
    provider.mount_at(&request, t0).await.unwrap();
    for _ in 0..100 {
        if provider.watch_ready(API) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(provider.watch_ready(API));
    // The setup's puts reach the stream at the feed's next poll: let them
    // pass, so they drop nothing read after.
    tokio::time::sleep(2 * watch::POLL).await;
    provider
        .mount_at(&request, t0 + Duration::from_secs(60))
        .await
        .unwrap();
    let before = env.decisions(API, "read");
    provider
        .mount_at(&request, t0 + Duration::from_secs(300))
        .await
        .unwrap();
    assert_eq!(env.decisions(API, "read"), before);
    env.put("billing/api/db-password", "bar").await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let refreshed = provider
        .mount_at(&request, t0 + Duration::from_secs(600))
        .await
        .unwrap();
    assert_eq!(files(&refreshed)[0].1, "bar");
    assert_eq!(env.decisions(API, "read"), before + 1);
    env.destroy().await.unwrap();
}

/// A volume with a path its identity may not read, mounted next to watched
/// ones: the path is asked for once (the read), never by the watch, which
/// would be refused whole and end the identity's stream.
#[tokio::test]
async fn a_denied_volume_leaves_the_identitys_watch_alone() {
    let env = Env::new().await.unwrap();
    env.grants.allow(API, Action::Read, "billing/api");
    env.put("billing/api/db-password", "foo").await.unwrap();
    env.put("billing/secret/x", "no").await.unwrap();
    let mut config = env.config.clone();
    config.watch = true;
    let provider = Provider::new(config);
    let token = env.token("billing", "api").unwrap();
    let allowed = r#"[{"path": "billing/api/db-password"}]"#;
    let request = env
        .request("api-1", &token, &[("objects", allowed)])
        .unwrap();
    let t0 = Instant::now();
    provider.mount_at(&request, t0).await.unwrap();
    for _ in 0..100 {
        if provider.watch_ready(API) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(provider.watch_ready(API));

    let denied = r#"[{"path": "billing/secret/x"}, {"path": "billing/api/db-password"}]"#;
    let request = env
        .request("api-2", &token, &[("objects", denied)])
        .unwrap();
    let refused = provider.mount_at(&request, t0).await.unwrap_err();
    assert_eq!(refused.code(), Code::PermissionDenied);
    tokio::time::sleep(2 * watch::POLL).await;
    let denials = env
        .audit
        .lines()
        .iter()
        .filter(|line| line.contains("\"denied\"") && line.contains("billing/secret/x"))
        .count();
    assert_eq!(denials, 1);
    assert!(provider.watch_ready(API));
    env.destroy().await.unwrap();
}
