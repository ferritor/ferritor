//! The agent's and the CSI provider's metrics for Prometheus end to end: a
//! round and a mount against a real server in process (with its token
//! exchange), scraped from the listener `[metrics]` starts. The families a
//! scrape returns are exactly the ones `agent.md`'s and `csi.md`'s tables
//! name, so the docs can't drift; no path, identity or pod is in it. One
//! test in its own binary, since the meter provider is process-wide.
//!
//! Unix only: the server, in process here, runs on Unix.
#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ferritor_agent::agent::Agent;
use ferritor_agent::config::Config;
use ferritor_agent::csi::config::ProviderConfig;
use ferritor_agent::csi::proto::MountRequest;
use ferritor_agent::csi::provider::Provider;
use ferritor_agent::metrics::{self, Chosen, MetricsConfig};
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
use ferritor_server::{grpc, tls};
use ferritor_testkit::jwt::{AUDIENCE, ISS, TokenIssuer};
use ferritor_testkit::pki::Ca;
use ferritor_testkit::{Captured, TestDatabase, TestResult};
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tonic::service::Routes;

/// The documentation the scrape is held to.
const AGENT_MD: &str = include_str!("../../../docs/src/content/docs/guides/agent.md");
const CSI_MD: &str = include_str!("../../../docs/src/content/docs/guides/csi.md");

const WRITER: &str = "ops/writer";

/// Writes for the writer, reads below `billing/app` for every identity.
struct Grants;

impl Authorizer for Grants {
    fn authorize(&self, caller: &Caller, action: Action, target: Target<'_>) -> Result<(), Denied> {
        let allowed = match (caller, action, target) {
            (Caller::Identity(id), Action::Write, _) => id.as_str() == WRITER,
            (Caller::Identity(_), Action::Read, Target::Path(path)) => {
                SecretPath::parse("billing/app").is_ok_and(|prefix| path.is_under(&prefix))
            }
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(Denied::new(caller, action, target))
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_scrape_holds_every_documented_metric_and_no_name() {
    // First of all: the instruments bind to the provider there is at their
    // first use.
    let running = metrics::start(
        &MetricsConfig {
            exporter: Chosen::Prometheus,
            listen_addr: "127.0.0.1:0".parse().ok(),
        },
        "ferritor-agent",
        true,
    )
    .await
    .unwrap();
    let addr = running.local_addr().unwrap();
    let env = Env::new().await.unwrap();
    env.put("billing/app/db", "v1").await.unwrap();

    // The agent: a round with an exchanged certificate.
    std::fs::write(
        env.dir.join("token"),
        env.token("billing", "agent").unwrap(),
    )
    .unwrap();
    let out = env.dir.join("out");
    let mut agent = Agent::new(
        Config::parse(&format!(
            "server = \"https://localhost:{port}\"\nca = \"{dir}/ca.pem\"\n\
             token_file = \"{dir}/token\"\nexchange = \"https://localhost:{exchange}\"\n\
             watch = false\n[[output]]\ndir = \"{out}\"\nallow_disk = true\n\
             [[output.secret]]\npath = \"billing/app/db\"\n",
            port = env.addr.port(),
            exchange = env.exchange.port(),
            dir = env.dir.display(),
            out = out.display(),
        ))
        .unwrap(),
    )
    .unwrap();
    let round = agent.poll(Instant::now()).await;
    assert!(!round.transient, "{round:?}");
    agent.set_watched(false, Instant::now());

    // The provider: one mount, as the driver asks.
    let provider = Provider::new(env.provider_config().unwrap());
    let token = env.token("billing", "api").unwrap();
    let request = env
        .request(
            "api-1",
            &token,
            &[("objects", r#"[{"path": "billing/app/db"}]"#)],
        )
        .unwrap();
    provider.mount_at(&request, Instant::now()).await.unwrap();

    // What this test doesn't make happen, recorded by hand so it shows.
    let agent_metrics = metrics::agent();
    agent_metrics.notification("command", "ok");
    agent_metrics.watch_event("ready");
    let provider_metrics = metrics::provider();
    provider_metrics.answered_from_memory("read");
    provider_metrics.watch_event("ready");

    let (status, body) = get(addr, "127.0.0.1").await.unwrap();
    assert_eq!(status, 200, "{body}");
    let scraped: BTreeSet<String> = families(&body)
        .into_iter()
        .filter(|f| f.starts_with("ferritor_agent_") || f.starts_with("ferritor_csi_"))
        .collect();
    let documented: BTreeSet<String> = documented_families(AGENT_MD, "ferritor.agent.")
        .into_iter()
        .chain(documented_families(CSI_MD, "ferritor.csi."))
        .collect();
    assert_eq!(scraped, documented);
    // What happened, as counted.
    for line in [
        "ferritor_agent_rounds_total{result=\"ok\"} 1",
        "ferritor_agent_calls_total{call=\"get\",result=\"ok\"} 1",
        "ferritor_agent_writes_total{result=\"ok\"} 1",
        "ferritor_agent_exchanges_total{result=\"ok\"} 1",
        "ferritor_agent_secrets{state=\"current\"} 1",
        "ferritor_agent_watch_ready 0",
        "ferritor_csi_mounts_total{result=\"ok\"} 1",
        "ferritor_csi_calls_total{call=\"get\",result=\"ok\"} 1",
        "ferritor_csi_exchanges_total{result=\"issued\"} 1",
        "ferritor_csi_identities 1",
        "ferritor_csi_volumes 1",
        "ferritor_csi_watch_streams 0",
    ] {
        assert!(body.lines().any(|l| l == line), "no {line:?} in:\n{body}");
    }
    let expiry = body
        .lines()
        .find_map(|l| l.strip_prefix("ferritor_agent_certificate_expiry_seconds "))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(expiry > now && expiry <= now + 3600, "{expiry} vs {now}");
    // No path, identity, pod or file name anywhere.
    for name in ["billing", "api-1", "agent", "/db", "k8s/"] {
        assert!(
            !body.lines().filter(|l| !l.starts_with('#')).any(|l| l
                .split_once('{')
                .is_some_and(|(_, labels)| labels.contains(name))),
            "{name:?} in a label:\n{body}"
        );
    }

    // On loopback, a scrape addressed elsewhere is refused (DNS rebinding).
    let (status, _) = get(addr, "metrics.example.com").await.unwrap();
    assert_eq!(status, 421);

    running.finish().await;
    assert!(TcpStream::connect(addr).await.is_err(), "still listening");
    env.destroy().await.unwrap();
}

/// The `# TYPE` names in a scrape.
fn families(body: &str) -> BTreeSet<String> {
    body.lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// The Prometheus column of a doc's metrics table (its "Metrics" section,
/// rows of instruments starting with `prefix`).
fn documented_families(doc: &str, prefix: &str) -> BTreeSet<String> {
    let section = doc
        .split("\n## ")
        .find(|s| s.starts_with("Metrics\n"))
        .unwrap_or_default();
    section
        .lines()
        .filter(|line| line.starts_with(&format!("| `{prefix}")))
        .filter_map(|line| line.split('|').nth(2))
        .map(|cell| cell.trim().trim_matches('`').to_owned())
        .collect()
}

/// `GET /metrics` with `host`, HTTP/1.1: the status and the body.
async fn get(addr: std::net::SocketAddr, host: &str) -> TestResult<(u16, String)> {
    let mut stream = TcpStream::connect(addr).await?;
    let request = format!("GET /metrics HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

/// A server with its token exchange: Kubernetes tokens map to
/// `k8s/<namespace>/<service account>`.
struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    secrets: Arc<Secrets>,
    issuer: TokenIssuer,
    dir: std::path::PathBuf,
    addr: std::net::SocketAddr,
    exchange: std::net::SocketAddr,
    serving: Vec<tokio::task::JoinHandle<()>>,
}

impl Env {
    async fn new() -> TestResult<Self> {
        let keys = TestDatabase::new(
            "KEYS_DATABASE_URL",
            "ferritor_agent_metrics_test",
            &ferritor_keystore::MIGRATOR,
        )
        .await?;
        let data = TestDatabase::new(
            "DATA_DATABASE_URL",
            "ferritor_agent_metrics_test",
            &ferritor_datastore::MIGRATOR,
        )
        .await?;
        let seal = Arc::new(Seal::new(Keystore::new(keys.pool().clone())));
        let shares = seal.init(ShareParams::new(3, 2)?).await?;
        for share in &shares[..2] {
            seal.unseal(&share.to_bytes(), false).await?;
        }
        seal.identity_init().await?;
        Namespaces::new(Arc::clone(&seal), Datastore::new(data.pool().clone()))
            .create("billing", &Labels::new())
            .await?;
        let gate = Arc::new(Gate::new(
            Arc::new(Grants) as Arc<dyn Authorizer>,
            AuditLog::new(Captured::default(), Duration::from_secs(5))?,
        ));
        let secrets = Arc::new(Secrets::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
            Arc::clone(&gate),
        ));
        let dir = std::env::temp_dir().join(format!("ferritor-metrics-e2e-{}", std::process::id()));
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
                            require: Vec::new(),
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
        let mut serving = Vec::new();
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
        Ok(Self {
            keys,
            data,
            secrets,
            issuer,
            dir,
            addr,
            exchange: exchange_addr,
            serving,
        })
    }

    fn provider_config(&self) -> TestResult<ProviderConfig> {
        Ok(ProviderConfig::parse(&format!(
            "server = \"https://localhost:{}\"\nca = \"{}\"\nexchange = \"https://localhost:{}\"\n\
             socket = \"{}\"\nwatch = false\n",
            self.addr.port(),
            self.dir.join("ca.pem").display(),
            self.exchange.port(),
            self.dir.join("ferritor.sock").display(),
        ))?)
    }

    async fn put(&self, path: &str, value: &str) -> TestResult<u32> {
        let caller = Caller::Identity(SecretPath::parse(WRITER)?);
        Ok(self
            .secrets
            .put(&caller, path, value.as_bytes())
            .await?
            .version)
    }

    /// A service account token for `namespace/account`.
    fn token(&self, namespace: &str, account: &str) -> TestResult<String> {
        self.issuer.token(&json!({
            "sub": format!("system:serviceaccount:{namespace}:{account}"),
            "kubernetes.io": {"namespace": namespace, "serviceaccount": {"name": account}},
        }))
    }

    /// A `MountRequest` as the driver builds it for pod `pod`.
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

    async fn destroy(self) -> TestResult<()> {
        for serving in &self.serving {
            serving.abort();
        }
        std::fs::remove_dir_all(&self.dir).ok();
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}
