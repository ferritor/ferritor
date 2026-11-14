//! Metrics for Prometheus end to end: real operations through `Secrets`,
//! scraped from the metrics listener in plaintext (loopback) and over TLS
//! with a client CA. The families a scrape returns are exactly the ones
//! `running.md`'s table names, so the two can't drift. One test in its own
//! binary, since the meter provider is process-wide.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::Labels;
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate, PolicyReload};
use ferritor_server::authz::{Action, Authorizer, Caller, Denied, Target};
use ferritor_server::metrics;
use ferritor_server::namespaces::Namespaces;
use ferritor_server::seal::Seal;
use ferritor_server::secrets::{Secrets, SecretsError};
use ferritor_server::tls;
use ferritor_testkit::pki::{Ca, Pem};
use ferritor_testkit::{TestDatabase, TestResult};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_util::sync::CancellationToken;

const ANON: Caller = Caller::Unauthenticated;

/// The documentation the scrape is held to.
const RUNNING: &str = include_str!("../../../docs/src/content/docs/operations/running.md");

/// Allows everything but deleting.
struct NoDeletes;

impl Authorizer for NoDeletes {
    fn authorize(&self, caller: &Caller, action: Action, target: Target<'_>) -> Result<(), Denied> {
        if action == Action::Delete {
            return Err(Denied::new(caller, action, target));
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn prometheus_scrapes_every_documented_metric_and_no_path() {
    let (_provider, scrape) = metrics::init_prometheus();

    let ca = Ca::new().unwrap();
    let server = ca.server().unwrap();
    let crl = ca
        .crl(&[], OffsetDateTime::now_utc() + time::Duration::days(1))
        .unwrap();
    let server_tls = tls::server_tls(
        server.cert.as_bytes(),
        server.key.as_bytes(),
        ca.cert.as_bytes(),
        Some(crl.as_bytes()),
    )
    .unwrap();

    let env = Env::new().await.unwrap();
    let _gauges = metrics::observe(
        Arc::clone(&env.seal),
        Some(server_tls.clone()),
        Arc::clone(&env.gate),
    );
    let _watch_gauges = metrics::observe_watch(ferritor_server::watch::Watch::new());
    env.gate
        .reload_policy(PolicyReload::Skipped("dev mode: no policy"));
    env.secrets.put(&ANON, "app/db", b"x").await.unwrap();
    env.secrets.get(&ANON, "app/db", None).await.unwrap();
    assert!(env.secrets.get(&ANON, "app/missing", None).await.is_err());
    assert!(matches!(
        env.secrets.delete(&ANON, "app/db").await,
        Err(SecretsError::Denied(_))
    ));
    // The counters nothing above reaches, once each, so every family shows.
    let recorded = metrics::metrics();
    recorded.admin_outcome("rotate", "succeeded");
    recorded.audit_failure("lost");
    recorded.purged(1);
    recorded.rewrapped(1);
    recorded.handshake_failure("metrics", "failed");
    recorded.rate_limited("rate");
    recorded.rate_limit_waited(Duration::from_millis(3));
    recorded.exchange("k8s", "issued");
    recorded.watch_resync("lagged");
    recorded.auto_unseal("held");

    // Plaintext on loopback.
    let stop = CancellationToken::new();
    let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_addr = plain.local_addr().unwrap();
    let plain_serving = tokio::spawn(tls::serve_metrics(
        scrape.clone().router(),
        plain,
        None,
        stop.clone().cancelled_owned(),
    ));
    let (status, unsealed) = get(connect(plain_addr).await.unwrap(), "localhost").await;
    assert_eq!(status, 200, "{unsealed}");

    // Exactly the documented families, under their Prometheus names.
    let documented = documented_families().unwrap();
    assert_eq!(families(&unsealed), documented);
    assert_eq!(documented.len(), 29);
    let line = |body: &str, prefix: &str| {
        body.lines()
            .find(|l| l.starts_with(prefix))
            .map(str::to_owned)
    };
    assert_eq!(
        line(&unsealed, "ferritor_sealed ").as_deref(),
        Some("ferritor_sealed 0")
    );
    assert!(
        unsealed
            .contains("ferritor_secret_requests_total{operation=\"delete\",result=\"denied\"} 1\n")
    );
    assert!(unsealed.contains(
        "ferritor_secret_request_duration_seconds_count{operation=\"get\",result=\"ok\"} 1\n"
    ));
    assert!(unsealed.contains("# TYPE ferritor_secret_request_duration_seconds histogram\n"));
    assert!(unsealed.contains("ferritor_namespaces 1\n"));
    // A scrape is no request: nothing in flight while it's answered.
    assert!(unsealed.contains("ferritor_in_flight 0\n"));
    // Never a path, a namespace's name or a value.
    assert!(!unsealed.contains("app/") && !unsealed.contains("\"app\""));

    // Not addressed to loopback (DNS rebinding): refused.
    let (status, _) = get(
        connect(plain_addr).await.unwrap(),
        "metrics.attacker.example",
    )
    .await;
    assert_eq!(status, 421);

    // The sealed gauge flips; what needs the keys goes.
    env.seal.seal().await;
    let (_, sealed) = get(connect(plain_addr).await.unwrap(), "127.0.0.1").await;
    assert_eq!(
        line(&sealed, "ferritor_sealed ").as_deref(),
        Some("ferritor_sealed 1")
    );
    assert!(!sealed.contains("ferritor_namespaces "));

    // Over TLS with the server's certificate and a client CA of its own.
    let scrapers = Ca::named("scrapers").unwrap();
    let secured = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secured_addr = secured.local_addr().unwrap();
    let secured_serving = tokio::spawn(tls::serve_metrics(
        scrape.clone().router(),
        secured,
        Some(
            server_tls
                .for_metrics(Some(scrapers.cert.as_bytes()))
                .unwrap(),
        ),
        stop.clone().cancelled_owned(),
    ));
    let scraper = scrapers.client("prometheus").unwrap();
    let stream = tls_connect(secured_addr, &ca, Some(&scraper))
        .await
        .unwrap();
    let (status, body) = get(stream, "localhost").await;
    assert_eq!(status, 200);
    // Any host: TLS needs no loopback check.
    assert!(body.contains("ferritor_sealed 1\n"));
    // No client certificate, or one from the main client CA: no scrape.
    for presented in [None, Some(ca.client("ops/alice").unwrap())] {
        let refused = match tls_connect(secured_addr, &ca, presented.as_ref()).await {
            Err(_) => true,
            Ok(stream) => get(stream, "localhost").await.0 != 200,
        };
        assert!(refused);
    }
    // TLS without a client CA: anyone may scrape.
    let open = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let open_addr = open.local_addr().unwrap();
    let open_serving = tokio::spawn(tls::serve_metrics(
        scrape.router(),
        open,
        Some(server_tls.for_metrics(None).unwrap()),
        stop.clone().cancelled_owned(),
    ));
    let stream = tls_connect(open_addr, &ca, None).await.unwrap();
    assert_eq!(get(stream, "localhost").await.0, 200);

    stop.cancel();
    for serving in [plain_serving, secured_serving, open_serving] {
        serving.await.unwrap().unwrap();
    }
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

/// The Prometheus column of `running.md`'s metrics table (its "Metrics"
/// section only).
fn documented_families() -> TestResult<BTreeSet<String>> {
    let section = RUNNING
        .split("\n## ")
        .find(|s| s.starts_with("Metrics\n"))
        .ok_or("running.md has no Metrics section")?;
    Ok(section
        .lines()
        .filter(|line| line.starts_with("| `ferritor."))
        .filter_map(|line| line.split('|').nth(2))
        .map(|cell| cell.trim().trim_matches('`').to_owned())
        .collect())
}

async fn connect(addr: std::net::SocketAddr) -> TestResult<TcpStream> {
    Ok(TcpStream::connect(addr).await?)
}

/// A TLS connection trusting `server_ca`, presenting `client` if given; an
/// error if the handshake fails.
async fn tls_connect(
    addr: std::net::SocketAddr,
    server_ca: &Ca,
    client: Option<&Pem>,
) -> TestResult<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(server_ca.cert.as_bytes())?)?;
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let config = match client {
        None => builder.with_no_client_auth(),
        Some(client) => builder.with_client_auth_cert(
            CertificateDer::pem_slice_iter(client.cert.as_bytes())
                .collect::<Result<Vec<_>, _>>()?,
            PrivateKeyDer::from_pem_slice(client.key.as_bytes())?,
        )?,
    };
    Ok(TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost")?, connect(addr).await?)
        .await?)
}

/// `GET /metrics` with `host`, HTTP/1.1: the status and the body (status 0
/// if the connection gave no answer).
async fn get(mut stream: impl AsyncRead + AsyncWrite + Unpin, host: &str) -> (u16, String) {
    let request = format!("GET /metrics HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).await.is_err() {
        return (0, String::new());
    }
    let mut raw = Vec::new();
    // A peer that closes without TLS's close_notify still sent its answer.
    let _ = stream.read_to_end(&mut raw).await;
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
    (status, body)
}

/// An initialized, unsealed server with secrets wired up.
struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    seal: Arc<Seal>,
    gate: Arc<Gate>,
    secrets: Secrets,
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
        let shares = seal.init(ShareParams::new(3, 2)?).await?;
        for share in &shares[..2] {
            seal.unseal(&share.to_bytes(), false).await?;
        }
        Namespaces::new(Arc::clone(&seal), Datastore::new(data.pool().clone()))
            .create("app", &Labels::new())
            .await?;
        let gate = Arc::new(Gate::new(
            Arc::new(NoDeletes),
            AuditLog::new(std::io::sink(), Duration::from_secs(5))?,
        ));
        let secrets = Secrets::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
            Arc::clone(&gate),
        );
        Ok(Self {
            keys,
            data,
            seal,
            gate,
            secrets,
        })
    }

    async fn destroy(self) -> TestResult<()> {
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}
