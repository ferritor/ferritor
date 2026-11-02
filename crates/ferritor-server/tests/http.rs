//! The JSON API over real connections, served the way `main` serves it: on
//! the same port as gRPC, through `tls::serve`. Plaintext HTTP/1.1 in dev
//! mode; with TLS, client certificates and a policy, over HTTP/1.1 and
//! HTTP/2 both (the client picks via ALPN).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::Labels;
use ferritor_core::proto::v1 as pb;
use ferritor_core::proto::v1::secrets_service_client::SecretsServiceClient;
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{Action, AllowAll, Authorizer, StoredPolicies};
use ferritor_server::health::{Readiness, SECRETS_SERVICE};
use ferritor_server::namespaces::Namespaces;
use ferritor_server::policies::Policies;
use ferritor_server::policy::{Policy, Rule};
use ferritor_server::ratelimit::{Clock, Limits, QUIET, Quota, Rate, SystemClock};
use ferritor_server::seal::Seal;
use ferritor_server::secrets::{MAX_VALUE_SIZE, Secrets};
use ferritor_server::{grpc, http, tls};
use ferritor_testkit::pki::{Ca, Pem};
use ferritor_testkit::{Captured, TestDatabase, TestResult};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{HeaderMap, Method, Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tonic::service::Routes;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

/// An unsealed server: the JSON API and gRPC's `SecretsService`.
struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    seal: Arc<Seal>,
    readiness: Arc<Readiness>,
    /// Two of them unseal.
    shares: Vec<Vec<u8>>,
    addr: SocketAddr,
    audit: Captured,
    gate: Arc<Gate>,
    serving: JoinHandle<()>,
}

impl Env {
    async fn start(
        bind: &str,
        tls_config: Option<tls::ServerTls>,
        authz: Arc<dyn Authorizer>,
    ) -> TestResult<Self> {
        Self::start_limited(bind, tls_config, authz, None, Arc::new(SystemClock)).await
    }

    async fn start_limited(
        bind: &str,
        tls_config: Option<tls::ServerTls>,
        authz: Arc<dyn Authorizer>,
        limits: Option<Limits>,
        clock: Arc<dyn Clock>,
    ) -> TestResult<Self> {
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
        let shares: Vec<Vec<u8>> = seal
            .init(ShareParams::new(3, 2)?)
            .await?
            .iter()
            .map(|share| share.to_bytes().to_vec())
            .collect();
        for share in &shares[..2] {
            seal.unseal(share, false).await?;
        }
        let namespaces = Namespaces::new(Arc::clone(&seal), Datastore::new(data.pool().clone()));
        for name in ["app", "billing", "other"] {
            namespaces.create(name, &Labels::new()).await?;
        }
        let audit = Captured::default();
        let gate = Arc::new(Gate::with_clock(
            authz,
            AuditLog::new(audit.clone(), Duration::from_secs(5))?,
            clock,
        ));
        if let Some(limits) = limits {
            gate.use_limits(limits, Duration::from_secs(10));
        }
        let secrets = Arc::new(Secrets::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
            Arc::clone(&gate),
        ));
        gate.use_stored_policies(Arc::clone(&seal) as Arc<dyn StoredPolicies>);
        let policies = Arc::new(Policies::new(Arc::clone(&seal), Arc::clone(&gate)));
        let listener = TcpListener::bind(bind).await?;
        let addr = listener.local_addr()?;
        let age = Duration::from_secs(600);
        let readiness = Readiness::new(Arc::clone(&seal));
        let routes = Routes::from(http::router(
            Arc::clone(&secrets),
            Arc::clone(&readiness),
            Arc::clone(&policies),
        ))
        .add_service(readiness.grpc().await)
        .add_service(grpc::secrets_service(secrets))
        .add_service(grpc::policy_service(policies));
        let serving = tokio::spawn(async move {
            tls::serve(
                tls::server(age, age),
                routes,
                listener,
                tls_config,
                std::future::pending(),
            )
            .await
            .ok();
        });
        Ok(Self {
            keys,
            data,
            seal,
            readiness,
            shares,
            addr,
            audit,
            gate,
            serving,
        })
    }

    /// [`Env::secured`], with rate limits.
    async fn limited(ca: &Ca, policy: &[Rule], limits: Limits) -> TestResult<Self> {
        Self::limited_on(ca, policy, limits, Arc::new(SystemClock)).await
    }

    /// [`Env::limited`] with the limiter's clock stopped: no budget or
    /// bucket refills while the test runs, however slow the machine.
    async fn limited_frozen(ca: &Ca, policy: &[Rule], limits: Limits) -> TestResult<Self> {
        Self::limited_on(ca, policy, limits, Arc::new(Frozen(Instant::now()))).await
    }

    async fn limited_on(
        ca: &Ca,
        policy: &[Rule],
        limits: Limits,
        clock: Arc<dyn Clock>,
    ) -> TestResult<Self> {
        let pem = ca.server()?;
        let tls_config = tls::server_tls(
            pem.cert.as_bytes(),
            pem.key.as_bytes(),
            ca.cert.as_bytes(),
            None,
        )?;
        Self::start_limited(
            "127.0.0.1:0",
            Some(tls_config),
            Arc::new(Policy::new(policy)?),
            Some(limits),
            clock,
        )
        .await
    }

    /// Like [`Env::secured`], with handshake limits.
    async fn secured_with_limits(
        ca: &Ca,
        policy: &[Rule],
        max_handshakes: usize,
        handshake_timeout: Duration,
    ) -> TestResult<Self> {
        let pem = ca.server()?;
        let tls_config = tls::server_tls(
            pem.cert.as_bytes(),
            pem.key.as_bytes(),
            ca.cert.as_bytes(),
            None,
        )?
        .with_handshake_limits(max_handshakes, handshake_timeout);
        Self::start(
            "127.0.0.1:0",
            Some(tls_config),
            Arc::new(Policy::new(policy)?),
        )
        .await
    }

    async fn plaintext() -> TestResult<Self> {
        Self::start("127.0.0.1:0", None, Arc::new(AllowAll)).await
    }

    /// TLS, client certificates from `ca`, and `policy`.
    async fn secured(ca: &Ca, policy: &[Rule]) -> TestResult<Self> {
        let pem = ca.server()?;
        let tls_config = tls::server_tls(
            pem.cert.as_bytes(),
            pem.key.as_bytes(),
            ca.cert.as_bytes(),
            None,
        )?;
        Self::start(
            "127.0.0.1:0",
            Some(tls_config),
            Arc::new(Policy::new(policy)?),
        )
        .await
    }

    async fn destroy(self) -> TestResult<()> {
        self.serving.abort();
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

/// How a test client talks: plaintext HTTP/1.1, or TLS offering exactly
/// one ALPN protocol (`http/1.1` or `h2`) with an optional client
/// certificate.
#[derive(Clone)]
enum Client {
    Plain,
    Tls {
        connector: TlsConnector,
        alpn: &'static [u8],
    },
}

impl Client {
    fn tls(ca: &Ca, identity: Option<&Pem>, alpn: &'static [u8]) -> TestResult<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from_pem_slice(ca.cert.as_bytes())?)?;
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots);
        let mut config = match identity {
            Some(pem) => builder.with_client_auth_cert(
                CertificateDer::pem_slice_iter(pem.cert.as_bytes()).collect::<Result<_, _>>()?,
                PrivateKeyDer::from_pem_slice(pem.key.as_bytes())?,
            )?,
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![alpn.to_vec()];
        Ok(Self::Tls {
            connector: TlsConnector::from(Arc::new(config)),
            alpn,
        })
    }

    /// One request on a fresh connection: status, headers, JSON body (or
    /// `Null` if empty).
    async fn send(
        &self,
        addr: SocketAddr,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> TestResult<(StatusCode, HeaderMap, Value)> {
        let authority = format!("localhost:{}", addr.port());
        self.send_raw(addr, &authority, method, uri, body.map(|b| b.to_string()))
            .await
    }

    /// [`Client::send`] addressed to `authority`, with a JSON body as is.
    async fn send_raw(
        &self,
        addr: SocketAddr,
        authority: &str,
        method: Method,
        uri: &str,
        body: Option<String>,
    ) -> TestResult<(StatusCode, HeaderMap, Value)> {
        let content_type = body.is_some().then_some("application/json");
        self.send_typed(addr, authority, method, uri, body, content_type)
            .await
    }

    /// [`Client::send_raw`] with any content type (or none).
    async fn send_typed(
        &self,
        addr: SocketAddr,
        authority: &str,
        method: Method,
        uri: &str,
        body: Option<String>,
        content_type: Option<&str>,
    ) -> TestResult<(StatusCode, HeaderMap, Value)> {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("http://{authority}{uri}"));
        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }
        let request = request.body(Full::new(Bytes::from(body.unwrap_or_default())))?;
        let tcp = TcpStream::connect(addr).await?;
        let response = match self {
            Self::Plain => http1(TokioIo::new(tcp), request).await?,
            Self::Tls { connector, alpn } => {
                let stream = connector
                    .connect(ServerName::try_from("localhost")?, tcp)
                    .await?;
                // The server picked the one protocol offered.
                assert_eq!(stream.get_ref().1.alpn_protocol(), Some(*alpn));
                if *alpn == b"h2" {
                    let (mut sender, connection) = hyper::client::conn::http2::handshake(
                        TokioExecutor::new(),
                        TokioIo::new(stream),
                    )
                    .await?;
                    tokio::spawn(connection);
                    sender.send_request(request).await?
                } else {
                    http1(TokioIo::new(stream), request).await?
                }
            }
        };
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await?.to_bytes();
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        Ok((status, headers, json))
    }
}

async fn http1<IO>(
    io: IO,
    request: Request<Full<Bytes>>,
) -> TestResult<hyper::Response<hyper::body::Incoming>>
where
    IO: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(connection);
    Ok(sender.send_request(request).await?)
}

fn put_body(value: &[u8]) -> Option<Value> {
    Some(json!({ "value": STANDARD.encode(value) }))
}

/// `(status, code)` of an error reply.
fn error(reply: &(StatusCode, HeaderMap, Value)) -> (StatusCode, String) {
    let code = reply.2["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    (reply.0, code)
}

#[tokio::test]
async fn crud_over_plain_http1() {
    let env = Env::plaintext().await.unwrap();
    let c = Client::Plain;
    let addr = env.addr;

    let value = b"s3cr\x00et\n";
    let (status, headers, first) = c
        .send(addr, Method::PUT, "/v1/secrets/app/db", put_body(b"old"))
        .await
        .unwrap();
    assert_eq!((status, &first["version"]), (StatusCode::OK, &json!(1)));
    assert_eq!(headers["cache-control"], "no-store");
    assert!(first.get("value").is_none());
    let (_, _, second) = c
        .send(addr, Method::PUT, "/v1/secrets/app/db", put_body(value))
        .await
        .unwrap();
    assert_eq!(second["version"], 2);

    let (status, headers, latest) = c
        .send(addr, Method::GET, "/v1/secrets/app/db", None)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(
        (&latest["path"], &latest["version"]),
        (&json!("app/db"), &json!(2))
    );
    assert_eq!(
        STANDARD.decode(latest["value"].as_str().unwrap()).unwrap(),
        value
    );
    let created_at = latest["created_at"].as_str().unwrap();
    assert!(
        created_at.ends_with('Z') && created_at.len() == 20,
        "{created_at}"
    );
    let (_, _, old) = c
        .send(addr, Method::GET, "/v1/secrets/app/db?version=1", None)
        .await
        .unwrap();
    assert_eq!(
        STANDARD.decode(old["value"].as_str().unwrap()).unwrap(),
        b"old"
    );

    // Listing, a page at a time.
    c.send(addr, Method::PUT, "/v1/secrets/app/other", put_body(b"x"))
        .await
        .unwrap();
    let (_, _, page) = c
        .send(
            addr,
            Method::GET,
            "/v1/secrets?prefix=app&page_size=1",
            None,
        )
        .await
        .unwrap();
    assert_eq!(page["secrets"][0]["path"], "app/db");
    assert!(page["secrets"][0].get("value").is_none());
    let token = page["next_page_token"].as_str().unwrap();
    let (_, _, rest) = c
        .send(
            addr,
            Method::GET,
            &format!("/v1/secrets?prefix=app&page_size=1&page_token={token}"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(rest["secrets"][0]["path"], "app/other");
    assert_eq!(rest["next_page_token"], "");
    let (_, _, all) = c
        .send(addr, Method::GET, "/v1/secrets", None)
        .await
        .unwrap();
    assert_eq!(all["secrets"].as_array().map(Vec::len), Some(2));

    let (status, _, body) = c
        .send(addr, Method::DELETE, "/v1/secrets/app/db", None)
        .await
        .unwrap();
    assert_eq!((status, body), (StatusCode::NO_CONTENT, Value::Null));
    let gone = c
        .send(addr, Method::GET, "/v1/secrets/app/db", None)
        .await
        .unwrap();
    assert_eq!(
        error(&gone),
        (StatusCode::NOT_FOUND, "not_found".to_owned())
    );
    assert_eq!(gone.2["error"]["message"], "secret `app/db` not found");
    env.destroy().await.unwrap();
}

/// Bad input is a 4xx with the JSON error shape; nothing guesses.
#[tokio::test]
async fn bad_requests_are_refused_as_json() {
    let env = Env::plaintext().await.unwrap();
    let c = Client::Plain;
    let addr = env.addr;
    let bad = StatusCode::BAD_REQUEST;
    let invalid = |reply| error(&reply) == (bad, "invalid_argument".to_owned());

    for uri in [
        "/v1/secrets/app//db",
        "/v1/secrets/app/db?version=0",
        // A typo must not quietly read the latest version.
        "/v1/secrets/app/db?verison=2",
        "/v1/secrets?prefix=app&page_token=zz",
    ] {
        assert!(
            invalid(c.send(addr, Method::GET, uri, None).await.unwrap()),
            "{uri}"
        );
    }
    let put = |body| c.send(addr, Method::PUT, "/v1/secrets/app/db", body);
    assert!(invalid(
        put(Some(json!({"value": "not base64!"}))).await.unwrap()
    ));
    // Valid JSON, but not the expected shape: axum's 422, kept.
    let unknown_field = put(Some(json!({"value": "eA==", "version": 3})))
        .await
        .unwrap();
    assert_eq!(
        error(&unknown_field),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_argument".to_owned()
        )
    );
    // No JSON content type.
    let unsupported = c
        .send(addr, Method::PUT, "/v1/secrets/app/db", None)
        .await
        .unwrap();
    assert_eq!(unsupported.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let nowhere = c
        .send(addr, Method::GET, "/v2/secrets", None)
        .await
        .unwrap();
    assert_eq!(
        error(&nowhere),
        (StatusCode::NOT_FOUND, "not_found".to_owned())
    );
    let wrong_method = c
        .send(addr, Method::POST, "/v1/secrets/app/db", None)
        .await
        .unwrap();
    assert_eq!(wrong_method.0, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(wrong_method.1["cache-control"], "no-store");

    // Nothing was stored by any of it.
    let (_, _, all) = c
        .send(addr, Method::GET, "/v1/secrets", None)
        .await
        .unwrap();
    assert_eq!(all["secrets"], json!([]));
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn a_sealed_server_answers_503_sealed() {
    let env = Env::plaintext().await.unwrap();
    env.seal.seal().await;
    let reply = Client::Plain
        .send(env.addr, Method::GET, "/v1/secrets/app/db", None)
        .await
        .unwrap();
    assert_eq!(
        error(&reply),
        (StatusCode::SERVICE_UNAVAILABLE, "sealed".to_owned())
    );
    assert_eq!(reply.2["error"]["message"], ferritor_core::messages::SEALED);
    env.destroy().await.unwrap();
}

/// gRPC health over plaintext: the status of `service` (`""`: overall).
async fn grpc_health(addr: SocketAddr, service: &str) -> TestResult<i32> {
    use tonic_health::pb::HealthCheckRequest;
    use tonic_health::pb::health_client::HealthClient;

    let channel = Endpoint::from_shared(format!("http://localhost:{}", addr.port()))?
        .connect()
        .await?;
    let reply = HealthClient::new(channel)
        .check(HealthCheckRequest {
            service: service.to_owned(),
        })
        .await?;
    Ok(reply.into_inner().status)
}

/// Waits for gRPC health to report `want` for `service`: the health
/// service follows the seal in a task of its own, a moment later.
async fn grpc_health_becomes(addr: SocketAddr, service: &str, want: i32) -> TestResult<()> {
    for _ in 0..200 {
        if grpc_health(addr, service).await? == want {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("health of {service:?} never became {want}").into())
}

/// The readiness check: `ferritor.v1.SecretsService` is SERVING only while
/// unsealed and not shutting down, over gRPC and `GET /v1/health` alike,
/// while the overall gRPC status (the CLI's preflight, a liveness check)
/// stays SERVING. Set from the start (never "unknown service"). Neither
/// asks the authorizer or writes an audit entry.
#[tokio::test]
async fn health_reports_a_sealed_server_as_not_ready() {
    use tonic_health::ServingStatus;

    let env = Env::plaintext().await.unwrap();
    let (serving, not_serving) = (
        ServingStatus::Serving as i32,
        ServingStatus::NotServing as i32,
    );
    let ready = |ready: bool, sealed: bool| {
        let status = if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        (status, json!({"ready": ready, "sealed": sealed}))
    };
    let http = || async {
        let (status, _, body) = Client::Plain
            .send(env.addr, Method::GET, "/v1/health", None)
            .await
            .unwrap();
        (status, body)
    };

    assert_eq!(
        grpc_health(env.addr, SECRETS_SERVICE).await.unwrap(),
        serving
    );
    assert_eq!(grpc_health(env.addr, "").await.unwrap(), serving);
    assert_eq!(http().await, ready(true, false));

    env.seal.seal().await;
    assert_eq!(http().await, ready(false, true));
    grpc_health_becomes(env.addr, SECRETS_SERVICE, not_serving)
        .await
        .unwrap();
    assert_eq!(grpc_health(env.addr, "").await.unwrap(), serving);

    for share in &env.shares[..2] {
        env.seal.unseal(share, false).await.unwrap();
    }
    assert_eq!(http().await, ready(true, false));
    grpc_health_becomes(env.addr, SECRETS_SERVICE, serving)
        .await
        .unwrap();

    // Shutting down: not ready any more, while still serving the drain.
    env.readiness.shutting_down();
    assert_eq!(http().await, ready(false, false));
    grpc_health_becomes(env.addr, SECRETS_SERVICE, not_serving)
        .await
        .unwrap();
    assert_eq!(grpc_health(env.addr, "").await.unwrap(), serving);
    assert!(env.audit.lines().is_empty(), "{:?}", env.audit.lines());
    env.destroy().await.unwrap();
}

/// In secured mode too, with a certificate the policy grants nothing: the
/// one bit needs no permission (the handshake still needs a certificate).
#[tokio::test]
async fn the_http_health_check_needs_no_permission() {
    let ca = Ca::new().unwrap();
    let env = Env::secured(&ca, &billing_policy()).await.unwrap();
    let nobody = ca.client("apps/nobody").unwrap();
    let c = Client::tls(&ca, Some(&nobody), b"http/1.1").unwrap();
    let (status, headers, body) = c
        .send(env.addr, Method::GET, "/v1/health", None)
        .await
        .unwrap();
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({"ready": true, "sealed": false}))
    );
    assert_eq!(headers["cache-control"], "no-store");
    assert!(env.audit.lines().is_empty(), "{:?}", env.audit.lines());
    env.destroy().await.unwrap();
}

fn billing_policy() -> Vec<Rule> {
    vec![Rule {
        name: None,
        identity: "apps/billing".to_owned(),
        actions: vec![Action::Read, Action::Write, Action::List],
        paths: vec!["billing".to_owned()],
        all_paths: false,
    }]
}

/// The policy decides per identity, over HTTP/1.1-only and HTTP/2-only
/// clients alike, and gRPC on the same port sees the same data.
#[tokio::test]
async fn tls_with_a_client_certificate_over_http1_and_h2() {
    let ca = Ca::new().unwrap();
    let env = Env::secured(&ca, &billing_policy()).await.unwrap();
    let billing = ca.client("apps/billing").unwrap();
    let addr = env.addr;

    for alpn in [&b"http/1.1"[..], b"h2"] {
        let c = Client::tls(&ca, Some(&billing), alpn).unwrap();
        let (status, _, _) = c
            .send(addr, Method::PUT, "/v1/secrets/billing/db", put_body(b"x"))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        let outside = c
            .send(addr, Method::GET, "/v1/secrets/other/db", None)
            .await
            .unwrap();
        assert_eq!(
            error(&outside),
            (StatusCode::FORBIDDEN, "permission_denied".to_owned())
        );
        assert_eq!(
            outside.2["error"]["message"],
            "permission denied: caller `apps/billing` may not read `other/db`"
        );
    }

    // gRPC on the same port, same identity, same data.
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&ca.cert))
        .identity(Identity::from_pem(&billing.cert, &billing.key));
    let channel = Endpoint::from_shared(format!("https://localhost:{}", addr.port()))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect_lazy();
    let read = SecretsServiceClient::new(channel)
        .get_secret(pb::GetSecretRequest {
            path: "billing/db".to_owned(),
            version: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        read.secret.and_then(|s| s.metadata).map(|m| m.version),
        Some(2)
    );

    // Every HTTP decision is in the audit log, with the identity.
    let audited: Vec<(String, String, String)> = env
        .audit
        .lines()
        .iter()
        .map(|line| {
            let e: Value = serde_json::from_str(line).unwrap();
            let s = |v: &Value| v.as_str().unwrap_or_default().to_owned();
            // A decision, or a write's outcome.
            let verdict = if e["event"] == "outcome" {
                &e["result"]
            } else {
                &e["decision"]
            };
            (s(&e["caller"]), s(&e["action"]), s(verdict))
        })
        .collect();
    let entry = |action: &str, decision: &str| {
        (
            "apps/billing".to_owned(),
            action.to_owned(),
            decision.to_owned(),
        )
    };
    assert_eq!(
        audited,
        [
            entry("write", "allowed"),
            entry("write", "succeeded"),
            entry("read", "denied"),
            entry("write", "allowed"),
            entry("write", "succeeded"),
            entry("read", "denied"),
            entry("read", "allowed"),
        ]
    );
    env.destroy().await.unwrap();
}

/// A path's history takes `list`, not `read`: a metadata-only identity
/// sees it but not the value, and the audit log records it as `list` on the
/// path, never as a read.
#[tokio::test]
async fn a_list_only_identity_sees_the_history_but_not_the_value() {
    let ca = Ca::new().unwrap();
    let mut policy = billing_policy();
    policy.push(Rule {
        name: None,
        identity: "apps/dashboard".to_owned(),
        actions: vec![Action::List],
        paths: vec!["billing".to_owned()],
        all_paths: false,
    });
    let env = Env::secured(&ca, &policy).await.unwrap();
    let addr = env.addr;
    let billing = Client::tls(&ca, Some(&ca.client("apps/billing").unwrap()), b"h2").unwrap();
    billing
        .send(addr, Method::PUT, "/v1/secrets/billing/db", put_body(b"x"))
        .await
        .unwrap();

    let dashboard = Client::tls(&ca, Some(&ca.client("apps/dashboard").unwrap()), b"h2").unwrap();
    let (status, _, history) = dashboard
        .send(addr, Method::GET, "/v1/versions/billing/db", None)
        .await
        .unwrap();
    assert_eq!(
        (status, &history["versions"][0]["version"]),
        (StatusCode::OK, &json!(1))
    );
    let value = dashboard
        .send(addr, Method::GET, "/v1/secrets/billing/db", None)
        .await
        .unwrap();
    assert_eq!(
        error(&value),
        (StatusCode::FORBIDDEN, "permission_denied".to_owned())
    );

    // The dashboard's decisions (each flushed before its request went on;
    // the writer's put outcome may land any time, so it's filtered out).
    let audited: Vec<(String, Value, String)> = env
        .audit
        .lines()
        .iter()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|e| e["event"] == "authorization" && e["caller"] == "apps/dashboard")
        .map(|e| {
            let s = |v: &Value| v.as_str().unwrap_or_default().to_owned();
            (s(&e["action"]), e["target"].clone(), s(&e["decision"]))
        })
        .collect();
    let target = json!({"kind": "path", "path": "billing/db"});
    assert_eq!(
        audited,
        [
            ("list".to_owned(), target.clone(), "allowed".to_owned()),
            ("read".to_owned(), target, "denied".to_owned()),
        ]
    );
    env.destroy().await.unwrap();
}

/// No certificate: refused at the handshake, before any HTTP.
#[tokio::test]
async fn without_a_client_certificate_there_is_no_connection() {
    let ca = Ca::new().unwrap();
    let env = Env::secured(&ca, &billing_policy()).await.unwrap();
    for alpn in [&b"http/1.1"[..], b"h2"] {
        let c = Client::tls(&ca, None, alpn).unwrap();
        assert!(
            c.send(env.addr, Method::GET, "/v1/secrets/billing/db", None)
                .await
                .is_err()
        );
    }
    assert!(env.audit.lines().is_empty());
    env.destroy().await.unwrap();
}

/// A certificate the CA signed but without a `ferritor://` identity gets
/// through the handshake, then a 401, recorded as a failed authentication.
#[tokio::test]
async fn a_certificate_without_an_identity_is_401_and_audited() {
    let ca = Ca::new().unwrap();
    let env = Env::secured(&ca, &billing_policy()).await.unwrap();
    let nameless = ca
        .issue(
            vec![ferritor_testkit::pki::uri("spiffe://apps/billing").unwrap()],
            vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth],
            None,
        )
        .unwrap();
    let c = Client::tls(&ca, Some(&nameless), b"http/1.1").unwrap();
    let reply = c
        .send(env.addr, Method::GET, "/v1/secrets/billing/db", None)
        .await
        .unwrap();
    assert_eq!(
        error(&reply),
        (StatusCode::UNAUTHORIZED, "unauthenticated".to_owned())
    );

    let mut lines = env.audit.lines();
    for _ in 0..100 {
        if !lines.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        lines = env.audit.lines();
    }
    let entry: Value = serde_json::from_str(&lines.concat()).unwrap();
    assert_eq!(
        (&entry["event"], &entry["action"], &entry["reason"]),
        (
            &json!("authentication"),
            &json!("read"),
            &json!("wrong_scheme")
        )
    );
    env.destroy().await.unwrap();
}

/// An HTTP/1.1 request as a browser sends it (origin-form target, `Host`
/// header), written by hand: status code and body.
async fn raw_get(addr: SocketAddr, host: &str, path: &str) -> TestResult<(u16, String)> {
    let mut tcp = TcpStream::connect(addr).await?;
    tcp.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut response = String::new();
    tcp.read_to_string(&mut response).await?;
    let status = response
        .split(' ')
        .nth(1)
        .ok_or("no status line")?
        .parse()?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

/// Dev mode allows everyone, so a page using DNS rebinding (its own name
/// resolving to 127.0.0.1) must get nothing: only requests addressed to
/// loopback are answered, on every route, gRPC's too, and a refused one
/// never reaches the authorizer.
#[tokio::test]
async fn dev_mode_answers_only_requests_addressed_to_loopback() {
    let env = Env::plaintext().await.unwrap();
    let port = env.addr.port();

    let (status, body) = raw_get(env.addr, &format!("attacker.example:{port}"), "/v1/secrets")
        .await
        .unwrap();
    assert_eq!(status, 421);
    assert!(body.contains("misdirected_request"), "{body}");
    // An absolute-form target names the host too.
    let absolute = Client::Plain
        .send_raw(
            env.addr,
            &format!("attacker.example:{port}"),
            Method::GET,
            "/v1/secrets",
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        error(&absolute),
        (
            StatusCode::MISDIRECTED_REQUEST,
            "misdirected_request".to_owned()
        )
    );
    // gRPC on the same port, under a foreign :authority.
    let foreign = Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
        .unwrap()
        .origin(format!("http://attacker.example:{port}").parse().unwrap())
        .connect_lazy();
    let put = pb::PutSecretRequest {
        path: "app/db".to_owned(),
        value: b"x".to_vec(),
        expected_version: None,
        labels: Default::default(),
    };
    assert!(
        SecretsServiceClient::new(foreign)
            .put_secret(put.clone())
            .await
            .is_err()
    );
    assert!(env.audit.lines().is_empty());

    // Loopback, by any of its names, with or without a port.
    for host in [
        format!("localhost:{port}"),
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
        "localhost".to_owned(),
    ] {
        let (status, body) = raw_get(env.addr, &host, "/v1/secrets").await.unwrap();
        assert_eq!(status, 200, "{host}: {body}");
    }
    let local = Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
        .unwrap()
        .connect_lazy();
    SecretsServiceClient::new(local)
        .put_secret(put)
        .await
        .unwrap();
    // Four lists, and the put with its outcome (queued, not waited for);
    // the refused requests never got that far.
    for _ in 0..100 {
        if env.audit.lines().len() >= 6 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(env.audit.lines().len(), 6);
    env.destroy().await.unwrap();
}

/// Dev mode may listen on any loopback address, and then answers requests
/// addressed to it: the Host check follows the same rule as where it may
/// listen (an IP literal can't be used for DNS rebinding).
#[tokio::test]
async fn dev_mode_on_another_loopback_address_answers_its_own_requests() {
    let env = Env::start("127.0.0.2:0", None, Arc::new(AllowAll))
        .await
        .unwrap();
    let authority = format!("127.0.0.2:{}", env.addr.port());
    let (status, body) = raw_get(env.addr, &authority, "/v1/secrets").await.unwrap();
    assert_eq!(status, 200, "{body}");
    // gRPC, addressed the way the CLI would (`--addr http://127.0.0.2:…`).
    let channel = Endpoint::from_shared(format!("http://{authority}"))
        .unwrap()
        .connect_lazy();
    SecretsServiceClient::new(channel)
        .put_secret(pb::PutSecretRequest {
            path: "app/db".to_owned(),
            value: b"x".to_vec(),
            expected_version: None,
            labels: Default::default(),
        })
        .await
        .unwrap();
    env.destroy().await.unwrap();
}

/// Check-and-set over both APIs, on the same versions: JSON answers a
/// mismatch with 409 `version_mismatch`, gRPC with FAILED_PRECONDITION, and
/// neither stores anything then.
#[tokio::test]
async fn check_and_set_over_both_apis() {
    let env = Env::plaintext().await.unwrap();
    let c = Client::Plain;
    let addr = env.addr;
    let mut grpc = SecretsServiceClient::new(
        Endpoint::from_shared(format!("http://127.0.0.1:{}", addr.port()))
            .unwrap()
            .connect_lazy(),
    );
    let put =
        |expected: u32| Some(json!({"value": STANDARD.encode(b"x"), "expected_version": expected}));

    let (status, _, created) = c
        .send(addr, Method::PUT, "/v1/secrets/app/db", put(0))
        .await
        .unwrap();
    assert_eq!((status, &created["version"]), (StatusCode::OK, &json!(1)));
    let again = c
        .send(addr, Method::PUT, "/v1/secrets/app/db", put(0))
        .await
        .unwrap();
    assert_eq!(
        error(&again),
        (StatusCode::CONFLICT, "version_mismatch".to_owned())
    );
    assert_eq!(
        again.2["error"]["message"],
        "`app/db` was changed: its latest version is 1, expected none (create only); read it again"
    );

    let grpc_put = |expected| pb::PutSecretRequest {
        path: "app/db".to_owned(),
        value: b"y".to_vec(),
        expected_version: Some(expected),
        labels: Default::default(),
    };
    let stored = grpc.put_secret(grpc_put(1)).await.unwrap().into_inner();
    assert_eq!(stored.metadata.map(|m| m.version), Some(2));
    let stale = grpc.put_secret(grpc_put(1)).await.unwrap_err();
    assert_eq!(
        (stale.code(), stale.message()),
        (
            tonic::Code::FailedPrecondition,
            "`app/db` was changed: its latest version is 2, expected 1; read it again"
        )
    );
    // Programs tell it apart from a sealed server by the reason, not the
    // message.
    assert_eq!(
        grpc::reason_of(&stale).as_deref(),
        Some(ferritor_core::messages::reason::VERSION_MISMATCH)
    );
    let stale_json = c
        .send(addr, Method::PUT, "/v1/secrets/app/db", put(1))
        .await
        .unwrap();
    assert_eq!(stale_json.0, StatusCode::CONFLICT);

    let (_, _, latest) = c
        .send(addr, Method::GET, "/v1/secrets/app/db", None)
        .await
        .unwrap();
    assert_eq!(latest["version"], 2);
    env.destroy().await.unwrap();
}

/// Restore over both APIs: JSON needs a JSON body even for the newest
/// (`{}`), so it stays behind a CORS preflight; gRPC's version 0 is the
/// newest. Without a version, a live one refuses it (409 / LIVE_VERSION);
/// nothing to restore is a 404 / NOT_FOUND.
#[tokio::test]
async fn restore_over_both_apis() {
    let env = Env::plaintext().await.unwrap();
    let c = Client::Plain;
    let addr = env.addr;
    for value in [b"one", b"two"] {
        c.send(addr, Method::PUT, "/v1/secrets/app/db", put_body(value))
            .await
            .unwrap();
    }
    c.send(addr, Method::DELETE, "/v1/secrets/app/db", None)
        .await
        .unwrap();

    let (status, _, newest) = c
        .send(addr, Method::POST, "/v1/restore/app/db", Some(json!({})))
        .await
        .unwrap();
    assert_eq!((status, &newest["version"]), (StatusCode::OK, &json!(2)));
    let (status, _, older) = c
        .send(
            addr,
            Method::POST,
            "/v1/restore/app/db",
            Some(json!({"version": 1})),
        )
        .await
        .unwrap();
    assert_eq!((status, &older["version"]), (StatusCode::OK, &json!(1)));

    // Refused: version 0, no JSON body, the wrong method, a live version,
    // nothing to restore.
    let zero = c
        .send(
            addr,
            Method::POST,
            "/v1/restore/app/db",
            Some(json!({"version": 0})),
        )
        .await
        .unwrap();
    assert_eq!(
        error(&zero),
        (StatusCode::BAD_REQUEST, "invalid_argument".to_owned())
    );
    let no_body = c
        .send(addr, Method::POST, "/v1/restore/app/db", None)
        .await
        .unwrap();
    assert_eq!(no_body.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let get = c
        .send(addr, Method::GET, "/v1/restore/app/db", None)
        .await
        .unwrap();
    assert_eq!(get.0, StatusCode::METHOD_NOT_ALLOWED);
    let live = c
        .send(addr, Method::POST, "/v1/restore/app/db", Some(json!({})))
        .await
        .unwrap();
    assert_eq!(
        error(&live),
        (StatusCode::CONFLICT, "live_version".to_owned())
    );
    let nothing = c
        .send(addr, Method::POST, "/v1/restore/app/none", Some(json!({})))
        .await
        .unwrap();
    assert_eq!(
        error(&nothing),
        (StatusCode::NOT_FOUND, "not_found".to_owned())
    );

    // gRPC: version 0 is the newest deleted.
    c.send(addr, Method::DELETE, "/v1/secrets/app/db", None)
        .await
        .unwrap();
    let mut grpc = SecretsServiceClient::new(
        Endpoint::from_shared(format!("http://127.0.0.1:{}", addr.port()))
            .unwrap()
            .connect_lazy(),
    );
    let restored = grpc
        .restore_secret(pb::RestoreSecretRequest {
            path: "app/db".to_owned(),
            version: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(restored.metadata.map(|m| m.version), Some(2));
    let live = grpc
        .restore_secret(pb::RestoreSecretRequest {
            path: "app/db".to_owned(),
            version: 0,
        })
        .await
        .unwrap_err();
    assert_eq!(
        (live.code(), grpc::reason_of(&live).as_deref()),
        (
            tonic::Code::FailedPrecondition,
            Some(ferritor_core::messages::reason::LIVE_VERSION)
        )
    );
    let missing = grpc
        .restore_secret(pb::RestoreSecretRequest {
            path: "app/db".to_owned(),
            version: 2,
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
    env.destroy().await.unwrap();
}

/// The history over both APIs: newest first, `deleted_at` only on deleted
/// versions (RFC 3339 over JSON, Unix seconds over gRPC), metadata only.
#[tokio::test]
async fn versions_over_both_apis() {
    let env = Env::plaintext().await.unwrap();
    let c = Client::Plain;
    let addr = env.addr;
    c.send(addr, Method::PUT, "/v1/secrets/app/db", put_body(b"one"))
        .await
        .unwrap();
    c.send(addr, Method::DELETE, "/v1/secrets/app/db", None)
        .await
        .unwrap();
    c.send(addr, Method::PUT, "/v1/secrets/app/db", put_body(b"two"))
        .await
        .unwrap();

    let (status, _, body) = c
        .send(addr, Method::GET, "/v1/versions/app/db", None)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    let versions = body["versions"].as_array().unwrap();
    assert_eq!(
        versions
            .iter()
            .map(|v| (v["version"].clone(), v["deleted_at"].is_string()))
            .collect::<Vec<_>>(),
        [(json!(2), false), (json!(1), true)]
    );
    assert_eq!(versions[1]["path"], "app/db");
    assert!(versions[0]["deleted_at"].is_null());
    assert!(versions.iter().all(|v| v.get("value").is_none()));
    assert!(
        versions[1]["deleted_at"]
            .as_str()
            .is_some_and(|at| at.ends_with('Z'))
    );
    assert_eq!(body["next_page_token"], "");

    let (_, _, paged) = c
        .send(addr, Method::GET, "/v1/versions/app/db?page_size=1", None)
        .await
        .unwrap();
    let token = paged["next_page_token"].as_str().unwrap().to_owned();
    let (_, _, rest) = c
        .send(
            addr,
            Method::GET,
            &format!("/v1/versions/app/db?page_size=1&page_token={token}"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        (
            &paged["versions"][0]["version"],
            &rest["versions"][0]["version"]
        ),
        (&json!(2), &json!(1))
    );

    let missing = c
        .send(addr, Method::GET, "/v1/versions/app/none", None)
        .await
        .unwrap();
    assert_eq!(
        error(&missing),
        (StatusCode::NOT_FOUND, "not_found".to_owned())
    );
    let typo = c
        .send(addr, Method::GET, "/v1/versions/app/db?pagesize=1", None)
        .await
        .unwrap();
    assert_eq!(typo.0, StatusCode::BAD_REQUEST);

    let mut grpc = SecretsServiceClient::new(
        Endpoint::from_shared(format!("http://127.0.0.1:{}", addr.port()))
            .unwrap()
            .connect_lazy(),
    );
    let reply = grpc
        .list_versions(pb::ListVersionsRequest {
            path: "app/db".to_owned(),
            page_size: 0,
            page_token: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        reply
            .versions
            .iter()
            .map(|v| (
                v.metadata.as_ref().map(|m| m.version),
                v.deleted_at_unix.is_some()
            ))
            .collect::<Vec<_>>(),
        [(Some(2), false), (Some(1), true)]
    );
    env.destroy().await.unwrap();
}

/// One limit for both APIs: exactly `MAX_VALUE_SIZE` is stored either way,
/// and one byte more is refused by `Secrets` with the same message, not by
/// a transport limit that differs between them. The JSON body limit leaves
/// room even for an encoder that escapes every `/`.
#[tokio::test]
async fn both_apis_take_values_up_to_the_limit_and_refuse_beyond_alike() {
    let env = Env::plaintext().await.unwrap();
    let c = Client::Plain;
    let addr = env.addr;
    let mut grpc = SecretsServiceClient::new(
        Endpoint::from_shared(format!("http://127.0.0.1:{}", addr.port()))
            .unwrap()
            .connect_lazy(),
    );
    let refused = format!(
        "the value is {} bytes; at most {MAX_VALUE_SIZE} are allowed",
        MAX_VALUE_SIZE + 1
    );

    // All 0xff: base64 of nothing but `/`, each escaped as `\/`.
    let largest = vec![0xff_u8; MAX_VALUE_SIZE];
    let escaped = STANDARD.encode(&largest).replace('/', "\\/");
    let (status, _, stored) = c
        .send_raw(
            addr,
            &format!("localhost:{}", addr.port()),
            Method::PUT,
            "/v1/secrets/app/big",
            Some(format!("{{\"value\":\"{escaped}\"}}")),
        )
        .await
        .unwrap();
    assert_eq!((status, &stored["version"]), (StatusCode::OK, &json!(1)));
    let too_big = c
        .send(
            addr,
            Method::PUT,
            "/v1/secrets/app/big",
            put_body(&vec![0; MAX_VALUE_SIZE + 1]),
        )
        .await
        .unwrap();
    assert_eq!(
        error(&too_big),
        (StatusCode::BAD_REQUEST, "invalid_argument".to_owned())
    );
    assert_eq!(too_big.2["error"]["message"], refused.as_str());

    // gRPC reads what JSON wrote, writes the same size back, and refuses
    // one byte more alike.
    let read = grpc
        .get_secret(pb::GetSecretRequest {
            path: "app/big".to_owned(),
            version: 0,
        })
        .await
        .unwrap()
        .into_inner();
    let value = read.secret.map(|s| s.value).unwrap_or_default();
    assert_eq!(value, largest);
    grpc.put_secret(pb::PutSecretRequest {
        path: "app/big".to_owned(),
        value,
        expected_version: None,
        labels: Default::default(),
    })
    .await
    .unwrap();
    let status = grpc
        .put_secret(pb::PutSecretRequest {
            path: "app/big".to_owned(),
            value: vec![0; MAX_VALUE_SIZE + 1],
            expected_version: None,
            labels: Default::default(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        (status.code(), status.message()),
        (tonic::Code::InvalidArgument, refused.as_str())
    );
    env.destroy().await.unwrap();
}

/// Stalled handshakes take up slots, but only so many: past the limit a
/// new connection waits (in the kernel's backlog) until a slot frees, here
/// when a stalled one times out, and is then served.
#[tokio::test]
async fn handshakes_in_progress_are_capped() {
    let ca = Ca::new().unwrap();
    let timeout = Duration::from_secs(1);
    let env = Env::secured_with_limits(&ca, &billing_policy(), 2, timeout)
        .await
        .unwrap();
    let billing = ca.client("apps/billing").unwrap();
    let c = Client::tls(&ca, Some(&billing), b"http/1.1").unwrap();
    // Connected, but never sending a ClientHello.
    let _stalled = [
        TcpStream::connect(env.addr).await.unwrap(),
        TcpStream::connect(env.addr).await.unwrap(),
    ];
    tokio::time::sleep(Duration::from_millis(100)).await;

    let started = Instant::now();
    let (status, _, _) = c
        .send(env.addr, Method::GET, "/v1/secrets?prefix=billing", None)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    let waited = started.elapsed();
    assert!(
        waited >= timeout - Duration::from_millis(250),
        "served after {waited:?}: the cap didn't hold it back"
    );
    env.destroy().await.unwrap();
}

/// Metadata over the JSON API: labels set with a PUT, read and changed
/// under /v1/metadata, and a listing filtered with repeated `label=k=v`.
/// The hand-parsed query string still refuses what it doesn't know.
#[tokio::test]
async fn metadata_and_labels_over_json() {
    let env = Env::plaintext().await.unwrap();
    let c = Client::Plain;
    let send = |method: Method, uri: &'static str, body: Option<Value>| {
        let c = c.clone();
        let addr = env.addr;
        async move { c.send(addr, method, uri, body).await.unwrap() }
    };
    let (status, _, _) = send(
        Method::PUT,
        "/v1/secrets/app/a",
        Some(json!({"value": STANDARD.encode(b"x"), "labels": {"team": "a"}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = send(Method::PUT, "/v1/secrets/app/b", put_body(b"y")).await;
    assert_eq!(status, StatusCode::OK);

    let (status, headers, meta) = send(Method::GET, "/v1/metadata/app/a", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(
        (
            &meta["path"],
            &meta["current_version"],
            &meta["oldest_version"],
            &meta["versions"],
            &meta["labels"]
        ),
        (
            &json!("app/a"),
            &json!(1),
            &json!(1),
            &json!(1),
            &json!({"team": "a"})
        )
    );
    assert!(
        meta["created_at"]
            .as_str()
            .is_some_and(|t| t.ends_with('Z'))
    );
    assert!(meta["labels_updated_at"].is_string());
    let (_, _, plain) = send(Method::GET, "/v1/metadata/app/b", None).await;
    assert_eq!(
        (&plain["labels"], &plain["labels_updated_at"]),
        (&json!({}), &Value::Null)
    );

    let (status, _, changed) = send(
        Method::PATCH,
        "/v1/metadata/app/b",
        Some(json!({"set": {"team": "a", "env": "prod"}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(changed, json!({"labels": {"env": "prod", "team": "a"}}));
    let (_, _, changed) = send(
        Method::PATCH,
        "/v1/metadata/app/b",
        Some(json!({"remove": ["env"]})),
    )
    .await;
    assert_eq!(changed, json!({"labels": {"team": "a"}}));

    let paths = |listing: &Value| -> Vec<String> {
        listing["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["path"].as_str().unwrap().to_owned())
            .collect()
    };
    let (_, _, both) = send(Method::GET, "/v1/secrets?prefix=app&label=team%3Da", None).await;
    assert_eq!(paths(&both), ["app/a", "app/b"]);
    let (_, _, none) = send(
        Method::GET,
        "/v1/secrets?label=team%3Da&label=env%3Dprod",
        None,
    )
    .await;
    assert!(paths(&none).is_empty());

    for (uri, message) in [
        (
            "/v1/secrets?lable=team%3Da",
            "unknown query parameter `lable`",
        ),
        (
            "/v1/secrets?label=team",
            "`team` is not a `key=value` label",
        ),
        (
            "/v1/secrets?label=t%3Da&label=t%3Db",
            "label `t` is given twice",
        ),
        ("/v1/secrets?prefix=a&prefix=b", "`prefix` is given twice"),
    ] {
        let refused = send(Method::GET, uri, None).await;
        assert_eq!(
            error(&refused),
            (StatusCode::BAD_REQUEST, "invalid_argument".to_owned()),
            "{uri}"
        );
        assert!(
            refused.2["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains(message)),
            "{uri}: {}",
            refused.2
        );
    }
    let never = send(Method::GET, "/v1/metadata/app/never", None).await;
    assert_eq!(
        error(&never),
        (StatusCode::NOT_FOUND, "not_found".to_owned())
    );
    let bad = send(
        Method::PATCH,
        "/v1/metadata/app/a",
        Some(json!({"set": {"bad key": "x"}})),
    )
    .await;
    assert_eq!(error(&bad).0, StatusCode::BAD_REQUEST);
    // Nothing to set or remove: refused, not audited as a change.
    let empty = send(Method::PATCH, "/v1/metadata/app/a", Some(json!({}))).await;
    assert_eq!(
        error(&empty),
        (StatusCode::BAD_REQUEST, "invalid_argument".to_owned())
    );
    env.destroy().await.unwrap();
}

/// The largest put fits through both APIs: the largest value with the most
/// labels at their longest. Over HTTP escaped as badly as JSON allows: a
/// value of 0xFF bytes is all `/` in base64, each sent as `\/`, and every
/// label character as `\uXXXX`. So a put one API accepts, the other does
/// too (the transport limits are computed from the same constants).
#[tokio::test]
async fn the_largest_put_fits_through_both_apis() {
    use ferritor_core::labels::{MAX_KEY_LEN, MAX_LABELS, MAX_VALUE_LEN};

    let env = Env::plaintext().await.unwrap();
    let value = vec![0xFF_u8; MAX_VALUE_SIZE];
    let labels: Vec<(String, String)> = (0..MAX_LABELS)
        .map(|i| {
            let mut key = format!("k{i:02}");
            key.push_str(&"k".repeat(MAX_KEY_LEN - key.len()));
            (key, "a".repeat(MAX_VALUE_LEN))
        })
        .collect();

    let escape =
        |s: &str| -> String { s.chars().map(|c| format!("\\u{:04x}", c as u32)).collect() };
    let encoded = STANDARD.encode(&value);
    // All `/`, but for the last group (1 MiB isn't a multiple of 3).
    assert!(
        encoded.as_bytes()[..encoded.len() - 4]
            .iter()
            .all(|b| *b == b'/')
    );
    let mut body = format!(r#"{{"value":"{}","labels":{{"#, encoded.replace('/', "\\/"));
    for (i, (key, label)) in labels.iter().enumerate() {
        if i > 0 {
            body.push(',');
        }
        body.push_str(&format!(r#""{}":"{}""#, escape(key), escape(label)));
    }
    body.push_str("}}");
    let authority = format!("localhost:{}", env.addr.port());
    let (status, _, reply) = Client::Plain
        .send_raw(
            env.addr,
            &authority,
            Method::PUT,
            "/v1/secrets/app/http",
            Some(body),
        )
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{reply}");

    let channel = Endpoint::from_shared(format!("http://localhost:{}", env.addr.port()))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut grpc = SecretsServiceClient::new(channel);
    grpc.put_secret(pb::PutSecretRequest {
        path: "app/grpc".to_owned(),
        value: value.clone(),
        expected_version: None,
        labels: labels.iter().cloned().collect(),
    })
    .await
    .unwrap();

    for path in ["app/http", "app/grpc"] {
        let meta = grpc
            .get_metadata(pb::GetMetadataRequest {
                path: path.to_owned(),
            })
            .await
            .unwrap()
            .into_inner()
            .metadata
            .unwrap();
        assert_eq!(meta.labels.len(), MAX_LABELS, "{path}");
    }
    env.destroy().await.unwrap();
}

fn policy_admin() -> Vec<Rule> {
    vec![Rule {
        name: Some("ops-admin".to_owned()),
        identity: "ops/admin".to_owned(),
        actions: vec![Action::Policy, Action::Read, Action::Write, Action::List],
        paths: vec![],
        all_paths: true,
    }]
}

/// The policy endpoints: the same operations and answers as gRPC's
/// `PolicyService`, through TLS, identity and the config rules. Typos are
/// refused (unknown fields, unknown or admin actions), bodies must be JSON,
/// and nothing answers with CORS headers.
#[tokio::test]
async fn the_json_api_manages_stored_policies() {
    let ca = Ca::new().unwrap();
    let env = Env::secured(&ca, &policy_admin()).await.unwrap();
    let addr = env.addr;
    let admin = Client::tls(&ca, Some(&ca.client("ops/admin").unwrap()), b"http/1.1").unwrap();
    let billing = Client::tls(&ca, Some(&ca.client("apps/billing").unwrap()), b"h2").unwrap();
    let put = |body: Value| {
        let admin = admin.clone();
        async move {
            admin
                .send(
                    addr,
                    Method::PUT,
                    "/v1/policies/apps/billing-read",
                    Some(body),
                )
                .await
                .unwrap()
        }
    };
    admin
        .send(addr, Method::PUT, "/v1/secrets/billing/db", put_body(b"x"))
        .await
        .unwrap();
    let read = || async {
        billing
            .send(addr, Method::GET, "/v1/secrets/billing/db", None)
            .await
            .unwrap()
            .0
    };
    assert_eq!(read().await, StatusCode::FORBIDDEN);

    let spec = json!({
        "identity": "apps/billing", "actions": ["read", "list"], "paths": ["billing"],
        "description": "billing app, read only", "expected_version": 0
    });
    let (status, headers, body) = put(spec.clone()).await;
    assert_eq!(
        (status, body),
        (
            StatusCode::OK,
            json!({"version": 1, "revision": 1, "created": true})
        )
    );
    assert!(!headers.contains_key("access-control-allow-origin"));
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(read().await, StatusCode::OK);
    // Check-and-set: 0 only creates.
    assert_eq!(
        error(&put(spec.clone()).await),
        (StatusCode::CONFLICT, "version_mismatch".to_owned())
    );

    // Typos and admin actions never reach the server's logic.
    let mut typo = spec.clone();
    typo["all_path"] = json!(true);
    assert_eq!(put(typo).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    let mut admin_action = spec.clone();
    admin_action["actions"] = json!(["rotate"]);
    let refused = put(admin_action).await;
    assert_eq!(refused.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        refused.2["error"]["message"]
            .as_str()
            .unwrap()
            .contains("admin action"),
        "{}",
        refused.2
    );
    let (status, _, _) = admin
        .send_typed(
            addr,
            &format!("localhost:{}", addr.port()),
            Method::POST,
            "/v1/policy-apply",
            Some(r#"{"policies": []}"#.to_owned()),
            Some("text/plain"),
        )
        .await
        .unwrap();
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let (status, _, listed) = admin
        .send(addr, Method::GET, "/v1/policies", None)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = listed["policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["apps/billing-read", "config:ops-admin"]);
    assert_eq!(
        (&listed["stored"], &listed["revision"]),
        (&json!("loaded"), &json!(1))
    );
    let (_, _, got) = admin
        .send(addr, Method::GET, "/v1/policies/apps/billing-read", None)
        .await
        .unwrap();
    assert_eq!(
        (&got["source"], &got["version"], &got["paths"]),
        (&json!("stored"), &json!(1), &json!(["billing"]))
    );
    let (_, _, checked) = admin
        .send(
            addr,
            Method::GET,
            "/v1/policy-check?identity=apps/billing&action=read&path=billing/db",
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        checked,
        json!({"allowed": true, "granted_by": ["apps/billing-read"], "enforced": true})
    );
    let (_, _, dry) = admin
        .send(
            addr,
            Method::POST,
            "/v1/policy-apply",
            Some(json!({"policies": [], "prune": true, "dry_run": true})),
        )
        .await
        .unwrap();
    assert_eq!(
        (&dry["dry_run"], &dry["deleted"]),
        (&json!(true), &json!(["apps/billing-read"]))
    );
    assert_eq!(read().await, StatusCode::OK);

    // Managing them takes `policy`.
    assert_eq!(
        error(
            &billing
                .send(addr, Method::GET, "/v1/policies", None)
                .await
                .unwrap()
        ),
        (StatusCode::FORBIDDEN, "permission_denied".to_owned())
    );

    // Sealed: the stored grant isn't in force, and that's what it says.
    env.seal.seal().await;
    let sealed = billing
        .send(addr, Method::GET, "/v1/secrets/billing/db", None)
        .await
        .unwrap();
    assert_eq!(
        error(&sealed),
        (StatusCode::SERVICE_UNAVAILABLE, "sealed".to_owned())
    );
    for share in &env.shares[..2] {
        env.seal.unseal(share, false).await.unwrap();
    }

    let (status, _, deleted) = admin
        .send(
            addr,
            Method::DELETE,
            "/v1/policies/apps/billing-read?expected_version=1",
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        (status, deleted),
        (StatusCode::OK, json!({"deleted": true, "revision": 2}))
    );
    assert_eq!(read().await, StatusCode::FORBIDDEN);
    env.destroy().await.unwrap();
}

/// The largest apply fits through both APIs: every policy the server may
/// store, with long descriptions (a dry run, so nothing is written).
#[tokio::test]
async fn the_largest_apply_fits_through_both_apis() {
    use ferritor_core::proto::v1 as pb;
    use ferritor_core::proto::v1::policy_service_client::PolicyServiceClient;

    let env = Env::plaintext().await.unwrap();
    let description = "d".repeat(1000);
    let policies: Vec<Value> = (0..ferritor_core::policy::MAX_APPLY)
        .map(|i| {
            json!({"name": format!("apps/app-{i:05}"), "identity": format!("apps/app-{i:05}"),
                   "actions": ["read"], "paths": ["billing"], "description": description})
        })
        .collect();
    let body = json!({"policies": policies, "dry_run": true});
    let (status, _, applied) = Client::Plain
        .send(env.addr, Method::POST, "/v1/policy-apply", Some(body))
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(
        applied["created"].as_array().map(Vec::len),
        Some(ferritor_core::policy::MAX_APPLY)
    );

    let mut client = PolicyServiceClient::connect(format!("http://localhost:{}", env.addr.port()))
        .await
        .unwrap();
    let request = pb::ApplyPoliciesRequest {
        policies: (0..ferritor_core::policy::MAX_APPLY)
            .map(|i| pb::PolicySpec {
                name: format!("apps/app-{i:05}"),
                identity: format!("apps/app-{i:05}"),
                actions: vec![pb::SecretAction::Read.into()],
                paths: vec!["billing".to_owned()],
                all_paths: false,
                description: description.clone(),
            })
            .collect(),
        expected_revision: None,
        prune: false,
        dry_run: true,
    };
    let reply = client.apply_policies(request).await.unwrap().into_inner();
    assert_eq!(reply.created.len(), ferritor_core::policy::MAX_APPLY);
    env.destroy().await.unwrap();
}

/// Every route `http::router` serves, as the OpenAPI description names it:
/// keep in step with both (the test below holds the description to this
/// list, and this list to the running server; nothing catches a route the
/// router serves but neither names).
const ROUTES: [(&str, &str); 15] = [
    ("GET", "/v1/health"),
    ("GET", "/v1/secrets"),
    ("GET", "/v1/secrets/{path}"),
    ("PUT", "/v1/secrets/{path}"),
    ("DELETE", "/v1/secrets/{path}"),
    ("POST", "/v1/restore/{path}"),
    ("GET", "/v1/versions/{path}"),
    ("GET", "/v1/metadata/{path}"),
    ("PATCH", "/v1/metadata/{path}"),
    ("GET", "/v1/policies"),
    ("GET", "/v1/policies/{name}"),
    ("PUT", "/v1/policies/{name}"),
    ("DELETE", "/v1/policies/{name}"),
    ("POST", "/v1/policy-apply"),
    ("GET", "/v1/policy-check"),
];

/// The OpenAPI description (`http::openapi`, the source of
/// `docs/openapi.json`) lists exactly the routes, and the server has every
/// one of them: no documented operation hits the router's "no such endpoint"
/// or "method not allowed" fallback.
#[tokio::test]
async fn the_openapi_spec_lists_every_route() {
    let spec = serde_json::to_value(http::openapi()).unwrap();
    assert_eq!(spec["openapi"], "3.1.0");
    let mut documented = Vec::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            documented.push((method.to_uppercase(), path.clone()));
        }
    }
    documented.sort();
    let mut expected: Vec<(String, String)> = ROUTES
        .iter()
        .map(|(m, p)| ((*m).to_owned(), (*p).to_owned()))
        .collect();
    expected.sort();
    assert_eq!(documented, expected);

    let env = Env::plaintext().await.unwrap();
    let unrouted = Client::Plain
        .send(env.addr, Method::GET, "/v1/no-such-route", None)
        .await
        .unwrap();
    assert_eq!(unrouted.0, StatusCode::NOT_FOUND);
    for (method, path) in ROUTES {
        let uri = path
            .replace("{path}", "billing/db")
            .replace("{name}", "apps/x");
        let body = ["PUT", "POST", "PATCH"]
            .contains(&method)
            .then(|| json!({}));
        let (status, _, reply) = Client::Plain
            .send(
                env.addr,
                Method::from_bytes(method.as_bytes()).unwrap(),
                &uri,
                body,
            )
            .await
            .unwrap();
        assert_ne!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
        assert_ne!(
            (status, reply),
            (unrouted.0, unrouted.2.clone()),
            "{method} {path}"
        );
    }
    env.destroy().await.unwrap();
}

/// The description makes `{path}` and `{name}` single parameters, so a
/// generated client sends `app%2Fdb`: the server takes it as `app/db`.
#[tokio::test]
async fn an_encoded_slash_in_a_path_parameter_is_a_slash() {
    let env = Env::plaintext().await.unwrap();
    let c = Client::Plain;
    let (status, _, _) = c
        .send(
            env.addr,
            Method::PUT,
            "/v1/secrets/app%2Fdb",
            put_body(b"x"),
        )
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    let (status, _, read) = c
        .send(env.addr, Method::GET, "/v1/secrets/app/db", None)
        .await
        .unwrap();
    assert_eq!((status, &read["path"]), (StatusCode::OK, &json!("app/db")));
    let (status, _, read) = c
        .send(env.addr, Method::GET, "/v1/secrets/app%2Fdb", None)
        .await
        .unwrap();
    assert_eq!((status, &read["path"]), (StatusCode::OK, &json!("app/db")));

    let (status, _, _) = c
        .send(
            env.addr,
            Method::PUT,
            "/v1/policies/apps%2Fx",
            Some(json!({"identity": "apps/x", "actions": ["read"], "paths": ["app"]})),
        )
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    let (status, _, policy) = c
        .send(env.addr, Method::GET, "/v1/policies/apps/x", None)
        .await
        .unwrap();
    assert_eq!(
        (status, &policy["name"]),
        (StatusCode::OK, &json!("apps/x"))
    );
    env.destroy().await.unwrap();
}

/// A client that gives up on a write can't cut it short (`tls::Detach`):
/// each put here waits on its path's lock (held by the test), its client
/// goes away (an HTTP/1.1 connection dropped; a gRPC call cancelled, which
/// resets its HTTP/2 stream), then the lock is released. Each put is still
/// stored, and audited with its outcome. Without the detaching, the server
/// dropped the call with its connection: rolled back, or after its commit
/// stored with no outcome at all.
#[tokio::test]
async fn a_write_whose_client_left_still_completes_and_is_audited() {
    let env = Env::plaintext().await.unwrap();
    let addr = env.addr;
    let channel = Endpoint::from_shared(format!("http://localhost:{}", addr.port()))
        .unwrap()
        .connect_lazy();
    type Cut = Box<dyn FnOnce() -> JoinHandle<()>>;
    let clients: [(&str, Cut); 2] = [
        (
            "app/http",
            Box::new(move || {
                tokio::spawn(async move {
                    let body = put_body(b"x");
                    Client::Plain
                        .send(addr, Method::PUT, "/v1/secrets/app/http", body)
                        .await
                        .ok();
                })
            }),
        ),
        (
            "app/grpc",
            Box::new(move || {
                tokio::spawn(async move {
                    SecretsServiceClient::new(channel)
                        .put_secret(pb::PutSecretRequest {
                            path: "app/grpc".to_owned(),
                            value: b"x".to_vec(),
                            expected_version: None,
                            labels: Default::default(),
                        })
                        .await
                        .ok();
                })
            }),
        ),
    ];
    for (path, client) in clients {
        let mut lock = env.data.pool().begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(1, hashtext($1))")
            .bind(path)
            .execute(&mut *lock)
            .await
            .unwrap();
        let client = client();
        env.data.wait_for_lock_waiters(1).await.unwrap();
        // The client goes away while its put waits; give the server time
        // to see the connection close (or the stream reset).
        client.abort();
        client.await.ok();
        tokio::time::sleep(Duration::from_millis(200)).await;
        lock.commit().await.unwrap();

        let outcome = r#""operation":"put""#;
        let target = format!(r#""path":"{path}""#);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !env.audit.lines().iter().any(|l| {
            l.contains(r#""event":"outcome""#) && l.contains(outcome) && l.contains(&target)
        }) {
            assert!(Instant::now() < deadline, "{path}: no outcome audited");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stored: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM secret_versions v JOIN paths p ON p.id = v.path_id
             WHERE p.path = $1",
        )
        .bind(path)
        .fetch_one(env.data.pool())
        .await
        .unwrap();
        assert_eq!(stored, 1, "{path}");
    }
    env.destroy().await.unwrap();
}

/// Limits with a server-wide cap of `cap` and `max_in_flight` per identity.
fn limits(cap: u32, max_in_flight: u32) -> TestResult<Limits> {
    Ok(Limits::new(
        std::num::NonZeroU32::new(cap).ok_or("a cap of 0")?,
        Quota {
            rate: None,
            max_in_flight: std::num::NonZeroU32::new(max_in_flight),
            max_watch_streams: None,
        },
        Vec::new(),
    ))
}

/// A gRPC channel to `addr` as `pem`.
fn channel(ca: &Ca, pem: &Pem, addr: SocketAddr) -> TestResult<tonic::transport::Channel> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&ca.cert))
        .identity(Identity::from_pem(&pem.cert, &pem.key));
    Ok(
        Endpoint::from_shared(format!("https://localhost:{}", addr.port()))?
            .tls_config(tls)?
            .connect_lazy(),
    )
}

/// The limit a `RATE_LIMITED` status names, if it is one.
fn rate_limited(status: &tonic::Status) -> Option<String> {
    use tonic_types::StatusExt as _;
    (status.code() == tonic::Code::ResourceExhausted
        && grpc::reason_of(status).as_deref() == Some("RATE_LIMITED"))
    .then(|| {
        status
            .get_error_details()
            .error_info()
            .and_then(|info| info.metadata.get("limit").cloned())
            .unwrap_or_default()
    })
}

/// Audit entries of `event`, waited for (some are queued).
async fn audited(env: &Env, event: &str, at_least: usize) -> Vec<Value> {
    for _ in 0..200 {
        let found: Vec<Value> = env
            .audit
            .lines()
            .iter()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|entry| entry["event"] == event)
            .collect();
        if found.len() >= at_least {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("fewer than {at_least} `{event}` entries");
}

fn read_request(path: &str) -> pb::GetSecretRequest {
    pb::GetSecretRequest {
        path: path.to_owned(),
        version: 0,
    }
}

fn put_request(path: &str) -> pb::PutSecretRequest {
    pb::PutSecretRequest {
        path: path.to_owned(),
        value: b"x".to_vec(),
        expected_version: None,
        labels: Default::default(),
    }
}

/// The JSON API answers a rate limit as gRPC does, in its own terms: 429
/// `rate_limited`, with `Retry-After` in whole seconds. On a stopped clock:
/// a second between the two requests would let the second through.
#[tokio::test]
async fn the_json_api_answers_a_rate_limit_with_429_and_retry_after() {
    let ca = Ca::new().unwrap();
    let one = std::num::NonZeroU32::MIN;
    let limits = Limits::new(
        std::num::NonZeroU32::new(36).unwrap(),
        Quota {
            rate: Some(Rate::new(one, one)),
            max_in_flight: None,
            max_watch_streams: None,
        },
        Vec::new(),
    );
    let env = Env::limited_frozen(&ca, &billing_policy(), limits)
        .await
        .unwrap();
    let billing = Client::tls(&ca, Some(&ca.client("apps/billing").unwrap()), b"h2").unwrap();

    let (status, _, _) = billing
        .send(env.addr, Method::GET, "/v1/secrets/billing/db", None)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, headers, body) = billing
        .send(env.addr, Method::GET, "/v1/secrets/billing/db", None)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "rate_limited");
    assert_eq!(
        headers.get("retry-after").and_then(|v| v.to_str().ok()),
        Some("1")
    );
    env.destroy().await.unwrap();
}

/// With the defaults (no rate), an application asking for a path it isn't
/// granted, one call at a time, gets 50 denials audited, then is refused
/// before any decision (`limit: denied`) without an audit entry, its
/// allowed requests too for the moment; the episode is reported once, and
/// its end with the count. On a stopped clock: the budget refills 10 a
/// second, so on a slow machine the real time let a few more through.
#[tokio::test]
async fn denials_are_budgeted_so_they_cannot_flood_the_audit_log() {
    let ca = Ca::new().unwrap();
    let env = Env::limited_frozen(&ca, &billing_policy(), limits(36, 9).unwrap())
        .await
        .unwrap();
    let billing = ca.client("apps/billing").unwrap();
    let mut client = SecretsServiceClient::new(channel(&ca, &billing, env.addr).unwrap());
    for i in 0..60 {
        let status = client
            .get_secret(read_request("other/db"))
            .await
            .unwrap_err();
        if i < 50 {
            assert_eq!(status.code(), tonic::Code::PermissionDenied, "request {i}");
        } else {
            assert_eq!(
                rate_limited(&status).as_deref(),
                Some("denied"),
                "request {i}"
            );
        }
    }
    // Its allowed reads wait for the budget too.
    let status = client
        .get_secret(read_request("billing/db"))
        .await
        .unwrap_err();
    assert_eq!(rate_limited(&status).as_deref(), Some("denied"));

    let denials = audited(&env, "authorization", 50).await;
    assert_eq!(
        denials.iter().filter(|e| e["decision"] == "denied").count(),
        50
    );
    let started = audited(&env, "rate_limited", 1).await;
    assert_eq!(started.len(), 1);
    assert_eq!(
        (
            &started[0]["caller"],
            &started[0]["limit"],
            &started[0]["state"]
        ),
        (&json!("apps/billing"), &json!("denied"), &json!("started"))
    );
    env.gate.end_quiet_limits(std::time::Instant::now() + QUIET);
    let both = audited(&env, "rate_limited", 2).await;
    assert_eq!(
        (&both[1]["state"], &both[1]["refused"]),
        (&json!("ended"), &json!(11))
    );
    env.destroy().await.unwrap();
}

/// An identity holds at most its calls in flight: two puts waiting on a
/// path lock (held by the test) fill its two slots, a third is refused
/// (`limit: in_flight`); an operator's admin call passes with the
/// server-wide cap full. Released, the puts finish and the slots free; a
/// reload that lowers the limit applies to the next request.
#[tokio::test]
async fn an_identity_holds_at_most_its_calls_in_flight() {
    let ca = Ca::new().unwrap();
    let mut policy = billing_policy();
    policy.extend(policy_admin());
    let env = Env::limited(&ca, &policy, limits(2, 2).unwrap())
        .await
        .unwrap();
    let billing = ca.client("apps/billing").unwrap();
    let admin = ca.client("ops/admin").unwrap();

    let mut lock = env.data.pool().begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(1, hashtext('billing/x'))")
        .execute(&mut *lock)
        .await
        .unwrap();
    let held: Vec<_> = (0..2)
        .map(|_| {
            let mut client = SecretsServiceClient::new(channel(&ca, &billing, env.addr).unwrap());
            tokio::spawn(async move { client.put_secret(put_request("billing/x")).await })
        })
        .collect();
    env.data.wait_for_lock_waiters(2).await.unwrap();

    let mut client = SecretsServiceClient::new(channel(&ca, &billing, env.addr).unwrap());
    let status = client
        .put_secret(put_request("billing/y"))
        .await
        .unwrap_err();
    assert_eq!(rate_limited(&status).as_deref(), Some("in_flight"));
    // The operator gets through, the cap full or not.
    use ferritor_core::proto::v1::policy_service_client::PolicyServiceClient;
    PolicyServiceClient::new(channel(&ca, &admin, env.addr).unwrap())
        .list_policies(pb::ListPoliciesRequest::default())
        .await
        .unwrap();

    lock.commit().await.unwrap();
    for put in held {
        put.await.unwrap().unwrap();
    }
    client.put_secret(put_request("billing/y")).await.unwrap();

    // Lowered to 1: one put waiting fills it, the next is refused.
    env.gate.reload_limits(limits(2, 1).unwrap());
    let mut lock = env.data.pool().begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(1, hashtext('billing/x'))")
        .execute(&mut *lock)
        .await
        .unwrap();
    let waiting = {
        let mut client = SecretsServiceClient::new(channel(&ca, &billing, env.addr).unwrap());
        tokio::spawn(async move { client.put_secret(put_request("billing/x")).await })
    };
    env.data.wait_for_lock_waiters(1).await.unwrap();
    let status = client
        .put_secret(put_request("billing/y"))
        .await
        .unwrap_err();
    assert_eq!(rate_limited(&status).as_deref(), Some("in_flight"));
    lock.commit().await.unwrap();
    waiting.await.unwrap().unwrap();
    env.destroy().await.unwrap();
}

/// A call waiting for a slot under the server-wide cap whose client leaves
/// never starts: no decision recorded, nothing stored. Once a call has its
/// slot, it runs to its end whatever its client does (`tls::Detach`).
#[tokio::test]
async fn a_call_waiting_for_the_cap_whose_client_leaves_never_starts() {
    let ca = Ca::new().unwrap();
    // Two calls per identity, but one under the cap: the second waits for
    // the cap, not for its identity.
    let env = Env::limited(&ca, &billing_policy(), limits(1, 2).unwrap())
        .await
        .unwrap();
    let billing = ca.client("apps/billing").unwrap();

    let mut lock = env.data.pool().begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(1, hashtext('billing/x'))")
        .execute(&mut *lock)
        .await
        .unwrap();
    let first = {
        let mut client = SecretsServiceClient::new(channel(&ca, &billing, env.addr).unwrap());
        tokio::spawn(async move { client.put_secret(put_request("billing/x")).await })
    };
    env.data.wait_for_lock_waiters(1).await.unwrap();
    // The cap's one slot is taken: this one waits for it.
    let waiting = {
        let c = Client::tls(&ca, Some(&billing), b"http/1.1").unwrap();
        let addr = env.addr;
        tokio::spawn(async move {
            c.send(
                addr,
                Method::PUT,
                "/v1/secrets/billing/never",
                put_body(b"x"),
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    waiting.abort();
    waiting.await.ok();
    tokio::time::sleep(Duration::from_millis(100)).await;
    lock.commit().await.unwrap();
    first.await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        !env.audit
            .lines()
            .iter()
            .any(|l| l.contains("billing/never")),
        "the abandoned call reached a decision"
    );
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM secret_versions v JOIN paths p ON p.id = v.path_id
             WHERE p.path = 'billing/never'",
    )
    .fetch_one(env.data.pool())
    .await
    .unwrap();
    assert_eq!(stored, 0);
    env.destroy().await.unwrap();
}

/// Undecided isn't denied: requests only a stored policy could allow, while
/// the server is sealed (`SEALED`), charge no denial budget, so right after
/// the unseal the application's allowed reads pass.
#[tokio::test]
async fn undecided_requests_charge_no_denials() {
    let ca = Ca::new().unwrap();
    let env = Env::limited(&ca, &policy_admin(), limits(36, 9).unwrap())
        .await
        .unwrap();
    let admin = ca.client("ops/admin").unwrap();
    let reader = ca.client("apps/reader").unwrap();
    let admin_http = Client::tls(&ca, Some(&admin), b"http/1.1").unwrap();
    let (status, _, _) = admin_http
        .send(
            env.addr,
            Method::PUT,
            "/v1/policies/apps/reader",
            Some(json!({"identity": "apps/reader", "actions": ["read"], "paths": ["app"]})),
        )
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = admin_http
        .send(env.addr, Method::PUT, "/v1/secrets/app/db", put_body(b"v"))
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);

    env.seal.seal().await;
    let mut client = SecretsServiceClient::new(channel(&ca, &reader, env.addr).unwrap());
    for _ in 0..60 {
        let status = client.get_secret(read_request("app/db")).await.unwrap_err();
        assert_eq!(grpc::reason_of(&status).as_deref(), Some("SEALED"));
    }
    for share in &env.shares[..2] {
        env.seal.unseal(share, false).await.unwrap();
    }
    client.get_secret(read_request("app/db")).await.unwrap();
    env.destroy().await.unwrap();
}

/// A certificate naming no caller is answered 401 and audited, but only as
/// often as its fingerprint's limit allows: the rest is one episode. On a
/// stopped clock: the limit refills once a second, and a slow machine's
/// time would let more be audited.
#[tokio::test]
async fn a_nameless_certificate_cannot_flood_the_audit_log() {
    let ca = Ca::new().unwrap();
    let env = Env::limited_frozen(&ca, &billing_policy(), limits(36, 9).unwrap())
        .await
        .unwrap();
    let nameless = ca
        .issue(
            vec![ferritor_testkit::pki::uri("spiffe://apps/billing").unwrap()],
            vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth],
            None,
        )
        .unwrap();
    let c = Client::tls(&ca, Some(&nameless), b"http/1.1").unwrap();
    for _ in 0..20 {
        let reply = c
            .send(env.addr, Method::GET, "/v1/secrets/billing/db", None)
            .await
            .unwrap();
        assert_eq!(reply.0, StatusCode::UNAUTHORIZED);
    }
    let episode = audited(&env, "rate_limited", 1).await;
    assert_eq!(
        (&episode[0]["limit"], &episode[0]["caller"]),
        (&json!("unauthenticated"), &Value::Null)
    );
    assert!(episode[0]["certificate"].is_string());
    assert_eq!(audited(&env, "authentication", 5).await.len(), 5);
    env.destroy().await.unwrap();
}

/// The limiter's clock, stopped (see [`Env::limited_frozen`]).
struct Frozen(Instant);

impl Clock for Frozen {
    fn now(&self) -> Instant {
        self.0
    }
}
