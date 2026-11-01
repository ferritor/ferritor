//! Workload identity over real connections, served the way `main` serves
//! it: a token and a CSR exchanged on the exchange's own listener (TLS, no
//! client certificate) for a certificate, which then works on the main
//! listener like one from the operators' PKI, until its CA is revoked, its
//! issuer removed, or a cutoff passes it.

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::Labels;
use ferritor_core::messages::reason;
use ferritor_core::path::SecretPath;
use ferritor_core::proto::v1 as pb;
use ferritor_core::proto::v1::identity_service_client::IdentityServiceClient;
use ferritor_core::proto::v1::secrets_service_client::SecretsServiceClient;
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
use ferritor_server::ratelimit::{Limits, Quota};
use ferritor_server::seal::{Seal, SealError};
use ferritor_server::secrets::Secrets;
use ferritor_server::{grpc, tls};
use ferritor_testkit::jwt::{AUDIENCE, ISS, TokenIssuer};
use ferritor_testkit::pki::Ca;
use ferritor_testkit::{Captured, TestDatabase, TestResult};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tonic::Code;
use tonic::service::Routes;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity as TlsIdentity};

/// Allows everything; records who asked.
#[derive(Default)]
struct Callers(Mutex<Vec<Caller>>);

impl Authorizer for Callers {
    fn authorize(&self, caller: &Caller, _: Action, _: Target<'_>) -> Result<(), Denied> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(caller.clone());
        Ok(())
    }
}

/// `[identity]` with one issuer, `ci`: `ci/{repository_owner}/deploy`.
fn identity(issuing: &TokenIssuer, listen_addr: SocketAddr) -> TestResult<Identity> {
    Ok(Identity {
        listen_addr,
        lifetime: Duration::from_secs(3600),
        issuers: vec![Issuer {
            name: "ci".to_owned(),
            iss: ISS.to_owned(),
            audience: AUDIENCE.to_owned(),
            max_token_age: DEFAULT_MAX_TOKEN_AGE,
            exchange_burst: DEFAULT_EXCHANGE_BURST,
            jwks: JwksSource::File(issuing.jwks.clone()),
            mappings: vec![Mapping {
                template: Template::parse("ci/{repository_owner}/deploy", "ci")?,
                require: Vec::new(),
            }],
            not_before: None,
        }],
        revoked: Vec::new(),
    })
}

/// An unsealed server with an issuing CA: the main listener (`SecretsService`,
/// client certificates from `ca` or the issuing CA) and the exchange's.
struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    seal: Arc<Seal>,
    gate: Arc<Gate>,
    shares: Vec<Vec<u8>>,
    ca: Ca,
    issuing: TokenIssuer,
    exchange: Arc<Exchange>,
    main_addr: SocketAddr,
    exchange_addr: SocketAddr,
    callers: Arc<Callers>,
    audit: Captured,
    serving: Vec<JoinHandle<()>>,
}

/// A workload's certificate and key, PEM.
struct Workload {
    cert: String,
    key: String,
    identity: String,
}

impl Env {
    async fn start() -> TestResult<Self> {
        Self::start_with(true).await
    }

    /// `issuing_ca`: whether the operators ran `ferritor identity init`.
    async fn start_with(issuing_ca: bool) -> TestResult<Self> {
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
        let seal = Arc::new(
            Seal::new(Keystore::new(keys.pool().clone()))
                .with_revision_floor(Arc::new(Datastore::new(data.pool().clone()))),
        );
        let shares: Vec<Vec<u8>> = seal
            .init(ShareParams::new(3, 2)?)
            .await?
            .iter()
            .map(|share| share.to_bytes().to_vec())
            .collect();
        for share in &shares[..2] {
            seal.unseal(share, false).await?;
        }
        if issuing_ca {
            seal.identity_init().await?;
        }
        Namespaces::new(Arc::clone(&seal), Datastore::new(data.pool().clone()))
            .create("app", &Labels::new())
            .await?;
        let callers = Arc::new(Callers::default());
        let audit = Captured::default();
        let gate = Arc::new(Gate::new(
            callers.clone(),
            AuditLog::new(audit.clone(), Duration::from_secs(5))?,
        ));
        let secrets = Arc::new(Secrets::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
            Arc::clone(&gate),
        ));
        let ca = Ca::new()?;
        let server_cert = ca.server()?;
        let tls_config = tls::server_tls(
            server_cert.cert.as_bytes(),
            server_cert.key.as_bytes(),
            ca.cert.as_bytes(),
            None,
        )?;
        let main = TcpListener::bind("127.0.0.1:0").await?;
        let main_addr = main.local_addr()?;
        let exchange_listener = TcpListener::bind("127.0.0.1:0").await?;
        let exchange_addr = exchange_listener.local_addr()?;
        let issuing = TokenIssuer::new(&std::env::temp_dir())?;
        let exchange = Arc::new(
            Exchange::new(
                Arc::clone(&seal),
                Arc::clone(&gate),
                identity(&issuing, exchange_addr)?,
            )
            .await?,
        );
        tls_config.use_workload_trust(exchange.trust());
        let exchange_tls = tls_config.without_client_auth()?;
        let age = Duration::from_secs(600);
        let routes = Routes::new(grpc::secrets_service(secrets));
        let serving_main = tokio::spawn(async move {
            tls::serve(
                tls::server(age, age),
                routes,
                main,
                Some(tls_config),
                std::future::pending(),
            )
            .await
            .ok();
        });
        let routes = Routes::new(grpc::identity_service(Arc::clone(&exchange)));
        let serving_exchange = tokio::spawn(async move {
            tls::serve(
                tls::server(age, age),
                routes,
                exchange_listener,
                Some(exchange_tls),
                std::future::pending(),
            )
            .await
            .ok();
        });
        Ok(Self {
            keys,
            data,
            seal,
            gate,
            shares,
            ca,
            issuing,
            exchange,
            main_addr,
            exchange_addr,
            callers,
            audit,
            serving: vec![serving_main, serving_exchange],
        })
    }

    fn tls(&self) -> ClientTlsConfig {
        ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&self.ca.cert))
    }

    /// The exchange, with no client certificate.
    fn exchange_client(&self) -> TestResult<IdentityServiceClient<Channel>> {
        let channel =
            Endpoint::from_shared(format!("https://localhost:{}", self.exchange_addr.port()))?
                .tls_config(self.tls())?
                .connect_lazy();
        Ok(IdentityServiceClient::new(channel))
    }

    /// Exchanges `token` for a certificate, with a fresh key's CSR.
    async fn exchange(&self, token: &str) -> TestResult<Result<Workload, tonic::Status>> {
        let key = rcgen::KeyPair::generate()?;
        let csr = rcgen::CertificateParams::default().serialize_request(&key)?;
        let answer = self
            .exchange_client()?
            .exchange_token(pb::ExchangeTokenRequest {
                token: token.to_owned(),
                csr: csr.der().to_vec(),
            })
            .await;
        Ok(answer.map(|answer| {
            let answer = answer.into_inner();
            Workload {
                cert: certificate_pem(&answer.certificate),
                key: key.serialize_pem(),
                identity: answer.identity,
            }
        }))
    }

    async fn deploy(&self, owner: &str) -> TestResult<Workload> {
        let token = self.issuing.token(&json!({"repository_owner": owner}))?;
        Ok(self.exchange(&token).await??)
    }

    /// The main listener, presenting `workload`'s certificate.
    fn secrets(&self, workload: Option<&Workload>) -> TestResult<SecretsServiceClient<Channel>> {
        let mut tls = self.tls();
        if let Some(workload) = workload {
            tls = tls.identity(TlsIdentity::from_pem(&workload.cert, &workload.key));
        }
        let channel =
            Endpoint::from_shared(format!("https://localhost:{}", self.main_addr.port()))?
                .tls_config(tls)?
                .connect_lazy();
        Ok(SecretsServiceClient::new(channel))
    }

    async fn get(client: &mut SecretsServiceClient<Channel>) -> Result<Vec<u8>, tonic::Status> {
        let answer = client
            .get_secret(pb::GetSecretRequest {
                path: "app/db".to_owned(),
                version: 0,
            })
            .await?;
        Ok(answer
            .into_inner()
            .secret
            .map(|secret| secret.value)
            .unwrap_or_default())
    }

    async fn put(&self, workload: &Workload) -> TestResult<()> {
        self.secrets(Some(workload))?
            .put_secret(pb::PutSecretRequest {
                path: "app/db".to_owned(),
                value: b"hunter2".to_vec(),
                ..Default::default()
            })
            .await?;
        Ok(())
    }

    /// The audit entries of `event`, once written (some are queued).
    async fn entries(&self, event: &str, at_least: usize) -> TestResult<Vec<Value>> {
        let mut found = Vec::new();
        for _ in 0..200 {
            found = self
                .audit
                .lines()
                .iter()
                .map(|line| serde_json::from_str::<Value>(line))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|entry| entry["event"] == event)
                .collect();
            if found.len() >= at_least {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(found)
    }

    async fn destroy(self) -> TestResult<()> {
        for serving in &self.serving {
            serving.abort();
        }
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

fn certificate_pem(der: &[u8]) -> String {
    let base64 = STANDARD.encode(der);
    let mut pem = "-----BEGIN CERTIFICATE-----\n".to_owned();
    for line in base64.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// The reason attached to `status`, if any.
fn reason_of(status: &tonic::Status) -> Option<String> {
    tonic_types::StatusExt::get_error_details(status)
        .error_info()
        .map(|info| info.reason.clone())
}

/// Whether a call presenting a certificate was refused as such: at the
/// handshake (a transport error, with the alert) or per request
/// (UNAUTHENTICATED).
fn refused_certificate(status: &tonic::Status) -> bool {
    status.code() == Code::Unauthenticated
        || (status.code() == Code::Unknown && format!("{status:?}").contains("fatal alert"))
}

#[tokio::test]
async fn an_exchanged_certificate_reads_secrets_as_its_identity() {
    let env = Env::start().await.unwrap();
    let workload = env.deploy("acme").await.unwrap();
    assert_eq!(workload.identity, "ci/acme/deploy");
    env.put(&workload).await.unwrap();
    let mut client = env.secrets(Some(&workload)).unwrap();
    assert_eq!(Env::get(&mut client).await.unwrap(), b"hunter2");
    let expected = Caller::Identity(SecretPath::parse("ci/acme/deploy").unwrap());
    let seen = env.callers.0.lock().unwrap().clone();
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|caller| *caller == expected), "{seen:?}");

    // The issuance is in the audit log: who, from which claims, which
    // serial; never the token.
    let issued = env.entries("exchange", 1).await.unwrap();
    assert_eq!(issued.len(), 1);
    let issued = &issued[0];
    assert_eq!(issued["outcome"], "issued");
    assert_eq!(issued["issuer"], "ci");
    assert_eq!(issued["identity"], "ci/acme/deploy");
    assert_eq!(issued["claims"]["repository_owner"], "acme");
    assert!(issued["serial"].as_str().is_some_and(|s| !s.is_empty()));
    let token = env
        .issuing
        .token(&json!({"repository_owner": "acme"}))
        .unwrap();
    let signature = token.rsplit('.').next().unwrap();
    let raw = String::from_utf8(env.audit.raw()).unwrap();
    assert!(!raw.contains(signature));
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn the_main_listener_still_needs_a_client_certificate() {
    let env = Env::start().await.unwrap();
    let mut client = env.secrets(None).unwrap();
    let refused = Env::get(&mut client).await.unwrap_err();
    assert!(refused_certificate(&refused), "{refused:?}");
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn bad_tokens_and_csrs_are_refused_and_audited() {
    let env = Env::start().await.unwrap();
    // A token from a key the issuer doesn't publish.
    let stranger = TokenIssuer::new(&std::env::temp_dir()).unwrap();
    let forged = stranger
        .token(&json!({"repository_owner": "acme"}))
        .unwrap();
    for token in [
        forged,
        "not a token".to_owned(),
        // No claim to map from.
        env.issuing.token(&json!({})).unwrap(),
        // Not one segment.
        env.issuing
            .token(&json!({"repository_owner": "acme/web"}))
            .unwrap(),
    ] {
        let refused = env.exchange(&token).await.unwrap().err().unwrap();
        assert_eq!(refused.code(), Code::Unauthenticated, "{refused:?}");
        assert_eq!(reason_of(&refused), Some(reason::TOKEN_REFUSED.to_owned()));
    }
    // A CSR that doesn't parse.
    let token = env
        .issuing
        .token(&json!({"repository_owner": "acme"}))
        .unwrap();
    let refused = env
        .exchange_client()
        .unwrap()
        .exchange_token(pb::ExchangeTokenRequest {
            token,
            csr: b"not a csr".to_vec(),
        })
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::InvalidArgument, "{refused:?}");
    let refusals = env.entries("exchange", 5).await.unwrap();
    assert_eq!(refusals.len(), 5);
    assert!(refusals.iter().all(|entry| entry["outcome"] == "refused"));
    assert!(refusals.iter().all(|entry| entry["reason"].is_string()));
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn nothing_is_issued_while_sealed_or_without_an_issuing_ca() {
    let env = Env::start().await.unwrap();
    let token = env
        .issuing
        .token(&json!({"repository_owner": "acme"}))
        .unwrap();
    env.seal.seal().await;
    let refused = env.exchange(&token).await.unwrap().err().unwrap();
    assert_eq!(refused.code(), Code::FailedPrecondition, "{refused:?}");
    assert_eq!(reason_of(&refused), Some(reason::SEALED.to_owned()));
    env.destroy().await.unwrap();

    // A server whose operators never ran `ferritor identity init`.
    let env = Env::start_with(false).await.unwrap();
    let token = env
        .issuing
        .token(&json!({"repository_owner": "acme"}))
        .unwrap();
    let refused = env.exchange(&token).await.unwrap().err().unwrap();
    assert_eq!(refused.code(), Code::FailedPrecondition, "{refused:?}");
    assert_eq!(reason_of(&refused), None);
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn a_seal_refuses_workload_certificates_on_open_connections() {
    let env = Env::start().await.unwrap();
    let workload = env.deploy("acme").await.unwrap();
    env.put(&workload).await.unwrap();
    let mut client = env.secrets(Some(&workload)).unwrap();
    Env::get(&mut client).await.unwrap();
    env.seal.seal().await;
    let refused = Env::get(&mut client).await.unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated, "{refused:?}");
    // Unsealed again: the same connection works again.
    for share in &env.shares[..2] {
        env.seal.unseal(share, false).await.unwrap();
    }
    Env::get(&mut client).await.unwrap();
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn a_rotation_keeps_the_retired_cas_certificates_until_revoked() {
    let env = Env::start().await.unwrap();
    let before = env.deploy("acme").await.unwrap();
    env.put(&before).await.unwrap();
    let mut open = env.secrets(Some(&before)).unwrap();
    Env::get(&mut open).await.unwrap();

    // Retired: what it signed still works, on open and new connections;
    // new certificates come from the new CA, and work too.
    env.seal.identity_rotate(false).await.unwrap();
    Env::get(&mut open).await.unwrap();
    Env::get(&mut env.secrets(Some(&before)).unwrap())
        .await
        .unwrap();
    let after = env.deploy("acme").await.unwrap();
    Env::get(&mut env.secrets(Some(&after)).unwrap())
        .await
        .unwrap();

    // Revoked, with every retired key: refused per request on the open
    // connection, and at the handshake on a new one.
    env.seal.identity_rotate(true).await.unwrap();
    let refused = Env::get(&mut open).await.unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated, "{refused:?}");
    let refused = Env::get(&mut env.secrets(Some(&before)).unwrap())
        .await
        .unwrap_err();
    assert!(refused_certificate(&refused), "{refused:?}");
    // And what the CA active until this rotation signed. Only what the
    // newest CA issues works.
    let refused = Env::get(&mut env.secrets(Some(&after)).unwrap())
        .await
        .unwrap_err();
    assert!(refused_certificate(&refused), "{refused:?}");
    let newest = env.deploy("acme").await.unwrap();
    Env::get(&mut env.secrets(Some(&newest)).unwrap())
        .await
        .unwrap();
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn removing_an_issuer_or_a_cutoff_refuses_what_it_issued() {
    let env = Env::start().await.unwrap();
    let acme = env.deploy("acme").await.unwrap();
    let other = env.deploy("other").await.unwrap();
    env.put(&acme).await.unwrap();
    let mut acme_open = env.secrets(Some(&acme)).unwrap();
    let mut other_open = env.secrets(Some(&other)).unwrap();
    Env::get(&mut acme_open).await.unwrap();
    Env::get(&mut other_open).await.unwrap();
    let issued = OffsetDateTime::now_utc().unix_timestamp();

    // One identity's cutoff: only its certificates issued before it.
    let mut config = identity(&env.issuing, env.exchange_addr).unwrap();
    config.revoked = vec![(SecretPath::parse("ci/acme/deploy").unwrap(), issued + 5)];
    env.exchange.reload(Some(config.clone())).await.unwrap();
    let refused = Env::get(&mut acme_open).await.unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated, "{refused:?}");
    Env::get(&mut other_open).await.unwrap();

    // The issuer's cutoff: all of them.
    config.revoked.clear();
    config.issuers[0].not_before = Some(issued + 5);
    env.exchange.reload(Some(config.clone())).await.unwrap();
    let refused = Env::get(&mut other_open).await.unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated, "{refused:?}");

    // Back without cutoffs: they work again; then the issuer is removed.
    config.issuers[0].not_before = None;
    env.exchange.reload(Some(config)).await.unwrap();
    Env::get(&mut other_open).await.unwrap();
    env.exchange.reload(None).await.unwrap();
    let refused = Env::get(&mut other_open).await.unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated, "{refused:?}");
    // And nothing more is exchanged.
    let token = env
        .issuing
        .token(&json!({"repository_owner": "acme"}))
        .unwrap();
    let refused = env.exchange(&token).await.unwrap().err().unwrap();
    assert_eq!(refused.code(), Code::Unauthenticated, "{refused:?}");
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn refused_exchanges_are_audited_at_a_bounded_rate() {
    let env = Env::start().await.unwrap();
    let unlimited = Quota {
        rate: None,
        max_in_flight: None,
        max_watch_streams: None,
    };
    env.gate.use_limits(
        Limits::new(NonZeroU32::MIN.saturating_add(999), unlimited, Vec::new()),
        Duration::from_secs(10),
    );
    let sent = 20;
    for _ in 0..sent {
        let refused = env.exchange("not a token").await.unwrap().err().unwrap();
        assert_eq!(refused.code(), Code::Unauthenticated);
    }
    let limited = env.entries("rate_limited", 1).await.unwrap();
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0]["limit"], "exchange_refused");
    assert_eq!(limited[0]["peer"], "127.0.0.1");
    let recorded = env.entries("exchange", 1).await.unwrap();
    assert!(
        !recorded.is_empty() && recorded.len() < sent,
        "{}",
        recorded.len()
    );
    env.destroy().await.unwrap();
}

/// A reload is recorded with the issuers and cutoffs it put in force, so
/// the log tells from when a cutoff refused certificates.
#[tokio::test]
async fn an_identity_reload_is_audited_with_what_it_put_in_force() {
    let env = Env::start().await.unwrap();
    let mut config = identity(&env.issuing, env.exchange_addr).unwrap();
    config.issuers[0].not_before = Some(1_792_800_000);
    config.revoked = vec![(SecretPath::parse("ci/acme/deploy").unwrap(), 1_792_843_200)];
    env.gate.identity_reloaded(Ok(Ok(Some(&config))));
    env.gate.identity_reloaded(Err("no such file".to_owned()));
    let reloads = env.entries("identity_reload", 2).await.unwrap();
    assert_eq!(reloads.len(), 2);
    assert_eq!(reloads[0]["result"], "succeeded");
    assert_eq!(reloads[0]["issuers"][0]["name"], "ci");
    assert_eq!(reloads[0]["issuers"][0]["not_before"], 1_792_800_000);
    assert_eq!(reloads[0]["revoked"][0]["identity"], "ci/acme/deploy");
    assert_eq!(reloads[1]["result"], "failed");
    assert_eq!(reloads[1]["reason"], "no such file");
    env.destroy().await.unwrap();
}

/// Writing the keys database can't make a CA: a row added with a key its
/// writer holds, or a revoked key flipped back to retired, doesn't verify
/// under the root key, so nothing it signed is trusted.
#[tokio::test]
async fn a_ca_written_into_the_keys_database_is_never_trusted() {
    use ferritor_server::identity::ca::{self, IssuingCa};

    let env = Env::start().await.unwrap();
    let now = OffsetDateTime::now_utc();
    let (pkcs8, certificate) = ca::generate(9, now).unwrap();
    let forged = IssuingCa::load(9, &pkcs8, &certificate).unwrap();
    sqlx::query(
        "INSERT INTO issuing_keys (version, certificate, state, retired_at)
         VALUES (9, $1, 'retired', now())",
    )
    .bind(&certificate)
    .execute(env.keys.pool())
    .await
    .unwrap();
    env.seal.refresh(None).await.unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)
        .unwrap();
    let identity = SecretPath::parse("ci/acme/deploy").unwrap();
    let issued = forged
        .issue(csr.der(), &identity, now, now + time::Duration::hours(1))
        .unwrap();
    let workload = Workload {
        cert: certificate_pem(&issued.certificate),
        key: key.serialize_pem(),
        identity: identity.to_string(),
    };
    let refused = Env::get(&mut env.secrets(Some(&workload)).unwrap())
        .await
        .unwrap_err();
    assert!(refused_certificate(&refused), "{refused:?}");

    // A revoked key brought back as retired stays cut off.
    let before = env.deploy("acme").await.unwrap();
    env.put(&before).await.unwrap();
    env.seal.identity_rotate(true).await.unwrap();
    sqlx::query("UPDATE issuing_keys SET state = 'retired' WHERE version = 1")
        .execute(env.keys.pool())
        .await
        .unwrap();
    env.seal.refresh(None).await.unwrap();
    let refused = Env::get(&mut env.secrets(Some(&before)).unwrap())
        .await
        .unwrap_err();
    assert!(refused_certificate(&refused), "{refused:?}");
    // What the active key issues still works.
    let after = env.deploy("acme").await.unwrap();
    Env::get(&mut env.secrets(Some(&after)).unwrap())
        .await
        .unwrap();
    env.destroy().await.unwrap();
}

/// A certificate longer-lived than ferritor ever issues is refused even with
/// a trusted CA's signature: only a key that left ferritor could have made it.
#[tokio::test]
async fn a_certificate_longer_than_any_ferritor_issues_is_refused() {
    let env = Env::start().await.unwrap();
    let ca = env
        .seal
        .keyring()
        .unwrap()
        .issuing()
        .active
        .clone()
        .unwrap();
    let now = OffsetDateTime::now_utc();
    let identity = SecretPath::parse("ci/acme/deploy").unwrap();
    let workload = |days: i64| {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap();
        let issued = ca
            .issue(csr.der(), &identity, now, now + time::Duration::days(days))
            .unwrap();
        Workload {
            cert: certificate_pem(&issued.certificate),
            key: key.serialize_pem(),
            identity: identity.to_string(),
        }
    };
    let (day, week) = (workload(1), workload(7));
    env.put(&day).await.unwrap();
    let refused = Env::get(&mut env.secrets(Some(&week)).unwrap())
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated, "{refused:?}");
    env.destroy().await.unwrap();
}

/// A revoking rotation can't be undone from the keys database alone: the
/// set as it was before (from a backup), or one row of it put back, is a
/// rollback or doesn't verify. A running server keeps the keys in force;
/// a restarted one, held to the floor in the data database, trusts none.
#[tokio::test]
async fn a_revoking_rotation_cant_be_rolled_back() {
    let env = Env::start().await.unwrap();
    let before = env.deploy("acme").await.unwrap();
    env.put(&before).await.unwrap();
    let pool = env.keys.pool();
    for backup in [
        "CREATE TABLE keys_backup AS SELECT * FROM issuing_keys",
        "CREATE TABLE set_backup AS SELECT * FROM issuing_set",
    ] {
        sqlx::query(backup).execute(pool).await.unwrap();
    }
    env.seal.identity_rotate(true).await.unwrap();
    let after = env.deploy("acme").await.unwrap();
    // The backup written back whole: genuinely tagged, but older.
    for restore in [
        "DELETE FROM issuing_keys",
        "INSERT INTO issuing_keys SELECT * FROM keys_backup",
        "UPDATE issuing_set SET revision = b.revision, tag = b.tag FROM set_backup b",
    ] {
        sqlx::query(restore).execute(pool).await.unwrap();
    }
    env.seal.refresh(None).await.unwrap();
    let refused = Env::get(&mut env.secrets(Some(&before)).unwrap())
        .await
        .unwrap_err();
    assert!(refused_certificate(&refused), "{refused:?}");
    Env::get(&mut env.secrets(Some(&after)).unwrap())
        .await
        .unwrap();

    // A restarted server (nothing remembered) is held to the floor.
    let restarted = Seal::new(Keystore::new(pool.clone()))
        .with_revision_floor(Arc::new(Datastore::new(env.data.pool().clone())));
    for share in &env.shares[..2] {
        restarted.unseal(share, false).await.unwrap();
    }
    let keyring = restarted.keyring().unwrap();
    assert!(keyring.issuing().stored.is_empty());
    assert!(keyring.issuing().active.is_none());

    // Only a revoking rotation replaces a set nobody vouches for: it
    // revokes every key in it, and issuing works again.
    assert!(matches!(
        restarted.identity_rotate(false).await,
        Err(SealError::IssuingKeysUnverified)
    ));
    let replaced = restarted.identity_rotate(true).await.unwrap();
    let states: Vec<_> = restarted
        .issuing_keys()
        .unwrap()
        .into_iter()
        .map(|k| (k.version, k.state.as_str()))
        .collect();
    // The backup had version 1 only: the new key is a version 2 again,
    // under a name of its own (its CA's name is random), so nothing the
    // lost version 2 signed matches it.
    assert_eq!(states, [(1, "revoked"), (2, "active")]);
    assert_eq!(replaced.version, 2);
    let refused = Env::get(&mut env.secrets(Some(&before)).unwrap())
        .await
        .unwrap_err();
    assert!(refused_certificate(&refused), "{refused:?}");
    env.destroy().await.unwrap();
}

/// Exchanges for one identity are held to a rate (a burst of 10), refused
/// as `RATE_LIMITED` with limit `exchanges` and audited as one episode;
/// another identity, even from the same issuer, has its own.
#[tokio::test]
async fn exchanges_for_one_identity_are_rate_limited() {
    let env = Env::start().await.unwrap();
    let unlimited = Quota {
        rate: None,
        max_in_flight: None,
        max_watch_streams: None,
    };
    env.gate.use_limits(
        Limits::new(NonZeroU32::MIN.saturating_add(999), unlimited, Vec::new()),
        Duration::from_secs(10),
    );
    let token = env
        .issuing
        .token(&json!({"repository_owner": "acme"}))
        .unwrap();
    let mut refused = Vec::new();
    for _ in 0..15 {
        if let Err(status) = env.exchange(&token).await.unwrap() {
            refused.push(status);
        }
    }
    assert!(
        !refused.is_empty() && refused.len() <= 5,
        "{}",
        refused.len()
    );
    for status in &refused {
        assert_eq!(status.code(), Code::ResourceExhausted, "{status:?}");
        assert_eq!(reason_of(status), Some(reason::RATE_LIMITED.to_owned()));
    }
    env.deploy("other").await.unwrap();
    let limited = env.entries("rate_limited", 1).await.unwrap();
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0]["limit"], "exchanges");
    assert_eq!(limited[0]["caller"], "ci/acme/deploy");
    // Neither issued nor audited as refused one by one.
    let exchanges = env.entries("exchange", 11).await.unwrap();
    assert!(exchanges.iter().all(|e| e["outcome"] == "issued"));
    env.destroy().await.unwrap();
}

/// The burst is the issuer's (`exchange_burst`), for deployments of many
/// replicas sharing an identity: with 30, thirty exchanges at once pass,
/// and a refusal says when to retry.
#[tokio::test]
async fn an_issuers_exchange_burst_is_configurable() {
    let env = Env::start().await.unwrap();
    let unlimited = Quota {
        rate: None,
        max_in_flight: None,
        max_watch_streams: None,
    };
    env.gate.use_limits(
        Limits::new(NonZeroU32::MIN.saturating_add(999), unlimited, Vec::new()),
        Duration::from_secs(10),
    );
    let mut config = identity(&env.issuing, env.exchange_addr).unwrap();
    config.issuers[0].exchange_burst = NonZeroU32::new(30).unwrap();
    env.exchange.reload(Some(config)).await.unwrap();
    let token = env
        .issuing
        .token(&json!({"repository_owner": "acme"}))
        .unwrap();
    for _ in 0..30 {
        env.exchange(&token).await.unwrap().unwrap();
    }
    let mut refused = None;
    for _ in 0..5 {
        if let Err(status) = env.exchange(&token).await.unwrap() {
            refused = Some(status);
            break;
        }
    }
    let refused = refused.unwrap();
    assert_eq!(refused.code(), Code::ResourceExhausted);
    let retry = tonic_types::StatusExt::get_error_details(&refused)
        .retry_info()
        .and_then(|info| info.retry_delay);
    assert!(
        retry.is_some_and(|wait| wait <= Duration::from_secs(1)),
        "{retry:?}"
    );
    env.destroy().await.unwrap();
}
