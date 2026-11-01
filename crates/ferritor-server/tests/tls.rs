//! TLS with client certificates, over real connections: the caller identity
//! reaches the authorizer, and everything else is turned away at the
//! handshake or as UNAUTHENTICATED.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

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
use ferritor_server::tls;
use ferritor_testkit::pki::{Ca, Pem, uri};
use ferritor_testkit::{Captured, TestDatabase, TestResult};
use rcgen::ExtendedKeyUsagePurpose;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tonic::Code;
use tonic::service::Routes;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

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

struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    ca: Ca,
    addr: String,
    callers: Arc<Callers>,
    /// What the audit log wrote.
    audit: Captured,
    /// A handle on the server's TLS, to reload its certificate.
    tls: tls::ServerTls,
    serving: JoinHandle<()>,
}

impl Env {
    async fn start(max_connection_age: Duration) -> TestResult<Self> {
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
        let callers = Arc::new(Callers::default());
        let ca = Ca::new()?;
        let server_cert = ca.server()?;
        let tls_config = tls::server_tls(
            server_cert.cert.as_bytes(),
            server_cert.key.as_bytes(),
            ca.cert.as_bytes(),
            None,
        )?;
        let tls_handle = tls_config.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = format!("https://localhost:{}", listener.local_addr()?.port());
        let audit = Captured::default();
        let gate = Arc::new(Gate::new(
            callers.clone(),
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
        let server = tls::server(max_connection_age, max_connection_age);
        let routes = Routes::new(SystemServiceServer::new(system));
        let serving = tokio::spawn(async move {
            tls::serve(
                server,
                routes,
                listener,
                Some(tls_config),
                std::future::pending(),
            )
            .await
            .ok();
        });
        Ok(Self {
            keys,
            data,
            ca,
            addr,
            callers,
            audit,
            tls: tls_handle,
            serving,
        })
    }

    /// A client trusting this CA, presenting `identity` if given.
    async fn client(&self, identity: Option<&Pem>) -> TestResult<SystemServiceClient<Channel>> {
        let mut tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&self.ca.cert));
        if let Some(pem) = identity {
            tls = tls.identity(Identity::from_pem(&pem.cert, &pem.key));
        }
        let channel = Endpoint::from_shared(self.addr.clone())?
            .tls_config(tls)?
            .connect_lazy();
        Ok(SystemServiceClient::new(channel))
    }

    async fn status(&self, identity: Option<&Pem>) -> TestResult<Result<(), tonic::Status>> {
        let mut client = self.client(identity).await?;
        Ok(client.status(pb::StatusRequest {}).await.map(drop))
    }

    /// The `(action, reason)` of the first rejected authentication, once
    /// written (it's queued, not waited for).
    async fn rejection(&self) -> TestResult<(String, String)> {
        for _ in 0..200 {
            for line in self.audit.lines() {
                let entry: serde_json::Value = serde_json::from_str(&line)?;
                if entry["event"] == "authentication" {
                    assert_eq!(entry["outcome"], "rejected");
                    assert!(
                        entry["peer"]
                            .as_str()
                            .is_some_and(|p| p.starts_with("127.0.0.1:"))
                    );
                    let field = |name: &str| entry[name].as_str().unwrap_or_default().to_owned();
                    return Ok((field("action"), field("reason")));
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err("no authentication entry".into())
    }

    async fn destroy(self) -> TestResult<()> {
        self.serving.abort();
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

const AGE: Duration = Duration::from_secs(600);

#[tokio::test]
async fn the_certificate_identity_reaches_the_authorizer() {
    let env = Env::start(AGE).await.unwrap();
    let alice = env.ca.client("ops/alice").unwrap();
    env.status(Some(&alice)).await.unwrap().unwrap();
    let seen = env.callers.0.lock().unwrap().clone();
    let alice = Caller::Identity(ferritor_core::path::SecretPath::parse("ops/alice").unwrap());
    // Status asks three times: Status, Rekey (whether to show a nonce) and
    // Unseal (whether to show the auto-unseal key and errors).
    assert_eq!(seen, [alice.clone(), alice.clone(), alice]);
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn no_client_certificate_is_turned_away() {
    let env = Env::start(AGE).await.unwrap();
    assert!(env.status(None).await.unwrap().is_err());
    assert!(env.callers.0.lock().unwrap().is_empty());
    env.destroy().await.unwrap();
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_turned_away() {
    let env = Env::start(AGE).await.unwrap();
    let stranger = Ca::new().unwrap().client("ops/alice").unwrap();
    assert!(env.status(Some(&stranger)).await.unwrap().is_err());
    assert!(env.callers.0.lock().unwrap().is_empty());
    env.destroy().await.unwrap();
}

/// With one CA for servers and clients, a server certificate must not work
/// as a client one: the verifier requires the client-auth key usage.
#[tokio::test]
async fn a_server_only_certificate_is_not_a_client_certificate() {
    let env = Env::start(AGE).await.unwrap();
    let server_only = env
        .ca
        .issue(
            vec![uri("ferritor://ops/alice").unwrap()],
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            None,
        )
        .unwrap();
    assert!(env.status(Some(&server_only)).await.unwrap().is_err());
    assert!(env.callers.0.lock().unwrap().is_empty());
    env.destroy().await.unwrap();
}

/// A certificate the CA signed but without a valid identity gets through
/// the handshake, and is then UNAUTHENTICATED, not anonymous.
#[tokio::test]
async fn a_valid_certificate_without_an_identity_is_unauthenticated() {
    let env = Env::start(AGE).await.unwrap();
    let nameless = env
        .ca
        .issue(
            vec![uri("spiffe://ops/alice").unwrap()],
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            None,
        )
        .unwrap();
    let refused = env.status(Some(&nameless)).await.unwrap().unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated);
    assert!(
        refused.message().contains("ferritor://"),
        "{}",
        refused.message()
    );
    assert!(env.callers.0.lock().unwrap().is_empty());
    assert_eq!(
        env.rejection().await.unwrap(),
        ("status".to_owned(), "wrong_scheme".to_owned())
    );
    env.destroy().await.unwrap();
}

/// The handshake alone doesn't enforce expiry: an open connection, or a
/// reconnect that resumes the TLS session from a ticket, keeps using the
/// certificate it started with. So expiry is checked on every request.
#[tokio::test]
async fn an_expired_certificate_stops_working_on_an_open_connection() {
    let env = Env::start(AGE).await.unwrap();
    let short_lived = env
        .ca
        .issue(
            vec![uri("ferritor://ops/alice").unwrap()],
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            Some(OffsetDateTime::now_utc() + time::Duration::seconds(2)),
        )
        .unwrap();
    let mut client = env.client(Some(&short_lived)).await.unwrap();
    client.status(pb::StatusRequest {}).await.unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;
    let refused = client.status(pb::StatusRequest {}).await.unwrap_err();
    assert_eq!(
        (refused.code(), refused.message()),
        (
            Code::Unauthenticated,
            "the client certificate has expired or is not yet valid"
        )
    );
    assert_eq!(
        env.rejection().await.unwrap(),
        ("status".to_owned(), "not_valid_now".to_owned())
    );
    // And a fresh connection is turned away at the handshake.
    assert!(env.status(Some(&short_lived)).await.unwrap().is_err());
    env.destroy().await.unwrap();
}

/// The fingerprint of the certificate the server presents on a fresh
/// handshake, as `alice` sees it.
async fn presented(env: &Env, alice: &Pem) -> TestResult<String> {
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto};

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(env.ca.cert.as_bytes())?)?;
    let config = ClientConfig::builder_with_provider(Arc::new(crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(
            CertificateDer::pem_slice_iter(alice.cert.as_bytes()).collect::<Result<_, _>>()?,
            PrivateKeyDer::from_pem_slice(alice.key.as_bytes())?,
        )?;
    let port = env.addr.rsplit(':').next().ok_or("no port")?;
    let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost")?, tcp)
        .await?;
    let leaf = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or("no certificate presented")?;
    Ok(ferritor_server::fingerprint(leaf))
}

/// A renewed server certificate takes effect without a restart: new
/// handshakes present it, and calls keep working. A key that doesn't match
/// its certificate is refused, and the current one stays.
#[tokio::test]
async fn the_server_certificate_reloads_without_a_restart() {
    let env = Env::start(AGE).await.unwrap();
    let alice = env.ca.client("ops/alice").unwrap();
    let before = presented(&env, &alice).await.unwrap();
    assert_eq!(before, env.tls.certificate_fingerprint());

    let renewed = env.ca.server().unwrap();
    let after = env
        .tls
        .reload_certificate(renewed.cert.as_bytes(), renewed.key.as_bytes())
        .unwrap();
    assert_ne!(after, before);
    assert_eq!(presented(&env, &alice).await.unwrap(), after);
    env.status(Some(&alice)).await.unwrap().unwrap();

    let other = env.ca.server().unwrap();
    let mismatched = env
        .tls
        .reload_certificate(renewed.cert.as_bytes(), other.key.as_bytes());
    assert!(matches!(mismatched, Err(tls::TlsSetupError::Identity(_))));
    assert_eq!(presented(&env, &alice).await.unwrap(), after);
    env.destroy().await.unwrap();
}

/// A server certificate that isn't valid now would fail every handshake:
/// a reload refuses it (the current one keeps working), and so does
/// startup, with a clear error instead of a server nobody can reach.
#[tokio::test]
async fn an_expired_server_certificate_is_refused_at_reload_and_startup() {
    let env = Env::start(AGE).await.unwrap();
    let alice = env.ca.client("ops/alice").unwrap();
    let current = presented(&env, &alice).await.unwrap();
    let expired = env
        .ca
        .issue(
            vec![rcgen::SanType::DnsName("localhost".try_into().unwrap())],
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            Some(OffsetDateTime::now_utc() - time::Duration::days(1)),
        )
        .unwrap();

    let refused = env
        .tls
        .reload_certificate(expired.cert.as_bytes(), expired.key.as_bytes())
        .unwrap_err();
    assert!(
        matches!(refused, tls::TlsSetupError::CertNotValidNow { .. }),
        "{refused}"
    );
    assert_eq!(presented(&env, &alice).await.unwrap(), current);
    env.status(Some(&alice)).await.unwrap().unwrap();

    let at_startup = tls::server_tls(
        expired.cert.as_bytes(),
        expired.key.as_bytes(),
        env.ca.cert.as_bytes(),
        None,
    );
    assert!(matches!(
        at_startup,
        Err(tls::TlsSetupError::CertNotValidNow { .. })
    ));
    env.destroy().await.unwrap();
}

/// A day from now: when the test CRLs are due for renewal.
fn tomorrow() -> OffsetDateTime {
    OffsetDateTime::now_utc() + time::Duration::days(1)
}

/// Revoking needs no restart and no new connection: a reloaded CRL applies
/// to the next request on a connection already open (whose handshake, or a
/// session resumed from it, never sees the new CRL), and fresh handshakes
/// are refused. Certificates it doesn't list keep working.
#[tokio::test]
async fn a_revoked_certificate_stops_working_on_an_open_connection() {
    let env = Env::start(AGE).await.unwrap();
    let (alice, bob) = (
        env.ca.client("ops/alice").unwrap(),
        env.ca.client("ops/bob").unwrap(),
    );
    let mut as_alice = env.client(Some(&alice)).await.unwrap();
    let mut as_bob = env.client(Some(&bob)).await.unwrap();
    as_alice.status(pb::StatusRequest {}).await.unwrap();
    as_bob.status(pb::StatusRequest {}).await.unwrap();

    let crl = env.ca.crl(&[&alice], tomorrow()).unwrap();
    let crls = env.tls.reload_crl(Some(crl.as_bytes())).unwrap().unwrap();
    assert_eq!(crls.iter().map(|crl| crl.revoked).collect::<Vec<_>>(), [1]);
    assert_eq!(env.tls.crls(), Some(crls));

    let refused = as_alice.status(pb::StatusRequest {}).await.unwrap_err();
    assert_eq!(
        (refused.code(), refused.message()),
        (
            Code::Unauthenticated,
            "the client certificate has been revoked"
        )
    );
    assert_eq!(
        env.rejection().await.unwrap(),
        ("status".to_owned(), "revoked".to_owned())
    );
    // A fresh connection fails at the handshake (rustls has the CRL too),
    // so no request exists to refuse: no second authentication entry.
    let at_handshake = env.status(Some(&alice)).await.unwrap().unwrap_err();
    assert_ne!(at_handshake.code(), Code::Unauthenticated, "{at_handshake}");
    as_bob.status(pb::StatusRequest {}).await.unwrap();
    env.status(Some(&bob)).await.unwrap().unwrap();
    // Bob's entries waited for the writer, so anything queued before is in.
    let rejected = env
        .audit
        .lines()
        .iter()
        .filter(|line| line.contains(r#""event":"authentication""#))
        .count();
    assert_eq!(rejected, 1);
    env.destroy().await.unwrap();
}

/// A CRL that doesn't check out is refused, and the current one stays;
/// removing the CRL file revokes nothing any more.
#[tokio::test]
async fn a_bad_crl_is_refused_and_the_current_one_stays() {
    let env = Env::start(AGE).await.unwrap();
    let (alice, bob) = (
        env.ca.client("ops/alice").unwrap(),
        env.ca.client("ops/bob").unwrap(),
    );
    let crl = env.ca.crl(&[&alice], tomorrow()).unwrap();
    env.tls.reload_crl(Some(crl.as_bytes())).unwrap();
    let in_force = env.tls.crls();

    // Same name as the client CA (rcgen's default), another key.
    let forged = Ca::new().unwrap().crl(&[&bob], tomorrow()).unwrap();
    let refused = env.tls.reload_crl(Some(forged.as_bytes())).unwrap_err();
    assert!(matches!(refused, tls::TlsSetupError::Crl(_)), "{refused}");
    assert!(matches!(
        env.tls.reload_crl(Some(b"not a CRL")),
        Err(tls::TlsSetupError::Crl(_))
    ));
    assert_eq!(env.tls.crls(), in_force);
    assert!(env.status(Some(&alice)).await.unwrap().is_err());
    env.status(Some(&bob)).await.unwrap().unwrap();

    assert_eq!(env.tls.reload_crl(None).unwrap(), None);
    assert_eq!(env.tls.crls(), None);
    env.status(Some(&alice)).await.unwrap().unwrap();
    env.destroy().await.unwrap();
}

/// At startup a CRL is checked the same way: one from elsewhere is a clear
/// error, not a server whose handshakes all fail.
#[tokio::test]
async fn a_crl_is_checked_at_startup() {
    let ca = Ca::new().unwrap();
    let server = ca.server().unwrap();
    let start = |crl: &str| {
        tls::server_tls(
            server.cert.as_bytes(),
            server.key.as_bytes(),
            ca.cert.as_bytes(),
            Some(crl.as_bytes()),
        )
    };
    let crl = ca.crl(&[], tomorrow()).unwrap();
    let crls = start(&crl).unwrap().crls().unwrap();
    assert_eq!(crls.len(), 1);
    assert_eq!(crls[0].number.as_deref(), Some("1"));
    let forged = Ca::new().unwrap().crl(&[], tomorrow()).unwrap();
    assert!(matches!(start(&forged), Err(tls::TlsSetupError::Crl(_))));
}
