//! TLS with client certificates: the transport, and who a caller is.
//!
//! The server requires a client certificate signed by the configured client
//! CA (rustls's WebPKI verifier, which also requires the "client
//! authentication" extended key usage). A caller's identity is the
//! certificate's single URI SAN of the form `ferritor://<name>`, where `<name>`
//! follows the secret-path rules (`ops/alice`). A certificate with no such
//! SAN, several, another scheme or a bad name is rejected rather than
//! guessed at, so a SAN some other CA put in for its own purposes can't
//! accidentally match a policy.
//!
//! Expiry and revocation are checked on every request ([`identity`]), not
//! just at the handshake: an HTTP/2 connection can stay open for days, and a
//! TLS session resumed from a ticket reuses the original chain without the
//! verifier seeing it again (observed: an expired certificate kept working
//! across a reconnect). Expiry is checked for every certificate the client
//! presented; revocation, with the optional CRL file (`[tls] crl`, see
//! [`crate::crl`]), for the client certificate itself, and the CRLs reload
//! on SIGHUP ([`ServerTls::reload_crl`]). Without a CRL file nothing is
//! revoked: rely on short-lived client certificates. Neither depends on
//! connection recycling ([`server`]); that is general hygiene, and changing
//! the trusted client CA needs a restart anyway.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::response::IntoResponse;

use ferritor_core::path::{PathError, SecretPath};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::client::danger::HandshakeSignatureValid;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::pem::{self, PemObject};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use tokio_rustls::rustls::server::VerifierBuilderError;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::{
    self, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig, SignatureScheme,
};
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tonic::service::Routes;
use tonic::transport::Server;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::audit::Gate;
use crate::authz::{Action, Caller};
use crate::crl::{CrlError, CrlInfo, Crls};
use crate::http;

/// The only URI SAN scheme accepted as a caller identity.
pub const IDENTITY_SCHEME: &str = "ferritor://";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("the client certificate could not be parsed")]
    Unparsable,
    #[error("the client certificate has expired or is not yet valid")]
    NotValidNow,
    #[error("the client certificate has been revoked")]
    Revoked,
    /// Its issuer has no CRL in force, or the request didn't come through
    /// [`serve`] (which provides the CRLs): refused, not assumed fine.
    #[error("the client certificate's revocation status is unknown")]
    RevocationUnknown,
    #[error("the client certificate has no `{IDENTITY_SCHEME}<name>` URI SAN")]
    Missing,
    #[error("the client certificate has more than one URI SAN; exactly one is accepted")]
    Ambiguous,
    #[error("the client certificate's URI SAN is not a `{IDENTITY_SCHEME}<name>` identity")]
    WrongScheme,
    #[error("the client certificate's identity name is invalid")]
    BadName(#[source] PathError),
}

impl IdentityError {
    /// A stable name for the audit log.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Unparsable => "unparsable",
            Self::NotValidNow => "not_valid_now",
            Self::Revoked => "revoked",
            Self::RevocationUnknown => "revocation_unknown",
            Self::Missing => "missing",
            Self::Ambiguous => "ambiguous",
            Self::WrongScheme => "wrong_scheme",
            Self::BadName(_) => "bad_name",
        }
    }
}

/// The caller identity in a client certificate chain (leaf first, as tonic's
/// `Request::peer_certs` gives it): the name in its one `ferritor://` URI SAN.
/// Called on every request, so it also checks every certificate presented
/// (leaf and any intermediates) is valid right now, and with `crls` that the
/// leaf isn't revoked: see the module docs on why the handshake alone isn't
/// enough.
///
/// A leaf the workload-identity issuing CA signed (`workload`, see
/// [`WorkloadTrust`]) isn't covered by the CRLs: instead its CA must still
/// be trusted, and the trust must admit its identity and issue time (an
/// issuer still configured, no cutoff after it).
pub fn identity(
    chain: &[impl AsRef<[u8]>],
    crls: Option<&Crls>,
    workload: Option<&dyn WorkloadTrust>,
) -> Result<SecretPath, IdentityError> {
    let mut certs = chain.iter().map(|der| {
        X509Certificate::from_der(der.as_ref())
            .map(|(_, cert)| cert)
            .map_err(|_| IdentityError::Unparsable)
    });
    let cert = certs.next().ok_or(IdentityError::Unparsable)??;
    if !cert.validity().is_valid() {
        return Err(IdentityError::NotValidNow);
    }
    for other in certs {
        if !other?.validity().is_valid() {
            return Err(IdentityError::NotValidNow);
        }
    }
    // Issued by a workload-identity CA: trusted (`Some(true)`) or revoked.
    let workload_issued = workload.and_then(|trust| {
        let issuer = cert.issuer().as_raw();
        trust
            .cas()
            .into_iter()
            .find(|ca| ca.subject == issuer)
            .map(|ca| ca.trusted)
    });
    match workload_issued {
        Some(false) => return Err(IdentityError::Revoked),
        Some(true) => {}
        None => {
            if let Some(crls) = crls {
                crls.check(&cert)?;
            }
        }
    }
    let sans = cert
        .subject_alternative_name()
        .map_err(|_| IdentityError::Unparsable)?;
    let mut uris = sans
        .iter()
        .flat_map(|san| san.value.general_names.iter())
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        });
    let uri = uris.next().ok_or(IdentityError::Missing)?;
    if uris.next().is_some() {
        return Err(IdentityError::Ambiguous);
    }
    let name = uri
        .strip_prefix(IDENTITY_SCHEME)
        .ok_or(IdentityError::WrongScheme)?;
    let identity = SecretPath::parse(name).map_err(IdentityError::BadName)?;
    if let (Some(true), Some(trust)) = (workload_issued, workload) {
        let validity = cert.validity();
        let not_before = validity.not_before.timestamp();
        let issued_at = not_before.saturating_add(crate::identity::ca::BACKDATE.whole_seconds());
        // Never longer than ferritor issues: one that is was signed by a key
        // that left ferritor (stolen before it was revoked or retired).
        let longest = i64::try_from(crate::identity::MAX_LIFETIME.as_secs())
            .unwrap_or(i64::MAX)
            .saturating_add(crate::identity::ca::BACKDATE.whole_seconds());
        let lifetime = validity.not_after.timestamp().saturating_sub(not_before);
        if lifetime > longest || !trust.admits(&identity, issued_at) {
            return Err(IdentityError::Revoked);
        }
    }
    Ok(identity)
}

/// A workload-identity issuing CA, as the TLS layer sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadCa {
    /// The CA certificate, DER.
    pub certificate: Vec<u8>,
    /// Its subject, DER: what an issued certificate's issuer is matched to.
    pub subject: Vec<u8>,
    /// Whether what it signed is trusted now (active, or retired with its
    /// certificates possibly still valid), or not (revoked).
    pub trusted: bool,
}

/// What decides about the client certificates the workload-identity
/// issuing CA signed (implemented by `identity::Trust`, from the keyring
/// and the `[identity]` config). Asked at every handshake and every
/// request, so a seal, a rotation (here or on another server) or a reload
/// takes effect at once, open connections included.
pub trait WorkloadTrust: Send + Sync + 'static {
    /// Every issuing CA there is (none while sealed).
    fn cas(&self) -> Vec<WorkloadCa>;
    /// Whether a certificate one of them signed for `identity`, issued at
    /// `issued_at` (unix seconds), may be used now: its identity under an
    /// issuer still configured, issued after any cutoff for either.
    fn admits(&self, identity: &SecretPath, issued_at: i64) -> bool;
}

/// The server's TLS: its certificate, and the CA every client certificate
/// must chain to (rustls's WebPKI verifier, which also requires the
/// client-auth key usage). Built here rather than with tonic's
/// `ServerTlsConfig`, which offers only `h2` in ALPN: the JSON API also
/// serves HTTP/1.1-only clients, and a client offering only `http/1.1`
/// would fail the handshake. Same crypto provider as tonic (ring).
///
/// The server certificate can be replaced while serving
/// ([`ServerTls::reload_certificate`], on SIGHUP), so renewing a
/// short-lived one needs no restart: new handshakes present the new one,
/// open connections keep theirs. So can the CRLs
/// ([`ServerTls::reload_crl`]), which apply to open connections too. The
/// client CA is fixed until a restart.
#[derive(Clone)]
pub struct ServerTls {
    acceptor: TlsAcceptor,
    certificate: Arc<CurrentCertificate>,
    client_auth: Arc<ClientAuth>,
    provider: Arc<CryptoProvider>,
    max_handshakes: usize,
    handshake_timeout: Duration,
    /// Which listener this serves, for the handshake-failure metric:
    /// `api`, `exchange` or `metrics`.
    listener: &'static str,
}

impl ServerTls {
    /// The SHA-256 fingerprint of the certificate presented now (the leaf,
    /// as DER): the usual way to name a certificate.
    pub fn certificate_fingerprint(&self) -> String {
        self.certificate.fingerprint()
    }

    /// When the certificate presented now expires, in unix seconds (for
    /// metrics: renewals are what to alert on).
    pub fn certificate_expiry(&self) -> Option<u64> {
        not_after(&self.certificate.current())
            .and_then(|expiry| u64::try_from(expiry.timestamp()).ok())
    }

    /// Replaces the server certificate and key, for every handshake from
    /// now on, and returns the new fingerprint. On any error (unreadable
    /// PEM, a key that doesn't match the certificate) the current one
    /// stays.
    pub fn reload_certificate(
        &self,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<String, TlsSetupError> {
        let certified = certified_key(cert_pem, key_pem, &self.provider)?;
        // Valid now (checked above), but a renewal should last longer than
        // what it replaces: say so if it doesn't.
        if let (Some(new), Some(current)) = (
            not_after(&certified),
            not_after(&self.certificate.current()),
        ) && new < current
        {
            tracing::warn!(
                new = %new,
                current = %current,
                "the reloaded server certificate expires sooner than the one it replaces"
            );
        }
        *self
            .certificate
            .0
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(certified);
        Ok(self.certificate_fingerprint())
    }

    /// The CRLs in force, one entry each; `None` without a CRL file.
    pub fn crls(&self) -> Option<Vec<CrlInfo>> {
        self.client_auth
            .current()
            .crls
            .map(|crls| crls.info().to_vec())
    }

    /// The earliest `nextUpdate` of the CRLs in force, in unix seconds (for
    /// metrics: a stale CRL may be missing revocations).
    pub fn crl_next_update(&self) -> Option<u64> {
        let crls = self.client_auth.current().crls?;
        let earliest = crls
            .info()
            .iter()
            .filter_map(CrlInfo::next_update_at)
            .min()?;
        u64::try_from(earliest).ok()
    }

    /// Replaces the CRLs (`None`: revoke nothing), for every handshake from
    /// now on and every request, open connections included, and returns the
    /// new ones. On any error the current ones stay.
    pub fn reload_crl(
        &self,
        crl_pem: Option<&[u8]>,
    ) -> Result<Option<Vec<CrlInfo>>, TlsSetupError> {
        let verifier = self.client_auth.verifier(crl_pem)?;
        let current = self.client_auth.current().crls;
        match (&verifier.crls, &current) {
            (None, Some(_)) => {
                tracing::warn!(
                    "the CRL file is no longer set: no client certificate is revoked now"
                );
            }
            (Some(new), Some(current)) => warn_if_older(new, current),
            _ => {}
        }
        let info = verifier.crls.as_ref().map(|crls| crls.info().to_vec());
        *self
            .client_auth
            .current
            .write()
            .unwrap_or_else(PoisonError::into_inner) = verifier;
        Ok(info)
    }

    /// The same server certificate (reloaded with it) on a listener that
    /// asks for no client certificate: only for the workload-identity
    /// exchange, which is how a workload gets its first one. gRPC only.
    pub fn without_client_auth(&self) -> Result<ServerTls, TlsSetupError> {
        let mut config = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .map_err(TlsSetupError::Identity)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(&self.certificate) as Arc<dyn ResolvesServerCert>);
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(ServerTls {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            certificate: Arc::clone(&self.certificate),
            client_auth: Arc::clone(&self.client_auth),
            provider: Arc::clone(&self.provider),
            max_handshakes: self.max_handshakes,
            handshake_timeout: self.handshake_timeout,
            listener: "exchange",
        })
    }

    /// The same server certificate (reloaded with it) on the Prometheus
    /// scrape listener ([`serve_metrics`]). With `client_ca_pem`, the
    /// handshake requires a client certificate from that CA: the scraper's
    /// credential, never a caller (no identity, no CRL, nothing audited);
    /// without, none is asked for.
    pub fn for_metrics(&self, client_ca_pem: Option<&[u8]>) -> Result<ServerTls, TlsSetupError> {
        let builder = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .map_err(TlsSetupError::Identity)?;
        let builder = match client_ca_pem {
            None => builder.with_no_client_auth(),
            Some(pem) => {
                let (roots, _) = client_roots(pem)?;
                builder.with_client_cert_verifier(
                    WebPkiClientVerifier::builder_with_provider(
                        Arc::new(roots),
                        Arc::clone(&self.provider),
                    )
                    .build()
                    .map_err(TlsSetupError::Verifier)?,
                )
            }
        };
        let mut config = builder
            .with_cert_resolver(Arc::clone(&self.certificate) as Arc<dyn ResolvesServerCert>);
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(ServerTls {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            certificate: Arc::clone(&self.certificate),
            client_auth: Arc::clone(&self.client_auth),
            provider: Arc::clone(&self.provider),
            max_handshakes: self.max_handshakes,
            handshake_timeout: self.handshake_timeout,
            listener: "metrics",
        })
    }

    /// Lets the handshake and every request trust the certificates the
    /// workload-identity issuing CA signs, as `trust` decides (once: a
    /// later call is ignored).
    pub fn use_workload_trust(&self, trust: Arc<dyn WorkloadTrust>) {
        if self.client_auth.workload.set(trust).is_err() {
            tracing::warn!("workload trust was already set; keeping the first");
        }
    }

    /// What [`identity`] checks revocation against, for the requests
    /// [`serve`] passes on.
    fn revocation(&self) -> Revocation {
        Revocation(Arc::clone(&self.client_auth))
    }

    /// At most `max` handshakes at once, each given `timeout` (defaults
    /// [`MAX_HANDSHAKES`] and [`HANDSHAKE_TIMEOUT`]; see [`serve`]).
    #[must_use]
    pub fn with_handshake_limits(self, max: usize, timeout: Duration) -> Self {
        Self {
            max_handshakes: max,
            handshake_timeout: timeout,
            ..self
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TlsSetupError {
    #[error("the server certificate is not valid PEM")]
    Cert(#[source] pem::Error),
    #[error("the server key is not valid PEM")]
    Key(#[source] pem::Error),
    #[error("the client CA is not valid PEM")]
    ClientCa(#[source] pem::Error),
    #[error("the client CA file holds no certificate")]
    NoClientCa,
    #[error("the client CA certificate was rejected")]
    BadClientCa(#[source] rustls::Error),
    #[error("the client certificate verifier could not be built")]
    Verifier(#[source] VerifierBuilderError),
    #[error("the CRL file was refused")]
    Crl(#[source] CrlError),
    #[error("the server certificate file holds no certificate")]
    NoCert,
    #[error("the server certificate could not be parsed")]
    UnparsableCert,
    /// Expired, or not valid yet (a clock-skewed CA): every handshake would
    /// fail with it.
    #[error("the server certificate is not valid now (valid from {not_before} to {not_after})")]
    CertNotValidNow {
        not_before: String,
        not_after: String,
    },
    #[error("the server certificate and key were rejected")]
    Identity(#[source] rustls::Error),
}

/// TLS for the server, requiring a client certificate signed by `client_ca`
/// and, with `crl_pem`, not revoked by its CRL.
pub fn server_tls(
    cert_pem: &[u8],
    key_pem: &[u8],
    client_ca_pem: &[u8],
    crl_pem: Option<&[u8]>,
) -> Result<ServerTls, TlsSetupError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (roots, cas) = client_roots(client_ca_pem)?;
    let hints = roots.subjects();
    let roots = Arc::new(roots);
    let verifier = verifier(&roots, &cas, &provider, crl_pem)?;
    let client_auth = Arc::new(ClientAuth {
        roots,
        cas,
        hints,
        provider: Arc::clone(&provider),
        current: RwLock::new(verifier),
        workload: OnceLock::new(),
        workload_verifier: Mutex::new(None),
    });
    let certificate = Arc::new(CurrentCertificate(RwLock::new(Arc::new(certified_key(
        cert_pem, key_pem, &provider,
    )?))));
    let mut config = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(TlsSetupError::Identity)?
        .with_client_cert_verifier(Arc::clone(&client_auth) as Arc<dyn ClientCertVerifier>)
        .with_cert_resolver(Arc::clone(&certificate) as Arc<dyn ResolvesServerCert>);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(ServerTls {
        acceptor: TlsAcceptor::from(Arc::new(config)),
        certificate,
        client_auth,
        provider,
        max_handshakes: MAX_HANDSHAKES,
        handshake_timeout: HANDSHAKE_TIMEOUT,
        listener: "api",
    })
}

/// The CA certificates in `client_ca_pem`, as roots and as read: at least
/// one.
fn client_roots(
    client_ca_pem: &[u8],
) -> Result<(RootCertStore, Vec<CertificateDer<'static>>), TlsSetupError> {
    let cas = CertificateDer::pem_slice_iter(client_ca_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(TlsSetupError::ClientCa)?;
    let mut roots = RootCertStore::empty();
    for ca in &cas {
        roots.add(ca.clone()).map_err(TlsSetupError::BadClientCa)?;
    }
    if roots.is_empty() {
        return Err(TlsSetupError::NoClientCa);
    }
    Ok((roots, cas))
}

/// A certificate chain (leaf first) and its key, checked to match.
fn certified_key(
    cert_pem: &[u8],
    key_pem: &[u8],
    provider: &CryptoProvider,
) -> Result<CertifiedKey, TlsSetupError> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(TlsSetupError::Cert)?;
    let leaf = certs.first().ok_or(TlsSetupError::NoCert)?;
    // Checked here, so for startup and every reload: a certificate that
    // isn't valid now would fail every handshake, taking the server off
    // the air (on a reload, where the current one still works).
    let (_, parsed) =
        X509Certificate::from_der(leaf.as_ref()).map_err(|_| TlsSetupError::UnparsableCert)?;
    let validity = parsed.validity();
    if !validity.is_valid() {
        return Err(TlsSetupError::CertNotValidNow {
            not_before: validity.not_before.to_string(),
            not_after: validity.not_after.to_string(),
        });
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(TlsSetupError::Key)?;
    CertifiedKey::from_der(certs, key, provider).map_err(TlsSetupError::Identity)
}

/// When a certified key's leaf certificate expires.
fn not_after(certified: &CertifiedKey) -> Option<x509_parser::time::ASN1Time> {
    let leaf = certified.cert.first()?;
    let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).ok()?;
    Some(parsed.validity().not_after)
}

/// The server certificate every handshake gets: whichever is current.
#[derive(Debug)]
struct CurrentCertificate(RwLock<Arc<CertifiedKey>>);

impl CurrentCertificate {
    fn current(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }

    fn fingerprint(&self) -> String {
        self.current()
            .cert
            .first()
            .map(|leaf| crate::fingerprint(leaf))
            .unwrap_or_default()
    }
}

impl ResolvesServerCert for CurrentCertificate {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

/// Warns about a reloaded CRL older than the one it replaces (a lower CRL
/// number from the same issuer): it may un-revoke certificates.
fn warn_if_older(new: &Crls, current: &Crls) {
    let number = |info: &CrlInfo| info.number.as_deref().and_then(|n| n.parse::<u128>().ok());
    for info in new.info() {
        let previous = current.info().iter().find(|c| c.issuer == info.issuer);
        if let (Some(new_number), Some(current_number)) = (number(info), previous.and_then(number))
            && new_number < current_number
        {
            tracing::warn!(
                issuer = info.issuer,
                new = new_number,
                current = current_number,
                "the reloaded CRL is older than the one it replaces: certificates revoked since \
                 may work again"
            );
        }
    }
}

/// The client certificate verifier every handshake uses: rustls's WebPKI
/// one, with whichever CRLs are current (the CA stays). Swapped as a
/// whole, together with the CRLs the per-request check uses, so the two
/// always check against the same CRLs.
#[derive(Debug)]
struct ClientAuth {
    roots: Arc<RootCertStore>,
    /// The client CA certificates, which every CRL must come from.
    cas: Vec<CertificateDer<'static>>,
    /// The CA's names, hinted to clients: fixed, like the CA.
    hints: Vec<DistinguishedName>,
    provider: Arc<CryptoProvider>,
    current: RwLock<Verifier>,
    /// Workload identity, once the server has it (see [`WorkloadTrust`]).
    workload: OnceLock<Arc<dyn WorkloadTrust>>,
    /// A verifier for the trusted issuing CAs, with the certificates it
    /// was built from: rebuilt when they change.
    workload_verifier: Mutex<Option<WorkloadVerifier>>,
}

/// The trusted issuing CAs (DER), and the verifier built from them.
type WorkloadVerifier = (Vec<Vec<u8>>, Arc<dyn ClientCertVerifier>);

impl std::fmt::Debug for dyn WorkloadTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkloadTrust")
    }
}

/// Which verifier a client certificate goes to.
enum Route {
    /// The client CA's (with its CRLs).
    Operator,
    /// The trusted issuing CAs' (no CRLs: their certificates are revoked
    /// by expiring, and by the trust's cutoffs).
    Workload(Arc<dyn ClientCertVerifier>),
    /// Signed by an issuing CA that's revoked.
    Revoked,
}

#[derive(Debug, Clone)]
struct Verifier {
    webpki: Arc<dyn ClientCertVerifier>,
    crls: Option<Arc<Crls>>,
}

/// A verifier for the client CA `roots` (`cas`, as certificates) with the
/// CRLs in `crl_pem`, if any: only the client certificate is checked (see
/// `crl`), a certificate whose status is unknown is refused, and a stale
/// CRL still counts.
fn verifier(
    roots: &Arc<RootCertStore>,
    cas: &[CertificateDer<'static>],
    provider: &Arc<CryptoProvider>,
    crl_pem: Option<&[u8]>,
) -> Result<Verifier, TlsSetupError> {
    let crls = crl_pem
        .map(|pem| Crls::parse(pem, cas).map_err(TlsSetupError::Crl))
        .transpose()?;
    let mut builder =
        WebPkiClientVerifier::builder_with_provider(Arc::clone(roots), Arc::clone(provider));
    if let Some(crls) = &crls {
        builder = builder
            .with_crls(crls.ders())
            .only_check_end_entity_revocation();
        for stale in crls.info().iter().filter(|info| info.is_stale()) {
            tracing::warn!(
                issuer = stale.issuer,
                next_update = stale.next_update,
                "a CRL is past its nextUpdate: still used, but it may be missing revocations \
                 (renew it and send SIGHUP)"
            );
        }
    }
    Ok(Verifier {
        webpki: builder.build().map_err(TlsSetupError::Verifier)?,
        crls: crls.map(Arc::new),
    })
}

impl ClientAuth {
    fn current(&self) -> Verifier {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn verifier(&self, crl_pem: Option<&[u8]>) -> Result<Verifier, TlsSetupError> {
        verifier(&self.roots, &self.cas, &self.provider, crl_pem)
    }

    fn webpki(&self) -> Arc<dyn ClientCertVerifier> {
        self.current().webpki
    }

    /// Where `leaf` goes: by its issuer, to the issuing CAs' verifier if
    /// one of them issued it, else to the client CA's. Choosing only
    /// decides which roots it's verified against, fully either way: a
    /// certificate naming an issuing CA it wasn't signed by fails there.
    fn route(&self, leaf: &CertificateDer<'_>) -> Result<Route, rustls::Error> {
        let Some(trust) = self.workload.get() else {
            return Ok(Route::Operator);
        };
        let Ok((_, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
            // The client CA's verifier refuses it, with its own error.
            return Ok(Route::Operator);
        };
        let cas = trust.cas();
        let Some(issuer) = cas.iter().find(|ca| ca.subject == cert.issuer().as_raw()) else {
            return Ok(Route::Operator);
        };
        if !issuer.trusted {
            return Ok(Route::Revoked);
        }
        let trusted: Vec<Vec<u8>> = cas
            .iter()
            .filter(|ca| ca.trusted)
            .map(|ca| ca.certificate.clone())
            .collect();
        let mut cached = self
            .workload_verifier
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((built_from, verifier)) = cached.as_ref()
            && *built_from == trusted
        {
            return Ok(Route::Workload(Arc::clone(verifier)));
        }
        let mut roots = RootCertStore::empty();
        for ca in &trusted {
            roots.add(CertificateDer::from(ca.clone()))?;
        }
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&self.provider),
        )
        .build()
        .map_err(|e| rustls::Error::General(e.to_string()))?;
        *cached = Some((trusted, Arc::clone(&verifier)));
        Ok(Route::Workload(verifier))
    }
}

impl ClientCertVerifier for ClientAuth {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        match self.route(end_entity)? {
            Route::Operator => self
                .webpki()
                .verify_client_cert(end_entity, intermediates, now),
            Route::Workload(verifier) => {
                verifier.verify_client_cert(end_entity, intermediates, now)
            }
            Route::Revoked => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Revoked,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki().verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki().verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki().supported_verify_schemes()
    }
}

/// The CRLs in force, as [`serve`] hands them to every request (a request
/// extension), for [`caller`].
#[derive(Clone)]
pub struct Revocation(Arc<ClientAuth>);

impl Revocation {
    fn current(&self) -> Option<Arc<Crls>> {
        self.0.current().crls
    }

    fn workload(&self) -> Option<Arc<dyn WorkloadTrust>> {
        self.0.workload.get().cloned()
    }
}

/// How long a client gets to complete the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// TLS handshakes in progress at once, at most (see [`ServerTls::with_handshake_limits`]).
pub const MAX_HANDSHAKES: usize = 256;

/// The server builder: gRPC and the JSON API (HTTP/1.1 too, for the
/// latter), with every connection closed once it's `max_connection_age`
/// plus `grace` old (`grace` lets in-flight calls finish). General hygiene
/// only: certificate expiry is enforced per request by [`identity`],
/// whatever these are set to. Serve it with [`serve`].
///
/// The grace period isn't optional: tonic 0.14.6 panics ("async fn resumed
/// after completion") when `max_connection_age` is set without
/// `max_connection_age_grace`, because its connection loop polls the
/// finished age timer again after starting a graceful shutdown.
pub fn server(max_connection_age: Duration, grace: Duration) -> Server {
    Server::builder()
        .accept_http1(true)
        .max_connection_age(max_connection_age)
        .max_connection_age_grace(grace)
}

/// Serves `routes` (gRPC services and the JSON API) with `server` on
/// `listener` until `shutdown`, then drains in-flight calls: over TLS with
/// client certificates if `tls` is given, plaintext otherwise.
///
/// Every request runs in a task of its own ([`Detach`]), so a client that
/// disconnects or times out can't cut a call short: a write it started
/// commits or rolls back, and records its audit outcome, as if the client
/// had waited. The drain waits for those tasks too, after the connections.
///
/// Plaintext is dev mode, where everyone is allowed, so it only answers
/// requests addressed to loopback ([`http::loopback_hosts_only`]), over
/// every route, gRPC's too. Listening on loopback isn't enough: with DNS
/// rebinding, a web page gets its own name resolved to 127.0.0.1, and the
/// browser, on the same machine, then lets it read the answers. Applied
/// here, so nothing can serve plaintext without it. Secured mode needs no
/// such check: a rebound name fails the server certificate's name check,
/// and the browser has no client certificate for it.
pub async fn serve(
    mut server: Server,
    routes: Routes,
    listener: TcpListener,
    tls: Option<ServerTls>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), tonic::transport::Error> {
    let tasks = TaskTracker::new();
    let detached = {
        let tasks = tasks.clone();
        tower::layer::layer_fn(move |inner| Detach {
            inner,
            tasks: tasks.clone(),
        })
    };
    let served = match tls {
        None => {
            let routes = Routes::from(
                http::loopback_hosts_only(routes)
                    .into_axum_router()
                    .layer(detached),
            );
            server
                .add_routes(routes)
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
                .await
        }
        Some(tls) => {
            // Every request gets the CRLs, for `caller`.
            let routes = Routes::from(
                routes
                    .into_axum_router()
                    .layer(axum::Extension(tls.revocation()))
                    .layer(detached),
            );
            let (connections, accepted) = mpsc::channel(64);
            // Stopped however this future ends: also when a caller drops it
            // (the shutdown deadline in `main`), where the loop would
            // otherwise sit in `accept` until one more connection arrived.
            let _accepting = AbortOnDrop(tokio::spawn(accept(listener, tls, connections)));
            server
                .add_routes(routes)
                .serve_with_incoming_shutdown(ReceiverStream::new(accepted), shutdown)
                .await
        }
    };
    // The connections are drained; a call whose client left may still run.
    tasks.close();
    tasks.wait().await;
    served
}

/// Serves the Prometheus scrape (`routes`, see [`crate::prometheus`]) on
/// `listener` until `shutdown`: over `tls` ([`ServerTls::for_metrics`]) or
/// plaintext. Never through [`Detach`], so a scrape opens no request scope:
/// it's outside every rate limit and the in-flight count, and the audit
/// gate never hears of it. Plaintext on a loopback address answers only
/// requests addressed to loopback, as dev mode does ([`serve`]: DNS
/// rebinding); plaintext anywhere else was asked for by name
/// (`metrics.tls = false`).
pub async fn serve_metrics(
    routes: axum::Router,
    listener: TcpListener,
    tls: Option<ServerTls>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), tonic::transport::Error> {
    let mut server = Server::builder().accept_http1(true);
    match tls {
        None => {
            let on_loopback = listener
                .local_addr()
                .is_ok_and(|addr| crate::config::is_loopback(addr.ip()));
            let routes = Routes::from(routes);
            let routes = if on_loopback {
                http::loopback_hosts_only(routes)
            } else {
                routes
            };
            server
                .add_routes(routes)
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
                .await
        }
        Some(tls) => {
            let (connections, accepted) = mpsc::channel(16);
            let _accepting = AbortOnDrop(tokio::spawn(accept(listener, tls, connections)));
            server
                .add_routes(Routes::from(routes))
                .serve_with_incoming_shutdown(ReceiverStream::new(accepted), shutdown)
                .await
        }
    }
}

/// Runs each request of the service it wraps in a task of its own (on
/// `tasks`), as a `ratelimit` request (its admission lives as long as the
/// call; a token tells its waits when the client left), and awaits it. Dropping the returned future, which hyper and h2
/// do when the connection closes or the client resets the call, no longer
/// drops the call: it runs to completion in its task. Without this, a put
/// cancelled after its `COMMIT` was sent was stored with no audit outcome
/// (seen under load: clients cut off at a deadline). A panic in the call
/// is passed on, as before.
#[derive(Clone)]
pub struct Detach<S> {
    inner: S,
    tasks: TaskTracker,
}

impl<S> tower::Service<axum::extract::Request> for Detach<S>
where
    S: tower::Service<
            axum::extract::Request,
            Response = axum::response::Response,
            Error = Infallible,
        > + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: axum::extract::Request) -> Self::Future {
        // The request's scope (see `ratelimit`): its admission, and a token
        // cancelled when this future is dropped (the client left), which
        // only the waits before a call has its slot watch.
        let cancelled = CancellationToken::new();
        let client_left = cancelled.clone().drop_guard();
        let call = self.tasks.spawn(crate::ratelimit::in_request(
            cancelled,
            self.inner.call(request),
        ));
        Box::pin(async move {
            let _client_left = client_left;
            match call.await {
                Ok(response) => response,
                Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                // Only when the runtime shuts down.
                Err(_) => Ok(axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()),
            }
        })
    }
}

/// Aborts the task when dropped.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Accepts TCP connections and runs each TLS handshake in its own task,
/// bounded by a timeout, so a slow or stalled client can't hold up anyone
/// else. Only so many run at once (see [`ServerTls`]'s limits): at the limit,
/// the next connection isn't accepted until one finishes, so it waits in
/// the kernel's backlog (delayed, not refused) instead of each stalled
/// handshake costing a task and a file descriptor without limit. Failed
/// handshakes (no client certificate, another CA) are dropped: rustls has
/// already sent the alert, and no request exists to audit.
async fn accept(
    listener: TcpListener,
    tls: ServerTls,
    connections: mpsc::Sender<io::Result<TlsStream<TcpStream>>>,
) {
    let handshakes = Arc::new(Semaphore::new(tls.max_handshakes));
    while !connections.is_closed() {
        let Ok(handshake) = Arc::clone(&handshakes).acquire_owned().await else {
            // Never closed; nothing to accept with.
            return;
        };
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Usually out of file descriptors: back off instead of
                // spinning.
                tracing::warn!(error = %e, "accepting a connection failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        tcp.set_nodelay(true).ok();
        let (acceptor, connections) = (tls.acceptor.clone(), connections.clone());
        let (timeout, listener) = (tls.handshake_timeout, tls.listener);
        tokio::spawn(async move {
            let result = tokio::time::timeout(timeout, acceptor.accept(tcp)).await;
            drop(handshake);
            match result {
                Ok(Ok(stream)) => {
                    connections.send(Ok(stream)).await.ok();
                }
                Ok(Err(e)) => {
                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                    crate::metrics::metrics().handshake_failure(listener, "failed");
                }
                Err(_) => {
                    tracing::debug!(%peer, "TLS handshake timed out");
                    crate::metrics::metrics().handshake_failure(listener, "timed_out");
                }
            }
        });
    }
}

/// Who is calling, from what tonic recorded about the connection (for gRPC
/// and the JSON API alike): the identity in the client certificate, or
/// [`Caller::Unauthenticated`] without one (only possible without TLS,
/// which is only allowed on loopback). A certificate that passed the
/// handshake but names no caller now (expired, revoked, …) is recorded in
/// the audit log, with the `action` the request was for, and refused.
/// `revocation` is the request's [`Revocation`] extension: without it a
/// certificate is refused, as its status is unknown.
pub fn caller(
    gate: &Gate,
    certs: Option<&[CertificateDer<'static>]>,
    revocation: Option<&Revocation>,
    peer: Option<SocketAddr>,
    action: Action,
) -> Result<Caller, IdentityError> {
    let Some(chain) = certs else {
        return Ok(Caller::Unauthenticated);
    };
    revocation
        .ok_or(IdentityError::RevocationUnknown)
        .and_then(|revocation| {
            identity(
                chain,
                revocation.current().as_deref(),
                revocation.workload().as_deref(),
            )
        })
        .map(Caller::Identity)
        .inspect_err(|e| {
            let fingerprint = chain.first().map(|leaf| crate::fingerprint(leaf));
            gate.rejected(action, peer, fingerprint.as_deref(), e);
        })
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair, SanType};

    use super::*;

    fn cert_with(sans: Vec<SanType>) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans;
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn identity_of(chain: &[Vec<u8>]) -> Result<SecretPath, IdentityError> {
        identity(chain, None, None)
    }

    fn uri(s: &str) -> SanType {
        SanType::URI(s.try_into().unwrap())
    }

    #[test]
    fn the_one_ferritor_uri_san_is_the_identity() {
        let cert = cert_with(vec![
            SanType::DnsName("host.example".try_into().unwrap()),
            uri("ferritor://ops/alice"),
        ]);
        assert_eq!(identity_of(&[cert]).unwrap().as_str(), "ops/alice");
    }

    /// Every certificate presented is re-checked, not just the leaf: an
    /// expired intermediate on a resumed session must not pass.
    #[test]
    fn an_expired_certificate_anywhere_in_the_chain_is_rejected() {
        let valid = cert_with(vec![uri("ferritor://ops/alice")]);
        let mut params = CertificateParams::default();
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        let key = KeyPair::generate().unwrap();
        let expired = params.self_signed(&key).unwrap().der().to_vec();

        assert!(identity_of(std::slice::from_ref(&valid)).is_ok());
        assert!(matches!(
            identity_of(&[valid, expired.clone()]),
            Err(IdentityError::NotValidNow)
        ));
        assert!(matches!(
            identity_of(&[expired]),
            Err(IdentityError::NotValidNow)
        ));
    }

    #[test]
    fn anything_else_is_rejected_not_guessed() {
        let cases = [
            (vec![], "Missing"),
            (
                vec![SanType::DnsName("a.example".try_into().unwrap())],
                "Missing",
            ),
            (vec![uri("ferritor://a"), uri("ferritor://b")], "Ambiguous"),
            (vec![uri("spiffe://ops/alice")], "WrongScheme"),
            (vec![uri("ferritor:///ops")], "BadName"),
            (vec![uri("ferritor://ops/../root")], "BadName"),
            (vec![uri("ferritor://")], "BadName"),
        ];
        for (sans, expected) in cases {
            let error = identity_of(&[cert_with(sans)]).unwrap_err();
            assert!(format!("{error:?}").starts_with(expected), "{error:?}");
        }
        assert!(matches!(
            identity_of(&[b"not a certificate".to_vec()]),
            Err(IdentityError::Unparsable)
        ));
        assert!(matches!(
            identity_of(&[] as &[Vec<u8>]),
            Err(IdentityError::Unparsable)
        ));
    }
}
