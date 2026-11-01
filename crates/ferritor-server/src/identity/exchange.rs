//! The token exchange: a workload's platform token and a CSR in, a
//! short-lived client certificate out (`IdentityService.ExchangeToken`,
//! served on its own listener). Verified ([`token`]), mapped
//! ([`mapping`]), issued by the issuing CA in the keyring ([`ca`]), and
//! recorded in the audit log before the certificate is handed out.
//!
//! Each issuer's keys come from a file (read at startup and on SIGHUP) or
//! an `https://` URL (fetched at startup, every [`REFRESH`], and once more,
//! at most every [`MIN_REFETCH`], when a token names a key the set lacks:
//! an issuer's key rotation). An issuer whose keys aren't there has its
//! tokens refused: the exchange fails closed and never waits on an issuer
//! beyond [`FETCH_TIMEOUT`].
//!
//! [`token`]: super::token
//! [`mapping`]: super::mapping
//! [`ca`]: super::ca

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt as _, Empty, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use time::OffsetDateTime;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};

use super::jwk::{Jwks, MAX_JWKS_BYTES};
use super::mapping::{self, MapError};
use super::token::{self, IssuerKeys as Checked, TokenError};
use super::trust::Trust;
use super::{Identity, JwksSource};
use crate::audit::{Exchanged, Gate};
use crate::identity::ca::CaError;
use crate::metrics::metrics;
use crate::seal::Seal;

/// How often URL keys are fetched again.
pub const REFRESH: Duration = Duration::from_secs(600);
/// The least time between two fetches of one issuer's keys.
pub const MIN_REFETCH: Duration = Duration::from_secs(60);
/// How long a fetch may take.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Why an exchange gave no certificate. Never carries the token. The
/// refusals carry their cause in the message (sent to the caller), not as a
/// source.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("the token was refused: {0}")]
    Token(TokenError),
    #[error("the token was refused: {0}")]
    Map(MapError),
    #[error("the token's issuer's keys aren't available (its JWKS didn't load); retry later")]
    KeysUnavailable,
    #[error("{}", ferritor_core::messages::SEALED)]
    Sealed,
    #[error("there is no workload-identity issuing CA (an operator runs `ferritor identity init`)")]
    NoIssuingKey,
    #[error("the CSR was refused: {0}")]
    Csr(CaError),
    #[error("issuing the certificate failed")]
    Issue(#[source] CaError),
    #[error("the exchange couldn't be recorded in the audit log, so nothing was issued")]
    Unaudited,
    /// Too many exchanges for this identity ([`crate::ratelimit::exchanges`]).
    #[error("too many token exchanges for this identity: retry later")]
    RateLimited(crate::ratelimit::Refused),
}

impl ExchangeError {
    /// A stable name, for the audit log and metrics.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Token(e) => match e {
                TokenError::Malformed(_) | TokenError::Missing(_) | TokenError::Critical => {
                    "malformed"
                }
                TokenError::Algorithm(_) | TokenError::KeyMismatch { .. } => "algorithm",
                TokenError::UnknownIssuer => "unknown_issuer",
                TokenError::UnknownKey { .. } => "unknown_key",
                TokenError::Signature => "signature",
                TokenError::Audience => "audience",
                TokenError::Expired | TokenError::TooOld => "expired",
                TokenError::NotYetValid | TokenError::IssuedInFuture => "not_yet_valid",
            },
            Self::Map(MapError::NoMapping) => "no_mapping",
            Self::Map(_) => "mapping",
            Self::KeysUnavailable => "keys_unavailable",
            Self::Sealed => "sealed",
            Self::NoIssuingKey => "no_issuing_key",
            Self::Csr(_) => "csr",
            Self::Issue(_) => "internal",
            Self::Unaudited => "unaudited",
            Self::RateLimited(_) => "rate_limited",
        }
    }
}

/// One issuer's keys, as currently loaded.
struct IssuerKeys {
    source: JwksSource,
    current: RwLock<Option<Arc<Jwks>>>,
    fetched: Mutex<Option<Instant>>,
}

impl IssuerKeys {
    fn new(source: JwksSource) -> Self {
        Self {
            source,
            current: RwLock::new(None),
            fetched: Mutex::new(None),
        }
    }

    fn current(&self) -> Option<Arc<Jwks>> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Loads the keys from their source; on failure the current ones stay.
    async fn load(&self) -> Result<usize, String> {
        *self.fetched.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        let bytes = match &self.source {
            JwksSource::File(path) => {
                std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?
            }
            JwksSource::Url { url, ca } => fetch(url, ca.as_deref()).await?,
        };
        let jwks = Jwks::parse(&bytes).map_err(|e| e.to_string())?;
        let keys = jwks.len();
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(jwks));
        Ok(keys)
    }

    /// For a URL source: loads again unless it was fetched within
    /// [`MIN_REFETCH`]. Whether it did.
    async fn refetch(&self) -> bool {
        if !matches!(self.source, JwksSource::Url { .. }) {
            return false;
        }
        let recent = self
            .fetched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some_and(|at| at.elapsed() < MIN_REFETCH);
        if recent {
            return false;
        }
        match self.load().await {
            Ok(_) => true,
            Err(error) => {
                tracing::warn!(error, "fetching a token issuer's keys failed");
                false
            }
        }
    }
}

/// The config in force, with each issuer's keys (same order).
struct State {
    identity: Identity,
    keys: Vec<Arc<IssuerKeys>>,
}

/// See the module docs.
pub struct Exchange {
    seal: Arc<Seal>,
    gate: Arc<Gate>,
    trust: Arc<Trust>,
    state: RwLock<Arc<State>>,
}

/// A certificate handed out.
#[derive(Clone, Debug)]
pub struct Issued {
    pub certificate: Vec<u8>,
    pub identity: String,
    pub not_after: OffsetDateTime,
}

/// Loads every issuer's keys: a file that doesn't load is an error (the
/// config points at it); a URL that doesn't answer is logged, and its
/// tokens refused until a fetch succeeds.
async fn load_keys(identity: &Identity) -> Result<Vec<Arc<IssuerKeys>>, String> {
    let mut all = Vec::with_capacity(identity.issuers.len());
    for issuer in &identity.issuers {
        let keys = Arc::new(IssuerKeys::new(issuer.jwks.clone()));
        match (keys.load().await, &issuer.jwks) {
            (Ok(count), _) => {
                tracing::info!(
                    issuer = issuer.name,
                    keys = count,
                    "token issuer's keys loaded"
                );
            }
            (Err(error), JwksSource::File(_)) => {
                return Err(format!("identity.issuer {:?}: {error}", issuer.name));
            }
            (Err(error), JwksSource::Url { .. }) => tracing::warn!(
                issuer = issuer.name,
                error,
                "fetching the token issuer's keys failed: its tokens are refused until a fetch succeeds"
            ),
        }
        all.push(keys);
    }
    Ok(all)
}

impl Exchange {
    pub async fn new(seal: Arc<Seal>, gate: Arc<Gate>, identity: Identity) -> Result<Self, String> {
        let keys = load_keys(&identity).await?;
        let trust = Arc::new(Trust::new(Arc::clone(&seal), &identity));
        Ok(Self {
            seal,
            gate,
            trust,
            state: RwLock::new(Arc::new(State { identity, keys })),
        })
    }

    /// What the TLS layer trusts of what this issues.
    pub fn trust(&self) -> Arc<Trust> {
        Arc::clone(&self.trust)
    }

    /// Takes a reloaded `[identity]` (SIGHUP). Its listener and lifetime
    /// stay as they were started; issuers, mappings, cutoffs and keys
    /// change. On an error the current ones stay. `None`: the section is
    /// gone, so nothing is exchanged and nothing issued is admitted.
    pub async fn reload(&self, identity: Option<Identity>) -> Result<(), String> {
        let Some(mut identity) = identity else {
            self.trust.reload(None);
            let current = self.state();
            let mut emptied = current.identity.clone();
            emptied.issuers.clear();
            emptied.revoked.clear();
            *self.state.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(State {
                identity: emptied,
                keys: Vec::new(),
            });
            return Ok(());
        };
        let keys = load_keys(&identity).await?;
        let current = self.state();
        identity.listen_addr = current.identity.listen_addr;
        self.trust.reload(Some(&identity));
        *self.state.write().unwrap_or_else(PoisonError::into_inner) =
            Arc::new(State { identity, keys });
        Ok(())
    }

    fn state(&self) -> Arc<State> {
        Arc::clone(&self.state.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Fetches every URL issuer's keys again (on a timer, from `main`).
    pub async fn refresh(&self) {
        let state = self.state();
        for (issuer, keys) in state.identity.issuers.iter().zip(&state.keys) {
            if matches!(keys.source, JwksSource::Url { .. })
                && let Err(error) = keys.load().await
            {
                tracing::warn!(
                    issuer = issuer.name,
                    error,
                    "refreshing a token issuer's keys failed"
                );
            }
        }
    }

    /// The exchange: `token` and `csr` (DER) in, a certificate out, with
    /// every outcome recorded (a refusal per peer at a bounded rate).
    pub async fn exchange(
        &self,
        peer: Option<SocketAddr>,
        token: &str,
        csr: &[u8],
    ) -> Result<Issued, ExchangeError> {
        let state = self.state();
        let result = self.exchange_with(&state, peer, token, csr).await;
        let (issuer, outcome) = match &result {
            Ok((issuer, _)) => (issuer.clone(), "issued"),
            Err((issuer, e)) => {
                // Unaudited: the log is what failed; rate limited: an
                // episode is recorded instead.
                if !matches!(e, ExchangeError::Unaudited | ExchangeError::RateLimited(_)) {
                    self.gate
                        .exchange_refused(peer, issuer.as_deref(), &e.to_string());
                }
                let outcome = match e {
                    ExchangeError::KeysUnavailable
                    | ExchangeError::Sealed
                    | ExchangeError::NoIssuingKey
                    | ExchangeError::Unaudited
                    | ExchangeError::Issue(_) => "unavailable",
                    ExchangeError::RateLimited(_) => "rate_limited",
                    _ => "refused",
                };
                (
                    issuer.clone().unwrap_or_else(|| "unknown".to_owned()),
                    outcome,
                )
            }
        };
        metrics().exchange(&issuer, outcome);
        result.map(|(_, issued)| issued).map_err(|(_, e)| e)
    }

    /// The exchange; the error carries the issuer's name once known.
    async fn exchange_with(
        &self,
        state: &State,
        peer: Option<SocketAddr>,
        token: &str,
        csr: &[u8],
    ) -> Result<(String, Issued), (Option<String>, ExchangeError)> {
        let now = OffsetDateTime::now_utc();
        let verified = match self.verify(state, token, now.unix_timestamp()) {
            Err(TokenError::UnknownKey { issuer }) => {
                // Its issuer may have rotated its keys: fetch that one's
                // once more (at most every MIN_REFETCH), then try again.
                let refetched = match state.keys.get(issuer) {
                    Some(keys) => keys.refetch().await,
                    None => false,
                };
                if refetched {
                    self.verify(state, token, now.unix_timestamp())
                } else {
                    Err(TokenError::UnknownKey { issuer })
                }
            }
            other => other,
        }
        .map_err(|e| match e {
            TokenError::UnknownIssuer if state.keys.iter().any(|k| k.current().is_none()) => {
                (None, ExchangeError::KeysUnavailable)
            }
            e => (None, ExchangeError::Token(e)),
        })?;
        let issuer = &state.identity.issuers[verified.issuer];
        let name = Some(issuer.name.clone());
        let mapped = mapping::map(&issuer.mappings, &verified.claims)
            .map_err(|e| (name.clone(), ExchangeError::Map(e)))?;
        self.gate
            .exchange_admitted(
                mapped.identity.as_str(),
                crate::ratelimit::exchanges(issuer.exchange_burst),
            )
            .map_err(|refused| (name.clone(), ExchangeError::RateLimited(refused)))?;
        let keyring = self
            .seal
            .keyring()
            .map_err(|_| (name.clone(), ExchangeError::Sealed))?;
        let ca = keyring
            .issuing()
            .active
            .clone()
            .ok_or((name.clone(), ExchangeError::NoIssuingKey))?;
        let lifetime =
            time::Duration::try_from(state.identity.lifetime).unwrap_or(time::Duration::HOUR);
        let expires = OffsetDateTime::from_unix_timestamp(verified.expires)
            .map_err(|_| (name.clone(), ExchangeError::Token(TokenError::Expired)))?;
        let not_after = (now + lifetime).min(expires);
        if not_after <= now {
            return Err((name, ExchangeError::Token(TokenError::Expired)));
        }
        let issued = ca
            .issue(csr, &mapped.identity, now, not_after)
            .map_err(|e| match e {
                CaError::Csr(_) | CaError::KeyType(_) => (name.clone(), ExchangeError::Csr(e)),
                e => (name.clone(), ExchangeError::Issue(e)),
            })?;
        self.gate
            .exchanged(&Exchanged {
                peer,
                issuer: &issuer.name,
                identity: mapped.identity.as_str(),
                claims: &mapped.claims,
                serial: &issued.serial,
                not_after,
            })
            .await
            .map_err(|_| (name.clone(), ExchangeError::Unaudited))?;
        tracing::info!(
            issuer = issuer.name,
            identity = %mapped.identity,
            serial = issued.serial,
            "workload certificate issued"
        );
        Ok((
            issuer.name.clone(),
            Issued {
                certificate: issued.certificate,
                identity: mapped.identity.to_string(),
                not_after,
            },
        ))
    }

    fn verify(&self, state: &State, token: &str, now: i64) -> Result<token::Verified, TokenError> {
        let loaded: Vec<Option<Arc<Jwks>>> = state.keys.iter().map(|k| k.current()).collect();
        // An issuer whose keys aren't loaded takes part with none: its
        // tokens find no key.
        let empty = Jwks::default();
        let issuers: Vec<Checked<'_>> = state
            .identity
            .issuers
            .iter()
            .zip(&loaded)
            .map(|(issuer, keys)| Checked {
                iss: &issuer.iss,
                audience: &issuer.audience,
                max_age: issuer.max_token_age,
                keys: keys.as_deref().unwrap_or(&empty),
            })
            .collect();
        token::verify(token, &issuers, now)
    }
}

/// Fetches a JWKS over https, verified with `ca` (PEM) or the public web
/// PKI roots, within [`FETCH_TIMEOUT`] and [`MAX_JWKS_BYTES`].
async fn fetch(url: &str, ca: Option<&Path>) -> Result<Vec<u8>, String> {
    tokio::time::timeout(FETCH_TIMEOUT, fetch_unbounded(url, ca))
        .await
        .map_err(|_| format!("{url}: no answer within {} s", FETCH_TIMEOUT.as_secs()))?
}

async fn fetch_unbounded(url: &str, ca: Option<&Path>) -> Result<Vec<u8>, String> {
    let uri: hyper::Uri = url.parse().map_err(|e| format!("{url}: {e}"))?;
    if uri.scheme_str() != Some("https") {
        return Err(format!("{url}: not https"));
    }
    let host = uri
        .host()
        .ok_or_else(|| format!("{url}: no host"))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(443);
    let mut roots = RootCertStore::empty();
    match ca {
        Some(ca) => {
            let pem = std::fs::read(ca).map_err(|e| format!("reading {}: {e}", ca.display()))?;
            for cert in CertificateDer::pem_slice_iter(&pem) {
                let cert = cert.map_err(|e| format!("{}: {e}", ca.display()))?;
                roots
                    .add(cert)
                    .map_err(|e| format!("{}: {e}", ca.display()))?;
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    let name = ServerName::try_from(host.clone()).map_err(|e| format!("{url}: {e}"))?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    tokio::spawn(connection);
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let request = hyper::Request::get(path)
        .header(hyper::header::HOST, host)
        .header(hyper::header::ACCEPT, "application/json")
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("{url}: {e}"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    if response.status() != hyper::StatusCode::OK {
        return Err(format!("{url}: HTTP {}", response.status()));
    }
    let body = Limited::new(response.into_body(), MAX_JWKS_BYTES)
        .collect()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    Ok(body.to_bytes().to_vec())
}
