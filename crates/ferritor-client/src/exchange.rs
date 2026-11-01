//! Workload identity (`docs/src/content/docs/guides/workload-identity.md`): a platform token exchanged for a
//! short-lived client certificate on the server's exchange listener (TLS,
//! no client certificate), then used like any other ([`Server::issued`]).
//! The key is generated here and never leaves the process; the server only
//! sees its CSR.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferritor_core::proto::v1::ExchangeTokenRequest;
use ferritor_core::proto::v1::identity_service_client::IdentityServiceClient;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use zeroize::Zeroizing;

use crate::retry::Retrying;
use crate::{CONNECT_TIMEOUT, REQUEST_TIMEOUT, Server, ServerError};

/// Why no certificate came.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("reading {}", .path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the token file {} is empty", .0.display())]
    EmptyToken(PathBuf),
    #[error("invalid exchange address {0:?}")]
    InvalidAddress(String, #[source] tonic::transport::Error),
    #[error("setting up TLS")]
    Tls(#[source] tonic::transport::Error),
    #[error("generating the key")]
    Key(#[source] rcgen::Error),
    #[error("the exchange at {addr} gave no certificate")]
    Refused {
        addr: String,
        #[source]
        source: Box<ServerError>,
    },
}

impl ExchangeError {
    /// The server's refusal, if it answered.
    pub fn server(&self) -> Option<&ServerError> {
        match self {
            Self::Refused { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Where to exchange, and what: the exchange listener's address, the CA to
/// verify it with (the main listener's), and the token's file (read at
/// each exchange: platforms replace it as it ages).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenSource {
    pub exchange_addr: String,
    pub ca: PathBuf,
    pub token_file: PathBuf,
}

/// A certificate the exchange issued, with its key.
pub struct Issued {
    /// PEM.
    pub certificate: String,
    key: Zeroizing<String>,
    /// The ferritor identity it names.
    pub identity: String,
    pub issued_at: SystemTime,
    pub not_after: SystemTime,
}

/// Never the key.
impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("identity", &self.identity)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl Issued {
    /// The private key, PEM.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// When to exchange again: two thirds into its life, so a renewal that
    /// fails has a third left to be retried in.
    pub fn renew_at(&self) -> SystemTime {
        let life = self
            .not_after
            .duration_since(self.issued_at)
            .unwrap_or(Duration::ZERO);
        self.issued_at + life * 2 / 3
    }
}

fn read(path: &Path) -> Result<Vec<u8>, ExchangeError> {
    std::fs::read(path).map_err(|source| ExchangeError::Read {
        path: path.to_owned(),
        source,
    })
}

/// Exchanges `source`'s token for a certificate, with a new P-256 key.
pub async fn exchange(source: &TokenSource) -> Result<Issued, ExchangeError> {
    let token = Zeroizing::new(read(&source.token_file)?);
    let token = Zeroizing::new(String::from_utf8_lossy(&token).trim().to_owned());
    if token.is_empty() {
        return Err(ExchangeError::EmptyToken(source.token_file.clone()));
    }
    exchange_token(&source.exchange_addr, &source.ca, &token).await
}

/// Exchanges `token` (handed over in memory: a pod's, by the CSI driver)
/// at `exchange_addr`, verified with `ca`, for a certificate with a new
/// P-256 key.
pub async fn exchange_token(
    exchange_addr: &str,
    ca: &Path,
    token: &str,
) -> Result<Issued, ExchangeError> {
    let ca = read(ca)?;
    let key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(ExchangeError::Key)?;
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)
        .map_err(ExchangeError::Key)?;
    let addr = exchange_addr.to_owned();
    let channel = Endpoint::from_shared(addr.clone())
        .map_err(|e| ExchangeError::InvalidAddress(addr.clone(), e))?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca)))
        .map_err(ExchangeError::Tls)?
        .connect_lazy();
    let issued_at = SystemTime::now();
    // A short rate limit (a burst used up by replicas starting together)
    // is waited out once, as for any call ([`crate::retry`]).
    let answer = IdentityServiceClient::new(Retrying::new(channel, None))
        .exchange_token(ExchangeTokenRequest {
            token: token.to_owned(),
            csr: csr.der().to_vec(),
        })
        .await
        .map(tonic::Response::into_inner)
        .map_err(|status| ExchangeError::Refused {
            addr: addr.clone(),
            source: Box::new(ServerError::from(status)),
        })?;
    let not_after = u64::try_from(answer.not_after_unix)
        .map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
        .unwrap_or(issued_at);
    Ok(Issued {
        certificate: certificate_pem(&answer.certificate),
        key: Zeroizing::new(key.serialize_pem()),
        identity: answer.identity,
        issued_at,
        not_after,
    })
}

/// A DER certificate as PEM.
fn certificate_pem(der: &[u8]) -> String {
    let base64 = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    // Base64 is ASCII, so any split falls between characters.
    let mut rest = base64.as_str();
    while !rest.is_empty() {
        let (line, after) = rest.split_at(rest.len().min(64));
        pem.push_str(line);
        pem.push('\n');
        rest = after;
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

impl Server {
    /// The main listener, with a certificate the exchange issued.
    pub fn issued(addr: &str, ca: &Path, issued: &Issued) -> Result<Self, crate::ConnectError> {
        let ca = std::fs::read(ca).map_err(|source| crate::ConnectError::Read {
            path: ca.to_owned(),
            source,
        })?;
        Ok(Self::with_tls(
            addr,
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(ca))
                .identity(tonic::transport::Identity::from_pem(
                    &issued.certificate,
                    issued.key(),
                )),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_is_two_thirds_into_the_life() {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let issued = Issued {
            certificate: String::new(),
            key: Zeroizing::new("THE-SECRET-KEY".to_owned()),
            identity: "ci/acme/deploy".to_owned(),
            issued_at,
            not_after: issued_at + Duration::from_secs(3600),
        };
        assert_eq!(issued.renew_at(), issued_at + Duration::from_secs(2400));
        let debug = format!("{issued:?}");
        assert!(!debug.contains("THE-SECRET-KEY"), "{debug}");
    }

    #[test]
    fn a_certificate_is_wrapped_at_64_columns() {
        let pem = certificate_pem(&[7; 100]);
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines[0], "-----BEGIN CERTIFICATE-----");
        assert_eq!(lines[1].len(), 64);
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[4], "-----END CERTIFICATE-----");
    }
}
