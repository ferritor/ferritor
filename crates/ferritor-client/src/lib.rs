//! Talking to a ferritor server over gRPC, for every client ferritor ships (the
//! `ferritor` CLI, the agent): the channel, TLS with a client certificate
//! checked by a health call before any real one ([`connect`]), short rate
//! limits waited out ([`retry`]), and the server's refusals as
//! [`ServerError`], with the reason to match on. A client certificate comes
//! from files, or from the server's token exchange ([`exchange`]).
//!
//! It writes nothing to stdout or stderr: what a client tells its user
//! (hints, the rate-limit notice) is the client's.

pub mod exchange;
pub mod retry;

use std::path::{Path, PathBuf};
use std::time::Duration;

use ferritor_core::messages;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::{Code, Response, Status};
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_client::HealthClient;
use tonic_types::StatusExt;
use zeroize::Zeroizing;

use crate::retry::{Retrying, WaitNotice};

/// Longer than the server's own database bounds, so its answer (even a
/// timeout) arrives before ours.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A call the server refused (or the transport failed), with what a caller
/// needs to decide what to do: the code, and the reason
/// (`ferritor_core::messages::reason`) to match on, never the message.
#[derive(Debug, thiserror::Error)]
#[error("{}", describe(*.code, .message, .cause.as_deref(), *.retry_after))]
pub struct ServerError {
    pub code: Code,
    pub message: String,
    /// The transport-level cause, if any (`connection error: received fatal
    /// alert: …`): what tells a refused TLS handshake from a timeout.
    pub cause: Option<String>,
    /// The server's `ErrorInfo` reason (`ferritor_core::messages::reason`), if
    /// any: what to match on, never the message.
    pub reason: Option<String>,
    /// Which limit refused it (`RATE_LIMITED`'s metadata: rate, in_flight,
    /// denied).
    pub limit: Option<String>,
    /// When the server says a retry could pass (`RetryInfo`).
    pub retry_after: Option<Duration>,
}

/// The server's message, or, if it sent none, what the code means: a bare
/// `error: ` tells the operator nothing.
fn describe(
    code: Code,
    message: &str,
    cause: Option<&str>,
    retry_after: Option<Duration>,
) -> String {
    let message = if message.trim().is_empty() {
        format!("{} (gRPC {code:?})", code.description())
    } else {
        message.to_owned()
    };
    let message = match cause {
        // Transport errors ("transport error", "operation was canceled")
        // only say what went wrong in their cause.
        Some(cause) if !message.contains(cause) => format!("{message}: {cause}"),
        _ => message,
    };
    match retry_after {
        // Whole seconds, rounded up: retrying at the printed time is never
        // too early.
        Some(wait) => format!(
            "{message} (in {} s)",
            wait.as_secs() + u64::from(wait.subsec_nanos() > 0)
        ),
        None => message,
    }
}

impl From<Status> for ServerError {
    fn from(status: Status) -> Self {
        let mut causes = Vec::new();
        let mut source = std::error::Error::source(&status);
        while let Some(s) = source {
            causes.push(s.to_string());
            source = s.source();
        }
        let details = status.get_error_details();
        let info = details
            .error_info()
            .filter(|info| info.domain == messages::DOMAIN);
        Self {
            code: status.code(),
            message: status.message().to_owned(),
            cause: (!causes.is_empty()).then(|| causes.join(": ")),
            reason: info.map(|info| info.reason.clone()),
            limit: info.and_then(|info| info.metadata.get("limit").cloned()),
            retry_after: details.retry_info().and_then(|retry| retry.retry_delay),
        }
    }
}

/// A call's reply, or its refusal as a [`ServerError`].
pub fn answer<T>(result: Result<Response<T>, Status>) -> Result<T, ServerError> {
    result.map(Response::into_inner).map_err(ServerError::from)
}

/// Connecting failed, so nothing was sent: TCP, or over TLS the handshake
/// (checked with a health call before any real one).
#[derive(Debug, thiserror::Error)]
#[error("can't reach the server at {addr}")]
pub struct Unreachable {
    addr: String,
    tls: bool,
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl Unreachable {
    /// Whether it was over TLS (so the handshake may be what failed).
    pub fn tls(&self) -> bool {
        self.tls
    }
}

/// Why no channel came up ([`connect`], [`Server::tls`]).
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("reading {}", .path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid server address {0:?}")]
    InvalidAddress(String, #[source] tonic::transport::Error),
    #[error("setting up TLS")]
    Tls(#[source] tonic::transport::Error),
    #[error(transparent)]
    Unreachable(#[from] Unreachable),
}

/// Where and how to connect: plain http (loopback servers only), or https
/// with the server's CA and a client certificate.
#[derive(Clone)]
pub struct Server {
    addr: String,
    tls: Option<ClientTlsConfig>,
    notice: Option<WaitNotice>,
}

/// Never the TLS configuration: it holds the client's private key.
impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("addr", &self.addr)
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

impl Server {
    /// A plaintext server (dev mode, loopback only).
    pub fn plain(addr: &str) -> Self {
        Self {
            addr: addr.to_owned(),
            tls: None,
            notice: None,
        }
    }

    /// A server over TLS: `ca` to verify it with, `cert` and `key` (PEM) the
    /// client certificate it requires. Read now, so a missing file is an
    /// error before anything is sent.
    pub fn tls(addr: &str, ca: &Path, cert: &Path, key: &Path) -> Result<Self, ConnectError> {
        let read = |path: &Path| {
            std::fs::read(path).map_err(|source| ConnectError::Read {
                path: path.to_owned(),
                source,
            })
        };
        let key = Zeroizing::new(read(key)?);
        Ok(Self::with_tls(
            addr,
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(read(ca)?))
                .identity(Identity::from_pem(read(cert)?, &*key)),
        ))
    }

    fn with_tls(addr: &str, tls: ClientTlsConfig) -> Self {
        Self {
            addr: addr.to_owned(),
            tls: Some(tls),
            notice: None,
        }
    }

    /// Told before each short rate-limit wait ([`retry`]); without one, the
    /// waits are silent.
    pub fn with_wait_notice(mut self, notice: WaitNotice) -> Self {
        self.notice = Some(notice);
        self
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }
}

/// The channel the generated clients use: short rate limits waited out
/// ([`retry`]).
pub type Transport = Retrying<Channel>;

/// A channel to `server`. Over TLS, a health call goes first, so a refused
/// client certificate is [`Unreachable`] (nothing was sent, for certain)
/// rather than surfacing on the first real call.
pub async fn connect(server: &Server) -> Result<Transport, ConnectError> {
    let addr = &server.addr;
    let endpoint = Endpoint::from_shared(addr.clone())
        .map_err(|e| ConnectError::InvalidAddress(addr.clone(), e))?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT);
    let Some(tls) = &server.tls else {
        return endpoint
            .connect()
            .await
            .map(|channel| Retrying::new(channel, server.notice))
            .map_err(|source| {
                Unreachable {
                    addr: addr.clone(),
                    tls: false,
                    source: source.into(),
                }
                .into()
            });
    };
    // With TLS 1.3 the server refuses a client certificate only after the
    // client considers the handshake done, so connecting "succeeds" and a
    // refusal surfaces on the first call, as an alert, a closed connection or
    // a broken pipe depending on timing: indistinguishable from a call cut
    // off midway. So a harmless health call goes first: if it gets any gRPC
    // answer, the handshake (certificate included) is done; if not, nothing
    // was sent, for certain.
    let channel = endpoint
        .tls_config(tls.clone())
        .map_err(ConnectError::Tls)?
        .connect_lazy();
    let check = HealthClient::new(channel.clone())
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await;
    match check {
        Ok(_) => Ok(Retrying::new(channel, server.notice)),
        Err(status) if matches!(status.code(), Code::NotFound | Code::Unimplemented) => {
            Ok(Retrying::new(channel, server.notice))
        }
        Err(status) => Err(Unreachable {
            addr: addr.clone(),
            tls: true,
            source: Box::new(ServerError::from(status)),
        }
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(message: &str, retry_after: Option<Duration>) -> ServerError {
        ServerError {
            code: Code::ResourceExhausted,
            message: message.to_owned(),
            cause: None,
            reason: None,
            limit: None,
            retry_after,
        }
    }

    /// A refusal reads as the server's message, or the code's meaning if
    /// it sent none, with the transport's cause and the retry time
    /// (rounded up to whole seconds) after it.
    #[test]
    fn a_refusal_says_what_and_when() {
        assert_eq!(refused("rate limited", None).to_string(), "rate limited");
        assert_eq!(
            refused("rate limited", Some(Duration::from_millis(4100))).to_string(),
            "rate limited (in 5 s)"
        );
        assert_eq!(
            refused("rate limited", Some(Duration::from_secs(2))).to_string(),
            "rate limited (in 2 s)"
        );
        let empty = refused(" ", None).to_string();
        assert!(empty.contains("(gRPC ResourceExhausted)"), "{empty}");
        let with_cause = ServerError {
            cause: Some("broken pipe".to_owned()),
            ..refused("transport error", None)
        };
        assert_eq!(with_cause.to_string(), "transport error: broken pipe");
    }

    /// A server's debug output shows where, never the client's key.
    #[test]
    fn a_server_never_shows_its_key() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("ferritor-client-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let key = "-----BEGIN PRIVATE KEY-----\nTHE-SECRET-KEY\n-----END PRIVATE KEY-----\n";
        for (name, contents) in [("ca.pem", "ca"), ("cert.pem", "cert"), ("key.pem", key)] {
            std::fs::write(dir.join(name), contents)?;
        }
        let server = Server::tls(
            "https://localhost:7070",
            &dir.join("ca.pem"),
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
        )?;
        std::fs::remove_dir_all(&dir)?;
        let debug = format!("{server:?}");
        assert!(!debug.contains("THE-SECRET-KEY"), "{debug}");
        assert!(debug.contains("https://localhost:7070"), "{debug}");
        Ok(())
    }

    /// A file that can't be read names itself, before anything is sent.
    #[test]
    fn a_missing_file_is_named() {
        let missing = Path::new("/nonexistent/ferritor/key.pem");
        let error = Server::tls("https://localhost:7070", missing, missing, missing).unwrap_err();
        assert!(matches!(&error, ConnectError::Read { path, .. } if path == missing));
        assert_eq!(error.to_string(), "reading /nonexistent/ferritor/key.pem");
    }
}
