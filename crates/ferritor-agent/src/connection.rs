//! The agent's channel to the server, rebuilt when the client certificate
//! (or its key, or the CA) changes on disk: the server checks the
//! certificate on every request, so a renewed one (cert-manager and similar
//! replace the files in place) must replace the old before it expires.
//! With workload identity the agent renews its own: it exchanges its token
//! again two thirds into the certificate's life, and after a failed round
//! (the certificate may be what was refused); a failed exchange keeps the
//! current certificate while it's valid, and is retried every
//! [`EXCHANGE_RETRY`].

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ferritor_client::exchange::{self, ExchangeError, Issued};
use ferritor_client::{ConnectError, Server, Transport};
use ferritor_core::proto::v1::secrets_service_client::SecretsServiceClient;

use crate::config::ServerSettings;

/// What tells a file changed: its modification time and length (following
/// symlinks, so a swapped `..data` link counts).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    path: PathBuf,
    modified: Option<SystemTime>,
    len: u64,
}

fn stamp(path: &Path) -> Result<Stamp, ConnectError> {
    let metadata = std::fs::metadata(path).map_err(|source| ConnectError::Read {
        path: path.to_owned(),
        source,
    })?;
    Ok(Stamp {
        path: path.to_owned(),
        modified: metadata.modified().ok(),
        len: metadata.len(),
    })
}

/// A short rate-limit wait (`ferritor_client::retry`), logged.
fn wait_notice(limit: &str, wait: Duration) {
    tracing::info!(
        limit,
        wait_ms = wait.as_millis(),
        "rate limited by the server; waiting"
    );
}

/// How long after a failed renewal the next is tried, while the current
/// certificate is still valid.
pub const EXCHANGE_RETRY: Duration = Duration::from_secs(30);

/// Why there's no client.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error("no client certificate: the token exchange failed")]
    Exchange(#[source] ExchangeError),
    /// Not after a successful [`Connection::renew`].
    #[error("no client certificate yet")]
    NoCertificate,
}

impl ConnectionError {
    /// When the server said to retry (an exchange rate-limited: replicas
    /// sharing an identity starting together).
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Exchange(e) => e.server().and_then(|server| server.retry_after),
            _ => None,
        }
    }
}

pub struct Connection {
    settings: ServerSettings,
    /// The files the current client was built from, as they were.
    stamps: Vec<Stamp>,
    client: Option<SecretsServiceClient<Transport>>,
    /// The certificate exchanged for the token, if that's how.
    issued: Option<Issued>,
    /// No renewal before this (one failed).
    retry_exchange: Option<SystemTime>,
    /// Exchange at the next call, due or not (after a failure).
    renew_now: bool,
}

impl Connection {
    pub fn new(settings: ServerSettings) -> Self {
        Self {
            settings,
            stamps: Vec::new(),
            client: None,
            issued: None,
            retry_exchange: None,
            renew_now: false,
        }
    }

    /// With workload identity: a certificate, exchanged again once due.
    /// A failed renewal keeps the current one while it's valid.
    async fn renew(&mut self) -> Result<(), ConnectionError> {
        let ServerSettings::Exchange { source, .. } = &self.settings else {
            return Ok(());
        };
        let now = SystemTime::now();
        let due = self.renew_now
            || self
                .issued
                .as_ref()
                .is_none_or(|issued| now >= issued.renew_at());
        // A failed round goes ahead regardless: the round's own backoff
        // spaces those out.
        let waiting = !self.renew_now && self.retry_exchange.is_some_and(|at| now < at);
        let valid = self
            .issued
            .as_ref()
            .is_some_and(|issued| now < issued.not_after);
        if !due || (waiting && valid) {
            return Ok(());
        }
        self.renew_now = false;
        match exchange::exchange(source).await {
            Ok(issued) => {
                tracing::info!(
                    identity = issued.identity,
                    not_after = ?issued.not_after,
                    "exchanged the token for a client certificate"
                );
                self.issued = Some(issued);
                self.retry_exchange = None;
                self.client = None;
                Ok(())
            }
            Err(e) if valid => {
                tracing::warn!(
                    error = %crate::agent::error_chain(&e),
                    retry_in_s = EXCHANGE_RETRY.as_secs(),
                    "renewing the client certificate failed; still using the current one"
                );
                self.retry_exchange = Some(now + EXCHANGE_RETRY);
                Ok(())
            }
            Err(e) => {
                self.issued = None;
                self.client = None;
                Err(ConnectionError::Exchange(e))
            }
        }
    }

    /// Drops the client, so the next call connects again (after a
    /// transient failure: the connection may be what failed). With
    /// workload identity the next call exchanges again too: the certificate
    /// may be what was refused (its CA revoked, a cutoff).
    pub fn reset(&mut self) {
        self.client = None;
        self.renew_now = true;
    }

    /// A client: the current one, or a new one if there's none or the
    /// certificate files changed since it was built.
    pub async fn client(&mut self) -> Result<SecretsServiceClient<Transport>, ConnectionError> {
        self.renew().await?;
        let stamps = self
            .settings
            .files()
            .into_iter()
            .map(stamp)
            .collect::<Result<Vec<_>, _>>()?;
        if self.client.is_some() && stamps != self.stamps {
            tracing::info!("the client certificate changed on disk; connecting with the new one");
            self.client = None;
        }
        if let Some(client) = &self.client {
            return Ok(client.clone());
        }
        let server = match &self.settings {
            ServerSettings::Plain(addr) => Server::plain(addr),
            ServerSettings::Tls {
                addr,
                ca,
                cert,
                key,
            } => Server::tls(addr, ca, cert, key)?,
            ServerSettings::Exchange { addr, source } => match &self.issued {
                Some(issued) => Server::issued(addr, &source.ca, issued)?,
                None => return Err(ConnectionError::NoCertificate),
            },
        }
        .with_wait_notice(wait_notice);
        let client = SecretsServiceClient::new(ferritor_client::connect(&server).await?);
        self.stamps = stamps;
        self.client = Some(client.clone());
        Ok(client)
    }
}
