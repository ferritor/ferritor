//! The two modes around [`Agent::poll`]: `once` (render, then exit) and
//! `run` (render, then keep the files current until stopped). `run` also
//! keeps a watch stream open (unless `watch = false`): a change of a
//! watched secret is read at once ([`Agent::changed`]); the regular rounds
//! go on beside it, further apart while it's ready
//! ([`Agent::round_interval`]) and back to the interval when it ends, so a
//! stream that can't be opened, or ends, costs latency, never a change.

use std::time::{Duration, Instant};

use ferritor_core::path::SecretPath;
use ferritor_core::proto::v1 as pb;
use ferritor_core::proto::v1::watch_secrets_response::Event;

use crate::agent::{Agent, Revoked};

/// Why `once` didn't finish.
#[derive(Debug, thiserror::Error)]
pub enum OnceError {
    /// Required secrets the server refused for good.
    #[error("refused by the server: {}", refused(.0))]
    Refused(Vec<(ferritor_core::path::SecretPath, Revoked)>),
    /// The server didn't let the render finish in time (unreachable,
    /// sealed, rate-limited…); the last failure is in the log.
    #[error("not rendered within {} s (see the log for the last failure)", .0.as_secs())]
    TimedOut(Duration),
}

fn refused(refused: &[(ferritor_core::path::SecretPath, Revoked)]) -> String {
    refused
        .iter()
        .map(|(path, kind)| format!("{path} ({kind:?})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Renders every output once: done when every required secret is written.
/// Transient failures are retried until `wait` runs out; a required secret
/// refused for good fails at once (an init container is restarted anyway).
pub async fn once(agent: &mut Agent, wait: Duration) -> Result<(), OnceError> {
    let deadline = Instant::now() + wait;
    loop {
        agent.poll(Instant::now()).await;
        if agent.rendered() {
            return Ok(());
        }
        let refused = agent.refused_required();
        if !refused.is_empty() {
            return Err(OnceError::Refused(refused));
        }
        let wake = agent.next_wake(Instant::now()).min(deadline);
        if Instant::now() >= deadline {
            return Err(OnceError::TimedOut(wait));
        }
        tokio::time::sleep_until(wake.into()).await;
    }
}

/// The first wait before opening a watch again; it doubles up to the
/// interval.
const FIRST_WATCH_RETRY: Duration = Duration::from_secs(1);

/// The watch stream as `run` keeps it.
struct Watching {
    stream: Option<tonic::Streaming<pb::WatchSecretsResponse>>,
    /// The paths it covers (to open it again when they change).
    paths: Vec<String>,
    /// No attempt to open one before this.
    retry_at: Instant,
    backoff: Duration,
}

impl Watching {
    fn new() -> Self {
        Self {
            stream: None,
            paths: Vec::new(),
            retry_at: Instant::now(),
            backoff: FIRST_WATCH_RETRY,
        }
    }

    /// Opens (or reopens, for a changed set of paths) the stream when due.
    async fn keep_open(&mut self, agent: &mut Agent) {
        let paths = agent.watch_paths();
        if self.stream.is_some() && paths == self.paths {
            return;
        }
        if self.stream.take().is_some() {
            // It covered other paths: not those until a new one is ready.
            agent.set_watched(false, Instant::now());
        }
        if paths.is_empty() || Instant::now() < self.retry_at {
            return;
        }
        match agent.watch(paths.clone()).await {
            Ok(stream) => {
                tracing::info!(paths = paths.len(), "watching for changes");
                self.stream = Some(stream);
                self.paths = paths;
                self.backoff = FIRST_WATCH_RETRY;
            }
            Err(error) => self.failed(&error, agent.interval()),
        }
    }

    fn failed(&mut self, error: &str, interval: Duration) {
        tracing::warn!(
            error,
            retry_in_s = self.backoff.as_secs(),
            "no watch stream; the regular rounds go on"
        );
        self.stream = None;
        self.retry_at = Instant::now() + self.backoff;
        self.backoff = (self.backoff * 2).min(interval);
    }

    /// The next message, or never without a stream.
    async fn next(&mut self) -> Result<Option<pb::WatchSecretsResponse>, tonic::Status> {
        match &mut self.stream {
            Some(stream) => stream.message().await,
            None => std::future::pending().await,
        }
    }
}

/// Renders, then keeps the files current, until `stop` resolves (the files
/// stay as they are).
pub async fn run(agent: &mut Agent, stop: impl std::future::Future<Output = ()>) {
    tokio::pin!(stop);
    let mut watching = Watching::new();
    loop {
        agent.poll(Instant::now()).await;
        loop {
            if agent.watches() {
                watching.keep_open(agent).await;
            }
            let wake = agent.next_wake(Instant::now());
            // A watch that can't be opened yet is tried again then too.
            let wake = if agent.watches() && watching.stream.is_none() {
                wake.min(watching.retry_at.max(Instant::now()))
            } else {
                wake
            };
            tokio::select! {
                () = tokio::time::sleep_until(wake.into()) => {
                    if Instant::now() >= agent.next_wake(Instant::now()) {
                        break;
                    }
                }
                () = &mut stop => return,
                message = watching.next() => match message {
                    // Subscribed: what changed before it is read by a round,
                    // and the rounds stretch while it lasts.
                    Ok(Some(pb::WatchSecretsResponse { event: Some(Event::Ready(_)) })) => {
                        agent.set_watched(true, Instant::now());
                        break;
                    }
                    Ok(Some(pb::WatchSecretsResponse { event: Some(Event::Changed(changed)) })) => {
                        if let Ok(path) = SecretPath::parse(&changed.path) {
                            let version = (changed.version > 0).then_some(changed.version);
                            agent.changed(&path, version, Instant::now()).await;
                        }
                    }
                    // Changes may have been missed: a round reads them.
                    Ok(Some(pb::WatchSecretsResponse { event: Some(Event::Resync(_)) })) => break,
                    Ok(Some(pb::WatchSecretsResponse { event: None })) => {}
                    Ok(None) => {
                        watching.failed("the watch stream ended", agent.interval());
                        agent.set_watched(false, Instant::now());
                    }
                    Err(status) => {
                        let error = ferritor_client::ServerError::from(status).to_string();
                        watching.failed(&error, agent.interval());
                        agent.set_watched(false, Instant::now());
                    }
                },
            }
        }
    }
}
