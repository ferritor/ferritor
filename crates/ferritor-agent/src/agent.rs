//! The loop's one round ([`Agent::poll`]): find out what changed, read
//! only that, write the sets that changed, tell the applications. Every
//! decision (what's due, what's backed off) is made against the `now` it's
//! given, so the tests can run minutes of polling without waiting.
//!
//! Refusals come in two kinds (`docs/src/content/docs/guides/agent.md`, "Failures"):
//!
//! - **transient** (the server unreachable, sealed, unverified, overloaded,
//!   rate-limited; a refused certificate): nobody decided anything about a
//!   secret. The round stops, the files stay, and the next round comes after
//!   a backoff from 1 s up to the interval (at least the server's retry
//!   time).
//! - **authoritative** (`PERMISSION_DENIED`, `NOT_FOUND`, a namespace gone,
//!   a path missing from its listing): someone decided. That secret backs
//!   off on its own, from the full interval at the first refusal, doubling
//!   up to ten intervals, never back to 1 s: replicas sharing an identity
//!   share its denial budget, and retries are what it counts. Its file
//!   follows `on_revoked`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ferritor_client::{ServerError, Transport, answer};
use ferritor_core::messages::reason;
use ferritor_core::path::SecretPath;
use ferritor_core::proto::v1 as pb;
use ferritor_core::proto::v1::secrets_service_client::SecretsServiceClient;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tonic::Code;
use zeroize::Zeroizing;

use crate::config::{Config, Detect, OnRevoked, Output, Secret, ServerSettings};
use crate::connection::Connection;
use crate::files::{FilesError, OutputFile, Writer};
use crate::notify;

/// The most a listing page holds (the server's maximum).
const PAGE_SIZE: u32 = 1000;
/// An authoritative refusal's backoff grows to this many intervals.
const MAX_REFUSAL_INTERVALS: u32 = 10;
/// The first transient backoff.
const FIRST_RETRY: Duration = Duration::from_secs(1);
/// While a watch stream vouches for every secret, rounds come this many
/// intervals apart ([`Agent::round_interval`])...
pub const WATCHED_STRETCH: u32 = 10;
/// ...but at most this far apart: an exchanged certificate (an hour) is
/// renewed by a round two thirds into its life, so a round at least every
/// ten minutes renews it in time, before its expiry ends the stream.
pub const WATCHED_ROUNDS_MAX: Duration = Duration::from_secs(600);

/// Why the server refused a call, for what to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Nobody decided anything: retry soon, keep everything.
    Transient { retry_after: Option<Duration> },
    /// Someone decided: back off long, follow `on_revoked`.
    Authoritative(Revoked),
}

/// What an authoritative refusal was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Revoked {
    /// The identity may not read it (or list its prefix).
    PermissionDenied,
    /// Deleted, never stored, or its namespace gone.
    NotFound,
    /// The request itself is wrong (a bad path, a bad version): a config
    /// mistake the server caught.
    Invalid,
}

/// Sorts a server's refusal.
pub fn classify(error: &ServerError) -> Refusal {
    match error.code {
        Code::PermissionDenied => Refusal::Authoritative(Revoked::PermissionDenied),
        Code::NotFound => Refusal::Authoritative(Revoked::NotFound),
        Code::FailedPrecondition if error.reason.as_deref() == Some(reason::NO_NAMESPACE) => {
            Refusal::Authoritative(Revoked::NotFound)
        }
        Code::InvalidArgument => Refusal::Authoritative(Revoked::Invalid),
        // Unavailable, sealed, unverified, rate-limited, a refused
        // certificate, timeouts, a dropped connection, and anything new.
        _ => Refusal::Transient {
            retry_after: error.retry_after,
        },
    }
}

/// A value as last delivered.
struct Delivered {
    version: u32,
    value: Zeroizing<Vec<u8>>,
}

/// A secret's authoritative refusal, while it lasts.
struct Refused {
    kind: Revoked,
    backoff: Duration,
    next_try: Instant,
}

struct SecretState {
    config: Secret,
    delivered: Option<Delivered>,
    refused: Option<Refused>,
}

impl SecretState {
    fn due(&self, now: Instant) -> bool {
        if self.config.version.is_some() && self.delivered.is_some() {
            // Pinned and delivered: never asked again.
            return false;
        }
        self.refused
            .as_ref()
            .is_none_or(|refused| now >= refused.next_try)
    }
}

struct OutputState {
    config: Output,
    writer: Writer,
    secrets: Vec<SecretState>,
    /// Whether a set was ever written (the first render is done).
    written: bool,
    /// Something changed since the last write.
    dirty: bool,
}

impl OutputState {
    /// Every required secret has a value: the first set can be written.
    fn complete(&self) -> bool {
        self.secrets
            .iter()
            .all(|s| !s.config.required || s.delivered.is_some())
    }
}

/// What a round did, for the loop and the tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Round {
    /// Calls made (each an audited decision on the server).
    pub calls: u32,
    /// Sets written.
    pub written: u32,
    /// The round stopped on a transient refusal.
    pub transient: bool,
}

/// The agent's state across rounds.
pub struct Agent {
    interval: Duration,
    watch: bool,
    /// A watch stream is ready and covers every secret that can change:
    /// the rounds are only its safety net, and stretch
    /// ([`Agent::round_interval`]).
    watched: bool,
    connection: Connection,
    outputs: Vec<OutputState>,
    /// While a transient refusal lasts: when to try again, and the current
    /// backoff.
    retry: Option<(Instant, Duration)>,
    /// When the next regular round is due.
    next_round: Option<Instant>,
    last_success: Option<OffsetDateTime>,
    last_error: Option<String>,
    jitter: Jitter,
}

impl Agent {
    /// Opens every output directory (checking it's in memory unless
    /// allowed) and prepares the connection; nothing is sent yet.
    pub fn new(config: Config) -> Result<Self, FilesError> {
        let mut outputs = Vec::with_capacity(config.outputs.len());
        for output in config.outputs {
            let writer = Writer::open(&output.dir, output.group, output.allow_disk)?;
            let secrets = output
                .secrets
                .iter()
                .cloned()
                .map(|config| SecretState {
                    config,
                    delivered: None,
                    refused: None,
                })
                .collect();
            outputs.push(OutputState {
                config: output,
                writer,
                secrets,
                written: false,
                dirty: true,
            });
        }
        Ok(Self {
            interval: config.interval,
            watch: config.watch,
            watched: false,
            connection: Connection::new(config.server),
            outputs,
            retry: None,
            next_round: None,
            last_success: None,
            last_error: None,
            jitter: Jitter::new(),
        })
    }

    /// Whether `run` keeps a watch stream open (`watch` in the config).
    pub fn watches(&self) -> bool {
        self.watch
    }

    /// The interval between regular rounds.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// The time between regular rounds now: the interval, or while a watch
    /// stream vouches for every secret, [`WATCHED_STRETCH`] times it, at
    /// most [`WATCHED_ROUNDS_MAX`] (and never less than the interval). The
    /// rounds then only catch what a stream can't tell (one that ended
    /// unnoticed); a refused secret's backoff and a transient retry keep
    /// their own times.
    pub fn round_interval(&self) -> Duration {
        if self.watched {
            (self.interval * WATCHED_STRETCH)
                .min(WATCHED_ROUNDS_MAX)
                .max(self.interval)
        } else {
            self.interval
        }
    }

    /// Whether a ready watch stream covers every secret that can change
    /// (`run` says so at its `ready`, and when it ends). Losing one brings
    /// the next round within an interval of `now`.
    pub fn set_watched(&mut self, watched: bool, now: Instant) {
        if self.watched && !watched {
            let soon = now + self.jitter.spread(self.interval);
            self.next_round = Some(self.next_round.map_or(soon, |at| at.min(soon)));
        }
        self.watched = watched;
    }

    /// Whether every output's first set is written.
    pub fn rendered(&self) -> bool {
        self.outputs.iter().all(|o| o.written)
    }

    /// A required secret refused for good before its first delivery: what
    /// `once` fails on at once (`run` keeps retrying it, slowly).
    pub fn refused_required(&self) -> Vec<(SecretPath, Revoked)> {
        self.outputs
            .iter()
            .flat_map(|o| &o.secrets)
            .filter(|s| s.config.required && s.delivered.is_none())
            .filter_map(|s| s.refused.as_ref().map(|r| (s.config.path.clone(), r.kind)))
            .collect()
    }

    /// When to call [`Agent::poll`] next: after a transient backoff if one
    /// is running, else at the next regular round, or sooner if a refused
    /// secret's backoff ends first.
    pub fn next_wake(&self, now: Instant) -> Instant {
        if let Some((at, _)) = self.retry {
            return at;
        }
        let regular = self.next_round.unwrap_or(now);
        self.outputs
            .iter()
            .flat_map(|o| &o.secrets)
            .filter_map(|s| s.refused.as_ref().map(|r| r.next_try))
            .filter(|at| *at > now)
            .fold(regular, Instant::min)
    }

    /// One round at `now`. Nothing happens before a transient backoff ends.
    pub async fn poll(&mut self, now: Instant) -> Round {
        let mut round = Round::default();
        if self.retry.is_some_and(|(at, _)| now < at) {
            return round;
        }
        match self.fetch(now, &mut round).await {
            Ok(()) => {
                self.retry = None;
                self.last_success = Some(OffsetDateTime::now_utc());
                self.last_error = None;
            }
            Err(failure) => {
                round.transient = true;
                self.connection.reset();
                let backoff = self
                    .retry
                    .map_or(FIRST_RETRY, |(_, backoff)| (backoff * 2).min(self.interval));
                let wait = self
                    .jitter
                    .spread(backoff)
                    .max(failure.retry_after.unwrap_or_default());
                tracing::warn!(error = %failure.message, retry_in_ms = wait.as_millis(), "round failed; the files stay as they are");
                self.last_error = Some(failure.message);
                self.retry = Some((now + wait, backoff));
            }
        }
        self.next_round = Some(now + self.jitter.spread(self.round_interval()));
        for output in &mut self.outputs {
            match write_if_changed(output) {
                Ok(true) => round.written += 1,
                Ok(false) => {}
                Err(e) => {
                    tracing::error!(dir = %output.config.dir.display(), error = %error_chain(&e), "writing the files failed");
                    self.last_error = Some(error_chain(&e));
                }
            }
            write_status(output, self.last_success, self.last_error.as_deref());
        }
        round
    }

    /// What a watch stream should cover: every secret that can change (not
    /// pinned) and isn't refused for good right now (a watch needs read on
    /// every path it names, so one refused path would refuse the stream).
    /// Sorted, so a change of the set is a change of the list.
    pub fn watch_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .outputs
            .iter()
            .flat_map(|o| &o.secrets)
            .filter(|s| s.config.version.is_none() && s.refused.is_none())
            .map(|s| s.config.path.as_str().to_owned())
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }

    /// A watch stream for `paths`, on the current connection.
    pub async fn watch(
        &mut self,
        paths: Vec<String>,
    ) -> Result<tonic::Streaming<pb::WatchSecretsResponse>, String> {
        let mut client = self
            .connection
            .client()
            .await
            .map_err(|e| error_chain(&e))?;
        client
            .watch_secrets(pb::WatchSecretsRequest {
                paths,
                prefixes: Vec::new(),
            })
            .await
            .map(tonic::Response::into_inner)
            .map_err(|status| ServerError::from(status).to_string())
    }

    /// The watch said `path`'s live version is `version` now (`None`: no
    /// live version): reads it at once if that isn't what its files hold,
    /// as a round would, and writes the sets that changed. A transient
    /// failure is left to the next round.
    pub async fn changed(
        &mut self,
        path: &SecretPath,
        version: Option<u32>,
        now: Instant,
    ) -> Round {
        let mut round = Round::default();
        let stale = self.outputs.iter().flat_map(|o| &o.secrets).any(|s| {
            &s.config.path == path
                && s.config.version.is_none()
                && s.due(now)
                && s.delivered.as_ref().map(|d| d.version) != version
        });
        if !stale {
            return round;
        }
        let mut client = match self.connection.client().await {
            Ok(client) => client,
            Err(e) => {
                tracing::warn!(error = %error_chain(&e), "reading a change failed; the next round will");
                round.transient = true;
                return round;
            }
        };
        round.calls += 1;
        let reply = answer(
            client
                .get_secret(pb::GetSecretRequest {
                    path: path.as_str().to_owned(),
                    version: 0,
                })
                .await,
        );
        let interval = self.interval;
        for output in &mut self.outputs {
            for secret in output
                .secrets
                .iter_mut()
                .filter(|s| &s.config.path == path && s.config.version.is_none())
            {
                match &reply {
                    Ok(reply) => accept(secret, reply.clone(), &mut output.dirty),
                    Err(e) => match classify(e) {
                        Refusal::Authoritative(kind) => {
                            refuse(secret, kind, now, interval, &mut output.dirty);
                        }
                        Refusal::Transient { .. } => round.transient = true,
                    },
                }
            }
        }
        if round.transient {
            if let Err(e) = &reply {
                tracing::warn!(path = %path, error = %e, "reading a change failed; the next round will");
            }
            self.connection.reset();
        }
        for output in &mut self.outputs {
            match write_if_changed(output) {
                Ok(true) => round.written += 1,
                Ok(false) => {}
                Err(e) => {
                    tracing::error!(dir = %output.config.dir.display(), error = %error_chain(&e), "writing the files failed");
                    self.last_error = Some(error_chain(&e));
                }
            }
            write_status(output, self.last_success, self.last_error.as_deref());
        }
        round
    }

    /// Asks the server about every due secret; stops at the first
    /// transient refusal.
    async fn fetch(&mut self, now: Instant, round: &mut Round) -> Result<(), Failure> {
        let mut client = self.connection.client().await.map_err(|e| Failure {
            message: error_chain(&e),
            retry_after: e.retry_after(),
        })?;
        let interval = self.interval;
        for output in &mut self.outputs {
            let listed = list(&mut client, output, now, round).await?;
            for secret in &mut output.secrets {
                if !secret.due(now) {
                    continue;
                }
                let version = match (secret.config.version, secret.config.detect) {
                    (Some(pinned), _) => pinned,
                    (None, Detect::Get) => 0,
                    (None, Detect::List) => match listed.get(&secret.config.path) {
                        // Under a prefix whose listing was refused: that
                        // refusal is this secret's.
                        Some(Listed::Refused(kind)) => {
                            refuse(secret, *kind, now, interval, &mut output.dirty);
                            continue;
                        }
                        Some(Listed::Version(listed)) => {
                            if secret
                                .delivered
                                .as_ref()
                                .is_some_and(|d| d.version == *listed)
                            {
                                secret.refused = None;
                                continue;
                            }
                            *listed
                        }
                        // Not in its listing: no live version.
                        None => {
                            refuse(secret, Revoked::NotFound, now, interval, &mut output.dirty);
                            continue;
                        }
                    },
                };
                round.calls += 1;
                let reply = answer(
                    client
                        .get_secret(pb::GetSecretRequest {
                            path: secret.config.path.as_str().to_owned(),
                            version,
                        })
                        .await,
                );
                match reply {
                    Ok(reply) => accept(secret, reply, &mut output.dirty),
                    Err(e) => match classify(&e) {
                        Refusal::Authoritative(kind) => {
                            refuse(secret, kind, now, interval, &mut output.dirty);
                        }
                        Refusal::Transient { retry_after } => {
                            return Err(Failure {
                                message: e.to_string(),
                                retry_after,
                            });
                        }
                    },
                }
            }
        }
        Ok(())
    }
}

/// A round stopped by a transient refusal.
struct Failure {
    message: String,
    retry_after: Option<Duration>,
}

/// A listing's answer for one path.
enum Listed {
    Version(u32),
    /// The listing itself was refused for good.
    Refused(Revoked),
}

/// Lists `output`'s prefixes whose secrets are due, every page, into path
/// → version. A prefix of more than one page is warned about: each page is
/// a call and an audited decision.
async fn list(
    client: &mut SecretsServiceClient<Transport>,
    output: &OutputState,
    now: Instant,
    round: &mut Round,
) -> Result<HashMap<SecretPath, Listed>, Failure> {
    let mut listed = HashMap::new();
    for prefix in &output.config.list_prefixes {
        let due = output.secrets.iter().any(|s| {
            s.config.detect == Detect::List
                && s.config.version.is_none()
                && s.config.path.is_under(prefix)
                && s.due(now)
        });
        if !due {
            continue;
        }
        let mut token = String::new();
        let mut pages = 0_u32;
        loop {
            round.calls += 1;
            pages += 1;
            let reply = answer(
                client
                    .list_secrets(pb::ListSecretsRequest {
                        prefix: prefix.as_str().to_owned(),
                        page_size: PAGE_SIZE,
                        page_token: token,
                        labels: HashMap::new(),
                    })
                    .await,
            );
            let page = match reply {
                Ok(page) => page,
                Err(e) => match classify(&e) {
                    Refusal::Authoritative(kind) => {
                        for secret in &output.secrets {
                            if secret.config.path.is_under(prefix) {
                                listed.insert(secret.config.path.clone(), Listed::Refused(kind));
                            }
                        }
                        break;
                    }
                    Refusal::Transient { retry_after } => {
                        return Err(Failure {
                            message: e.to_string(),
                            retry_after,
                        });
                    }
                },
            };
            for secret in page.secrets {
                if let Ok(path) = SecretPath::parse(&secret.path) {
                    listed.insert(path, Listed::Version(secret.version));
                }
            }
            if page.next_page_token.is_empty() {
                break;
            }
            token = page.next_page_token;
        }
        if pages > 1 {
            tracing::warn!(prefix = %prefix, pages, "listing took more than one page, each an audited call: narrow list_prefix to the application's own secrets");
        }
    }
    Ok(listed)
}

/// A value read: delivered if new, and any refusal is over. The set is
/// rewritten only if the file's content changes (a new version or value,
/// or a value `on_revoked = "remove"` took away coming back), never because
/// a refusal ended: with `keep`, the file already holds it, and a rewrite
/// would tell the application of a change that isn't one.
fn accept(secret: &mut SecretState, reply: pb::GetSecretResponse, dirty: &mut bool) {
    let Some(read) = reply.secret else { return };
    let version = read.metadata.map_or(0, |m| m.version);
    let value = Zeroizing::new(read.value);
    if let Some(refused) = secret.refused.take() {
        tracing::info!(path = %secret.config.path, was = ?refused.kind, version, "readable again");
    }
    let changed = secret
        .delivered
        .as_ref()
        .is_none_or(|d| d.version != version || d.value != value);
    if changed {
        tracing::info!(path = %secret.config.path, version, "new version");
        secret.delivered = Some(Delivered { version, value });
        *dirty = true;
    }
}

/// An authoritative refusal: the secret backs off from the full interval,
/// doubling up to ten intervals; its file follows `on_revoked`.
fn refuse(
    secret: &mut SecretState,
    kind: Revoked,
    now: Instant,
    interval: Duration,
    dirty: &mut bool,
) {
    let backoff = match &secret.refused {
        None => interval,
        Some(refused) => (refused.backoff * 2).min(interval * MAX_REFUSAL_INTERVALS),
    };
    if secret.refused.as_ref().is_none_or(|r| r.kind != kind) {
        tracing::warn!(
            path = %secret.config.path,
            refused = ?kind,
            on_revoked = ?secret.config.on_revoked,
            delivered = secret.delivered.is_some(),
            "refused by the server; retrying slowly"
        );
    }
    secret.refused = Some(Refused {
        kind,
        backoff,
        next_try: now + backoff,
    });
    if secret.config.on_revoked == OnRevoked::Remove && secret.delivered.take().is_some() {
        *dirty = true;
    }
}

/// Writes `output`'s set if something changed and the set can be written
/// (the first one only once every required secret has a value); tells the
/// application after every write but the first. Returns whether it wrote.
fn write_if_changed(output: &mut OutputState) -> Result<bool, FilesError> {
    if !output.dirty || !(output.written || output.complete()) {
        return Ok(false);
    }
    let files: Vec<OutputFile> = output
        .secrets
        .iter()
        .filter_map(|s| {
            s.delivered.as_ref().map(|d| OutputFile {
                name: s.config.file.clone(),
                contents: d.value.clone(),
                mode: s.config.mode,
            })
        })
        .collect();
    output.writer.write(&files)?;
    let first = !output.written;
    output.written = true;
    output.dirty = false;
    tracing::info!(dir = %output.config.dir.display(), files = files.len(), "files written");
    if !first {
        notify::changed(&output.config.notify);
    }
    Ok(true)
}

#[derive(serde::Serialize)]
struct Status<'a> {
    last_success: Option<String>,
    last_error: Option<&'a str>,
    rendered: bool,
    secrets: Vec<SecretStatus<'a>>,
}

#[derive(serde::Serialize)]
struct SecretStatus<'a> {
    path: &'a str,
    file: &'a str,
    /// The version in the file, if any.
    version: Option<u32>,
    /// While the server refuses it for good.
    refused: Option<Revoked>,
}

fn write_status(
    output: &OutputState,
    last_success: Option<OffsetDateTime>,
    last_error: Option<&str>,
) {
    let status = Status {
        last_success: last_success.and_then(|t| t.format(&Rfc3339).ok()),
        last_error,
        rendered: output.written,
        secrets: output
            .secrets
            .iter()
            .map(|s| SecretStatus {
                path: s.config.path.as_str(),
                file: &s.config.file,
                version: s.delivered.as_ref().map(|d| d.version),
                refused: s.refused.as_ref().map(|r| r.kind),
            })
            .collect(),
    };
    let mode = output
        .config
        .secrets
        .iter()
        .map(|s| s.mode)
        .fold(crate::config::DEFAULT_FILE_MODE, |a, b| a | b);
    if let Err(e) = output.writer.write_status(&status, mode) {
        tracing::warn!(dir = %output.config.dir.display(), error = %error_chain(&e), "writing the status file failed");
    }
}

/// `error: source: source…`.
pub fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut chain = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        let message = s.to_string();
        if !chain.contains(&message) {
            chain.push_str(": ");
            chain.push_str(&message);
        }
        source = s.source();
    }
    chain
}

/// Spreads waits by ±10 %, so agents started together don't poll in step.
/// Not security-relevant: seeded from the clock and the process id.
struct Jitter(u64);

impl Jitter {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        Self(u64::from(nanos) ^ (u64::from(std::process::id()) << 32) | 1)
    }

    fn spread(&mut self, base: Duration) -> Duration {
        // xorshift64
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        // 0.9 to 1.1 of the base, in thousandths.
        let thousandths = 900 + u32::try_from(self.0 % 201).unwrap_or(100);
        base * thousandths / 1000
    }
}

impl ServerSettings {
    pub(crate) fn files(&self) -> Vec<&std::path::Path> {
        match self {
            Self::Plain(_) => Vec::new(),
            Self::Tls { ca, cert, key, .. } => vec![ca.as_path(), cert.as_path(), key.as_path()],
            // The certificate is exchanged again before it ages (see
            // `Connection`); the token file is read at each exchange.
            Self::Exchange { source, .. } => vec![source.ca.as_path()],
        }
    }
}
