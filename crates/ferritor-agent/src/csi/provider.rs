//! The provider: `Mount` (a volume's files, for the pod whose token came
//! with it) and `Version`, served to the driver on a node-local socket.
//!
//! Per node it keeps, in memory only:
//!
//! - which identity each pod token exchanged to (by the token's SHA-256,
//!   until the token expires), so a pod is served only as the identity its
//!   own token maps to;
//! - a certificate (and a connection) per identity, exchanged again with a
//!   pod's token two thirds into its life;
//! - reads and listings per identity, shared for `share_reads` between the
//!   pods of that identity, never across identities;
//! - authoritative refusals per identity and path (and per token), with
//!   the agent's backoff: from `refusal_backoff`, doubling to ten times it,
//!   during which the kubelet's retries are answered from memory;
//! - each volume's delivered values, for `onRevoked = "keep"` and for the
//!   files a refresh doesn't read again, until the volume hasn't been seen
//!   for `forget_volumes_after` (the driver never says a volume is gone).
//!
//! Every decision is taken against the `now` given to [`Provider::mount_at`],
//! so the tests can run backoffs without waiting.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant, SystemTime};

use ferritor_client::exchange::{self, ExchangeError, Issued};
use ferritor_client::{Server, ServerError, Transport, answer};
use ferritor_core::messages::reason;
use ferritor_core::path::SecretPath;
use ferritor_core::proto::v1 as pb;
use ferritor_core::proto::v1::secrets_service_client::SecretsServiceClient;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use tonic::{Code, Request, Response, Status};
use zeroize::Zeroizing;

use super::config::ProviderConfig;
use super::proto;
use super::request::{self, Source, Volume};
use crate::agent::{Refusal, Revoked, classify, error_chain};
use crate::config::OnRevoked;
use crate::metrics::{self, call_result};

/// The most a listing page holds (the server's maximum).
const PAGE_SIZE: u32 = 1000;
/// An authoritative refusal's backoff grows to this many first backoffs.
const MAX_REFUSAL_STEPS: u32 = 10;

type Client = SecretsServiceClient<Transport>;
type TokenHash = [u8; 32];

/// A value as read, shared (the pods of one identity, a volume's memory)
/// and wiped when the last holder lets go.
#[derive(Clone)]
struct Read {
    version: u32,
    value: Arc<Zeroizing<Vec<u8>>>,
}

/// An authoritative refusal, while it lasts.
#[derive(Clone)]
struct Refused {
    kind: Revoked,
    message: String,
    backoff: Duration,
    next_try: Instant,
}

impl Refused {
    /// The next refusal after `previous` (if any) at `now`.
    fn next(
        previous: Option<&Refused>,
        kind: Revoked,
        message: String,
        now: Instant,
        base: Duration,
    ) -> Self {
        let backoff = previous.map_or(base, |p| (p.backoff * 2).min(base * MAX_REFUSAL_STEPS));
        Self {
            kind,
            message,
            backoff,
            next_try: now + backoff,
        }
    }
}

/// What a pod's token exchanged to.
enum TokenEntry {
    Mapped { identity: String, until: SystemTime },
    Refused(Refused),
}

struct IdentityEntry {
    issued: Arc<Issued>,
    client: Option<Client>,
    /// No renewal before this (one failed).
    retry_renewal: Option<SystemTime>,
}

/// A listing: every live secret below a prefix, with its version.
type Listing = Vec<(SecretPath, u32)>;

/// One volume's files as last delivered, by secret path.
struct VolumeState {
    identity: String,
    delivered: BTreeMap<SecretPath, (String, Read)>,
    seen: Instant,
}

/// A read or a listing, shared within its identity: valid for
/// `share_reads` from `at`, or, made while the identity's watch was ready
/// (`watch`: its generation) with no change heard during the call, for as
/// long as that watch stays ready and covers it, until a change of it.
struct Cached<T> {
    at: Instant,
    value: T,
    watch: Option<u64>,
}

/// An identity's watch stream: what it covers, and whether it's ready (its
/// generation once `ready` arrived).
struct IdentityWatch {
    paths: BTreeSet<SecretPath>,
    prefixes: BTreeSet<SecretPath>,
    generation: u64,
    ready: bool,
    ended: bool,
    /// When it ended: none is opened again before a refusal backoff, so a
    /// stream the server refuses can't be retried by every mount.
    ended_at: Option<Instant>,
    /// Changes heard so far: a read that saw this move during its call
    /// isn't trusted beyond the window.
    heard: u64,
    task: tokio::task::JoinHandle<()>,
}

impl IdentityWatch {
    fn covers(&self, path: &SecretPath) -> bool {
        self.paths.contains(path) || self.prefixes.iter().any(|p| path == p || path.is_under(p))
    }
}

impl Drop for IdentityWatch {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
struct State {
    tokens: HashMap<TokenHash, TokenEntry>,
    identities: HashMap<String, IdentityEntry>,
    reads: HashMap<(String, SecretPath), Cached<Read>>,
    listings: HashMap<(String, SecretPath), Cached<Listing>>,
    watches: HashMap<String, IdentityWatch>,
    next_generation: u64,
    /// By identity and path (a listing's: its prefix).
    refusals: HashMap<(String, SecretPath), Refused>,
    volumes: HashMap<String, VolumeState>,
}

/// Why a mount gave no files: transient (the volume stays as it is; the
/// kubelet retries a first mount) or authoritative, or a mistake in the
/// `SecretProviderClass`.
#[derive(Debug)]
enum Failed {
    Transient(String),
    Refused(String),
    Invalid(String),
}

/// A transient failure is `FAILED_PRECONDITION`, never `UNAVAILABLE`: the
/// driver's gRPC client retries `UNAVAILABLE` within the call (3 attempts),
/// which stretches a failing first mount until the kubelet's next call
/// overlaps it, finds the volume mounted, has its error masked as a
/// remount's, and the pod starts with an empty volume (seen in a cluster).
/// With a code it doesn't retry, the pod waits in `ContainerCreating`.
impl From<Failed> for Status {
    fn from(failed: Failed) -> Self {
        match failed {
            Failed::Transient(message) => Status::failed_precondition(message),
            Failed::Refused(message) => Status::permission_denied(message),
            Failed::Invalid(message) => Status::invalid_argument(message),
        }
    }
}

/// See the module docs.
pub struct Provider {
    config: ProviderConfig,
    state: Arc<Mutex<State>>,
    /// One exchange at a time per token: a pod's volumes mount together,
    /// with the same token, and must not each exchange it.
    exchanging: Mutex<HashMap<TokenHash, Arc<tokio::sync::Mutex<()>>>>,
    /// Observed from `state` at each collection. Dropping them doesn't
    /// unregister their callbacks: those hold only a `Weak` of the state,
    /// so once the provider is gone they observe nothing.
    _gauges: Vec<opentelemetry::metrics::ObservableGauge<u64>>,
}

/// What reading one secret gave.
enum Outcome {
    Read(Read),
    Refused(Revoked, String),
}

/// The gauges observed from the provider's state: counts only, never who.
fn observe(state: Weak<Mutex<State>>) -> Vec<opentelemetry::metrics::ObservableGauge<u64>> {
    let meter = metrics::provider_meter();
    let gauge = |name: &'static str, description: &'static str, count: fn(&State) -> usize| {
        let state = Weak::clone(&state);
        meter
            .u64_observable_gauge(name)
            .with_description(description)
            .with_callback(move |gauge| {
                if let Some(state) = state.upgrade() {
                    let state = state.lock().unwrap_or_else(PoisonError::into_inner);
                    gauge.observe(u64::try_from(count(&state)).unwrap_or(u64::MAX), &[]);
                }
            })
            .build()
    };
    vec![
        gauge(
            "ferritor.csi.identities",
            "Identities the provider holds a certificate for",
            |state| state.identities.len(),
        ),
        gauge(
            "ferritor.csi.volumes",
            "Volumes remembered (mounted within forget_volumes_after_secs)",
            |state| state.volumes.len(),
        ),
        gauge(
            "ferritor.csi.watch.streams",
            "Identities' watch streams open and ready",
            |state| {
                state
                    .watches
                    .values()
                    .filter(|w| w.ready && !w.ended)
                    .count()
            },
        ),
    ]
}

fn hash(token: &str) -> TokenHash {
    Sha256::digest(token.as_bytes()).into()
}

fn transient(e: &ServerError) -> Failed {
    Failed::Transient(e.to_string())
}

impl Provider {
    pub fn new(config: ProviderConfig) -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        Self {
            config,
            _gauges: observe(Arc::downgrade(&state)),
            state,
            exchanging: Mutex::new(HashMap::new()),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A volume's files, for the pod whose token came with the request.
    pub async fn mount_at(
        &self,
        request: &proto::MountRequest,
        now: Instant,
    ) -> Result<proto::MountResponse, Status> {
        // Measured on the clock, for the metric only: nothing is decided by it.
        let started = Instant::now();
        let (volume, expires) = match request::parse(request, &self.config.audience) {
            Ok(parsed) => parsed,
            Err(e) => {
                metrics::provider().mount("invalid", started.elapsed());
                return Err(Failed::Invalid(e).into());
            }
        };
        self.forget_idle(now);
        let result = self.mount_volume(&volume, expires, now).await;
        let outcome = match &result {
            Ok(_) => "ok",
            Err(Failed::Transient(_)) => "failed",
            Err(Failed::Refused(_)) => "refused",
            Err(Failed::Invalid(_)) => "invalid",
        };
        metrics::provider().mount(outcome, started.elapsed());
        match &result {
            Ok(response) => {
                tracing::debug!(pod = volume.pod, files = response.files.len(), "mounted")
            }
            Err(Failed::Transient(error)) => tracing::warn!(
                pod = volume.pod,
                error,
                "mount failed for now; the volume stays as it is"
            ),
            Err(Failed::Refused(error) | Failed::Invalid(error)) => {
                tracing::warn!(pod = volume.pod, error, "mount refused");
            }
        }
        result.map_err(Status::from)
    }

    async fn mount_volume(
        &self,
        volume: &Volume,
        expires: Option<OffsetDateTime>,
        now: Instant,
    ) -> Result<proto::MountResponse, Failed> {
        let identity = self.identity(volume, expires, now).await?;
        let mut client = self.client(&identity, volume).await?;
        let mounted = self.read_volume(&identity, volume, &mut client, now).await;
        // After the reads, so what they found refused is left out: a watch
        // needs every permission it names, and asking for one more than
        // the reads have would cost a denial and end the identity's stream.
        if self.config.watch && !matches!(mounted, Err(Failed::Transient(_))) {
            self.keep_watching(&identity, &client, &volume.source);
        }
        mounted
    }

    /// The volume's files for `identity`, on `client`.
    async fn read_volume(
        &self,
        identity: &str,
        volume: &Volume,
        client: &mut Client,
        now: Instant,
    ) -> Result<proto::MountResponse, Failed> {
        let kept: BTreeMap<SecretPath, (String, Read)> = self
            .state()
            .volumes
            .get(&volume.target)
            .map(|v| v.delivered.clone())
            .unwrap_or_default();
        // (path, file, the version a listing showed)
        let wanted: Vec<(SecretPath, String, Option<u32>)> = match &volume.source {
            Source::Objects(objects) => objects
                .iter()
                .map(|o| (o.path.clone(), o.file.clone(), None))
                .collect(),
            Source::Prefix(prefix) => {
                match self.listing(identity, prefix, client, now).await? {
                    Ok(listing) => {
                        // A name the volume can't hold skips that secret,
                        // never the volume: one put under the prefix
                        // mustn't keep every pod mounting it from starting.
                        let mut wanted = Vec::with_capacity(listing.len());
                        for (path, version) in listing {
                            match request::file_below(prefix, &path) {
                                Some(file) => wanted.push((path, file, Some(version))),
                                None => tracing::warn!(
                                    pod = volume.pod,
                                    path = %path,
                                    "skipped: no file name for it (a name starting with '..' \
                                     is the driver's); rename the secret"
                                ),
                            }
                        }
                        let wanted = without_conflicts(wanted, &kept, &volume.pod);
                        if wanted.is_empty() {
                            // The driver writes nothing for no files, and
                            // treats a missing version list as an error.
                            return Err(Failed::Refused(format!(
                                "nothing is stored below {prefix}"
                            )));
                        }
                        wanted
                    }
                    Err((kind, message)) => {
                        return match (volume.on_revoked, kept.is_empty()) {
                            (OnRevoked::Keep, false) => {
                                tracing::warn!(pod = volume.pod, prefix = %prefix, refused = ?kind, "listing refused; keeping the files delivered");
                                Ok(self.respond(identity, volume, kept, now))
                            }
                            _ => Err(Failed::Refused(message)),
                        };
                    }
                }
            }
        };
        let mut files = BTreeMap::new();
        for (path, file, listed) in wanted {
            let kept_here = kept.get(&path).map(|(_, read)| read.clone());
            let outcome = match (listed, &kept_here) {
                // Listed at the version this volume already has.
                (Some(version), Some(read)) if read.version == version => {
                    Outcome::Read(read.clone())
                }
                _ => self.read(identity, &path, listed, client, now).await?,
            };
            match outcome {
                Outcome::Read(read) => {
                    files.insert(path, (file, read));
                }
                Outcome::Refused(kind, message) => match (volume.on_revoked, kept_here) {
                    (OnRevoked::Keep, Some(read)) => {
                        // e2e/cluster.sh's onRevoked check looks for this line's
                        // text: reword both together.
                        tracing::warn!(pod = volume.pod, path = %path, refused = ?kind, "refused; keeping the value delivered");
                        files.insert(path, (file, read));
                    }
                    // A first mount can't be complete without it: the pod
                    // waits (the kubelet's retries answered from memory).
                    (_, None) if kept.is_empty() => {
                        return Err(Failed::Refused(message));
                    }
                    _ => {
                        tracing::warn!(pod = volume.pod, path = %path, refused = ?kind, "refused; its file goes");
                    }
                },
            }
        }
        if files.is_empty() {
            return Err(Failed::Refused(
                "every secret of the volume is refused: the driver can't empty a volume, so \
                 it stays as it is"
                    .to_owned(),
            ));
        }
        check_files(&files, self.config.max_volume_bytes)?;
        Ok(self.respond(identity, volume, files, now))
    }

    /// Records `files` as the volume's, and builds the response.
    fn respond(
        &self,
        identity: &str,
        volume: &Volume,
        files: BTreeMap<SecretPath, (String, Read)>,
        now: Instant,
    ) -> proto::MountResponse {
        let response = proto::MountResponse {
            object_version: files
                .iter()
                .map(|(path, (_, read))| proto::ObjectVersion {
                    id: path.as_str().to_owned(),
                    version: read.version.to_string(),
                })
                .collect(),
            error: None,
            files: files
                .values()
                .map(|(file, read)| proto::File {
                    path: file.clone(),
                    mode: i32::try_from(volume.mode).unwrap_or(0o644),
                    contents: read.value.to_vec(),
                })
                .collect(),
        };
        self.state().volumes.insert(
            volume.target.clone(),
            VolumeState {
                identity: identity.to_owned(),
                delivered: files,
                seen: now,
            },
        );
        response
    }

    /// The identity `volume`'s token maps to: from memory if this token
    /// exchanged before, else by exchanging it (which also gives that
    /// identity a certificate). A refused token is remembered, with
    /// backoff.
    async fn identity(
        &self,
        volume: &Volume,
        expires: Option<OffsetDateTime>,
        now: Instant,
    ) -> Result<String, Failed> {
        let key = hash(&volume.token);
        let lock = Arc::clone(
            self.exchanging
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(key)
                .or_default(),
        );
        let result = {
            let _one_at_a_time = lock.lock().await;
            self.identity_once(volume, key, expires, now).await
        };
        let mut exchanging = self
            .exchanging
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // The last waiter takes the lock's entry away.
        if Arc::strong_count(&lock) <= 2 {
            exchanging.remove(&key);
        }
        result
    }

    /// [`Provider::identity`], once the token's turn has come (another
    /// mount with it may just have exchanged it: looked up first).
    async fn identity_once(
        &self,
        volume: &Volume,
        key: TokenHash,
        expires: Option<OffsetDateTime>,
        now: Instant,
    ) -> Result<String, Failed> {
        let previous = {
            let state = self.state();
            match state.tokens.get(&key) {
                Some(TokenEntry::Mapped { identity, until }) if SystemTime::now() < *until => {
                    return Ok(identity.clone());
                }
                Some(TokenEntry::Refused(refused)) if now < refused.next_try => {
                    metrics::provider().answered_from_memory("refusal");
                    return Err(Failed::Refused(refused.message.clone()));
                }
                Some(TokenEntry::Refused(refused)) => Some(refused.clone()),
                _ => None,
            }
        };
        match exchange::exchange_token(&self.config.exchange, &self.config.ca, &volume.token).await
        {
            Ok(issued) => {
                metrics::provider().exchange("issued");
                let identity = issued.identity.clone();
                let until = expires
                    .map(SystemTime::from)
                    .unwrap_or(issued.not_after)
                    .min(issued.not_after.max(SystemTime::now()));
                tracing::info!(pod = volume.pod, identity, "the pod's token exchanged");
                let mut state = self.state();
                state.tokens.insert(
                    key,
                    TokenEntry::Mapped {
                        identity: identity.clone(),
                        until,
                    },
                );
                adopt(&mut state, issued);
                Ok(identity)
            }
            Err(e) => {
                let refused = token_refused(&e);
                metrics::provider().exchange(if refused { "refused" } else { "failed" });
                if refused {
                    let message = format!("the pod's token was refused: {}", error_chain(&e));
                    let entry = Refused::next(
                        previous.as_ref(),
                        Revoked::PermissionDenied,
                        message.clone(),
                        now,
                        self.config.refusal_backoff,
                    );
                    self.state().tokens.insert(key, TokenEntry::Refused(entry));
                    Err(Failed::Refused(message))
                } else {
                    Err(Failed::Transient(format!(
                        "exchanging the pod's token: {}",
                        error_chain(&e)
                    )))
                }
            }
        }
    }

    /// A client for `identity`, renewing its certificate with this pod's
    /// token when due (a failure keeps the current one while it's valid).
    async fn client(&self, identity: &str, volume: &Volume) -> Result<Client, Failed> {
        let (issued, client, due) = {
            let state = self.state();
            let entry = state
                .identities
                .get(identity)
                .ok_or_else(|| Failed::Transient(format!("no certificate for {identity}")))?;
            let now = SystemTime::now();
            let due =
                now >= entry.issued.renew_at() && entry.retry_renewal.is_none_or(|at| now >= at);
            (Arc::clone(&entry.issued), entry.client.clone(), due)
        };
        if due {
            let renewed =
                exchange::exchange_token(&self.config.exchange, &self.config.ca, &volume.token)
                    .await;
            metrics::provider().exchange(match &renewed {
                Ok(_) => "issued",
                Err(e) if token_refused(e) => "refused",
                Err(_) => "failed",
            });
            match renewed {
                Ok(renewed) if renewed.identity == identity => {
                    adopt(&mut self.state(), renewed);
                    return Box::pin(self.client(identity, volume)).await;
                }
                Ok(other) => {
                    // The server maps this token elsewhere now (its config
                    // changed): forget the mapping, retry next time.
                    let mut state = self.state();
                    state.tokens.remove(&hash(&volume.token));
                    let moved = other.identity.clone();
                    adopt(&mut state, other);
                    return Err(Failed::Transient(format!(
                        "the pod's token maps to {moved} now, not {identity}"
                    )));
                }
                Err(e) => {
                    let still_valid = SystemTime::now() < issued.not_after;
                    tracing::warn!(identity, error = %error_chain(&e), still_valid, "renewing the certificate failed");
                    if let Some(entry) = self.state().identities.get_mut(identity) {
                        entry.retry_renewal = Some(SystemTime::now() + Duration::from_secs(30));
                    }
                    if !still_valid {
                        return Err(exchange_failed(&e));
                    }
                }
            }
        }
        if let Some(client) = client {
            return Ok(client);
        }
        let server = Server::issued(&self.config.server, &self.config.ca, &issued)
            .map_err(|e| Failed::Transient(error_chain(&e)))?;
        let transport = ferritor_client::connect(&server)
            .await
            .map_err(|e| Failed::Transient(error_chain(&e)))?;
        let client = SecretsServiceClient::new(transport);
        if let Some(entry) = self.state().identities.get_mut(identity)
            && Arc::ptr_eq(&entry.issued, &issued)
        {
            entry.client = Some(client.clone());
        }
        Ok(client)
    }

    /// The identity's watch generation and changes heard, if it's ready and
    /// covers `item`: taken before a call, so a change during it is seen.
    fn watch_mark(&self, identity: &str, item: &SecretPath) -> Option<(u64, u64)> {
        let state = self.state();
        let watch = state.watches.get(identity)?;
        (watch.ready && !watch.ended && watch.covers(item))
            .then_some((watch.generation, watch.heard))
    }

    /// Whether `identity`'s watch stream is open and ready (for tests and
    /// diagnostics).
    pub fn watch_ready(&self, identity: &str) -> bool {
        self.state()
            .watches
            .get(identity)
            .is_some_and(|w| w.ready && !w.ended)
    }

    /// Keeps a watch stream open for `identity` covering `source` (with
    /// what it already covers): opened, or opened again wider, on
    /// `client`, when it doesn't. Its changes drop what they make stale.
    fn keep_watching(&self, identity: &str, client: &Client, source: &Source) {
        let mut state = self.state();
        // Not what's refused: a watch needs every permission it names.
        let refused = |item: &SecretPath| {
            state
                .refusals
                .contains_key(&(identity.to_owned(), item.clone()))
        };
        let (needs_path, needs_prefix): (Vec<SecretPath>, Vec<SecretPath>) = match source {
            Source::Objects(objects) => (
                objects
                    .iter()
                    .map(|o| o.path.clone())
                    .filter(|p| !refused(p))
                    .collect(),
                Vec::new(),
            ),
            Source::Prefix(prefix) if refused(prefix) => (Vec::new(), Vec::new()),
            Source::Prefix(prefix) => (Vec::new(), vec![prefix.clone()]),
        };
        if needs_path.is_empty() && needs_prefix.is_empty() {
            return;
        }
        if let Some(watch) = state.watches.get(identity)
            && watch
                .ended_at
                .is_some_and(|at| at.elapsed() < self.config.refusal_backoff)
        {
            return;
        }
        let (mut paths, mut prefixes) = match state.watches.get(identity) {
            Some(watch)
                if !watch.ended
                    && needs_path.iter().all(|p| watch.paths.contains(p))
                    && needs_prefix.iter().all(|p| watch.prefixes.contains(p)) =>
            {
                return;
            }
            Some(watch) if !watch.ended => (watch.paths.clone(), watch.prefixes.clone()),
            _ => (BTreeSet::new(), BTreeSet::new()),
        };
        paths.extend(needs_path);
        prefixes.extend(needs_prefix);
        state.next_generation += 1;
        let generation = state.next_generation;
        let task = tokio::spawn(watch_stream(
            Arc::clone(&self.state),
            identity.to_owned(),
            generation,
            client.clone(),
            paths.clone(),
            prefixes.clone(),
        ));
        // The previous stream (if any) ends as it's dropped.
        state.watches.insert(
            identity.to_owned(),
            IdentityWatch {
                paths,
                prefixes,
                generation,
                ready: false,
                ended: false,
                ended_at: None,
                heard: 0,
                task,
            },
        );
    }

    /// Forgets `identity`'s connection after a transient failure (it may be
    /// what failed).
    fn reset(&self, identity: &str) {
        if let Some(entry) = self.state().identities.get_mut(identity) {
            entry.client = None;
        }
    }

    /// Every live secret below `prefix` for `identity` (shared), or its
    /// authoritative refusal (remembered). A transient failure fails the
    /// mount.
    async fn listing(
        &self,
        identity: &str,
        prefix: &SecretPath,
        client: &mut Client,
        now: Instant,
    ) -> Result<Result<Listing, (Revoked, String)>, Failed> {
        let key = (identity.to_owned(), prefix.clone());
        let previous = {
            let state = self.state();
            if let Some(refused) = state.refusals.get(&key)
                && now < refused.next_try
            {
                metrics::provider().answered_from_memory("refusal");
                return Ok(Err((refused.kind, refused.message.clone())));
            }
            if let Some(cached) = state.listings.get(&key)
                && fresh(
                    &state,
                    identity,
                    prefix,
                    cached,
                    now,
                    self.config.share_reads,
                )
            {
                metrics::provider().answered_from_memory("listing");
                return Ok(Ok(cached.value.clone()));
            }
            state.refusals.get(&key).cloned()
        };
        let watched = self.watch_mark(identity, prefix);
        let mut listing = Vec::new();
        let mut token = String::new();
        loop {
            let page = answer(
                client
                    .list_secrets(pb::ListSecretsRequest {
                        prefix: prefix.as_str().to_owned(),
                        page_size: PAGE_SIZE,
                        page_token: token,
                        labels: HashMap::new(),
                    })
                    .await,
            );
            metrics::provider().call("list", call_result(page.as_ref().map(|_| ())));
            let page = match page {
                Ok(page) => page,
                Err(e) => {
                    return match classify(&e) {
                        Refusal::Authoritative(kind) => {
                            let message = format!("listing {prefix}: {e}");
                            self.state().refusals.insert(
                                key,
                                Refused::next(
                                    previous.as_ref(),
                                    kind,
                                    message.clone(),
                                    now,
                                    self.config.refusal_backoff,
                                ),
                            );
                            Ok(Err((kind, message)))
                        }
                        Refusal::Transient { .. } => {
                            self.reset(identity);
                            Err(transient(&e))
                        }
                    };
                }
            };
            for secret in page.secrets {
                if let Ok(path) = SecretPath::parse(&secret.path) {
                    listing.push((path, secret.version));
                }
            }
            if page.next_page_token.is_empty() {
                break;
            }
            token = page.next_page_token;
        }
        let mut state = self.state();
        state.refusals.remove(&key);
        let watch = still_marked(&state, identity, watched);
        if !self.config.share_reads.is_zero() || watch.is_some() {
            state.listings.insert(
                key,
                Cached {
                    at: now,
                    value: listing.clone(),
                    watch,
                },
            );
        }
        Ok(Ok(listing))
    }

    /// `path` for `identity` (at `listed`, if a listing showed a version):
    /// shared, remembered when refused. A transient failure fails the mount.
    async fn read(
        &self,
        identity: &str,
        path: &SecretPath,
        listed: Option<u32>,
        client: &mut Client,
        now: Instant,
    ) -> Result<Outcome, Failed> {
        let key = (identity.to_owned(), path.clone());
        let previous = {
            let state = self.state();
            if let Some(refused) = state.refusals.get(&key)
                && now < refused.next_try
            {
                metrics::provider().answered_from_memory("refusal");
                return Ok(Outcome::Refused(refused.kind, refused.message.clone()));
            }
            if let Some(cached) = state.reads.get(&key)
                && fresh(&state, identity, path, cached, now, self.config.share_reads)
                && listed.is_none_or(|version| version == cached.value.version)
            {
                metrics::provider().answered_from_memory("read");
                return Ok(Outcome::Read(cached.value.clone()));
            }
            state.refusals.get(&key).cloned()
        };
        let watched = self.watch_mark(identity, path);
        let reply = answer(
            client
                .get_secret(pb::GetSecretRequest {
                    path: path.as_str().to_owned(),
                    version: 0,
                })
                .await,
        );
        metrics::provider().call("get", call_result(reply.as_ref().map(|_| ())));
        match reply {
            Ok(reply) => {
                let Some(secret) = reply.secret else {
                    return Err(Failed::Transient(format!("{path}: an empty answer")));
                };
                let read = Read {
                    version: secret.metadata.map_or(0, |m| m.version),
                    value: Arc::new(Zeroizing::new(secret.value)),
                };
                let mut state = self.state();
                if state.refusals.remove(&key).is_some() {
                    tracing::info!(identity, path = %path, "readable again");
                }
                let watch = still_marked(&state, identity, watched);
                if !self.config.share_reads.is_zero() || watch.is_some() {
                    state.reads.insert(
                        key,
                        Cached {
                            at: now,
                            value: read.clone(),
                            watch,
                        },
                    );
                }
                Ok(Outcome::Read(read))
            }
            Err(e) => match classify(&e) {
                Refusal::Authoritative(kind) => {
                    let message = format!("{path}: {e}");
                    self.state().refusals.insert(
                        key,
                        Refused::next(
                            previous.as_ref(),
                            kind,
                            message.clone(),
                            now,
                            self.config.refusal_backoff,
                        ),
                    );
                    Ok(Outcome::Refused(kind, message))
                }
                Refusal::Transient { .. } => {
                    self.reset(identity);
                    Err(transient(&e))
                }
            },
        }
    }

    /// Drops what outlived its use: volumes not seen for
    /// `forget_volumes_after` (their values with them), shared reads past
    /// their window, expired token mappings and certificates, refusals long
    /// past their backoff.
    fn forget_idle(&self, now: Instant) {
        let forget = self.config.forget_volumes_after;
        let share = self.config.share_reads;
        let wall = SystemTime::now();
        let mut state = self.state();
        state
            .volumes
            .retain(|_, volume| now.saturating_duration_since(volume.seen) < forget);
        let in_use: BTreeSet<String> = state.volumes.values().map(|v| v.identity.clone()).collect();
        state
            .watches
            .retain(|identity, _| in_use.contains(identity));
        let watches = &state.watches;
        let keep = |identity: &str, path: &SecretPath, at: Instant, watch: Option<u64>| {
            now.saturating_duration_since(at) < share
                || watch.is_some_and(|generation| {
                    watches.get(identity).is_some_and(|w| {
                        w.generation == generation && w.ready && !w.ended && w.covers(path)
                    })
                })
        };
        let reads: Vec<(String, SecretPath)> = state
            .reads
            .iter()
            .filter(|((identity, path), c)| !keep(identity, path, c.at, c.watch))
            .map(|(key, _)| key.clone())
            .collect();
        let listings: Vec<(String, SecretPath)> = state
            .listings
            .iter()
            .filter(|((identity, path), c)| !keep(identity, path, c.at, c.watch))
            .map(|(key, _)| key.clone())
            .collect();
        for key in reads {
            state.reads.remove(&key);
        }
        for key in listings {
            state.listings.remove(&key);
        }
        state.tokens.retain(|_, entry| match entry {
            TokenEntry::Mapped { until, .. } => wall < *until,
            TokenEntry::Refused(refused) => {
                now.saturating_duration_since(refused.next_try) < forget
            }
        });
        state
            .identities
            .retain(|_, entry| wall < entry.issued.not_after);
        state
            .refusals
            .retain(|_, refused| now.saturating_duration_since(refused.next_try) < forget);
    }
}

/// Whether `cached` (of `item`, for `identity`) may be used at `now`:
/// within the shared window, or vouched for by the identity's watch,
/// still ready and covering it, of the generation it was made under.
fn fresh<T>(
    state: &State,
    identity: &str,
    item: &SecretPath,
    cached: &Cached<T>,
    now: Instant,
    share: Duration,
) -> bool {
    now < cached.at + share
        || cached.watch.is_some_and(|generation| {
            state.watches.get(identity).is_some_and(|w| {
                w.generation == generation && w.ready && !w.ended && w.covers(item)
            })
        })
}

/// What a call's result may be cached under: the watch's generation, if
/// it was ready and covering when the call began (`mark`) and heard no
/// change since.
fn still_marked(state: &State, identity: &str, mark: Option<(u64, u64)>) -> Option<u64> {
    let (generation, heard) = mark?;
    let watch = state.watches.get(identity)?;
    (watch.generation == generation && watch.ready && !watch.ended && watch.heard == heard)
        .then_some(generation)
}

/// Takes `issued` as its identity's certificate if it lives longer than
/// the one held.
fn adopt(state: &mut State, issued: Issued) {
    let newer = state
        .identities
        .get(&issued.identity)
        .is_none_or(|entry| issued.not_after > entry.issued.not_after);
    if newer {
        state.identities.insert(
            issued.identity.clone(),
            IdentityEntry {
                issued: Arc::new(issued),
                client: None,
                retry_renewal: None,
            },
        );
    }
}

/// The exchange refused the pod's token (authoritative), rather than
/// failing for now.
fn token_refused(e: &ExchangeError) -> bool {
    e.server().is_some_and(|server| {
        server.reason.as_deref() == Some(reason::TOKEN_REFUSED)
            || server.code == Code::Unauthenticated
    })
}

fn exchange_failed(e: &ExchangeError) -> Failed {
    Failed::Transient(format!("exchanging the pod's token: {}", error_chain(e)))
}

/// `wanted` without the secrets whose file would also be a directory of
/// another's (`a` and `a/b`): of each such pair the one this volume
/// already has stays, else the shallower; the other is skipped, with a
/// warning naming it. So a secret added under a prefix can't take away a
/// file a pod already has, nor fail the volume.
fn without_conflicts(
    wanted: Vec<(SecretPath, String, Option<u32>)>,
    kept: &BTreeMap<SecretPath, (String, Read)>,
    pod: &str,
) -> Vec<(SecretPath, String, Option<u32>)> {
    let mut skipped = std::collections::HashSet::new();
    for (shallow_path, shallow, _) in &wanted {
        for (deep_path, deep, _) in &wanted {
            let nested = deep
                .strip_prefix(shallow.as_str())
                .is_some_and(|rest| rest.starts_with('/'));
            if !nested {
                continue;
            }
            let (keep, skip) = if kept.contains_key(deep_path) && !kept.contains_key(shallow_path) {
                (deep_path, shallow_path)
            } else {
                (shallow_path, deep_path)
            };
            if skipped.insert(skip.clone()) {
                tracing::warn!(
                    pod,
                    path = %skip,
                    conflicts_with = %keep,
                    "skipped: its file would be a file and a directory at once; rename one"
                );
            }
        }
    }
    wanted
        .into_iter()
        .filter(|(path, _, _)| !skipped.contains(path))
        .collect()
}

/// The set as the driver will write it: no file that's also a directory
/// (`a` and `a/b`), and not larger than `max` bytes.
fn check_files(files: &BTreeMap<SecretPath, (String, Read)>, max: usize) -> Result<(), Failed> {
    let names: Vec<&str> = files.values().map(|(file, _)| file.as_str()).collect();
    for name in &names {
        if names.iter().any(|other| {
            other
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('/'))
        }) {
            return Err(Failed::Invalid(format!(
                "{name} would be a file and a directory: rename one of the secrets"
            )));
        }
    }
    let total: usize = files.values().map(|(_, read)| read.value.len()).sum();
    if total > max {
        return Err(Failed::Invalid(format!(
            "the volume's files total {total} bytes, over max_volume_bytes ({max}): split it \
             into volumes of their own"
        )));
    }
    Ok(())
}

#[tonic::async_trait]
impl proto::csi_driver_provider_server::CsiDriverProvider for Arc<Provider> {
    async fn version(
        &self,
        _: Request<proto::VersionRequest>,
    ) -> Result<Response<proto::VersionResponse>, Status> {
        Ok(Response::new(proto::VersionResponse {
            version: "v1alpha1".to_owned(),
            runtime_name: "ferritor-csi-provider".to_owned(),
            runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
        }))
    }

    async fn mount(
        &self,
        request: Request<proto::MountRequest>,
    ) -> Result<Response<proto::MountResponse>, Status> {
        self.mount_at(request.get_ref(), Instant::now())
            .await
            .map(Response::new)
    }
}

/// One identity's watch stream: ready once subscribed; every change drops
/// the identity's cached reads and listings it covers, a resync all of
/// them; ended (so the next mount opens another) when the stream ends.
async fn watch_stream(
    state: Arc<Mutex<State>>,
    identity: String,
    generation: u64,
    mut client: Client,
    paths: BTreeSet<SecretPath>,
    prefixes: BTreeSet<SecretPath>,
) {
    use ferritor_core::proto::v1::watch_secrets_response::Event;
    let lock = || state.lock().unwrap_or_else(PoisonError::into_inner);
    let request = pb::WatchSecretsRequest {
        paths: paths.iter().map(|p| p.as_str().to_owned()).collect(),
        prefixes: prefixes.iter().map(|p| p.as_str().to_owned()).collect(),
    };
    let opened = client
        .watch_secrets(request)
        .await
        .map_err(ServerError::from);
    metrics::provider().call("watch", call_result(opened.as_ref().map(|_| ())));
    let ended = match opened {
        Ok(response) => {
            let mut stream = response.into_inner();
            loop {
                match stream.message().await {
                    Ok(Some(message)) => {
                        let mut state = lock();
                        let current = state
                            .watches
                            .get(&identity)
                            .is_some_and(|w| w.generation == generation);
                        if !current {
                            return;
                        }
                        match message.event {
                            Some(Event::Ready(_)) => {
                                metrics::provider().watch_event("ready");
                                tracing::info!(identity, "watching for changes");
                                if let Some(watch) = state.watches.get_mut(&identity) {
                                    watch.ready = true;
                                }
                            }
                            Some(Event::Changed(changed)) => {
                                metrics::provider().watch_event("changed");
                                if let Ok(path) = SecretPath::parse(&changed.path) {
                                    state.reads.remove(&(identity.clone(), path.clone()));
                                    state.listings.retain(|(who, prefix), _| {
                                        !(who == &identity
                                            && (path == *prefix || path.is_under(prefix)))
                                    });
                                }
                                if let Some(watch) = state.watches.get_mut(&identity) {
                                    watch.heard += 1;
                                }
                            }
                            Some(Event::Resync(_)) => {
                                metrics::provider().watch_event("resync");
                                state.reads.retain(|(who, _), _| who != &identity);
                                state.listings.retain(|(who, _), _| who != &identity);
                                if let Some(watch) = state.watches.get_mut(&identity) {
                                    watch.heard += 1;
                                }
                            }
                            None => {}
                        }
                    }
                    Ok(None) => {
                        metrics::provider().watch_event("ended");
                        break "the stream ended".to_owned();
                    }
                    Err(status) => {
                        metrics::provider().watch_event("failed");
                        break ServerError::from(status).to_string();
                    }
                }
            }
        }
        Err(e) => {
            metrics::provider().watch_event("failed");
            e.to_string()
        }
    };
    tracing::info!(
        identity,
        reason = ended,
        "no watch stream; caching for the shared window"
    );
    let mut state = lock();
    if let Some(watch) = state.watches.get_mut(&identity)
        && watch.generation == generation
    {
        watch.ended = true;
        watch.ready = false;
        watch.ended_at = Some(Instant::now());
    }
}
