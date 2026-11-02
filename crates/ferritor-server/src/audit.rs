//! The audit log: one JSON line per authorization decision, written where
//! the [`Authorizer`] is asked, so no operation can skip it. [`Gate`] is the
//! only way the services ask: it authorizes, then records.
//!
//! ```json
//! {"time":"2026-10-14T09:30:00.123Z","event":"authorization","caller":"apps/billing","action":"read","target":{"kind":"path","path":"billing/db"},"decision":"allowed"}
//! ```
//!
//! `caller` is the `ferritor://<name>` identity, or `null` for an
//! unauthenticated caller (dev mode). Targets: `path` and `below` (with a
//! `path`), `all`, `system`. Never values, shares or nonces: only who asked
//! for what, and the answer. `allowed` means the policy allowed it, not
//! that it then succeeded (it may still find the server sealed, or the
//! secret missing).
//!
//! **Fail closed.** An allowed request whose entry can't be written (and
//! flushed) in time is refused: an unrecorded read is worse than a failed
//! one. Only seal is exempt. It's the emergency stop and only reduces
//! exposure, so its entry is queued without waiting and a failure to record
//! it is logged, never allowed to delay or block it. A denied request stays
//! denied either way.
//!
//! The writing happens on a dedicated thread: a stalled stdout (a full pipe
//! nobody reads) then stalls only that thread, while requests time out as
//! unaudited instead of blocking runtime workers, and seal keeps working.
//! An entry that timed out may still be written later, so the log may show
//! an `allowed` that was then refused for want of auditing; never the
//! reverse. At shutdown, `main` waits (briefly) for the writer to reach
//! the end of the queue ([`Drain`]): a seal's entry may still be in it, and
//! "seal, then stop the service" is a likely incident sequence.
//!
//! **Failed authentication** is recorded too: a client certificate that
//! passed the handshake but names no caller now (no or a malformed
//! `ferritor://` identity, or expired on an open connection), turned away
//! before the authorizer is asked:
//!
//! ```json
//! {"time":"…","event":"authentication","peer":"10.0.0.7:51234","action":"read","outcome":"rejected","reason":"not_valid_now","detail":"the client certificate has expired or is not yet valid"}
//! ```
//!
//! The request is refused either way, so nothing waits for that entry.
//!
//! **Outcomes.** An `authorization` entry says a call was allowed, not what
//! it did. Every allowed call that changes state also gets an `outcome`
//! entry once it's done, with the same target: every admin call but
//! `status` (target `system`, operation the gRPC method), and every secret
//! write, from either API (`put`: the version stored, how many older ones
//! it trimmed under `max_versions`, the expected version of a
//! check-and-set; `delete`: how many versions it marked deleted). So a
//! deletion a write caused shows up too:
//!
//! ```json
//! {"time":"…","event":"outcome","caller":"ops/alice","action":"rekey","target":{"kind":"system"},"operation":"rekey_verify","result":"succeeded","details":{"phase":"complete","progress":3,"required":3,"generation":2}}
//! {"time":"…","event":"outcome","caller":"apps/billing","action":"write","target":{"kind":"path","path":"billing/db"},"operation":"put","result":"succeeded","details":{"version":12,"trimmed":1}}
//! ```
//!
//! `result` is `succeeded` (with `details`), `failed` or `unknown` (with
//! `error`). A failed call that still changed something says so in
//! `details`: a rekey cancel that found the rekey already committed adopts
//! it (`{"adopted_generation": 2}`), a key change an auditor must not
//! miss. `unknown` means it may or may not have taken effect: a write the
//! keys database didn't confirm in time, a secret write whose commit didn't
//! confirm, a rekey commit that couldn't be confirmed, or a rewrap pass cut
//! short partway. Details hold counts, versions, generations and phases;
//! never values, shares or nonces. Nothing can be
//! refused at that point, so outcome entries are queued without waiting,
//! and a failure to record one is logged.
//!
//! **Not recorded:** failed TLS handshakes (no certificate, an unknown CA,
//! wrong key usage, expired at connect time). rustls refuses those before
//! any request exists, so nothing reaches this log. Neither are requests
//! rejected for malformed input before the authorizer is asked (an invalid
//! secret path or page token): no decision was made.
//!
//! **Tamper evidence.** The writer links every line into a hash chain
//! (`ferritor_core::audit_chain`, which has the details): each ends with its
//! `seq` and the SHA-256 of the line before (`prev`), and each chain begins
//! with a `chain_start` entry: at every server start, after a chain end,
//! and after a failed write. With a signing key (`audit_signing_key`,
//! required in secured mode) it also writes signed `checkpoint` entries,
//! after every `CHECKPOINT_EVERY` (256) entries and at least every
//! [`CHECKPOINT_INTERVAL`] while entries arrive, and at shutdown a signed
//! `chain_end` (the [`Drain`]). Only a chain ending in one is proven whole:
//! `ferritor audit verify` calls the others open (the last in the file: a
//! running or crashed server), unterminated or unverifiable, and exits 2
//! for them, 1 for a broken one, 0 only if every entry is signed. So
//! appended lines, a cut, an edit, an insertion or a deletion never pass as
//! complete; a whole chain removed from a file holding several runs isn't
//! noticed, which shipping the log off the host as it's written covers.
//! Chaining happens in the writer thread, the one place lines are ordered,
//! so the chain is the order of the file. A write that fails ends its chain:
//! the next write ends any partial line with a newline and starts a new
//! chain, so one failure costs one unterminated chain, not the rest of the
//! run. Without a key (dev mode) the log is still chained, but unsigned, and
//! `chain_start` says so (`"key": null`).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Semaphore, mpsc, oneshot};

use ed25519_dalek::SigningKey;
use ferritor_core::audit_chain::{Chain, Seal};

use crate::authz::{Action, Authorizer, Caller, Denied, Stored, StoredPolicies, Target};
use crate::crl::CrlInfo;
use crate::metrics::metrics;
use crate::policy::PolicyInfo;
use crate::ratelimit::{self, Admission, Clock, Episodes, Limiter, Limits, Quota, SystemClock};
use crate::seal::{PolicyRefresh, Refreshed};
use crate::tls::IdentityError;
use ferritor_core::path::{Namespace, SecretPath};

/// Entries waiting for the writer, at most.
const QUEUE: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("encoding the audit entry failed")]
    Encode(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("writing the audit log failed")]
    Write(#[source] io::Error),
    #[error("the audit log did not take the entry in time")]
    Timeout,
    #[error("the audit log queue is full")]
    Full,
    #[error("the audit log writer has stopped")]
    Stopped,
}

/// Told a write's result; `None` where nobody waits for it.
type Written = Option<oneshot::Sender<io::Result<()>>>;

enum Pending {
    Entry {
        line: Vec<u8>,
        written: Written,
    },
    /// Sign what's written so far, if anything is unsigned (a tick), then
    /// flush.
    Checkpoint {
        written: Written,
    },
    /// End the chain (the [`Drain`], at shutdown): a signed `chain_end`,
    /// then flush. Anything written later starts a new chain.
    End {
        written: Written,
    },
}

/// A signed log checkpoints at least this often while entries arrive, so
/// the tail no signature covers yet stays short (see
/// `ferritor_core::audit_chain`); and after every `CHECKPOINT_EVERY` entries.
pub const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(10);

/// Writes JSON lines, in order, on its own thread, each linked into a hash
/// chain (`ferritor_core::audit_chain`): `seq` and `prev` end every line.
pub struct AuditLog {
    queue: mpsc::Sender<Pending>,
    timeout: Duration,
}

impl AuditLog {
    /// Starts the writer thread for `out`; it ends when the log is dropped.
    /// A recorded entry has been written and flushed within `timeout`.
    /// Nothing waits for queued entries at exit; [`AuditLog::stdout`], the
    /// server's log, comes with a [`Drain`] for that. Chained, but
    /// unsigned: no checkpoints.
    pub fn new(out: impl Write + Send + 'static, timeout: Duration) -> io::Result<Self> {
        Self::start(out, timeout, None, CHECKPOINT_INTERVAL).map(|(log, _)| log)
    }

    /// Like [`AuditLog::new`], with checkpoints signed by `key`, and a
    /// [`Drain`].
    pub fn signed(
        out: impl Write + Send + 'static,
        timeout: Duration,
        key: SigningKey,
    ) -> io::Result<(Self, Drain)> {
        Self::start(out, timeout, Some(key), CHECKPOINT_INTERVAL)
    }

    /// `every`: [`CHECKPOINT_INTERVAL`], except in tests.
    fn start(
        out: impl Write + Send + 'static,
        timeout: Duration,
        key: Option<SigningKey>,
        every: Duration,
    ) -> io::Result<(Self, Drain)> {
        let signed = key.is_some();
        let chain = Chain::new(key).map_err(io::Error::other)?;
        let (queue, entries) = mpsc::channel::<Pending>(QUEUE);
        std::thread::Builder::new()
            .name("ferritor-audit".to_owned())
            .spawn(move || write_chain(out, chain, entries))?;
        if signed {
            // Holds no sender, so it doesn't keep the writer alive: it ends
            // at the first tick after the log and its drains are gone.
            let ticks = queue.downgrade();
            std::thread::Builder::new()
                .name("ferritor-audit-checkpoints".to_owned())
                .spawn(move || {
                    loop {
                        std::thread::sleep(every);
                        let Some(queue) = ticks.upgrade() else { break };
                        // A full queue checkpoints soon anyway (CHECKPOINT_EVERY).
                        queue.try_send(Pending::Checkpoint { written: None }).ok();
                    }
                })?;
        }
        let drain = Drain(queue.clone());
        Ok((Self { queue, timeout }, drain))
    }

    /// Writes to a duplicate of the stdout file descriptor, not through
    /// [`io::stdout`]: that one treats a closed stdout as a sink and reports
    /// success, which would lose every entry silently. Duplicating fails
    /// (and so does startup) if there's no stdout; afterwards a write error
    /// (say, the reader of a pipe went away) is reported, so requests fail
    /// closed. The duplicate shares the open file, so `>>` still appends.
    /// Nothing else may write to stdout: the server logs to stderr.
    /// Checkpoints are signed with `key`, if given.
    pub fn stdout(timeout: Duration, key: Option<SigningKey>) -> io::Result<(Self, Drain)> {
        let fd = io::stdout().as_fd().try_clone_to_owned()?;
        Self::start(File::from(fd), timeout, key, CHECKPOINT_INTERVAL)
    }

    /// Returns once `line` is written and flushed.
    async fn written(&self, line: Vec<u8>) -> Result<(), AuditError> {
        let (written, result) = oneshot::channel();
        tokio::time::timeout(self.timeout, async {
            self.queue
                .send(Pending::Entry {
                    line,
                    written: Some(written),
                })
                .await
                .map_err(|_| AuditError::Stopped)?;
            result
                .await
                .map_err(|_| AuditError::Stopped)?
                .map_err(AuditError::Write)
        })
        .await
        .map_err(|_| AuditError::Timeout)?
    }

    /// Queues `line` without waiting for anything.
    fn queued(&self, line: Vec<u8>) -> Result<(), AuditError> {
        self.queue
            .try_send(Pending::Entry {
                line,
                written: None,
            })
            .map_err(|e| match e {
                TrySendError::Full(_) => AuditError::Full,
                TrySendError::Closed(_) => AuditError::Stopped,
            })
    }
}

/// What a SIGHUP made of the policy, for [`Gate::reload_policy`].
pub enum PolicyReload {
    /// Swap this in.
    Reloaded(Arc<dyn Authorizer>, PolicyInfo),
    /// Nothing to reload (dev mode); the current one stays.
    Skipped(&'static str),
    /// The current one stays; this is why.
    Failed(String),
}

/// What an admin call did, for [`Gate::outcome`].
#[derive(Debug)]
pub enum Outcome {
    /// Done; the details (a JSON object) say what it did.
    Succeeded(serde_json::Value),
    /// It didn't do what was asked (see the error). `details` for what
    /// happened instead, if anything did (a cancel that found the rekey
    /// committed adopts the new generation).
    Failed {
        error: String,
        details: Option<serde_json::Value>,
    },
    /// It may or may not have taken effect.
    Unknown(String),
}

/// A flush barrier for shutdown: [`Drain::wait`] queues the chain's end and
/// returns once the writer has reached it, so everything queued before it
/// (a last seal's entry, say) is written and flushed, and in a signed log
/// covered by a signed `chain_end`: a clean exit leaves the chain complete.
/// Anything written after it starts a new chain. A call still running when
/// the drain limit ran out may write such entries; that chain never gets an
/// end, so once the next run starts it verifies as unterminated (exit 2):
/// expected after a shutdown that cut calls off, not a sign of tampering. It doesn't wait for
/// the gates to be dropped: a connection abandoned at the drain deadline
/// may still hold one, with nothing left to write.
#[must_use = "wait for it before exiting, or queued entries are lost"]
#[derive(Clone)]
pub struct Drain(mpsc::Sender<Pending>);

impl Drain {
    /// `false` if the queue isn't written within `limit` (stdout stalled,
    /// or failing).
    pub async fn wait(self, limit: Duration) -> bool {
        let (written, result) = oneshot::channel();
        let marker = Pending::End {
            written: Some(written),
        };
        tokio::time::timeout(limit, async {
            self.0.send(marker).await.is_ok() && matches!(result.await, Ok(Ok(())))
        })
        .await
        .unwrap_or(false)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Refused {
    #[error("permission denied")]
    Denied(#[source] Denied),
    /// Undecided: only a stored policy could allow it, and none is in force
    /// while sealed.
    #[error("{}", ferritor_core::messages::SEALED)]
    Sealed,
    /// Undecided: only a stored policy could allow it, and the stored set
    /// didn't verify.
    #[error("{}", ferritor_core::messages::POLICY_UNVERIFIED)]
    PolicyUnverified,
    /// Allowed, but not recorded: refused anyway (fail closed).
    #[error("{}", ferritor_core::messages::UNAUDITED)]
    Unaudited(#[source] AuditError),
    /// Over one of the caller's limits (see `ratelimit`): refused before
    /// any decision, so nothing about the policy is revealed or recorded.
    #[error("rate limited ({}): too many requests from this caller; retry later", .0.limit.name())]
    Limited(ratelimit::Refused),
    /// No call slot under the server-wide cap came free in time, or the
    /// client left while waiting for one: nothing was done.
    #[error("the server is busy: no call slot came free in time; retry later")]
    Overloaded,
}

/// The [`Authorizer`] and the [`AuditLog`] together, so that asking one
/// always records in the other. The authorizer can be replaced while
/// serving ([`Gate::reload_policy`]): each check uses whichever is current when
/// it asks, and a call already authorized finishes under the old one.
pub struct Gate {
    authz: RwLock<Arc<dyn Authorizer>>,
    /// The stored policies (`policies`), asked about a secret request the
    /// config rules didn't allow. Unset: none (as before stored policies).
    stored: OnceLock<Arc<dyn StoredPolicies>>,
    /// The stored-policy failure last reported, by its condition
    /// (`Unverified::report_key`) and whether a verified set stayed in
    /// force, so a failure that persists is logged and audited once, not on
    /// every poll, however its details vary.
    stored_failure: Mutex<Option<(String, bool)>>,
    log: AuditLog,
    /// The rate limits in force (see `ratelimit`); unset, nothing is
    /// limited.
    limits: RwLock<Option<Arc<Limits>>>,
    limiter: Limiter<SecretPath, Arc<dyn Clock>>,
    /// Certificates that name no caller, by fingerprint.
    unauthenticated: Limiter<String, Arc<dyn Clock>>,
    /// Token exchanges, by the identity they map to.
    exchanges: Limiter<String, Arc<dyn Clock>>,
    /// The server-wide cap on calls in flight, and how long a call waits
    /// for a slot under it. Set once: it takes effect at startup.
    server_cap: OnceLock<(Arc<Semaphore>, Duration)>,
    /// Refusal episodes, by identity (or fingerprint, for
    /// `Limit::Unauthenticated`).
    episodes: Episodes<String>,
}

/// What the config rules and the stored policies together decided.
enum Decision {
    Allowed,
    Denied(Denied),
    /// Undecided (secret actions only): see [`Refused::Sealed`].
    Sealed,
    /// Undecided (secret actions only): see [`Refused::PolicyUnverified`].
    Unverified,
}

impl Decision {
    /// As the audit log and metrics spell it.
    fn name(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied(_) => "denied",
            Self::Sealed => "sealed",
            Self::Unverified => "unverified",
        }
    }
}

impl Gate {
    pub fn new(authz: Arc<dyn Authorizer>, log: AuditLog) -> Self {
        Self::with_clock(authz, log, Arc::new(SystemClock))
    }

    /// [`Gate::new`], its rate limits on `clock`: the real time, or a test's,
    /// which a limit's outcome mustn't depend on the machine's speed.
    pub fn with_clock(authz: Arc<dyn Authorizer>, log: AuditLog, clock: Arc<dyn Clock>) -> Self {
        Self {
            authz: RwLock::new(authz),
            stored: OnceLock::new(),
            stored_failure: Mutex::new(None),
            log,
            limits: RwLock::new(None),
            limiter: Limiter::new(Arc::clone(&clock)),
            unauthenticated: Limiter::new(Arc::clone(&clock)),
            exchanges: Limiter::new(clock),
            server_cap: OnceLock::new(),
            episodes: Episodes::default(),
        }
    }

    /// Starts limiting requests (see `ratelimit`): `limits`, with calls
    /// waiting up to `wait` for a slot under the server-wide cap. Once:
    /// later, [`Gate::reload_limits`].
    pub fn use_limits(&self, limits: Limits, wait: Duration) {
        let permits = usize::try_from(limits.server_max_in_flight.get()).unwrap_or(usize::MAX);
        if self
            .server_cap
            .set((Arc::new(Semaphore::new(permits)), wait))
            .is_err()
        {
            tracing::warn!("rate limits were already in use; keeping the server-wide cap");
        }
        *self.limits.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(limits));
    }

    /// The most watch streams `caller` may have open, under the limits in
    /// force (`None`: no limit, as before any are in use, and for no
    /// caller, which only dev mode's loopback has).
    pub fn max_watch_streams(&self, caller: &Caller) -> Option<std::num::NonZeroU32> {
        let Caller::Identity(identity) = caller else {
            return None;
        };
        self.limits
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()?
            .quota(identity)
            .max_watch_streams
    }

    /// Replaces the limits in force (a SIGHUP). The server-wide cap stays as
    /// it started: a change to it takes effect at the next restart.
    pub fn reload_limits(&self, limits: Limits) {
        let mut current = self.limits.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(running) = current.as_ref()
            && running.server_max_in_flight != limits.server_max_in_flight
        {
            tracing::warn!(
                running = running.server_max_in_flight.get(),
                configured = limits.server_max_in_flight.get(),
                "rate_limit.server_max_in_flight takes effect at the next restart"
            );
        }
        *current = Some(Arc::new(limits));
    }

    fn limits(&self) -> Option<Arc<Limits>> {
        self.limits
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// A request's admission (see `ratelimit`, and the "Rate limits"
    /// sections of `docs/src/content/docs/operations/running.md` and AGENTS.md), at its first
    /// check: an admin action the config rules allow passes freely
    /// (operators always get through, `seal` above all); anything else
    /// takes its identity's limits (denial budget, calls in flight, rate),
    /// then a slot under the server-wide cap, waiting for one if needed,
    /// but only as long as the client does. Nothing here is audited per
    /// request: refusals are reported as episodes.
    async fn admit(
        &self,
        request: &ratelimit::Request,
        caller: &Caller,
        action: Action,
        target: Target<'_>,
    ) -> Result<Admission, Refused> {
        let Some(limits) = self.limits() else {
            return Ok(Admission::default());
        };
        if action.secret().is_none() && self.permits(caller, action, target) {
            return Ok(Admission::default());
        }
        let slot = match caller {
            Caller::Identity(identity) => Some(
                self.limiter
                    .admit(identity, &limits.quota(identity), Some(ratelimit::DENIALS))
                    .map_err(|refused| self.limited(identity.as_str(), refused))?,
            ),
            Caller::Unauthenticated => None,
        };
        let permit = match self.server_cap.get() {
            None => None,
            Some((cap, wait)) => {
                let started = Instant::now();
                let acquire = tokio::time::timeout(*wait, Arc::clone(cap).acquire_owned());
                let acquired = tokio::select! {
                    acquired = acquire => acquired.ok().and_then(Result::ok),
                    // Nothing has started: a client that left takes its
                    // call with it (and wasn't refused: not counted).
                    () = request.cancelled().cancelled() => return Err(Refused::Overloaded),
                };
                metrics().rate_limit_waited(started.elapsed());
                let Some(permit) = acquired else {
                    metrics().rate_limited("server");
                    return Err(Refused::Overloaded);
                };
                Some(permit)
            }
        };
        Ok(Admission { slot, permit })
    }

    /// A refusal by `who`'s limits: reported when it starts an episode.
    fn limited(&self, who: &str, refused: ratelimit::Refused) -> Refused {
        metrics().rate_limited(refused.limit.name());
        if self
            .episodes
            .refused(&who.to_owned(), refused.limit, Instant::now())
        {
            tracing::warn!(caller = who, limit = refused.limit.name(), "rate limited");
            self.queue_lifecycle(Event::RateLimited {
                caller: Some(who),
                certificate: None,
                peer: None,
                limit: refused.limit.name(),
                state: "started",
                refused: None,
            });
        }
        Refused::Limited(refused)
    }

    /// Ends the refusal episodes quiet since [`ratelimit::QUIET`] at `now`
    /// (reported with their counts), and forgets idle callers. On a timer,
    /// from `main`.
    pub fn end_quiet_limits(&self, now: Instant) {
        for ended in self.episodes.end_quiet(now) {
            let (caller, certificate, peer) = match ended.limit {
                ratelimit::Limit::Unauthenticated => (None, Some(ended.key.as_str()), None),
                ratelimit::Limit::ExchangeRefused => (None, None, Some(ended.key.as_str())),
                _ => (Some(ended.key.as_str()), None, None),
            };
            tracing::info!(
                caller,
                certificate,
                peer,
                limit = ended.limit.name(),
                refused = ended.refused,
                "no longer rate limited"
            );
            self.queue_lifecycle(Event::RateLimited {
                caller,
                certificate,
                peer,
                limit: ended.limit.name(),
                state: "ended",
                refused: Some(ended.refused),
            });
        }
        self.limiter.evict_idle();
        self.unauthenticated.evict_idle();
        self.exchanges.evict_idle();
    }

    /// Lets the stored policies decide what the config rules don't (once:
    /// later calls are ignored).
    pub fn use_stored_policies(&self, stored: Arc<dyn StoredPolicies>) {
        if self.stored.set(stored).is_err() {
            tracing::warn!("stored policies were already set; keeping the first");
        }
    }

    /// The current authorizer. The lock is held only to clone the `Arc`.
    fn authz(&self) -> Arc<dyn Authorizer> {
        Arc::clone(&self.authz.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// The config rules in force (secured mode), for listing and checking.
    pub fn config_policy(&self) -> Arc<dyn Authorizer> {
        self.authz()
    }

    /// The config rules first; for a secret action they don't allow, the
    /// stored policies. Admin actions are the config rules' alone: a stored
    /// policy never grants one, so a refusal there is a plain denial, sealed
    /// or not. Only a secret request the stored policies would decide, while
    /// they aren't in force, is undecided.
    fn decide(&self, caller: &Caller, action: Action, target: Target<'_>) -> Decision {
        let denied = match self.authz().authorize(caller, action, target) {
            Ok(()) => return Decision::Allowed,
            Err(denied) => denied,
        };
        let (Some(stored), Some(secret), Caller::Identity(identity)) =
            (self.stored.get(), action.secret(), caller)
        else {
            return Decision::Denied(denied);
        };
        match stored.decide(identity, secret, target) {
            Stored::Allowed => Decision::Allowed,
            Stored::Denied => Decision::Denied(denied),
            Stored::Sealed => Decision::Sealed,
            Stored::Unverified => Decision::Unverified,
        }
    }

    /// Records the policy the server starts with (`None`: dev mode, allow
    /// everything), so the first decisions are covered too.
    pub fn policy_loaded(&self, policy: Option<&PolicyInfo>) {
        self.queue_lifecycle(Event::PolicyLoaded {
            mode: if policy.is_some() { "secured" } else { "dev" },
            rules: policy.map(|p| p.rules),
            fingerprint: policy.map(|p| p.fingerprint.clone()),
        });
    }

    /// Applies what a SIGHUP made of the policy: swaps in a reloaded one,
    /// or keeps the current one (skipped, or failed); records it either way
    /// (`"event": "policy_reload"`). Queued without waiting: there's no
    /// caller to refuse.
    pub fn reload_policy(&self, reload: PolicyReload) {
        let result = match &reload {
            PolicyReload::Reloaded(..) => "succeeded",
            PolicyReload::Skipped(_) => "skipped",
            PolicyReload::Failed(_) => "failed",
        };
        metrics().reload("policy", result);
        let event = match reload {
            PolicyReload::Reloaded(authz, info) => {
                *self.authz.write().unwrap_or_else(PoisonError::into_inner) = authz;
                Event::PolicyReload {
                    result: "succeeded",
                    source: "config",
                    trigger: None,
                    revision: None,
                    rules: Some(info.rules),
                    fingerprint: Some(info.fingerprint),
                    reason: None,
                }
            }
            PolicyReload::Skipped(reason) => Event::PolicyReload {
                result: "skipped",
                source: "config",
                trigger: None,
                revision: None,
                rules: None,
                fingerprint: None,
                reason: Some(reason.to_owned()),
            },
            PolicyReload::Failed(error) => Event::PolicyReload {
                result: "failed",
                source: "config",
                trigger: None,
                revision: None,
                rules: None,
                fingerprint: None,
                reason: Some(error),
            },
        };
        self.queue_lifecycle(event);
    }

    /// Records what a load of the stored policies did (`policies`), on a
    /// change of state only: a different set in force; a failure (an error:
    /// someone changed the keys database, or put an older set back), once,
    /// and again only if the reason changes; the recovery that ends one.
    /// Every attempt is counted (`ferritor.reloads`, kind `policy_store`), so a
    /// condition that persists stays visible without repeating it.
    pub fn stored_policies_reloaded(&self, trigger: &'static str, refresh: &PolicyRefresh) {
        let mut reported = self
            .stored_failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (result, revision, rules, fingerprint, reason) = match refresh {
            PolicyRefresh::Skipped(_) => return,
            PolicyRefresh::Unchanged | PolicyRefresh::Loaded { changed: false, .. }
                if reported.is_none() =>
            {
                metrics().reload("policy_store", "unchanged");
                return;
            }
            PolicyRefresh::Unchanged => {
                // Still the set from before the failure: nothing new loaded.
                metrics().reload("policy_store", "unchanged");
                return;
            }
            PolicyRefresh::Loaded {
                revision,
                policies,
                fingerprint,
                ..
            } => {
                let result = if reported.take().is_some() {
                    tracing::warn!(
                        trigger,
                        revision,
                        policies,
                        "the stored policies verify again"
                    );
                    "recovered"
                } else {
                    tracing::info!(trigger, revision, policies, "stored policies loaded");
                    "changed"
                };
                (
                    result,
                    Some(*revision),
                    Some(*policies),
                    Some(fingerprint.clone()),
                    None,
                )
            }
            PolicyRefresh::Failed { reason, kept } => {
                let result = reason.kind();
                metrics().reload("policy_store", result);
                let what = if *kept {
                    "keeping the last verified set in force"
                } else {
                    "no stored policy is in force: requests only they would allow are refused \
                     (POLICY_UNVERIFIED)"
                };
                let text = format!("{reason}; {what}");
                let key = (reason.report_key(), *kept);
                if reported.as_ref() == Some(&key) {
                    // Already reported: counted above, not repeated. The
                    // detail may differ (another database error).
                    tracing::debug!(trigger, %reason, "the stored policies still don't load");
                    return;
                }
                if result == "failed" {
                    tracing::warn!(trigger, %reason, "couldn't load the stored policies; {what}");
                } else {
                    tracing::error!(
                        trigger,
                        %reason,
                        "STORED POLICIES DON'T VERIFY: {what}. Re-apply them from their source of \
                         truth (`ferritor policy apply --prune`), then find out who changed the keys \
                         database"
                    );
                }
                *reported = Some(key);
                drop(reported);
                self.queue_lifecycle(Event::PolicyReload {
                    result,
                    source: "database",
                    trigger: Some(trigger),
                    revision: None,
                    rules: None,
                    fingerprint: None,
                    reason: Some(text),
                });
                return;
            }
        };
        drop(reported);
        metrics().reload("policy_store", result);
        self.queue_lifecycle(Event::PolicyReload {
            result,
            source: "database",
            trigger: Some(trigger),
            revision,
            rules,
            fingerprint,
            reason,
        });
    }

    /// Records that a seal took the stored policies out of force (they
    /// come back, verified, with the next unseal). Queued without waiting.
    pub fn stored_policies_dropped(&self) {
        self.queue_lifecycle(Event::PolicyReload {
            result: "succeeded",
            source: "seal",
            trigger: None,
            revision: None,
            rules: Some(0),
            fingerprint: None,
            reason: None,
        });
    }

    /// Records the server certificate presented at startup (its SHA-256).
    pub fn certificate_loaded(&self, fingerprint: &str) {
        self.queue_lifecycle(Event::CertificateLoaded {
            fingerprint: fingerprint.to_owned(),
        });
    }

    /// Records a server certificate reload: the new fingerprint, or why the
    /// current one stays.
    pub fn certificate_reloaded(&self, reloaded: Result<String, String>) {
        let (result, fingerprint, reason) = match reloaded {
            Ok(fingerprint) => ("succeeded", Some(fingerprint), None),
            Err(error) => ("failed", None, Some(error)),
        };
        metrics().reload("certificate", result);
        self.queue_lifecycle(Event::CertificateReload {
            result,
            fingerprint,
            reason,
        });
    }

    /// Records an `[identity]` reload: the issuers and cutoffs now in force
    /// (`None`: the section is gone, nothing issued is admitted), why it
    /// was skipped (`Ok(Err)`), or why the current ones stay (`Err`).
    pub fn identity_reloaded(
        &self,
        reloaded: Result<Result<Option<&crate::identity::Identity>, &str>, String>,
    ) {
        let (result, in_force, reason) = match reloaded {
            Ok(Ok(identity)) => ("succeeded", Some(identity), None),
            Ok(Err(skipped)) => ("skipped", None, Some(skipped.to_owned())),
            Err(error) => ("failed", None, Some(error)),
        };
        metrics().reload("identity", result);
        let issuers = in_force.map(|identity| {
            identity.map_or_else(Vec::new, |identity| {
                identity
                    .issuers
                    .iter()
                    .map(|issuer| IssuerInForce {
                        name: issuer.name.clone(),
                        not_before: issuer.not_before,
                    })
                    .collect()
            })
        });
        let revoked = in_force.map(|identity| {
            identity.map_or_else(Vec::new, |identity| {
                identity
                    .revoked
                    .iter()
                    .map(|(identity, not_before)| RevokedInForce {
                        identity: identity.to_string(),
                        not_before: *not_before,
                    })
                    .collect()
            })
        });
        self.queue_lifecycle(Event::IdentityReload {
            result,
            issuers,
            revoked,
            reason,
        });
    }

    /// Records the CRLs in force at startup (secured mode): one entry each,
    /// or null without a CRL file, when nothing is revoked.
    pub fn revocation_loaded(&self, crls: Option<Vec<CrlInfo>>) {
        self.queue_lifecycle(Event::RevocationLoaded { crls });
    }

    /// Records a CRL reload: the CRLs now in force (null: none), or why
    /// the current ones stay.
    pub fn revocation_reloaded(&self, reloaded: Result<Option<Vec<CrlInfo>>, String>) {
        let (result, crls, reason) = match reloaded {
            Ok(crls) => ("succeeded", Some(crls), None),
            Err(error) => ("failed", None, Some(error)),
        };
        metrics().reload("crl", result);
        self.queue_lifecycle(Event::RevocationReload {
            result,
            crls,
            reason,
        });
    }

    /// Records KEK versions rows use that the keyring lacks, found after
    /// an unseal (see `keyring::check_against_data`).
    pub fn kek_check(&self, found: &crate::keyring::Unloaded) {
        let names = |list: &[Namespace]| list.iter().map(ToString::to_string).collect();
        self.queue_lifecycle(Event::KekCheck {
            lost_namespaces: names(&found.lost_namespaces),
            deleted_namespaces: names(&found.deleted_namespaces),
            missing: kek_refs(&found.missing),
            destroyed: kek_refs(&found.destroyed),
        });
    }

    /// Records a keyring refresh that changed something or failed (see
    /// `keyring`): what triggered it, and each namespace's active KEK
    /// version now and any vanished KEKs, or why it couldn't. Namespaces
    /// are named: the audit log is for operators.
    pub fn keyring_refreshed(&self, trigger: &'static str, refreshed: Result<&Refreshed, String>) {
        self.queue_lifecycle(match refreshed {
            Ok(r) => Event::KeyringRefresh {
                trigger,
                result: "succeeded",
                active: Some(
                    r.active
                        .iter()
                        .map(|(ns, version)| (ns.to_string(), *version))
                        .collect(),
                ),
                vanished: kek_refs(&r.vanished),
                reason: None,
            },
            Err(reason) => Event::KeyringRefresh {
                trigger,
                result: "failed",
                active: None,
                vanished: Vec::new(),
                reason: Some(reason),
            },
        });
    }

    /// An auto-unseal attempt (`result` from the metric's fixed set), queued
    /// like every lifecycle entry. Never the wrap's ciphertext.
    pub fn auto_unsealed(
        &self,
        result: &'static str,
        provider: &'static str,
        key_id: Option<String>,
        reason: Option<String>,
    ) {
        self.queue_lifecycle(Event::AutoUnseal {
            result,
            provider,
            key_id,
            reason,
        });
    }

    /// Audit entries waiting for the writer (for metrics): it climbs while
    /// stdout stalls, before anything is refused for want of auditing.
    pub fn audit_queue_depth(&self) -> u64 {
        u64::try_from(QUEUE.saturating_sub(self.log.queue.capacity())).unwrap_or(u64::MAX)
    }

    /// Server lifecycle entries (not requests): queued, a failure logged.
    fn queue_lifecycle(&self, event: Event<'_>) {
        if let Err(e) = line(event).and_then(|line| self.log.queued(line)) {
            let error = crate::error_chain(&e);
            tracing::error!(%error, "AUDIT LOG FAILED: a lifecycle entry went unrecorded");
            metrics().audit_failure("lost");
        }
    }

    /// Authorizes and records the decision; see the module docs for what
    /// happens when it can't be recorded.
    pub async fn check(
        &self,
        caller: &Caller,
        action: Action,
        target: Target<'_>,
    ) -> Result<(), Refused> {
        // A request's first check admits it (see `ratelimit`); the
        // admission lives as long as the request.
        if let Some(request) = ratelimit::current()
            && request.claim()
        {
            let admission = self.admit(&request, caller, action, target).await?;
            request.hold(admission);
        }
        let decision = self.decide(caller, action, target);
        metrics().decision(action.name(), decision.name());
        // A denial charges the caller's denial budget, after it's recorded
        // (below); undecided requests (sealed, unverified) charge nothing.
        let charge = matches!(decision, Decision::Denied(_)) && self.limits().is_some();
        let recorded = match line(Event::Authorization {
            caller: caller_name(caller),
            action,
            target: target.into(),
            decision: decision.name(),
        }) {
            Err(e) => Err(e),
            // The emergency stop never waits for the log.
            Ok(line) if action == Action::Seal => self.log.queued(line),
            Ok(line) => self.log.written(line).await,
        };
        match (decision, recorded) {
            (Decision::Allowed, Ok(())) => Ok(()),
            (Decision::Allowed, Err(e)) if action == Action::Seal => {
                let error = crate::error_chain(&e);
                tracing::error!(%error, %caller, "AUDIT LOG FAILED: sealing without a record");
                metrics().audit_failure("lost");
                Ok(())
            }
            (Decision::Allowed, Err(e)) => {
                let error = crate::error_chain(&e);
                tracing::error!(%error, %caller, %action, %target, "AUDIT LOG FAILED: request refused");
                metrics().audit_failure("refused");
                Err(Refused::Unaudited(e))
            }
            (refused, recorded) => {
                if let Err(e) = recorded {
                    let error = crate::error_chain(&e);
                    tracing::error!(%error, %caller, %action, %target, "AUDIT LOG FAILED: a refusal went unrecorded");
                    metrics().audit_failure("lost");
                }
                if charge && let Caller::Identity(identity) = caller {
                    self.limiter.charge_denial(identity, ratelimit::DENIALS);
                }
                Err(match refused {
                    Decision::Denied(denied) => Refused::Denied(denied),
                    Decision::Sealed => Refused::Sealed,
                    _ => Refused::PolicyUnverified,
                })
            }
        }
    }

    /// Records a request turned away before it reached the authorizer: its
    /// certificate passed the handshake but names no caller now (see
    /// [`crate::tls::identity`]). It's refused anyway, so nothing waits for
    /// the entry, and failing to record it is only logged.
    /// Limited by `certificate` (its fingerprint) to
    /// [`ratelimit::UNAUTHENTICATED`]: past that, not recorded (reported as
    /// an episode), so a certificate naming no caller can't flood the log.
    /// Records a certificate issued in a token exchange, and waits for it
    /// to be written: fail closed, like an allowed request, so the caller
    /// must not hand the certificate out if this fails.
    pub async fn exchanged(&self, issued: &Exchanged<'_>) -> Result<(), AuditError> {
        let recorded = line(Event::Exchange {
            peer: issued.peer.map(|peer| peer.to_string()),
            outcome: "issued",
            issuer: Some(issued.issuer),
            identity: Some(issued.identity),
            claims: Some(issued.claims),
            serial: Some(issued.serial),
            not_after: Some(issued.not_after.to_string()),
            reason: None,
        });
        match recorded {
            Ok(line) => self.log.written(line).await,
            Err(e) => Err(e),
        }
        .inspect_err(|e| {
            let error = crate::error_chain(e);
            tracing::error!(%error, "AUDIT LOG FAILED: token exchange refused");
            metrics().audit_failure("refused");
        })
    }

    /// Whether a token exchange for `identity` may go ahead now, under
    /// `rate` (its issuer's, [`ratelimit::exchanges`]; while rate limits
    /// are on). A refusal is
    /// counted, and audited as an episode, keyed by the identity, never
    /// per request.
    pub fn exchange_admitted(
        &self,
        identity: &str,
        rate: ratelimit::Rate,
    ) -> Result<(), ratelimit::Refused> {
        if self.limits().is_none() {
            return Ok(());
        }
        let quota = Quota {
            rate: Some(rate),
            max_in_flight: None,
            max_watch_streams: None,
        };
        let key = identity.to_owned();
        match self.exchanges.admit(&key, &quota, None) {
            Ok(_) => Ok(()),
            Err(refused) => {
                let limit = ratelimit::Limit::Exchanges;
                metrics().rate_limited(limit.name());
                if self.episodes.refused(&key, limit, Instant::now()) {
                    tracing::warn!(identity, "rate limited: token exchanges");
                    self.queue_lifecycle(Event::RateLimited {
                        caller: Some(identity),
                        certificate: None,
                        peer: None,
                        limit: limit.name(),
                        state: "started",
                        refused: None,
                    });
                }
                Err(ratelimit::Refused {
                    limit,
                    retry_after: refused.retry_after,
                })
            }
        }
    }

    /// Records a refused token exchange (queued, not waited for: nothing
    /// was issued). A peer address refused too often goes unrecorded past
    /// [`ratelimit::UNAUTHENTICATED`]'s rate, reported as an episode, as
    /// unauthenticated certificates are, so a flood can't fill the log.
    pub fn exchange_refused(&self, peer: Option<SocketAddr>, issuer: Option<&str>, reason: &str) {
        if let (Some(peer), Some(_)) = (peer, self.limits()) {
            let quota = Quota {
                rate: Some(ratelimit::UNAUTHENTICATED),
                max_in_flight: None,
                max_watch_streams: None,
            };
            let key = peer.ip().to_string();
            if self.unauthenticated.admit(&key, &quota, None).is_err() {
                metrics().rate_limited(ratelimit::Limit::ExchangeRefused.name());
                if self
                    .episodes
                    .refused(&key, ratelimit::Limit::ExchangeRefused, Instant::now())
                {
                    tracing::warn!(peer = key, "rate limited: refused token exchanges");
                    self.queue_lifecycle(Event::RateLimited {
                        caller: None,
                        certificate: None,
                        peer: Some(&key),
                        limit: ratelimit::Limit::ExchangeRefused.name(),
                        state: "started",
                        refused: None,
                    });
                }
                return;
            }
        }
        self.queue_lifecycle(Event::Exchange {
            peer: peer.map(|peer| peer.to_string()),
            outcome: "refused",
            issuer,
            identity: None,
            claims: None,
            serial: None,
            not_after: None,
            reason: Some(reason.to_owned()),
        });
    }

    pub fn rejected(
        &self,
        action: Action,
        peer: Option<SocketAddr>,
        certificate: Option<&str>,
        error: &IdentityError,
    ) {
        if let (Some(certificate), Some(_)) = (certificate, self.limits()) {
            let quota = Quota {
                rate: Some(ratelimit::UNAUTHENTICATED),
                max_in_flight: None,
                max_watch_streams: None,
            };
            let key = certificate.to_owned();
            if self.unauthenticated.admit(&key, &quota, None).is_err() {
                metrics().rate_limited(ratelimit::Limit::Unauthenticated.name());
                if self
                    .episodes
                    .refused(&key, ratelimit::Limit::Unauthenticated, Instant::now())
                {
                    tracing::warn!(certificate, "rate limited: a certificate naming no caller");
                    self.queue_lifecycle(Event::RateLimited {
                        caller: None,
                        certificate: Some(certificate),
                        peer: None,
                        limit: ratelimit::Limit::Unauthenticated.name(),
                        state: "started",
                        refused: None,
                    });
                }
                return;
            }
        }
        let recorded = line(Event::Authentication {
            peer: peer.map(|peer| peer.to_string()),
            action,
            outcome: "rejected",
            reason: error.reason(),
            detail: crate::error_chain(error),
        })
        .and_then(|line| self.log.queued(line));
        if let Err(e) = recorded {
            let error = crate::error_chain(&e);
            tracing::error!(%error, %action, "AUDIT LOG FAILED: a rejected authentication went unrecorded");
            metrics().audit_failure("lost");
        }
    }

    /// Records what an admin call did, once it's done (see the module
    /// docs). Queued, not waited for: it already happened.
    pub fn outcome(
        &self,
        caller: &Caller,
        action: Action,
        target: Target<'_>,
        operation: &'static str,
        outcome: Outcome,
    ) {
        let (result, details, error) = match outcome {
            Outcome::Succeeded(details) => ("succeeded", Some(details), None),
            Outcome::Failed { error, details } => ("failed", details, Some(error)),
            Outcome::Unknown(error) => ("unknown", None, Some(error)),
        };
        if let Target::System = target {
            metrics().admin_outcome(operation, result);
        }
        let recorded = line(Event::Outcome {
            caller: caller_name(caller),
            action,
            target: target.into(),
            operation,
            result,
            details,
            error,
        })
        .and_then(|line| self.log.queued(line));
        if let Err(e) = recorded {
            let error = crate::error_chain(&e);
            tracing::error!(%error, %caller, operation, result, "AUDIT LOG FAILED: an outcome went unrecorded");
            metrics().audit_failure("lost");
        }
    }

    /// Asks without recording: only to shape a response (whether a status
    /// shows the rekey nonce), never to decide whether to do something. A
    /// decision to act goes through [`Gate::check`].
    pub fn permits(&self, caller: &Caller, action: Action, target: Target<'_>) -> bool {
        matches!(self.decide(caller, action, target), Decision::Allowed)
    }
}

/// A certificate issued in a token exchange, for [`Gate::exchanged`].
pub struct Exchanged<'a> {
    pub peer: Option<SocketAddr>,
    pub issuer: &'a str,
    pub identity: &'a str,
    /// The claims the mapping read (what made the identity; never secret).
    pub claims: &'a BTreeMap<String, String>,
    pub serial: &'a str,
    pub not_after: time::OffsetDateTime,
}

#[derive(Serialize)]
struct Line<'a> {
    time: String,
    #[serde(flatten)]
    event: Event<'a>,
}

/// A token issuer in force after an `[identity]` reload.
#[derive(Serialize)]
struct IssuerInForce {
    name: String,
    /// Its cutoff (unix seconds): its certificates issued before are refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<i64>,
}

/// One identity's cutoff in force after an `[identity]` reload.
#[derive(Serialize)]
struct RevokedInForce {
    identity: String,
    not_before: i64,
}

/// A KEK by namespace and version, as the audit log writes it.
#[derive(Serialize)]
pub struct KekRef {
    namespace: String,
    version: u32,
}

pub fn kek_refs(keks: &[(Namespace, u32)]) -> Vec<KekRef> {
    keks.iter()
        .map(|(ns, version)| KekRef {
            namespace: ns.to_string(),
            version: *version,
        })
        .collect()
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Event<'a> {
    Authorization {
        /// `None`: unauthenticated (dev mode).
        caller: Option<&'a str>,
        action: Action,
        target: TargetEntry<'a>,
        decision: &'static str,
    },
    Authentication {
        peer: Option<String>,
        action: Action,
        outcome: &'static str,
        reason: &'static str,
        detail: String,
    },
    /// A refusal episode by a limit (see `ratelimit`) started or ended:
    /// requests it refuses aren't recorded one by one.
    RateLimited {
        #[serde(skip_serializing_if = "Option::is_none")]
        caller: Option<&'a str>,
        /// A certificate naming no caller, by fingerprint.
        #[serde(skip_serializing_if = "Option::is_none")]
        certificate: Option<&'a str>,
        /// A peer address whose token exchanges were refused.
        #[serde(skip_serializing_if = "Option::is_none")]
        peer: Option<&'a str>,
        limit: &'static str,
        state: &'static str,
        /// How many it refused (when it ends).
        #[serde(skip_serializing_if = "Option::is_none")]
        refused: Option<u64>,
    },
    PolicyLoaded {
        mode: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        rules: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fingerprint: Option<String>,
    },
    PolicyReload {
        result: &'static str,
        /// `config` (the `[[policy]]` rules), `database` (the stored
        /// policies) or `seal` (a seal dropped the stored ones).
        source: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        trigger: Option<&'static str>,
        /// The stored set's revision.
        #[serde(skip_serializing_if = "Option::is_none")]
        revision: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rules: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fingerprint: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    CertificateLoaded {
        fingerprint: String,
    },
    /// A workload's token exchange: a certificate issued, or refused.
    /// Never the token.
    Exchange {
        #[serde(skip_serializing_if = "Option::is_none")]
        peer: Option<String>,
        outcome: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        issuer: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        identity: Option<&'a str>,
        /// The claims that made the identity (never secret).
        #[serde(skip_serializing_if = "Option::is_none")]
        claims: Option<&'a BTreeMap<String, String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        serial: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        not_after: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// An auto-unseal attempt that unsealed, or a failure when it starts or
    /// changes (never every retry).
    AutoUnseal {
        result: &'static str,
        provider: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        key_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    KeyringRefresh {
        trigger: &'static str,
        result: &'static str,
        /// Each namespace's active KEK version.
        #[serde(skip_serializing_if = "Option::is_none")]
        active: Option<BTreeMap<String, u32>>,
        /// KEKs kept for reading only: the keys database lost them.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        vanished: Vec<KekRef>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    IdentityReload {
        result: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        issuers: Option<Vec<IssuerInForce>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        revoked: Option<Vec<RevokedInForce>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    CertificateReload {
        result: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        fingerprint: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    KekCheck {
        lost_namespaces: Vec<String>,
        deleted_namespaces: Vec<String>,
        missing: Vec<KekRef>,
        destroyed: Vec<KekRef>,
    },
    RevocationLoaded {
        crls: Option<Vec<CrlInfo>>,
    },
    RevocationReload {
        result: &'static str,
        /// Absent if it failed; null if there are no CRLs now.
        #[serde(skip_serializing_if = "Option::is_none")]
        crls: Option<Option<Vec<CrlInfo>>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Outcome {
        caller: Option<&'a str>,
        action: Action,
        target: TargetEntry<'a>,
        operation: &'static str,
        result: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<serde_json::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

fn caller_name(caller: &Caller) -> Option<&str> {
    match caller {
        Caller::Unauthenticated => None,
        Caller::Identity(name) => Some(name.as_str()),
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TargetEntry<'a> {
    Path { path: &'a str },
    Below { path: &'a str },
    All,
    System,
}

impl<'a> From<Target<'a>> for TargetEntry<'a> {
    fn from(target: Target<'a>) -> Self {
        match target {
            Target::Path(path) => Self::Path {
                path: path.as_str(),
            },
            Target::Below(path) => Self::Below {
                path: path.as_str(),
            },
            Target::All => Self::All,
            Target::System => Self::System,
        }
    }
}

/// The writer thread: the chain's start, then every entry linked into it,
/// with a checkpoint whenever one is due or asked for, and the chain's end
/// when the [`Drain`] asks.
fn write_chain(out: impl Write, chain: Chain, mut entries: mpsc::Receiver<Pending>) {
    let lost = |e: &dyn std::fmt::Display| {
        tracing::error!(error = %e, "AUDIT LOG WRITE FAILED: an entry is lost");
        metrics().audit_failure("lost");
    };
    let mut writer = Writer {
        out,
        chain,
        cut: false,
    };
    // At once, so the chain starts before anything is recorded; if it
    // fails, the first entry tries again.
    if let Err(e) = writer.start() {
        lost(&e);
    }
    let answer = |written: Written, result: io::Result<()>| match (written, result) {
        (Some(written), result) => {
            written.send(result).ok();
        }
        (None, Err(e)) => lost(&e),
        (None, Ok(())) => {}
    };
    while let Some(pending) = entries.blocking_recv() {
        match pending {
            Pending::Entry { line, written } => {
                answer(written, writer.entry(&line));
                if writer.chain.checkpoint_due() {
                    answer(None, writer.seal(Seal::Checkpoint));
                }
            }
            Pending::Checkpoint { written } => answer(written, writer.seal(Seal::Checkpoint)),
            Pending::End { written } => answer(written, writer.seal(Seal::End)),
        }
    }
}

/// The output and the chain being written to it.
struct Writer<W> {
    out: W,
    chain: Chain,
    /// The last write failed partway: the file ends in part of a line.
    cut: bool,
}

impl<W: Write> Writer<W> {
    /// A new chain's start (after the end of the last one, or a failed
    /// write).
    fn start(&mut self) -> io::Result<()> {
        let start = self.chain.start(&now()).map_err(io::Error::other)?;
        self.put(&start, None)
    }

    /// `line` linked into the chain, starting a new one first if needed.
    fn entry(&mut self, line: &[u8]) -> io::Result<()> {
        if self.chain.needs_start() {
            self.start()?;
        }
        let linked = self.chain.link(line).map_err(io::Error::other)?;
        self.put(&linked, None)
    }

    /// A checkpoint if there's something new to sign, or the chain's end;
    /// else (unsigned, or no chain open) just a flush.
    fn seal(&mut self, seal: Seal) -> io::Result<()> {
        match self.chain.seal(seal, &now()).map_err(io::Error::other)? {
            Some(line) => self.put(&line, Some(seal)),
            None => self.out.flush(),
        }
    }

    /// Writes and flushes `line`. The chain moves on once every byte is
    /// written, even if the flush then fails: the line is in the file. A
    /// write that fails ends the chain there: the next line starts a new
    /// one, after a newline if part of this line was written, so the
    /// fragment stays a line of its own instead of running into the next.
    fn put(&mut self, line: &[u8], seal: Option<Seal>) -> io::Result<()> {
        if self.cut {
            self.out.write_all(b"\n")?;
            self.cut = false;
        }
        let mut done = 0;
        while done < line.len() {
            match self.out.write(&line[done..]) {
                Ok(0) => {
                    self.failed(done);
                    return Err(io::ErrorKind::WriteZero.into());
                }
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.failed(done);
                    return Err(e);
                }
            }
        }
        self.chain.written(line, seal);
        self.out.flush()
    }

    fn failed(&mut self, written: usize) {
        self.chain.write_failed();
        self.cut = written > 0;
    }
}

/// Now, RFC 3339 (UTC).
fn now() -> String {
    // Formatting a current UTC time can't fail in practice; an entry with
    // an empty time beats losing it.
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// One JSON line, newline included.
fn line(event: Event<'_>) -> Result<Vec<u8>, AuditError> {
    let time = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| AuditError::Encode(Box::new(e)))?;
    let mut line =
        serde_json::to_vec(&Line { time, event }).map_err(|e| AuditError::Encode(Box::new(e)))?;
    line.push(b'\n');
    Ok(line)
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Instant;

    use ferritor_core::path::SecretPath;
    use ferritor_testkit::Captured;

    use ferritor_core::audit_chain::{self, ChainState, Verdict};

    use super::*;

    /// Refuses one action, allows the rest.
    struct Refusing(Action);

    impl Authorizer for Refusing {
        fn authorize(
            &self,
            caller: &Caller,
            action: Action,
            target: Target<'_>,
        ) -> Result<(), Denied> {
            if action == self.0 {
                return Err(Denied::new(caller, action, target));
            }
            Ok(())
        }
    }

    /// A stdout that fails, like a closed pipe.
    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    /// A stdout nobody reads: every write blocks until the test ends.
    struct Stalled(mpsc::Receiver<()>);

    impl Write for Stalled {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.0.recv().ok();
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn gate(out: impl Write + Send + 'static) -> Gate {
        Gate::new(
            Arc::new(Refusing(Action::Delete)),
            AuditLog::new(out, Duration::from_millis(200)).unwrap(),
        )
    }

    fn alice() -> Caller {
        Caller::Identity(SecretPath::parse("ops/alice").unwrap())
    }

    /// Each line without its time, which is checked separately.
    fn entries(audit: &Captured) -> Vec<serde_json::Value> {
        audit
            .lines()
            .iter()
            .map(|line| {
                let mut entry: serde_json::Value = serde_json::from_str(line).unwrap();
                let time = entry["time"].as_str().unwrap().to_owned();
                OffsetDateTime::parse(&time, &Rfc3339).unwrap();
                entry.as_object_mut().unwrap().remove("time");
                entry
            })
            .collect()
    }

    #[tokio::test]
    async fn every_decision_is_one_json_line() {
        let audit = Captured::default();
        let gate = gate(audit.clone());
        let db = SecretPath::parse("app/db").unwrap();
        gate.check(&alice(), Action::Read, Target::Path(&db))
            .await
            .unwrap();
        assert!(matches!(
            gate.check(&Caller::Unauthenticated, Action::Delete, Target::Path(&db))
                .await,
            Err(Refused::Denied(_))
        ));
        gate.check(&alice(), Action::List, Target::Below(&db))
            .await
            .unwrap();
        gate.check(&alice(), Action::List, Target::All)
            .await
            .unwrap();
        gate.check(&alice(), Action::Rekey, Target::System)
            .await
            .unwrap();
        // Only shapes a reply: not recorded.
        assert!(gate.permits(&alice(), Action::Rekey, Target::System));

        let entry = |caller: Option<&str>, action: &str, target, decision: &str| {
            serde_json::json!({
                "event": "authorization",
                "caller": caller,
                "action": action,
                "target": target,
                "decision": decision,
            })
        };
        let path = |kind: &str| serde_json::json!({"kind": kind, "path": "app/db"});
        assert_eq!(
            entries(&audit),
            [
                entry(Some("ops/alice"), "read", path("path"), "allowed"),
                entry(None, "delete", path("path"), "denied"),
                entry(Some("ops/alice"), "list", path("below"), "allowed"),
                entry(
                    Some("ops/alice"),
                    "list",
                    serde_json::json!({"kind": "all"}),
                    "allowed"
                ),
                entry(
                    Some("ops/alice"),
                    "rekey",
                    serde_json::json!({"kind": "system"}),
                    "allowed"
                ),
            ]
        );
    }

    #[tokio::test]
    async fn a_rejected_authentication_is_recorded_without_a_caller() {
        let audit = Captured::default();
        let gate = gate(audit.clone());
        let peer = "10.0.0.7:51234".parse().ok();
        gate.rejected(Action::Read, peer, None, &IdentityError::NotValidNow);
        drop(gate);
        // Queued, not waited for: give the writer a moment.
        for _ in 0..100 {
            if !audit.lines().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            entries(&audit),
            [serde_json::json!({
                "event": "authentication",
                "peer": "10.0.0.7:51234",
                "action": "read",
                "outcome": "rejected",
                "reason": "not_valid_now",
                "detail": "the client certificate has expired or is not yet valid",
            })]
        );
    }

    /// Slow to write, so entries are still queued when the gate goes.
    struct Slow(Captured);

    impl Write for Slow {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            std::thread::sleep(Duration::from_millis(20));
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Shutdown: the drain returns once everything queued before it is
    /// written, gates still alive or not (a connection abandoned at the
    /// drain deadline may hold one); a stalled stdout makes it say so.
    #[tokio::test]
    async fn the_drain_waits_for_queued_entries() {
        let audit = Captured::default();
        let (log, drain) = AuditLog::start(
            Slow(audit.clone()),
            Duration::from_secs(1),
            None,
            CHECKPOINT_INTERVAL,
        )
        .unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        for _ in 0..5 {
            gate.check(&alice(), Action::Seal, Target::System)
                .await
                .unwrap();
        }
        assert!(audit.lines().len() < 5);
        assert!(drain.wait(Duration::from_secs(2)).await);
        assert_eq!(audit.lines().len(), 5);
        drop(gate);

        let (unblock, blocked) = mpsc::channel();
        let (log, drain) = AuditLog::start(
            Stalled(blocked),
            Duration::from_secs(1),
            None,
            CHECKPOINT_INTERVAL,
        )
        .unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        gate.check(&alice(), Action::Seal, Target::System)
            .await
            .unwrap();
        assert!(!drain.wait(Duration::from_millis(100)).await);
        drop(unblock);
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn verified(audit: &Captured) -> audit_chain::Report {
        audit_chain::verify(audit.raw().as_slice(), &[signing_key().verifying_key()]).unwrap()
    }

    /// What the server writes verifies with the public key, and the drain
    /// at shutdown ends the chain with a signed chain_end: a clean exit
    /// leaves it complete. Anything after the drain starts a new chain.
    #[tokio::test]
    async fn the_drain_ends_the_chain_and_a_clean_exit_is_proven() {
        let audit = Captured::default();
        let (log, drain) =
            AuditLog::signed(audit.clone(), Duration::from_secs(1), signing_key()).unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        gate.check(&alice(), Action::Read, Target::System)
            .await
            .unwrap();
        gate.outcome(
            &alice(),
            Action::Seal,
            Target::System,
            "seal",
            Outcome::Unknown("x".to_owned()),
        );
        // Not yet ended: open, as a running server's chain is.
        assert_eq!(verified(&audit).chains[0].state, ChainState::Open);
        assert!(drain.clone().wait(Duration::from_secs(2)).await);
        let report = verified(&audit);
        assert_eq!(report.verdict(), Verdict::Proven, "{report:?}");
        // start, the decision, the outcome, chain_end.
        assert_eq!(
            (report.chains[0].entries, report.chains[0].signed_through),
            (4, Some(3))
        );
        // A second drain has nothing to end.
        assert!(drain.clone().wait(Duration::from_secs(2)).await);
        assert_eq!(verified(&audit).chains[0].entries, 4);
        // Written after the end: a new chain, ended by the next drain.
        gate.check(&alice(), Action::Read, Target::System)
            .await
            .unwrap();
        assert!(drain.wait(Duration::from_secs(2)).await);
        let report = verified(&audit);
        assert_eq!(report.verdict(), Verdict::Proven, "{report:?}");
        assert_eq!(report.chains.len(), 2);
        // The entries themselves are unchanged, but for the chain's fields.
        assert_eq!(audit.lines().len(), 3);
    }

    /// Signed after every CHECKPOINT_EVERY entries, and at least every
    /// interval while entries arrive, without anyone asking.
    #[tokio::test]
    async fn checkpoints_come_by_count_and_by_time() {
        let audit = Captured::default();
        let (log, drain) = AuditLog::start(
            audit.clone(),
            Duration::from_secs(1),
            Some(signing_key()),
            Duration::from_secs(3600),
        )
        .unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        for _ in 0..audit_chain::CHECKPOINT_EVERY {
            gate.check(&alice(), Action::Status, Target::System)
                .await
                .unwrap();
        }
        let report = verified(&audit);
        assert_eq!(report.chains[0].state, ChainState::Open, "{report:?}");
        // The start and 255 entries, then a checkpoint; one entry after it.
        assert_eq!(report.chains[0].signed_through, Some(256));
        assert_eq!(report.chains[0].unsigned_tail, 1);
        drop((gate, drain));

        let audit = Captured::default();
        let (log, _drain) = AuditLog::start(
            audit.clone(),
            Duration::from_secs(1),
            Some(signing_key()),
            Duration::from_millis(20),
        )
        .unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        gate.check(&alice(), Action::Status, Target::System)
            .await
            .unwrap();
        for _ in 0..100 {
            if verified(&audit).chains[0].unsigned_tail == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let report = verified(&audit);
        assert_eq!(report.chains[0].unsigned_tail, 0, "{report:?}");
        // Idle: no checkpoint without anything new to sign.
        let lines = audit.raw().len();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(audit.raw().len(), lines);
    }

    /// Writes part of one line, then fails (a disk filling up, say).
    struct FailsOnce {
        out: Captured,
        calls: usize,
        at: usize,
    }

    impl Write for FailsOnce {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == self.at {
                let half = buf.len() / 2;
                return self.out.write(&buf[..half]);
            }
            if self.calls == self.at + 1 {
                return Err(io::ErrorKind::StorageFull.into());
            }
            self.out.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A failed write costs only its own chain: the fragment is ended with
    /// a newline, and a new chain starts at the next write, so the incident
    /// shows as one unterminated chain with a damaged last line, and
    /// everything after it is proven as usual.
    #[tokio::test]
    async fn a_failed_write_starts_a_new_chain() {
        let audit = Captured::default();
        // Write calls: the start (1), an entry (2), the next entry half
        // written (3), then failing (4).
        let failing = FailsOnce {
            out: audit.clone(),
            calls: 0,
            at: 3,
        };
        let (log, drain) =
            AuditLog::signed(failing, Duration::from_secs(1), signing_key()).unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        let alice = alice();
        let check = || gate.check(&alice, Action::Read, Target::System);
        check().await.unwrap();
        assert!(matches!(check().await, Err(Refused::Unaudited(_))));
        check().await.unwrap();
        assert!(drain.wait(Duration::from_secs(2)).await);

        let report = verified(&audit);
        assert_eq!(report.verdict(), Verdict::Unproven, "{report:?}");
        assert_eq!(report.chains.len(), 2);
        assert_eq!(report.chains[0].state, ChainState::Unterminated);
        assert_eq!(
            report.chains[0].damaged_last_line.as_ref().map(|p| p.line),
            Some(3)
        );
        assert_eq!(report.chains[1].state, ChainState::Complete);
        assert_eq!(report.chains[1].first_line, 4);
    }

    /// Without a key (dev mode) the log is still chained, but has no
    /// checkpoints, and says it's unsigned.
    #[tokio::test]
    async fn an_unsigned_log_is_chained_without_checkpoints() {
        let audit = Captured::default();
        let gate = gate(audit.clone());
        gate.check(&alice(), Action::Read, Target::System)
            .await
            .unwrap();
        let raw = String::from_utf8(audit.raw()).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].contains(r#""event":"chain_start""#) && lines[0].contains(r#""key":null"#)
        );
        assert!(lines[1].ends_with(r#""}"#) && lines[1].contains(r#","seq":1,"prev":""#));
        assert!(matches!(
            &verified(&audit).chains[0].state,
            ChainState::Unverifiable(why) if why.contains("not signed")
        ));
    }

    /// Waits for `n` lines (lifecycle entries are queued, not waited for).
    async fn lines(audit: &Captured, n: usize) {
        for _ in 0..100 {
            if audit.lines().len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// A reloaded policy decides from the next check on; a skipped or
    /// failed reload keeps the running one. Every entry names the policy by
    /// fingerprint, the one at startup included, so each decision falls
    /// between two entries naming the policy it ran under.
    #[tokio::test]
    async fn policy_and_certificate_lifecycle_is_recorded() {
        use crate::policy::{PolicyInfo, Rule};

        let audit = Captured::default();
        let gate = gate(audit.clone());
        let delete = |gate: &Gate| gate.permits(&alice(), Action::Delete, Target::All);
        let rules = vec![Rule {
            name: None,
            identity: "ops/alice".to_owned(),
            actions: vec![Action::Delete],
            paths: Vec::new(),
            all_paths: true,
        }];
        let info = PolicyInfo::of(&rules).unwrap();
        assert_eq!(info.fingerprint.len(), 64);

        gate.policy_loaded(Some(&info));
        gate.certificate_loaded("ab12");
        assert!(!delete(&gate));
        gate.reload_policy(PolicyReload::Reloaded(
            Arc::new(Refusing(Action::Read)),
            info.clone(),
        ));
        assert!(delete(&gate));
        gate.reload_policy(PolicyReload::Skipped("dev mode: no policy"));
        gate.reload_policy(PolicyReload::Failed("the policy is invalid".to_owned()));
        assert!(delete(&gate));
        gate.certificate_reloaded(Err("the server key is not valid PEM".to_owned()));
        gate.policy_loaded(None);
        // The stored policies: a change and a failure are recorded, a load
        // that changed nothing only counted; a seal drops them.
        gate.stored_policies_reloaded("poll", &PolicyRefresh::Unchanged);
        gate.stored_policies_reloaded(
            "unseal",
            &PolicyRefresh::Loaded {
                revision: 4,
                policies: 2,
                fingerprint: "cd34".to_owned(),
                changed: true,
            },
        );
        let failed = PolicyRefresh::Failed {
            reason: crate::policy_store::Unverified::Set,
            kept: true,
        };
        // A failure that persists is recorded once, not on every poll; the
        // recovery that ends it is.
        for _ in 0..3 {
            gate.stored_policies_reloaded("periodic", &failed);
            gate.stored_policies_reloaded("poll", &PolicyRefresh::Unchanged);
        }
        gate.stored_policies_reloaded(
            "periodic",
            &PolicyRefresh::Loaded {
                revision: 4,
                policies: 2,
                fingerprint: "cd34".to_owned(),
                changed: false,
            },
        );
        gate.stored_policies_reloaded("poll", &PolicyRefresh::Unchanged);
        // A flapping keys database fails with a different error each time:
        // one condition, one entry (with the first error), then the
        // recovery.
        for error in ["timed out", "connection refused", "timed out"] {
            gate.stored_policies_reloaded(
                "poll",
                &PolicyRefresh::Failed {
                    reason: crate::policy_store::Unverified::Unreadable(error.to_owned()),
                    kept: true,
                },
            );
        }
        // Nothing in force any more is a real change, though: reported.
        gate.stored_policies_reloaded(
            "unseal",
            &PolicyRefresh::Failed {
                reason: crate::policy_store::Unverified::Unreadable("refused".to_owned()),
                kept: false,
            },
        );
        gate.stored_policies_reloaded(
            "poll",
            &PolicyRefresh::Loaded {
                revision: 4,
                policies: 2,
                fingerprint: "cd34".to_owned(),
                changed: true,
            },
        );
        gate.stored_policies_dropped();

        lines(&audit, 14).await;
        let fp = serde_json::json!(info.fingerprint);
        assert_eq!(
            entries(&audit),
            [
                serde_json::json!({"event": "policy_loaded", "mode": "secured", "rules": 1, "fingerprint": fp}),
                serde_json::json!({"event": "certificate_loaded", "fingerprint": "ab12"}),
                serde_json::json!({"event": "policy_reload", "result": "succeeded", "source": "config", "rules": 1, "fingerprint": fp}),
                serde_json::json!({"event": "policy_reload", "result": "skipped", "source": "config", "reason": "dev mode: no policy"}),
                serde_json::json!({"event": "policy_reload", "result": "failed", "source": "config", "reason": "the policy is invalid"}),
                serde_json::json!({"event": "certificate_reload", "result": "failed", "reason": "the server key is not valid PEM"}),
                serde_json::json!({"event": "policy_loaded", "mode": "dev"}),
                serde_json::json!({"event": "policy_reload", "result": "changed", "source": "database", "trigger": "unseal", "revision": 4, "rules": 2, "fingerprint": "cd34"}),
                serde_json::json!({"event": "policy_reload", "result": "integrity", "source": "database", "trigger": "periodic",
                    "reason": "the policy set doesn't verify (a policy added or removed in the keys database); keeping the last verified set in force"}),
                serde_json::json!({"event": "policy_reload", "result": "recovered", "source": "database", "trigger": "periodic", "revision": 4, "rules": 2, "fingerprint": "cd34"}),
                serde_json::json!({"event": "policy_reload", "result": "failed", "source": "database", "trigger": "poll",
                    "reason": "the stored policies couldn't be read: timed out; keeping the last verified set in force"}),
                serde_json::json!({"event": "policy_reload", "result": "failed", "source": "database", "trigger": "unseal",
                    "reason": "the stored policies couldn't be read: refused; no stored policy is in force: requests only they would allow are refused (POLICY_UNVERIFIED)"}),
                serde_json::json!({"event": "policy_reload", "result": "recovered", "source": "database", "trigger": "poll", "revision": 4, "rules": 2, "fingerprint": "cd34"}),
                serde_json::json!({"event": "policy_reload", "result": "succeeded", "source": "seal", "rules": 0}),
            ]
        );
    }

    /// The CRLs in force are named at startup and on every reload: by
    /// issuer, number and fingerprint, never the revoked serials; null when
    /// there are none (nothing revoked).
    #[tokio::test]
    async fn revocation_lifecycle_is_recorded() {
        use tokio_rustls::rustls::pki_types::CertificateDer;
        use tokio_rustls::rustls::pki_types::pem::PemObject;

        let ca = ferritor_testkit::pki::Ca::named("clients").unwrap();
        let alice = ca.client("ops/alice").unwrap();
        let next_update = time::OffsetDateTime::now_utc() + time::Duration::days(1);
        let pem = ca.crl(&[&alice], next_update).unwrap();
        let crls = crate::crl::Crls::parse(
            pem.as_bytes(),
            &[CertificateDer::from_pem_slice(ca.cert.as_bytes()).unwrap()],
        )
        .unwrap();
        let info = crls.info().to_vec();

        let audit = Captured::default();
        let gate = gate(audit.clone());
        gate.revocation_loaded(None);
        gate.revocation_reloaded(Ok(Some(info.clone())));
        gate.revocation_reloaded(Err("the CRL file was refused".to_owned()));
        gate.revocation_reloaded(Ok(None));

        lines(&audit, 4).await;
        let crl = serde_json::json!({
            "issuer": "CN=clients",
            "number": "1",
            "this_update": info[0].this_update,
            "next_update": info[0].next_update,
            "revoked": 1,
            "fingerprint": info[0].fingerprint,
        });
        assert_eq!(
            entries(&audit),
            [
                serde_json::json!({"event": "revocation_loaded", "crls": null}),
                serde_json::json!({"event": "revocation_reload", "result": "succeeded", "crls": [crl]}),
                serde_json::json!({"event": "revocation_reload", "result": "failed", "reason": "the CRL file was refused"}),
                serde_json::json!({"event": "revocation_reload", "result": "succeeded", "crls": null}),
            ]
        );
    }

    /// Same rules, same fingerprint, however the file was written; any
    /// change to a rule, a different one.
    #[test]
    fn a_policy_fingerprint_follows_the_rules() {
        use crate::policy::{PolicyInfo, Rule};

        let rule = |actions: Vec<Action>| Rule {
            name: None,
            identity: "ops/alice".to_owned(),
            actions,
            paths: vec!["app".to_owned()],
            all_paths: false,
        };
        let a = PolicyInfo::of(&[rule(vec![Action::Read])]).unwrap();
        assert_eq!(a, PolicyInfo::of(&[rule(vec![Action::Read])]).unwrap());
        assert_ne!(
            a,
            PolicyInfo::of(&[rule(vec![Action::Read, Action::List])]).unwrap()
        );
    }

    /// Fail closed, except seal; a denial stays a denial.
    #[tokio::test]
    async fn an_unwritable_log_refuses_everything_but_seal() {
        let gate = gate(Broken);
        assert!(matches!(
            gate.check(&alice(), Action::Read, Target::All).await,
            Err(Refused::Unaudited(AuditError::Write(_)))
        ));
        assert!(matches!(
            gate.check(&alice(), Action::Status, Target::System).await,
            Err(Refused::Unaudited(AuditError::Write(_)))
        ));
        assert!(matches!(
            gate.check(&alice(), Action::Delete, Target::All).await,
            Err(Refused::Denied(_))
        ));
        gate.check(&alice(), Action::Seal, Target::System)
            .await
            .unwrap();
    }

    /// A stalled stdout costs a request the timeout, then a refusal; seal
    /// doesn't wait at all, not even once the queue is full.
    #[tokio::test]
    async fn a_stalled_log_times_out_but_never_delays_seal() {
        let (unblock, blocked) = mpsc::channel();
        let gate = gate(Stalled(blocked));

        let started = Instant::now();
        assert!(matches!(
            gate.check(&alice(), Action::Read, Target::All).await,
            Err(Refused::Unaudited(AuditError::Timeout))
        ));
        assert!(started.elapsed() >= Duration::from_millis(200));

        let started = Instant::now();
        for _ in 0..QUEUE + 10 {
            gate.check(&alice(), Action::Seal, Target::System)
                .await
                .unwrap();
        }
        assert!(started.elapsed() < Duration::from_millis(200));
        drop(unblock);
    }
}
