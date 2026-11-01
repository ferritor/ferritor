//! The rate limiter (what's limited and how it answers:
//! `docs/src/content/docs/operations/running.md`, "Rate limits"; what a change must keep: AGENTS.md,
//! "Rate limits"), on its own: per key (an identity, or an unauthenticated
//! certificate's fingerprint), a request rate (GCRA), calls in flight, and
//! a budget of denials. It knows nothing of the server: the authorization
//! steps decide what's limited, with which quota, and what a refusal
//! answers.
//!
//! GCRA keeps one timestamp per bucket, the theoretical arrival time (TAT):
//! when the bucket would be empty again if every request so far had come
//! exactly at the rate. A request passes if, counted in, the TAT is at most
//! `burst` intervals ahead of now. So at most `burst` requests pass at one
//! instant, and at most `burst + rate × window` in any window.
//!
//! Time comes from a [`Clock`] the limiter is handed: [`SystemClock`] in
//! production, a fake one in tests, which then never sleep.
//!
//! Also here, for the wiring (`audit::Gate`, `tls::Detach`): the limits as
//! configured ([`Limits`]), the request a task serves ([`in_request`],
//! [`current`]), and the refusal episodes the audit log reports
//! ([`Episodes`]).

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ferritor_core::path::SecretPath;
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

/// Where the limiter's time comes from.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// The real time.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// The highest rate a setting may give: one request a microsecond. Far
/// beyond what one server serves, and well within the GCRA interval's
/// precision (above 10⁹ the interval would round to zero, no limit at all).
pub const MAX_RATE: u32 = 1_000_000;

/// A request rate: `per_second` on average, up to `burst` at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    per_second: NonZeroU32,
    burst: NonZeroU32,
}

impl Rate {
    pub fn new(per_second: NonZeroU32, burst: NonZeroU32) -> Self {
        Self { per_second, burst }
    }

    /// The time one request takes up at the rate.
    fn interval(self) -> Duration {
        Duration::from_secs(1) / self.per_second.get()
    }

    /// How far ahead of now the TAT may be: `burst` intervals.
    fn tolerance(self) -> Duration {
        self.interval() * self.burst.get()
    }
}

/// One GCRA bucket: its theoretical arrival time, `None` while full.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bucket {
    tat: Option<Instant>,
}

impl Bucket {
    /// The TAT if one more request were counted in at `now`, or how long
    /// until one would pass.
    fn next(self, rate: Rate, now: Instant) -> Result<Instant, Duration> {
        let next = self.tat.map_or(now, |tat| tat.max(now)) + rate.interval();
        let ahead = next.saturating_duration_since(now);
        match ahead.checked_sub(rate.tolerance()) {
            Some(wait) if !wait.is_zero() => Err(wait),
            _ => Ok(next),
        }
    }

    /// Takes one request at `now`, or says how long until one would pass.
    pub fn take(&mut self, rate: Rate, now: Instant) -> Result<(), Duration> {
        self.tat = Some(self.next(rate, now)?);
        Ok(())
    }

    /// Whether one more request would pass at `now`, without taking it.
    pub fn check(self, rate: Rate, now: Instant) -> Result<(), Duration> {
        self.next(rate, now).map(drop)
    }

    /// Full again: nothing to remember.
    fn is_full(self, now: Instant) -> bool {
        self.tat.is_none_or(|tat| tat <= now)
    }
}

/// What a key may do. A limit left out is no limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Quota {
    pub rate: Option<Rate>,
    pub max_in_flight: Option<NonZeroU32>,
    /// Watch streams open at once (`watch`): held for a stream's life,
    /// outside any request, so not among the calls in flight.
    pub max_watch_streams: Option<NonZeroU32>,
}

/// Which limit refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Limit {
    /// Its denial budget is empty.
    Denied,
    /// As many of its calls as it may have are running.
    InFlight,
    /// Too many requests too fast.
    Rate,
    /// A certificate that names no caller, too often (keyed by its
    /// fingerprint, at [`UNAUTHENTICATED`]).
    Unauthenticated,
    /// Refused token exchanges from one peer address, too often (keyed by
    /// it, at [`UNAUTHENTICATED`]): their audit entries are left out.
    ExchangeRefused,
    /// Token exchanges for one identity, too often (keyed by it, at
    /// [`exchanges`]).
    Exchanges,
}

impl Limit {
    /// As named in answers, metrics and the audit log.
    pub fn name(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::InFlight => "in_flight",
            Self::Rate => "rate",
            Self::Unauthenticated => "unauthenticated",
            Self::ExchangeRefused => "exchange_refused",
            Self::Exchanges => "exchanges",
        }
    }
}

/// A refusal: which limit, and when a retry could pass (`None` when no time
/// is known: a slot frees when some call ends).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused {
    pub limit: Limit,
    pub retry_after: Option<Duration>,
}

#[derive(Debug, Default)]
struct Entry {
    rate: Bucket,
    denials: Bucket,
    /// Raised under the map's lock, lowered by a [`Slot`]'s drop without
    /// it (the call's end takes no lock). An entry is only evicted at 0,
    /// and a lowering never makes a full entry look busy, so eviction
    /// stays sound.
    in_flight: Arc<AtomicU32>,
}

impl Entry {
    fn is_idle(&self, now: Instant) -> bool {
        self.in_flight.load(Ordering::Acquire) == 0
            && self.rate.is_full(now)
            && self.denials.is_full(now)
    }
}

/// The limiter, per key `K`: two instances keep identities and
/// certificate fingerprints apart.
pub struct Limiter<K, C = SystemClock> {
    clock: C,
    entries: Mutex<HashMap<K, Entry>>,
}

impl<K: Hash + Eq + Clone, C: Clock> Limiter<K, C> {
    pub fn new(clock: C) -> Self {
        Self {
            clock,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<K, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A request from `key`, in the design's order: its denial budget
    /// (checked, not charged: only a recorded denial charges it), a slot
    /// among its calls in flight, then a token at its rate (the slot is
    /// counted only once the rate passes, so a refusal costs nothing). The
    /// slot is held until the returned [`Slot`] is dropped, when the call
    /// ends.
    pub fn admit(&self, key: &K, quota: &Quota, denials: Option<Rate>) -> Result<Slot, Refused> {
        let now = self.clock.now();
        with_entry(&mut self.entries(), key, |entry| {
            if let Some(denials) = denials
                && let Err(wait) = entry.denials.check(denials, now)
            {
                return Err(Refused {
                    limit: Limit::Denied,
                    retry_after: Some(wait),
                });
            }
            if quota
                .max_in_flight
                .is_some_and(|max| entry.in_flight.load(Ordering::Acquire) >= max.get())
            {
                return Err(Refused {
                    limit: Limit::InFlight,
                    retry_after: None,
                });
            }
            if let Some(rate) = quota.rate
                && let Err(wait) = entry.rate.take(rate, now)
            {
                return Err(Refused {
                    limit: Limit::Rate,
                    retry_after: Some(wait),
                });
            }
            entry.in_flight.fetch_add(1, Ordering::AcqRel);
            Ok(Slot {
                in_flight: Arc::clone(&entry.in_flight),
            })
        })
    }

    /// `key` was denied, and the denial recorded: charges its budget (an
    /// empty one stays empty; the next request finds it so).
    pub fn charge_denial(&self, key: &K, denials: Rate) {
        let now = self.clock.now();
        with_entry(&mut self.entries(), key, |entry| {
            // Already empty: nothing more to take.
            entry.denials.take(denials, now).ok();
        });
    }

    /// Calls of `key` in flight now.
    pub fn in_flight(&self, key: &K) -> u32 {
        self.entries()
            .get(key)
            .map_or(0, |entry| entry.in_flight.load(Ordering::Acquire))
    }

    /// Forgets keys with nothing to remember (no call in flight, every
    /// bucket full again); returns them. A forgotten key starts full, as it
    /// would anyway.
    pub fn evict_idle(&self) -> Vec<K> {
        let now = self.clock.now();
        let mut evicted = Vec::new();
        self.entries().retain(|key, entry| {
            let idle = entry.is_idle(now);
            if idle {
                evicted.push(key.clone());
            }
            !idle
        });
        evicted
    }
}

/// Runs `f` on `key`'s entry, created on a miss: the key is cloned only
/// then, never on the hot path of a key already known.
fn with_entry<K: Hash + Eq + Clone, R>(
    entries: &mut HashMap<K, Entry>,
    key: &K,
    f: impl FnOnce(&mut Entry) -> R,
) -> R {
    match entries.get_mut(key) {
        Some(entry) => f(entry),
        None => f(entries.entry(key.clone()).or_default()),
    }
}

/// One call in flight; given back when dropped (no lock taken).
pub struct Slot {
    in_flight: Arc<AtomicU32>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The denial budget, the same for everyone: denials are what a misbehaving
/// or probing client produces, never a well-behaved one's load.
pub const DENIALS: Rate = Rate {
    per_second: NonZeroU32::MIN.saturating_add(9),
    burst: NonZeroU32::MIN.saturating_add(49),
};

/// The rate for certificates that name no caller (keyed by fingerprint):
/// each is answered 401 and audited, so they're held down too.
pub const UNAUTHENTICATED: Rate = Rate {
    per_second: NonZeroU32::MIN,
    burst: NonZeroU32::MIN.saturating_add(4),
};

/// The rate of token exchanges for one identity (an issuer's mapped name):
/// one a second, with its issuer's `exchange_burst` at once. A workload
/// renews once per two thirds of its certificate's life; more is a loop,
/// each costing a signature and an audit entry waited for.
pub fn exchanges(burst: NonZeroU32) -> Rate {
    Rate {
        per_second: NonZeroU32::MIN,
        burst,
    }
}

/// How long without a refusal ends an episode ([`Episodes`]).
pub const QUIET: Duration = Duration::from_secs(10);

/// The limits in force: the server-wide cap on calls in flight, the
/// default quota, and identities' own (exact, or a prefix by whole
/// segments; the most specific wins, and each identity has its own
/// counters, also under a prefix).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub server_max_in_flight: NonZeroU32,
    pub default: Quota,
    /// Most specific first.
    overrides: Vec<(SecretPath, Quota)>,
}

impl Limits {
    pub fn new(
        server_max_in_flight: NonZeroU32,
        default: Quota,
        mut overrides: Vec<(SecretPath, Quota)>,
    ) -> Self {
        overrides.sort_by_key(|(path, _)| std::cmp::Reverse(path.as_str().len()));
        Self {
            server_max_in_flight,
            default,
            overrides,
        }
    }

    /// `identity`'s quota: its own entry (exact, else the longest prefix),
    /// or the default.
    pub fn quota(&self, identity: &SecretPath) -> Quota {
        self.overrides
            .iter()
            .find(|(path, _)| identity == path || identity.is_under(path))
            .map_or(self.default, |(_, quota)| *quota)
    }
}

/// What a request holds while it runs: its slot among its identity's calls
/// in flight, and its permit under the server-wide cap (each `None` where
/// not limited). Dropped when the request's task ends.
#[derive(Default)]
pub struct Admission {
    pub slot: Option<Slot>,
    pub permit: Option<OwnedSemaphorePermit>,
}

/// The request a task serves (`tls::Detach` opens one per request): when
/// its client left, and the admission it holds. A request is admitted once,
/// at its first authorization check, however many it makes.
pub struct Request {
    cancelled: CancellationToken,
    claimed: AtomicBool,
    admission: Mutex<Option<Admission>>,
}

impl Request {
    /// Whether this is the request's first check (the one that admits).
    pub fn claim(&self) -> bool {
        !self.claimed.swap(true, Ordering::SeqCst)
    }

    /// Cancelled once the request's client is gone. Only the waits before
    /// a call has its permit watch it: after that, the call runs to its end.
    pub fn cancelled(&self) -> &CancellationToken {
        &self.cancelled
    }

    /// Keeps `admission` until the request ends.
    pub fn hold(&self, admission: Admission) {
        *self
            .admission
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(admission);
    }
}

tokio::task_local! {
    static REQUEST: Arc<Request>;
}

/// Calls in flight in this process, every one, limited or not (for
/// metrics: the server-wide cap counts only the limited ones).
static CALLS_IN_FLIGHT: AtomicU64 = AtomicU64::new(0);

pub fn calls_in_flight() -> u64 {
    CALLS_IN_FLIGHT.load(Ordering::Relaxed)
}

/// Counts a call in [`CALLS_IN_FLIGHT`] while it lives.
struct Counted;

impl Counted {
    fn enter() -> Self {
        CALLS_IN_FLIGHT.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        CALLS_IN_FLIGHT.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Runs `call` as a request whose client is gone once `cancelled` is.
pub fn in_request<F: Future>(
    cancelled: CancellationToken,
    call: F,
) -> impl Future<Output = F::Output> {
    let scoped = REQUEST.scope(
        Arc::new(Request {
            cancelled,
            claimed: AtomicBool::new(false),
            admission: Mutex::new(None),
        }),
        call,
    );
    async move {
        let _counted = Counted::enter();
        scoped.await
    }
}

/// The request this task serves, if it serves one (background work and
/// tests driving `Secrets` directly don't: nothing is limited there).
pub fn current() -> Option<Arc<Request>> {
    REQUEST.try_with(Arc::clone).ok()
}

/// Refusal episodes, per key and limit, for the audit log: one entry when
/// a key starts being refused, one when it has been quiet for [`QUIET`],
/// with the count. Never ended at the first request let through, which
/// would make a key hovering at a limit start and end an episode per
/// refusal.
pub struct Episodes<K> {
    open: Mutex<HashMap<(K, Limit), Open>>,
}

struct Open {
    last: Instant,
    refused: u64,
}

/// An episode that ended: its key, its limit, how many were refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ended<K> {
    pub key: K,
    pub limit: Limit,
    pub refused: u64,
}

impl<K: Hash + Eq + Clone> Default for Episodes<K> {
    fn default() -> Self {
        Self {
            open: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: Hash + Eq + Clone> Episodes<K> {
    /// `key` was refused by `limit` at `now`: whether that starts an
    /// episode (to report).
    pub fn refused(&self, key: &K, limit: Limit, now: Instant) -> bool {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        match open.get_mut(&(key.clone(), limit)) {
            Some(episode) => {
                episode.last = now;
                episode.refused += 1;
                false
            }
            None => {
                open.insert(
                    (key.clone(), limit),
                    Open {
                        last: now,
                        refused: 1,
                    },
                );
                true
            }
        }
    }

    /// The episodes with no refusal for [`QUIET`] by `now`, ended.
    pub fn end_quiet(&self, now: Instant) -> Vec<Ended<K>> {
        let mut ended = Vec::new();
        self.open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(key, limit), episode| {
                let quiet = now.saturating_duration_since(episode.last) >= QUIET;
                if quiet {
                    ended.push(Ended {
                        key: key.clone(),
                        limit: *limit,
                        refused: episode.refused,
                    });
                }
                !quiet
            });
        ended
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use proptest::prelude::*;

    use super::*;

    /// A clock that only moves when told.
    #[derive(Clone)]
    struct FakeClock {
        start: Instant,
        offset_nanos: Arc<AtomicU64>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                start: Instant::now(),
                offset_nanos: Arc::new(AtomicU64::new(0)),
            }
        }

        fn advance(&self, by: Duration) {
            let nanos = u64::try_from(by.as_nanos()).unwrap();
            self.offset_nanos.fetch_add(nanos, Ordering::SeqCst);
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.start + Duration::from_nanos(self.offset_nanos.load(Ordering::SeqCst))
        }
    }

    fn rate(per_second: u32, burst: u32) -> Rate {
        Rate::new(
            NonZeroU32::new(per_second).unwrap(),
            NonZeroU32::new(burst).unwrap(),
        )
    }

    /// No denial budget, for tests about the other limits.
    fn plenty() -> Option<Rate> {
        None
    }

    #[test]
    fn a_burst_passes_then_the_rate_holds_with_the_wait_to_retry() {
        let clock = FakeClock::new();
        let limiter = Limiter::new(clock.clone());
        let quota = Quota {
            rate: Some(rate(10, 3)),
            max_in_flight: None,
            max_watch_streams: None,
        };
        for _ in 0..3 {
            drop(limiter.admit(&"a", &quota, plenty()).unwrap());
        }
        let refused = limiter.admit(&"a", &quota, plenty()).err().unwrap();
        assert_eq!(refused.limit, Limit::Rate);
        assert_eq!(refused.retry_after, Some(Duration::from_millis(100)));
        clock.advance(Duration::from_millis(99));
        assert!(limiter.admit(&"a", &quota, plenty()).is_err());
        clock.advance(Duration::from_millis(1));
        drop(limiter.admit(&"a", &quota, plenty()).unwrap());
        // Another key has a bucket of its own.
        drop(limiter.admit(&"b", &quota, plenty()).unwrap());
    }

    #[test]
    fn calls_in_flight_are_limited_and_given_back_when_they_end() {
        let limiter = Limiter::new(FakeClock::new());
        let quota = Quota {
            rate: None,
            max_in_flight: NonZeroU32::new(2),
            max_watch_streams: None,
        };
        let first = limiter.admit(&"a", &quota, plenty()).unwrap();
        let _second = limiter.admit(&"a", &quota, plenty()).unwrap();
        assert_eq!(
            limiter.admit(&"a", &quota, plenty()).err(),
            Some(Refused {
                limit: Limit::InFlight,
                retry_after: None
            })
        );
        assert_eq!(limiter.in_flight(&"a"), 2);
        drop(first);
        assert_eq!(limiter.in_flight(&"a"), 1);
        let _third = limiter.admit(&"a", &quota, plenty()).unwrap();
    }

    #[test]
    fn a_rate_refusal_gives_its_slot_back_and_an_in_flight_one_costs_no_token() {
        let clock = FakeClock::new();
        let limiter = Limiter::new(clock.clone());
        let quota = Quota {
            rate: Some(rate(1, 1)),
            max_in_flight: NonZeroU32::new(1),
            max_watch_streams: None,
        };
        let held = limiter.admit(&"a", &quota, plenty()).unwrap();
        // In flight refuses first: the rate isn't asked, nothing is taken.
        assert_eq!(
            limiter.admit(&"a", &quota, plenty()).err().map(|r| r.limit),
            Some(Limit::InFlight)
        );
        drop(held);
        // The rate refuses: the slot it took is back.
        assert_eq!(
            limiter.admit(&"a", &quota, plenty()).err().map(|r| r.limit),
            Some(Limit::Rate)
        );
        assert_eq!(limiter.in_flight(&"a"), 0);
        // One interval later exactly one passes: the in-flight refusal took
        // no token.
        clock.advance(Duration::from_secs(1));
        drop(limiter.admit(&"a", &quota, plenty()).unwrap());
    }

    #[test]
    fn the_denial_budget_is_charged_by_denials_only_and_refuses_everything_while_empty() {
        let clock = FakeClock::new();
        let limiter = Limiter::new(clock.clone());
        let budget = rate(10, 2);
        let open = Quota::default();
        // Admitting checks the budget, never charges it.
        for _ in 0..5 {
            drop(limiter.admit(&"a", &open, Some(budget)).unwrap());
        }
        limiter.charge_denial(&"a", budget);
        limiter.charge_denial(&"a", budget);
        // Charged again while empty: stays empty, no harm.
        limiter.charge_denial(&"a", budget);
        let refused = limiter.admit(&"a", &open, Some(budget)).err().unwrap();
        assert_eq!(refused.limit, Limit::Denied);
        assert_eq!(refused.retry_after, Some(Duration::from_millis(100)));
        // Others aren't affected.
        drop(limiter.admit(&"b", &open, Some(budget)).unwrap());
        clock.advance(Duration::from_millis(100));
        drop(limiter.admit(&"a", &open, Some(budget)).unwrap());
    }

    #[test]
    fn idle_keys_are_forgotten_and_start_full() {
        let clock = FakeClock::new();
        let limiter = Limiter::new(clock.clone());
        let quota = Quota {
            rate: Some(rate(1, 1)),
            max_in_flight: None,
            max_watch_streams: None,
        };
        let held = limiter.admit(&"busy", &quota, plenty()).unwrap();
        drop(limiter.admit(&"done", &quota, plenty()).unwrap());
        // Neither bucket is full yet.
        assert!(limiter.evict_idle().is_empty());
        clock.advance(Duration::from_secs(1));
        // "busy" still has a call in flight.
        assert_eq!(limiter.evict_idle(), vec!["done"]);
        drop(held);
        assert_eq!(limiter.evict_idle(), vec!["busy"]);
        drop(limiter.admit(&"done", &quota, plenty()).unwrap());
    }

    #[test]
    fn the_most_specific_entry_wins_and_each_identity_counts_on_its_own() {
        let path = |p: &str| SecretPath::parse(p).unwrap();
        let quota = |n: u32| Quota {
            rate: None,
            max_in_flight: NonZeroU32::new(n),
            max_watch_streams: None,
        };
        let limits = Limits::new(
            NonZeroU32::new(64).unwrap(),
            quota(4),
            vec![(path("apps"), quota(8)), (path("apps/batch"), quota(32))],
        );
        assert_eq!(limits.quota(&path("ops/alice")), quota(4));
        assert_eq!(limits.quota(&path("apps/web")), quota(8));
        assert_eq!(limits.quota(&path("apps/batch")), quota(32));
        assert_eq!(limits.quota(&path("apps/batch/nightly")), quota(32));
        // Whole segments: `apps/batchy` isn't under `apps/batch`.
        assert_eq!(limits.quota(&path("apps/batchy")), quota(8));

        // Under one prefix, each identity has its own slots.
        let limiter = Limiter::new(FakeClock::new());
        let q = limits.quota(&path("apps/batch/nightly"));
        let held: Vec<_> = (0..32)
            .map(|_| {
                limiter
                    .admit(&path("apps/batch/nightly"), &q, plenty())
                    .unwrap()
            })
            .collect();
        assert!(
            limiter
                .admit(&path("apps/batch/nightly"), &q, plenty())
                .is_err()
        );
        drop(
            limiter
                .admit(&path("apps/batch/hourly"), &q, plenty())
                .unwrap(),
        );
        drop(held);
    }

    #[test]
    fn a_key_hovering_at_a_limit_is_one_episode_ended_after_the_quiet_period() {
        let start = Instant::now();
        let episodes = Episodes::default();
        let mut started = 0;
        // Refused every other second for a minute: one episode.
        for second in (0..60).step_by(2) {
            let now = start + Duration::from_secs(second);
            if episodes.refused(&"a", Limit::InFlight, now) {
                started += 1;
            }
            assert!(episodes.end_quiet(now + Duration::from_secs(1)).is_empty());
        }
        assert_eq!(started, 1);
        let last = start + Duration::from_secs(58);
        assert!(
            episodes
                .end_quiet(last + QUIET - Duration::from_millis(1))
                .is_empty()
        );
        assert_eq!(
            episodes.end_quiet(last + QUIET),
            vec![Ended {
                key: "a",
                limit: Limit::InFlight,
                refused: 30
            }]
        );
        // Another limit is another episode; a new refusal starts afresh.
        assert!(episodes.refused(&"a", Limit::Rate, last + QUIET));
        assert!(episodes.refused(&"a", Limit::InFlight, last + QUIET));
    }

    proptest! {
        /// Whatever the timing: at most `burst` pass at one instant, at
        /// most `burst + rate × window` in any window, and a refusal's wait
        /// is exact (the request passes after it, not a nanosecond before).
        #[test]
        fn the_rate_holds_in_every_window(
            per_second in 1u32..50,
            burst in 1u32..10,
            gaps in proptest::collection::vec(0u64..200, 1..200),
        ) {
            let r = rate(per_second, burst);
            let start = Instant::now();
            let mut bucket = Bucket::default();
            let mut passed: Vec<Instant> = Vec::new();
            let mut now = start;
            for gap in gaps {
                now += Duration::from_millis(gap);
                match bucket.take(r, now) {
                    Ok(()) => passed.push(now),
                    Err(wait) => {
                        let mut early = bucket;
                        prop_assert!(early.take(r, now + wait - Duration::from_nanos(1)).is_err());
                        prop_assert!(bucket.check(r, now + wait).is_ok());
                    }
                }
            }
            let interval = r.interval().as_nanos();
            for (i, &from) in passed.iter().enumerate() {
                for &to in &passed[i..] {
                    let window = (to - from).as_nanos();
                    let count = passed.iter().filter(|&&t| t >= from && t <= to).count();
                    let most = u128::from(burst) + window / interval;
                    prop_assert!(count as u128 <= most, "{count} in {window} ns, at most {most}");
                }
            }
        }
    }
}
