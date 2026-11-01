//! The watch hub: one change feed per server, fanned out to the
//! `WatchSecrets` streams this server serves. The feed polls the data
//! database every [`POLL`] for the live versions changed since its last
//! poll, by every server's writes (`Datastore::changes_since`, migration
//! 0004): exact under concurrent commits, and a poll that fails is retried
//! from the same mark, so nothing is lost while the database is away. The
//! streams themselves (authorization, rechecks, ending) are `grpc`'s.
//!
//! A stream that may have missed changes is told so (`Resync`), and must
//! read again what it watches: when more than [`MAX_PER_POLL`] changed at
//! once, or the data database restarted or failed over (every stream), and
//! when a stream falls more than [`BUFFER`] changes behind (that stream
//! alone). A stream is only told it's
//! subscribed once the feed is live (its mark taken), so it never misses a
//! change committed after it.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ferritor_datastore::{Change, ChangeMark, Changes, Datastore};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, broadcast, watch};
use tokio_util::sync::CancellationToken;

use crate::error_chain;
use crate::metrics::metrics;

/// Changes held for streams that haven't taken them yet; one further
/// behind is told to resync.
pub const BUFFER: usize = 4096;
/// Streams one server serves at once; one more is RESOURCE_EXHAUSTED.
pub const MAX_STREAMS: usize = 4096;
/// Streams one identity may have open on one server, unless its rate
/// limits say otherwise (`max_watch_streams`): so no one identity takes
/// every one of [`MAX_STREAMS`].
pub const DEFAULT_MAX_PER_IDENTITY: u32 = 256;
/// Paths and prefixes one stream may watch, together.
pub const MAX_ITEMS: usize = 1024;
/// How often a stream rechecks its client certificate (expired, revoked,
/// its issuing CA no longer trusted) and every permission it was granted.
pub const RECHECK: Duration = Duration::from_secs(30);
/// How long a new stream waits for the feed to be live.
pub const LIVE_WAIT: Duration = Duration::from_secs(10);
/// How often the feed asks the data database what changed: the most a
/// change waits before its streams hear of it (and one small query per
/// server this often).
pub const POLL: Duration = Duration::from_millis(250);
/// Changes one poll tells one by one; more is a `Resync` for every stream.
pub const MAX_PER_POLL: u32 = 10_000;
/// How long one transaction may hold the feed back (every poll reads all
/// changes since it began) before the feed warns of it.
pub const HELD_BACK_WARNING: Duration = Duration::from_secs(300);
/// The longest wait between two attempts after the database failed.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// What a stream is sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Change(Change),
    /// Changes may have been missed: read everything again.
    Resync,
}

/// See the module docs.
pub struct Watch {
    events: broadcast::Sender<Event>,
    streams: Arc<Semaphore>,
    /// Streams open per identity, for those with a cap.
    per_identity: Arc<Mutex<HashMap<String, u32>>>,
    live: watch::Sender<bool>,
    closing: CancellationToken,
    held: Mutex<Held>,
}

/// The oldest transaction running at the last mark, and since when the
/// marks have had it (`ChangeMark::oldest_running`).
#[derive(Default)]
struct Held {
    by: Option<(u64, std::time::Instant)>,
    warned: bool,
}

/// A stream's subscription: its events, and its place among the server's
/// streams (released when dropped).
pub struct Subscription {
    pub events: broadcast::Receiver<Event>,
    _slot: OwnedSemaphorePermit,
    _identity_slot: Option<IdentitySlot>,
}

/// A stream's place among its identity's: released when dropped.
struct IdentitySlot {
    counts: Arc<Mutex<HashMap<String, u32>>>,
    identity: String,
}

impl Drop for IdentitySlot {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.identity) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.identity);
            }
        }
    }
}

/// Why no subscription.
#[derive(Debug, thiserror::Error)]
pub enum SubscribeError {
    #[error("this server serves as many watch streams as it can; try another, or later")]
    Full,
    #[error("this identity has as many watch streams open as it may ({0}); close one")]
    IdentityFull(NonZeroU32),
    #[error("the change feed can't reach the data database; retry")]
    NotLive,
    #[error("the server is shutting down")]
    Closing,
}

impl Default for Watch {
    fn default() -> Self {
        Self {
            events: broadcast::channel(BUFFER).0,
            streams: Arc::new(Semaphore::new(MAX_STREAMS)),
            per_identity: Arc::default(),
            live: watch::Sender::new(false),
            closing: CancellationToken::new(),
            held: Mutex::default(),
        }
    }
}

impl Watch {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Runs the feed on `store` until the server closes: takes a mark,
    /// then polls from it every [`POLL`]. A failed poll is retried from the
    /// same mark, with backoff, so nothing is lost; new streams wait for
    /// the feed meanwhile, open ones hear of the changes once it's back.
    pub async fn run(self: Arc<Self>, store: Datastore) {
        let mut backoff = Duration::from_secs(1);
        let mut mark = None;
        while !self.closing.is_cancelled() {
            let wait = match &mark {
                None => match store.change_mark().await {
                    Ok(first) => {
                        mark = Some(first);
                        self.live.send_replace(true);
                        POLL
                    }
                    Err(e) => {
                        tracing::warn!(error = %error_chain(&e), "change feed can't start");
                        backoff
                    }
                },
                Some(since) => match store.changes_since(since, MAX_PER_POLL).await {
                    Ok(Changes::Since(next, changes)) => {
                        for change in changes {
                            self.send(Event::Change(change));
                        }
                        mark = Some(next);
                        self.recovered();
                        backoff = Duration::from_secs(1);
                        POLL
                    }
                    Ok(Changes::TooMany(next)) => {
                        tracing::warn!(
                            limit = MAX_PER_POLL,
                            "more changes at once than a poll tells: every watch reads again"
                        );
                        metrics().watch_resync("too_many");
                        self.send(Event::Resync);
                        mark = Some(next);
                        self.recovered();
                        POLL
                    }
                    Ok(Changes::Restarted(next)) => {
                        tracing::warn!(
                            "the data database restarted or failed over: every watch reads again"
                        );
                        metrics().watch_resync("restarted");
                        self.send(Event::Resync);
                        mark = Some(next);
                        self.recovered();
                        POLL
                    }
                    Err(e) => {
                        if self.live.send_replace(false) {
                            tracing::warn!(
                                error = %error_chain(&e),
                                "change feed can't poll; retrying from where it was"
                            );
                        }
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        backoff
                    }
                },
            };
            if let Some(mark) = &mark {
                self.note_held(mark);
            }
            tokio::select! {
                () = self.closing.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
        }
    }

    /// Follows the oldest transaction running at each mark: one that stays
    /// past [`HELD_BACK_WARNING`] is warned of once, and its end noted.
    fn note_held(&self, mark: &ChangeMark) {
        self.note_oldest(mark.oldest_running(), std::time::Instant::now());
    }

    /// [`Watch::note_held`], at `now`; true when it warns.
    fn note_oldest(&self, oldest: Option<u64>, now: std::time::Instant) -> bool {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        match (held.by, oldest) {
            (Some((xid, _)), Some(now)) if xid == now => {}
            (_, oldest) => {
                if held.warned {
                    tracing::info!("the transaction holding the change feed back has ended");
                }
                held.by = oldest.map(|xid| (xid, now));
                held.warned = false;
            }
        }
        let Some((xid, since)) = held.by else {
            return false;
        };
        let held_for = now.saturating_duration_since(since);
        if !held.warned && held_for >= HELD_BACK_WARNING {
            held.warned = true;
            tracing::warn!(
                transaction = xid,
                held_s = held_for.as_secs(),
                "a transaction open this long on the data database's Postgres server (any \
                 database there) makes every change feed poll read every change since it \
                 began: find it in pg_stat_activity by backend_xid and end it"
            );
            return true;
        }
        false
    }

    /// How long the oldest transaction running has held the feed back
    /// (zero with none).
    pub fn held_back(&self) -> Duration {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .by
            .map_or(Duration::ZERO, |(_, since)| since.elapsed())
    }

    /// Live again after failed polls.
    fn recovered(&self) {
        if !self.live.send_replace(true) {
            tracing::info!("change feed polling again");
        }
    }

    fn send(&self, event: Event) {
        // No receiver: no stream open, nothing to tell.
        self.events.send(event).ok();
    }

    /// A subscription, once the feed is live (at most [`LIVE_WAIT`]):
    /// counted among `identity`'s streams too, if it's given with its cap.
    pub async fn subscribe(
        &self,
        identity: Option<(&str, NonZeroU32)>,
    ) -> Result<Subscription, SubscribeError> {
        if self.closing.is_cancelled() {
            return Err(SubscribeError::Closing);
        }
        let identity_slot = match identity {
            None => None,
            Some((identity, cap)) => {
                let mut counts = self
                    .per_identity
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let count = counts.entry(identity.to_owned()).or_insert(0);
                if *count >= cap.get() {
                    return Err(SubscribeError::IdentityFull(cap));
                }
                *count += 1;
                Some(IdentitySlot {
                    counts: Arc::clone(&self.per_identity),
                    identity: identity.to_owned(),
                })
            }
        };
        let slot = match Arc::clone(&self.streams).try_acquire_owned() {
            Ok(slot) => slot,
            Err(TryAcquireError::NoPermits | TryAcquireError::Closed) => {
                return Err(SubscribeError::Full);
            }
        };
        // Subscribed first, then live: a change once live is never missed.
        let events = self.events.subscribe();
        let mut live = self.live.subscribe();
        tokio::time::timeout(LIVE_WAIT, live.wait_for(|live| *live))
            .await
            .map_err(|_| SubscribeError::NotLive)?
            .map_err(|_| SubscribeError::NotLive)?;
        Ok(Subscription {
            events,
            _slot: slot,
            _identity_slot: identity_slot,
        })
    }

    /// Ended when the server starts to shut down: every stream ends then,
    /// so none holds the drain open.
    pub fn closing(&self) -> CancellationToken {
        self.closing.clone()
    }

    /// Ends every stream and the feed (the shutdown's drain).
    pub fn close(&self) {
        self.closing.cancel();
    }

    /// Whether the feed polls (new streams are subscribed).
    pub fn is_live(&self) -> bool {
        *self.live.borrow()
    }

    /// Streams open now.
    pub fn streams(&self) -> usize {
        MAX_STREAMS - self.streams.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// At most [`MAX_STREAMS`] at once; a closed stream frees its place, and
    /// none is given once the server is closing.
    #[tokio::test]
    async fn streams_are_capped_and_freed() -> Result<(), SubscribeError> {
        let hub = Watch::new();
        hub.live.send_replace(true);
        let mut open = Vec::with_capacity(MAX_STREAMS);
        for _ in 0..MAX_STREAMS {
            open.push(hub.subscribe(None).await?);
        }
        assert_eq!(hub.streams(), MAX_STREAMS);
        assert!(matches!(
            hub.subscribe(None).await,
            Err(SubscribeError::Full)
        ));
        open.pop();
        open.push(hub.subscribe(None).await?);
        hub.close();
        open.pop();
        assert!(matches!(
            hub.subscribe(None).await,
            Err(SubscribeError::Closing)
        ));
        Ok(())
    }

    /// An identity's own cap, counted apart from every other identity's,
    /// and freed as its streams close.
    #[tokio::test]
    async fn an_identitys_streams_are_capped() -> Result<(), SubscribeError> {
        let hub = Watch::new();
        hub.live.send_replace(true);
        let two = NonZeroU32::MIN.saturating_add(1);
        let first = hub.subscribe(Some(("a", two))).await?;
        let _second = hub.subscribe(Some(("a", two))).await?;
        assert!(matches!(
            hub.subscribe(Some(("a", two))).await,
            Err(SubscribeError::IdentityFull(_))
        ));
        let _other = hub.subscribe(Some(("b", two))).await?;
        let _uncounted = hub.subscribe(None).await?;
        drop(first);
        let _again = hub.subscribe(Some(("a", two))).await?;
        Ok(())
    }

    /// The same oldest transaction poll after poll is followed from its
    /// first sighting, warned of once past the threshold, and forgotten
    /// when it ends; a quiet database (none running) holds nothing back.
    #[test]
    fn a_transaction_held_open_is_warned_of_once() {
        let hub = Watch::new();
        let t0 = std::time::Instant::now();
        assert!(!hub.note_oldest(None, t0));
        assert_eq!(hub.held_back(), Duration::ZERO);
        assert!(!hub.note_oldest(Some(7), t0));
        assert!(!hub.note_oldest(Some(7), t0 + HELD_BACK_WARNING / 2));
        assert!(hub.note_oldest(Some(7), t0 + HELD_BACK_WARNING));
        assert!(!hub.note_oldest(Some(7), t0 + HELD_BACK_WARNING * 2));
        // Another one: followed from now, not from the first's start.
        let t1 = t0 + HELD_BACK_WARNING * 3;
        assert!(!hub.note_oldest(Some(9), t1));
        assert!(!hub.note_oldest(Some(9), t1 + HELD_BACK_WARNING / 2));
        assert!(hub.note_oldest(Some(9), t1 + HELD_BACK_WARNING));
        assert!(!hub.note_oldest(None, t1 + HELD_BACK_WARNING * 2));
        assert_eq!(hub.held_back(), Duration::ZERO);
    }
}
