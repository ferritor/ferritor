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
//! **Where it goes.** A file of its own (`audit_file`, [`AuditLog::open`]),
//! a collector over OTLP (`[audit_otlp]`, `audit_otlp`), or both; secured
//! mode needs one. Only dev mode without either writes it to stdout
//! ([`AuditLog::stdout`]); the server's logs go to stderr. The file is
//! reopened on SIGHUP ([`AuditLog::reopen`]) and rotated by size with
//! `audit_file_max_bytes` ([`Rotation`]): either way the chain ends in the
//! old file and a new one starts in the new, so a rotated file holds whole
//! chains.
//!
//! The writing happens on a dedicated thread: a stalled file (a hung disk)
//! or stdout (a full pipe nobody reads) then stalls only that thread, while requests time out as
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
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Semaphore, mpsc, oneshot};

use ed25519_dalek::SigningKey;
use ferritor_core::audit_chain::{Chain, Seal};

use crate::audit_otlp::Otlp;
pub use crate::audit_otlp::OtlpSettings;
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

/// The writer takes what's queued, up to this many entries or about
/// [`BATCH_BYTES`], writes it, sends it to the collector in one export
/// (with `[audit_otlp]`) and only then answers: one round trip per batch,
/// not per entry.
const BATCH: usize = 512;
/// A batch's lines, about at most: the batch ends once it's past this, so
/// with lines up to 1 MiB (the verifier's limit) about 2 MiB, still below
/// a collector's usual 4 MiB limit on a request.
const BATCH_BYTES: usize = 1024 * 1024;

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
    /// Close the file and open its path again (SIGHUP, once logrotate has
    /// moved it): the chain ends in the old file and a new one starts in
    /// the new. Nothing for a stream (stdout).
    Reopen,
}

/// Where the writer writes: a stream (stdout, a test's buffer) or a file
/// it can reopen.
trait Sink: Write + Send + 'static {
    /// Whether [`Sink::reopen`] does anything: a file, not a stream.
    fn reopens(&self) -> bool {
        false
    }

    /// Closes the output and opens it again.
    fn reopen(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Whether it has reached its size and is due a rotation
    /// ([`Sink::rotate`]).
    fn full(&self) -> bool {
        false
    }

    /// Moves the output aside (keeping a few) and opens a new one: whether
    /// it moved (the old one is no longer the one written to), and how the
    /// whole went. A rename that worked and an open that didn't: moved,
    /// and an error.
    fn rotate(&mut self) -> (bool, io::Result<()>) {
        (false, Ok(()))
    }
}

/// A stream: written as it is, never reopened.
struct Stream<W>(W);

impl<W: Write> Write for Stream<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<W: Write + Send + 'static> Sink for Stream<W> {}

/// No file and no stdout: `[audit_otlp]` alone. Every line goes to the
/// collector only.
struct Nowhere;

impl Write for Nowhere {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Sink for Nowhere {}

/// Rotating the audit log's file by size (`audit_file_max_bytes`): once it
/// holds `max_bytes`, it's renamed `<path>.1` (the older ones moving up to
/// `<path>.<keep>`, the oldest dropped) and a new file starts, each holding
/// whole chains. So it never takes much more than `keep + 1` times
/// `max_bytes` of disk, with nothing outside the server to rotate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rotation {
    pub max_bytes: u64,
    /// Rotated files kept, at least 1.
    pub keep: u32,
}

/// The audit log's file (`audit_file`), appended to, created `0600`. A
/// reopen that fails leaves it closed: every write then tries to open it
/// again and fails while it can't, so requests are refused (fail closed)
/// until the path can be opened again.
struct AuditFile {
    path: PathBuf,
    file: Option<File>,
    rotation: Option<Rotation>,
    /// The file's size as written to (what it had when opened, plus).
    len: u64,
    /// After a rotation that failed, the size to try again at: another
    /// `max_bytes` on, not after every line.
    retry_at: Option<u64>,
}

impl AuditFile {
    fn open(path: &Path, rotation: Option<Rotation>) -> io::Result<Self> {
        let file = open_append(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            path: path.to_owned(),
            file: Some(file),
            rotation,
            len,
            retry_at: None,
        })
    }

    /// `<path>.<n>`.
    fn rotated(&self, n: u32) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }

    /// Opens the path afresh, its size as it is: a new file's count starts
    /// over, nothing kept from the old one (its size, a retry threshold).
    /// Until it opens, nothing counts as full.
    fn open_again(&mut self) -> io::Result<()> {
        self.file = None;
        self.len = 0;
        self.retry_at = None;
        let file = open_append(&self.path)?;
        self.len = file.metadata()?.len();
        self.file = Some(file);
        Ok(())
    }

    fn file(&mut self) -> io::Result<&mut File> {
        if self.file.is_none() {
            // Its size with it, so rotation counts from what's there.
            self.open_again()?;
        }
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("the audit log file is closed"))
    }
}

impl Write for AuditFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.file()?.write(buf)?;
        self.len += u64::try_from(written).unwrap_or(u64::MAX);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.file {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl Sink for AuditFile {
    fn reopens(&self) -> bool {
        true
    }

    fn reopen(&mut self) -> io::Result<()> {
        // Closed first: if the path can't be opened, nothing more goes to
        // the old file (logrotate may compress or delete it).
        self.open_again()
    }

    fn full(&self) -> bool {
        self.rotation
            .is_some_and(|rotation| self.len >= self.retry_at.unwrap_or(rotation.max_bytes))
    }

    fn rotate(&mut self) -> (bool, io::Result<()>) {
        let Some(rotation) = self.rotation else {
            return (false, Ok(()));
        };
        let moved = (|| {
            for n in (1..rotation.keep).rev() {
                match std::fs::rename(self.rotated(n), self.rotated(n + 1)) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                    _ => {}
                }
            }
            std::fs::rename(&self.path, self.rotated(1))
        })();
        if let Err(e) = moved {
            // Still written to as it is: refusing requests for want of a
            // rename would be worse. Tried again another max_bytes on.
            self.retry_at = Some(self.len.saturating_add(rotation.max_bytes));
            return (false, Err(e));
        }
        self.retry_at = None;
        // Moved: if the new file won't open, every write tries again (and is
        // refused meanwhile), as after a failed reopen.
        (true, self.open_again())
    }
}

/// `path` opened for appending, created `0600` if it doesn't exist (an
/// existing file keeps its mode: startup warns if others may read it). A
/// file whose last line was cut off (a crash, a full disk) gets a newline
/// first, so the fragment stays a line of its own instead of running into
/// the new chain's start.
fn open_append(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::FileExt;
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    let len = file.metadata()?.len();
    if len > 0 {
        let mut last = [0u8];
        file.read_exact_at(&mut last, len - 1)?;
        if last != *b"\n" {
            file.write_all(b"\n")?;
        }
    }
    Ok(file)
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
    /// Nothing waits for queued entries at exit; [`AuditLog::file`] and
    /// [`AuditLog::stdout`], the server's, come with a [`Drain`] for that. Chained, but
    /// unsigned: no checkpoints.
    pub fn new(out: impl Write + Send + 'static, timeout: Duration) -> io::Result<Self> {
        Self::start(Stream(out), None, timeout, None, CHECKPOINT_INTERVAL).map(|(log, _)| log)
    }

    /// Like [`AuditLog::new`], with checkpoints signed by `key`, and a
    /// [`Drain`].
    pub fn signed(
        out: impl Write + Send + 'static,
        timeout: Duration,
        key: SigningKey,
    ) -> io::Result<(Self, Drain)> {
        Self::start(Stream(out), None, timeout, Some(key), CHECKPOINT_INTERVAL)
    }

    /// `every`: [`CHECKPOINT_INTERVAL`], except in tests.
    fn start(
        out: impl Sink,
        otlp: Option<(OtlpSettings, Duration)>,
        timeout: Duration,
        key: Option<SigningKey>,
        every: Duration,
    ) -> io::Result<(Self, Drain)> {
        let signed = key.is_some();
        let chain = Chain::new(key).map_err(io::Error::other)?;
        let (queue, entries) = mpsc::channel::<Pending>(QUEUE);
        // The collector's client is built on the writer thread, its runtime
        // with it: a runtime must never be dropped inside the server's own
        // (it panics there), and the thread is where it's used.
        let (built, ready) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("ferritor-audit".to_owned())
            .spawn(move || {
                let otlp = match otlp
                    .map(|(settings, timeout)| Otlp::new(&settings, timeout))
                    .transpose()
                {
                    Ok(otlp) => {
                        built.send(Ok(())).ok();
                        otlp
                    }
                    Err(e) => {
                        built.send(Err(e)).ok();
                        return;
                    }
                };
                write_chain(out, otlp, chain, entries);
            })?;
        ready
            .recv()
            .map_err(|_| io::Error::other("the audit writer stopped while starting"))??;
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
    /// Dev mode only, without an audit device (`audit_file`,
    /// `[audit_otlp]`); nothing else writes to stdout (the server logs to
    /// stderr). Checkpoints are signed with `key`, if given. A
    /// [`AuditLog::reopen`] does nothing.
    pub fn stdout(timeout: Duration, key: Option<SigningKey>) -> io::Result<(Self, Drain)> {
        let fd = io::stdout().as_fd().try_clone_to_owned()?;
        Self::start(
            Stream(File::from(fd)),
            None,
            timeout,
            key,
            CHECKPOINT_INTERVAL,
        )
    }

    /// Appends to the file at `path` (`audit_file`), created `0600`; fails
    /// (and so does startup) if it can't be opened. [`AuditLog::reopen`]
    /// opens the path again, for logrotate. A recorded entry has been
    /// written to the file: in the kernel's cache, not necessarily on disk
    /// yet. Checkpoints are signed with `key`, if given.
    pub fn file(
        path: &Path,
        timeout: Duration,
        key: Option<SigningKey>,
    ) -> io::Result<(Self, Drain)> {
        Self::open(Some((path, None)), None, timeout, key)
    }

    /// The server's audit devices: the file at `file` (rotated by size
    /// with a [`Rotation`]), the collector of `otlp`, or both (every entry
    /// then written to the file and acknowledged by the collector before
    /// it counts as recorded); neither is stdout ([`AuditLog::stdout`], dev
    /// mode). Fails if the file can't be opened; the collector is connected
    /// to when first used. An export waits at most three quarters of
    /// `timeout`: an entry it refuses is usually refused as a failed write,
    /// but one queued behind an export still in flight may wait past
    /// `timeout`, and is then refused as a timeout (and may be delivered
    /// later, as any entry that timed out).
    pub fn open(
        file: Option<(&Path, Option<Rotation>)>,
        otlp: Option<OtlpSettings>,
        timeout: Duration,
        key: Option<SigningKey>,
    ) -> io::Result<(Self, Drain)> {
        let otlp = otlp.map(|settings| (settings, timeout.mul_f32(0.75)));
        match file {
            // The file first: a path that won't open fails before anything
            // else is built.
            Some((path, rotation)) => Self::start(
                AuditFile::open(path, rotation)?,
                otlp,
                timeout,
                key,
                CHECKPOINT_INTERVAL,
            ),
            None if otlp.is_some() => Self::start(Nowhere, otlp, timeout, key, CHECKPOINT_INTERVAL),
            None => Self::stdout(timeout, key),
        }
    }

    /// Queues a reopen of the file (SIGHUP): the chain so far ends in the
    /// old file (signed, with a key) and a new one starts in the file now at
    /// the path; entries queued before it go to the old file, those after
    /// to the new. The writer logs how it went. Never waits: `false` only
    /// if it couldn't be queued (the queue full: the file stalled).
    pub fn reopen(&self) -> bool {
        self.queue.try_send(Pending::Reopen).is_ok()
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

/// Where a caller would be, in the scheduler's entries (see `schedule`):
/// no identity can be it (one never holds a `:`), so it's never a caller's.
pub const SCHEDULER: &str = "ferritor:scheduler";

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
    /// `false` if the queue isn't written within `limit` (the file or
    /// stdout stalled, or failing).
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

    /// Reopens the audit log's file (SIGHUP; see [`AuditLog::reopen`]):
    /// queued ahead of anything recorded after it, never waited for.
    pub fn reopen_audit_log(&self) {
        if !self.log.reopen() {
            tracing::error!(
                "AUDIT LOG NOT REOPENED: its queue is full (the file stalled); send SIGHUP again"
            );
            metrics().reload("audit_log", "failed");
        }
    }

    /// Audit entries waiting for the writer (for metrics): it climbs while
    /// the audit log stalls, before anything is refused for want of
    /// auditing.
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
        self.record_outcome(caller_name(caller), action, target, operation, outcome);
    }

    /// Records that a scheduled run of `task` starts (see `schedule`), as
    /// [`SCHEDULER`], and waits for it to be written: fail closed, like an
    /// allowed request, so the run must not start if this fails.
    pub async fn scheduled(&self, action: Action, task: &'static str) -> Result<(), AuditError> {
        let recorded = line(Event::Scheduled {
            caller: SCHEDULER,
            action,
            task,
        });
        match recorded {
            Ok(line) => self.log.written(line).await,
            Err(e) => Err(e),
        }
        .inspect_err(|e| {
            let error = crate::error_chain(e);
            tracing::error!(%error, task, "AUDIT LOG FAILED: a scheduled run didn't start");
            metrics().audit_failure("refused");
        })
    }

    /// Records how a scheduled run of `task` ended, as [`SCHEDULER`].
    /// Queued, like any outcome.
    pub fn scheduled_outcome(&self, action: Action, task: &'static str, outcome: Outcome) {
        self.record_outcome(Some(SCHEDULER), action, Target::System, task, outcome);
    }

    fn record_outcome(
        &self,
        caller: Option<&str>,
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
            caller,
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
            let caller = caller.unwrap_or("unauthenticated");
            tracing::error!(%error, caller, operation, result, "AUDIT LOG FAILED: an outcome went unrecorded");
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
    /// A scheduled run starts (see `schedule`), written before its first
    /// batch.
    Scheduled {
        caller: &'static str,
        action: Action,
        task: &'static str,
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
/// when the [`Drain`] asks. It takes what's queued as a batch: every line
/// written, the batch sent to the collector (if any), then every entry
/// answered, each with its own write's result and the export's.
fn write_chain(
    out: impl Sink,
    otlp: Option<Otlp>,
    chain: Chain,
    mut entries: mpsc::Receiver<Pending>,
) {
    let lost = |e: &dyn std::fmt::Display| {
        tracing::error!(error = %e, "AUDIT LOG WRITE FAILED: an entry is lost");
        metrics().audit_failure("lost");
    };
    let mut writer = Writer {
        out,
        otlp,
        chain,
        cut: false,
        broken: false,
    };
    // At once, so the chain starts before anything is recorded; if it
    // fails, the first entry tries again.
    if let Err(e) = writer.start().and_then(|()| writer.ship()) {
        lost(&e);
    }
    let answer = |written: Written, result: io::Result<()>| match (written, result) {
        (Some(written), result) => {
            written.send(result).ok();
        }
        (None, Err(e)) => lost(&e),
        (None, Ok(())) => {}
    };
    let mut answers: Vec<(Written, io::Result<()>)> = Vec::new();
    while let Some(first) = entries.blocking_recv() {
        let mut next = Some(first);
        let (mut count, mut bytes) = (0, 0);
        while let Some(pending) = next.take() {
            match pending {
                Pending::Entry { line, written } => {
                    bytes += line.len();
                    answers.push((written, writer.entry(&line)));
                    if writer.chain.checkpoint_due() {
                        answers.push((None, writer.seal(Seal::Checkpoint)));
                    }
                }
                Pending::Checkpoint { written } => {
                    answers.push((written, writer.seal(Seal::Checkpoint)));
                }
                Pending::End { written } => {
                    answers.push((written, writer.end()));
                    // Never a rotation here: it would start a new chain after
                    // the drain's end. The next entry rotates it if it must.
                    count += 1;
                    if count < BATCH && bytes < BATCH_BYTES {
                        next = entries.try_recv().ok();
                    }
                    continue;
                }
                Pending::Reopen => writer.reopen(),
            }
            if writer.out.full() {
                writer.rotate();
            }
            count += 1;
            if count < BATCH && bytes < BATCH_BYTES {
                next = entries.try_recv().ok();
            }
        }
        let shipped = writer.ship();
        for (written, result) in answers.drain(..) {
            let result = match (&shipped, result) {
                (_, Err(e)) => Err(e),
                (Err(e), Ok(())) => Err(io::Error::new(e.kind(), e.to_string())),
                (Ok(()), Ok(())) => Ok(()),
            };
            answer(written, result);
        }
    }
}

/// The outputs and the chain being written to them.
struct Writer<W> {
    out: W,
    /// `[audit_otlp]`'s collector: every line written to `out` also goes to
    /// it, at the batch's end ([`Writer::ship`]).
    otlp: Option<Otlp>,
    chain: Chain,
    /// The last write failed partway: the file ends in part of a line.
    cut: bool,
    /// A write or an export failed since the last chain started: entries
    /// were lost and the chain was broken off, so it can't be ended.
    broken: bool,
}

impl<W: Sink> Writer<W> {
    /// Sends the collector the lines written since the last export, and
    /// waits for its acknowledgement. One that doesn't come breaks the
    /// chain off: the collector may lack those lines, so the next line
    /// starts a new chain, which both outputs get.
    fn ship(&mut self) -> io::Result<()> {
        let Some(otlp) = &mut self.otlp else {
            return Ok(());
        };
        let shipped = otlp.export();
        if let Err(error) = &shipped {
            tracing::error!(%error, "AUDIT LOG NOT DELIVERED to the collector: entries refused");
            self.chain.write_failed();
            self.broken = true;
        }
        shipped
    }

    /// A file grown to its size: the chain ends in it (a signed
    /// `chain_end`), it's moved aside and a new file starts with a new
    /// chain. A rename that fails keeps writing to the file as it is.
    fn rotate(&mut self) {
        if let Err(error) = self.seal(Seal::End) {
            tracing::error!(%error, "the audit log's chain couldn't be ended before rotating");
        }
        let (moved, rotated) = self.out.rotate();
        if moved {
            // The fragment, if any, went with the old file: no part of a line
            // to end in the new one. Kept when it didn't move: the same file,
            // whose cut line still needs its newline.
            self.cut = false;
        }
        match (moved, rotated) {
            (_, Ok(())) => tracing::info!("rotated the audit log file (audit_file_max_bytes)"),
            (true, Err(error)) => tracing::error!(
                %error,
                "AUDIT LOG NOT REOPENED after rotating it: requests are refused until its file \
                 can be opened (tried again at every entry)"
            ),
            (false, Err(error)) => tracing::error!(
                %error,
                "AUDIT LOG FILE NOT ROTATED: still writing to it, past audit_file_max_bytes \
                 (tried again once it has grown as much again)"
            ),
        }
        self.chain.write_failed();
        if let Err(error) = self.start() {
            tracing::error!(%error, "AUDIT LOG WRITE FAILED: the new chain's start");
        }
    }

    /// A file's reopen (a stream's is nothing): ends the chain in the old
    /// file (a signed `chain_end`; unsigned, a flush), opens the path again
    /// and starts a chain there. If the path
    /// can't be opened, the chain is broken off: the next entry tries to
    /// open it and starts a new chain once it can.
    fn reopen(&mut self) {
        if !self.out.reopens() {
            return;
        }
        if let Err(error) = self.seal(Seal::End) {
            tracing::error!(%error, "the audit log's chain couldn't be ended before the reopen");
        }
        match self.out.reopen() {
            Ok(()) => {
                tracing::info!("reopened the audit log file");
                metrics().reload("audit_log", "succeeded");
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    "AUDIT LOG NOT REOPENED: requests are refused until its file can be opened \
                     (tried again at every entry)"
                );
                metrics().reload("audit_log", "failed");
            }
        }
        // A new file: no part of a line to end in it, and a new chain.
        self.cut = false;
        self.chain.write_failed();
        if let Err(error) = self.start() {
            tracing::error!(%error, "AUDIT LOG WRITE FAILED: the new chain's start");
        }
    }

    /// A new chain's start (after the end of the last one, or a failed
    /// write).
    fn start(&mut self) -> io::Result<()> {
        let start = self.chain.start(&now()).map_err(io::Error::other)?;
        let started = self.put(&start, None);
        // Written in full, the new chain stands, even if the flush then
        // failed (the error still goes back): nothing lost is in it.
        if !self.chain.needs_start() {
            self.broken = false;
        }
        started
    }

    /// The drain's end: the chain's signed `chain_end`. A chain a failure
    /// broke off can't be ended, and entries were lost: an error, so the
    /// drain says so. One already ended (a second drain) is fine.
    fn end(&mut self) -> io::Result<()> {
        if self.broken {
            return Err(io::Error::other(
                "audit entries were lost and the chain broken off: it couldn't be ended",
            ));
        }
        self.seal(Seal::End)
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
        if let Some(otlp) = &mut self.otlp {
            otlp.push(line, self.chain.id(), self.chain.next_seq());
        }
        self.chain.written(line, seal);
        self.out.flush()
    }

    fn failed(&mut self, written: usize) {
        self.chain.write_failed();
        self.broken = true;
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
            Stream(Slow(audit.clone())),
            None,
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
            Stream(Stalled(blocked)),
            None,
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

    /// A directory of its own for a test's audit files, removed when
    /// dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ferritor-audit-{name}-{}-{}",
                std::process::id(),
                now().replace(':', "")
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn verified_file(path: &Path) -> audit_chain::Report {
        let file = std::io::BufReader::new(File::open(path).unwrap());
        audit_chain::verify(file, &[signing_key().verifying_key()]).unwrap()
    }

    /// logrotate's way: the file renamed, then SIGHUP. The chain ends in
    /// the old file and a new one starts in the new, each proven whole;
    /// what was recorded before the reopen is in the old one, what after in
    /// the new. A new file is created 0600.
    #[tokio::test]
    async fn a_reopen_ends_the_chain_in_the_old_file_and_starts_one_in_the_new() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("reopen");
        let (path, rotated) = (dir.0.join("audit.log"), dir.0.join("audit.log.1"));
        let (log, drain) =
            AuditLog::file(&path, Duration::from_secs(1), Some(signing_key())).unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        gate.check(&alice(), Action::Read, Target::System)
            .await
            .unwrap();
        std::fs::rename(&path, &rotated).unwrap();
        gate.reopen_audit_log();
        gate.check(&alice(), Action::List, Target::System)
            .await
            .unwrap();
        assert!(drain.wait(Duration::from_secs(2)).await);

        let old = verified_file(&rotated);
        assert_eq!(old.verdict(), Verdict::Proven, "{old:?}");
        // start, the read, chain_end.
        assert_eq!(old.chains.len(), 1);
        assert_eq!(old.chains[0].entries, 3);
        let new = verified_file(&path);
        assert_eq!(new.verdict(), Verdict::Proven, "{new:?}");
        // start, the list, chain_end (the drain).
        assert_eq!(new.chains[0].entries, 3);
        let actions = |path: &Path| -> Vec<String> {
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .filter_map(|entry| entry["action"].as_str().map(str::to_owned))
                .collect()
        };
        assert_eq!(actions(&rotated), ["read"]);
        assert_eq!(actions(&path), ["list"]);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// A reopen that can't open the path fails closed: requests are refused
    /// unaudited, nothing more goes to the old file, and once the path can
    /// be opened again the next entry starts a new chain there.
    #[tokio::test]
    async fn a_failed_reopen_refuses_until_the_file_can_be_opened() {
        let dir = TempDir::new("failed-reopen");
        let logs = dir.0.join("logs");
        std::fs::create_dir(&logs).unwrap();
        let (path, moved) = (logs.join("audit.log"), dir.0.join("moved"));
        let (log, drain) =
            AuditLog::file(&path, Duration::from_secs(1), Some(signing_key())).unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        gate.check(&alice(), Action::Read, Target::System)
            .await
            .unwrap();
        // The whole directory gone: the path can't be created.
        std::fs::rename(&logs, &moved).unwrap();
        gate.reopen_audit_log();
        assert!(matches!(
            gate.check(&alice(), Action::List, Target::System).await,
            Err(Refused::Unaudited(AuditError::Write(_)))
        ));
        std::fs::create_dir(&logs).unwrap();
        gate.check(&alice(), Action::Write, Target::System)
            .await
            .unwrap();
        assert!(drain.wait(Duration::from_secs(2)).await);

        // The old file: its chain ended before the reopen, nothing after.
        let old = verified_file(&moved.join("audit.log"));
        assert_eq!(old.verdict(), Verdict::Proven, "{old:?}");
        assert_eq!(old.chains[0].entries, 3);
        // The new one: a chain from the first entry it could take.
        let new = verified_file(&path);
        assert_eq!(new.verdict(), Verdict::Proven, "{new:?}");
        assert_eq!((new.chains.len(), new.chains[0].entries), (1, 3));
    }

    /// A collector on loopback, keeping every audit record's body, in
    /// order; refusing every export while `refuse` is set.
    #[derive(Clone, Default)]
    struct Collector {
        bodies: Arc<Mutex<Vec<String>>>,
        /// Each record's `ferritor.audit.chain` and `ferritor.audit.seq`.
        places: Arc<Mutex<Vec<(String, i64)>>>,
        refuse: Arc<std::sync::atomic::AtomicBool>,
    }

    #[tonic::async_trait]
    impl opentelemetry_proto::tonic::collector::logs::v1::logs_service_server::LogsService
        for Collector
    {
        async fn export(
            &self,
            request: tonic::Request<
                opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest,
            >,
        ) -> Result<
            tonic::Response<
                opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceResponse,
            >,
            tonic::Status,
        > {
            use opentelemetry_proto::tonic::common::v1::any_value::Value;
            if self.refuse.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(tonic::Status::unavailable("refusing"));
            }
            let mut bodies = self.bodies.lock().unwrap_or_else(PoisonError::into_inner);
            for scope in request
                .into_inner()
                .resource_logs
                .into_iter()
                .flat_map(|r| r.scope_logs)
            {
                assert_eq!(
                    scope.scope.map(|s| s.name).as_deref(),
                    Some("ferritor.audit")
                );
                for record in scope.log_records {
                    let attribute = |key: &str| {
                        record
                            .attributes
                            .iter()
                            .find(|kv| kv.key == key)
                            .and_then(|kv| kv.value.clone())
                            .and_then(|v| v.value)
                    };
                    match (
                        attribute("ferritor.audit.chain"),
                        attribute("ferritor.audit.seq"),
                    ) {
                        (Some(Value::StringValue(chain)), Some(Value::IntValue(seq))) => self
                            .places
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push((chain, seq)),
                        other => panic!("no chain and seq: {other:?}"),
                    }
                    match record.body.and_then(|b| b.value) {
                        Some(Value::StringValue(body)) => bodies.push(body),
                        other => panic!("not a string body: {other:?}"),
                    }
                }
            }
            Ok(tonic::Response::new(Default::default()))
        }
    }

    impl Collector {
        /// Serving on a loopback port of its own, for the test's life.
        async fn serve(&self) -> OtlpSettings {
            use opentelemetry_proto::tonic::collector::logs::v1::logs_service_server::LogsServiceServer;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let service = LogsServiceServer::new(self.clone());
            tokio::spawn(
                tonic::transport::Server::builder()
                    .add_service(service)
                    .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
            );
            OtlpSettings {
                endpoint: format!("http://{addr}"),
                ca_pem: None,
                client: None,
            }
        }

        /// The bodies so far, one per line, as `ferritor audit verify`
        /// reads them.
        fn log(&self) -> Vec<u8> {
            self.bodies
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .flat_map(|body| format!("{body}\n").into_bytes())
                .collect()
        }

        fn verified(&self) -> audit_chain::Report {
            audit_chain::verify(self.log().as_slice(), &[signing_key().verifying_key()]).unwrap()
        }
    }

    /// `[audit_otlp]` alone: every line reaches the collector as a record
    /// whose body is the line, so the chain verifies from what it stored,
    /// proven whole once the drain has ended it.
    #[tokio::test(flavor = "multi_thread")]
    async fn over_otlp_the_collector_holds_a_chain_that_verifies() {
        let collector = Collector::default();
        let settings = collector.serve().await;
        let (log, drain) = AuditLog::open(
            None,
            Some(settings),
            Duration::from_secs(2),
            Some(signing_key()),
        )
        .unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        for action in [Action::Read, Action::List, Action::Write] {
            gate.check(&alice(), action, Target::System).await.unwrap();
        }
        assert!(drain.wait(Duration::from_secs(5)).await);
        let report = collector.verified();
        assert_eq!(report.verdict(), Verdict::Proven, "{report:?}");
        // start, three decisions, chain_end.
        assert_eq!((report.chains.len(), report.chains[0].entries), (1, 5));
        // Each record says where it goes: its chain's id (chain_start's)
        // and its line's own seq, so a backend can put them back in order.
        let bodies = collector.bodies.lock().unwrap().clone();
        let places = collector.places.lock().unwrap().clone();
        let start: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
        for ((chain, seq), body) in places.iter().zip(&bodies) {
            let line: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(chain.as_str(), start["chain"].as_str().unwrap());
            assert_eq!(Some(*seq), line["seq"].as_i64(), "{body}");
        }
    }

    /// A file that won't open fails `open` before anything else is built,
    /// and a collector's client that can't be built fails it too: errors,
    /// never a panic in the server's runtime (a runtime dropped there
    /// would be one).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_that_cant_start_is_an_error_not_a_panic() {
        let settings = Collector::default().serve().await;
        let missing = Path::new("/nonexistent/ferritor/audit.log");
        assert!(
            AuditLog::open(
                Some((missing, None)),
                Some(settings),
                Duration::from_secs(2),
                None
            )
            .is_err()
        );
        let bad = OtlpSettings {
            endpoint: "not a url".to_owned(),
            ca_pem: None,
            client: None,
        };
        assert!(AuditLog::open(None, Some(bad), Duration::from_secs(2), None).is_err());
    }

    /// A collector that doesn't acknowledge fails closed: the request is
    /// refused unaudited. Once it does again, the next entry starts a new
    /// chain there, so the lost batch is a gap the verifier reports, never
    /// a seam it misses.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_collector_refusing_refuses_requests_until_it_acknowledges() {
        let collector = Collector::default();
        let settings = collector.serve().await;
        let (log, drain) = AuditLog::open(
            None,
            Some(settings),
            Duration::from_secs(2),
            Some(signing_key()),
        )
        .unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        gate.check(&alice(), Action::Read, Target::System)
            .await
            .unwrap();
        collector
            .refuse
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            gate.check(&alice(), Action::List, Target::System).await,
            Err(Refused::Unaudited(AuditError::Write(_)))
        ));
        collector
            .refuse
            .store(false, std::sync::atomic::Ordering::SeqCst);
        gate.check(&alice(), Action::Write, Target::System)
            .await
            .unwrap();
        assert!(drain.wait(Duration::from_secs(5)).await);
        let report = collector.verified();
        // The first chain cut off where the collector refused; the second,
        // from the next entry on, whole.
        assert_eq!(report.verdict(), Verdict::Unproven, "{report:?}");
        assert_eq!(report.chains.len(), 2);
        assert_eq!(report.chains[1].state, ChainState::Complete);
    }

    /// Both devices: every line in the file and at the collector alike.
    #[tokio::test(flavor = "multi_thread")]
    async fn with_a_file_and_otlp_both_hold_the_same_lines() {
        let dir = TempDir::new("both");
        let path = dir.0.join("audit.log");
        let collector = Collector::default();
        let settings = collector.serve().await;
        let (log, drain) = AuditLog::open(
            Some((&path, None)),
            Some(settings),
            Duration::from_secs(2),
            Some(signing_key()),
        )
        .unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        gate.check(&alice(), Action::Read, Target::System)
            .await
            .unwrap();
        assert!(drain.wait(Duration::from_secs(5)).await);
        assert_eq!(std::fs::read(&path).unwrap(), collector.log());
        assert_eq!(collector.verified().verdict(), Verdict::Proven);
    }

    /// Past `max_bytes` the file is moved aside (`.1`, the older up to
    /// `.keep`, the oldest dropped) and a new one starts: every file holds
    /// whole chains, each proven, and no more files than kept.
    #[tokio::test]
    async fn a_file_past_its_size_rotates_and_keeps_only_so_many() {
        let dir = TempDir::new("rotate");
        let path = dir.0.join("audit.log");
        let rotation = Rotation {
            max_bytes: 2_000,
            keep: 2,
        };
        let (log, drain) = AuditLog::start(
            AuditFile::open(&path, Some(rotation)).unwrap(),
            None,
            Duration::from_secs(1),
            Some(signing_key()),
            CHECKPOINT_INTERVAL,
        )
        .unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        for _ in 0..60 {
            gate.check(&alice(), Action::Read, Target::System)
                .await
                .unwrap();
        }
        assert!(drain.wait(Duration::from_secs(2)).await);
        let rotated = |n: u32| dir.0.join(format!("audit.log.{n}"));
        assert!(rotated(1).exists() && rotated(2).exists());
        assert!(!rotated(3).exists(), "kept more than 2");
        for file in [path.clone(), rotated(1), rotated(2)] {
            let report = verified_file(&file);
            assert_eq!(
                report.verdict(),
                Verdict::Proven,
                "{}: {report:?}",
                file.display()
            );
            // A rotated file stopped at about its size: one line past it at
            // most, and its chain_end.
            let len = std::fs::metadata(&file).unwrap().len();
            assert!(len < 2_000 + 1_000, "{}: {len}", file.display());
        }
    }

    /// A file whose last line was cut off (a crash) gets a newline before
    /// the new chain starts: the fragment is a line of its own, and the new
    /// chain verifies whole.
    #[tokio::test]
    async fn a_cut_off_last_line_never_runs_into_the_new_chain() {
        let dir = TempDir::new("cut");
        let path = dir.0.join("audit.log");
        std::fs::write(&path, b"{\"time\":\"t\",\"event\":\"auth").unwrap();
        let (log, drain) =
            AuditLog::file(&path, Duration::from_secs(1), Some(signing_key())).unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        gate.check(&alice(), Action::Read, Target::System)
            .await
            .unwrap();
        assert!(drain.wait(Duration::from_secs(2)).await);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.starts_with("{\"time\":\"t\",\"event\":\"auth\n{"),
            "{text}"
        );
        let report = verified_file(&path);
        // The fragment is outside any chain (unproven), the chain whole.
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].state, ChainState::Complete);
    }

    /// A drain after entries were lost (the collector refused them) says
    /// so: the chain was broken off and couldn't be ended. Once a chain
    /// starts again and ends, a drain is fine.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_drain_after_lost_entries_says_so() {
        let collector = Collector::default();
        let settings = collector.serve().await;
        let (log, drain) = AuditLog::open(
            None,
            Some(settings),
            Duration::from_secs(2),
            Some(signing_key()),
        )
        .unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        collector
            .refuse
            .store(true, std::sync::atomic::Ordering::SeqCst);
        gate.outcome(
            &alice(),
            Action::Write,
            Target::System,
            "put",
            Outcome::Unknown("x".to_owned()),
        );
        assert!(!drain.clone().wait(Duration::from_secs(5)).await);
        collector
            .refuse
            .store(false, std::sync::atomic::Ordering::SeqCst);
        gate.check(&alice(), Action::Read, Target::System)
            .await
            .unwrap();
        assert!(drain.clone().wait(Duration::from_secs(5)).await);
        assert!(drain.wait(Duration::from_secs(5)).await);
    }

    /// The drain's `chain_end` never triggers a rotation: that would start a
    /// new chain after shutdown's end, left open. With a size so small every
    /// line crosses it, the file in place after the drain still ends whole.
    #[tokio::test]
    async fn no_rotation_follows_the_drains_end() {
        let dir = TempDir::new("end");
        let path = dir.0.join("audit.log");
        let rotation = Rotation {
            max_bytes: 1,
            keep: 2,
        };
        let (log, drain) = AuditLog::start(
            AuditFile::open(&path, Some(rotation)).unwrap(),
            None,
            Duration::from_secs(1),
            Some(signing_key()),
            CHECKPOINT_INTERVAL,
        )
        .unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        gate.check(&alice(), Action::Read, Target::System)
            .await
            .unwrap();
        assert!(drain.wait(Duration::from_secs(2)).await);
        let report = verified_file(&path);
        assert_eq!(report.verdict(), Verdict::Proven, "{report:?}");
    }

    /// A rotation that moved the file but couldn't open the new one, then a
    /// failed retry (no file to rename): once the path opens again, the new
    /// file rotates at its own `max_bytes`, nothing carried over from the
    /// old file's size.
    #[test]
    fn a_reopened_file_rotates_at_its_own_size() {
        let dir = TempDir::new("recover");
        let logs = dir.0.join("logs");
        std::fs::create_dir(&logs).unwrap();
        let path = logs.join("audit.log");
        let rotation = Rotation {
            max_bytes: 100,
            keep: 2,
        };
        let mut file = AuditFile::open(&path, Some(rotation)).unwrap();
        file.write_all(&[b'x'; 150]).unwrap();
        assert!(file.full());
        // What a rotation whose rename worked but whose open didn't leaves:
        // the file moved away, no handle, and (the directory gone) nothing
        // to open or rename at the path.
        std::fs::rename(&path, dir.0.join("moved")).unwrap();
        std::fs::remove_dir(&logs).unwrap();
        file.file = None;
        // The next check retries the rotation, which fails: nothing to
        // rename. Its threshold must not outlive the file it was for.
        let (moved, retried) = file.rotate();
        assert!(!moved && retried.is_err(), "no file to rename");
        // The path comes back: the next write opens it, counting from 0.
        std::fs::create_dir(&logs).unwrap();
        file.write_all(&[b'y'; 60]).unwrap();
        assert!(!file.full());
        file.write_all(&[b'y'; 60]).unwrap();
        assert!(
            file.full(),
            "rotates at its own max_bytes, not the old file's"
        );
    }

    /// Writes into `audit`, failing the `write`th write and the `flush`th
    /// flush (counted from 1).
    struct Scripted {
        audit: Captured,
        write: usize,
        flush: usize,
        writes: usize,
        flushes: usize,
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.writes == self.write {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.audit.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.flushes == self.flush {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            Ok(())
        }
    }

    /// A lost entry breaks the chain off; the next one starts a new chain,
    /// whose start is written in full but whose flush fails. The new chain
    /// stands: the entry after it goes in, and the drain ends it, proven.
    #[tokio::test]
    async fn a_recovered_chain_ends_even_if_its_starts_flush_failed() {
        let audit = Captured::default();
        // Writes: the first start (1), entry A (2, fails), the new start
        // (3), entry C (4), the end (5). Flushes: start (1), new start (2,
        // fails), C (3), end (4).
        let out = Scripted {
            audit: audit.clone(),
            write: 2,
            flush: 2,
            writes: 0,
            flushes: 0,
        };
        let (log, drain) = AuditLog::start(
            Stream(out),
            None,
            Duration::from_secs(1),
            Some(signing_key()),
            CHECKPOINT_INTERVAL,
        )
        .unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        for refused in [Action::Read, Action::List] {
            assert!(gate.check(&alice(), refused, Target::System).await.is_err());
        }
        gate.check(&alice(), Action::Write, Target::System)
            .await
            .unwrap();
        assert!(
            drain.wait(Duration::from_secs(2)).await,
            "the drain ended it"
        );
        let report = verified(&audit);
        let last = report.chains.last().unwrap();
        assert_eq!(last.state, ChainState::Complete, "{report:?}");
    }

    /// Stdout has nothing to reopen: a SIGHUP leaves its chain going.
    #[tokio::test]
    async fn a_reopen_on_stdout_changes_nothing() {
        let audit = Captured::default();
        let (log, drain) =
            AuditLog::signed(audit.clone(), Duration::from_secs(1), signing_key()).unwrap();
        let gate = Gate::new(Arc::new(Refusing(Action::Delete)), log);
        gate.check(&alice(), Action::Read, Target::System)
            .await
            .unwrap();
        gate.reopen_audit_log();
        gate.check(&alice(), Action::List, Target::System)
            .await
            .unwrap();
        assert!(drain.wait(Duration::from_secs(2)).await);
        let report = verified(&audit);
        assert_eq!(report.verdict(), Verdict::Proven, "{report:?}");
        assert_eq!((report.chains.len(), report.chains[0].entries), (1, 4));
    }

    /// Signed after every CHECKPOINT_EVERY entries, and at least every
    /// interval while entries arrive, without anyone asking.
    #[tokio::test]
    async fn checkpoints_come_by_count_and_by_time() {
        let audit = Captured::default();
        let (log, drain) = AuditLog::start(
            Stream(audit.clone()),
            None,
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
            Stream(audit.clone()),
            None,
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
