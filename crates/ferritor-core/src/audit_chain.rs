//! The audit log's hash chain and signed checkpoints: [`Chain`] is what the
//! server's audit writer keeps, [`verify`] what `ferritor audit verify` runs.
//!
//! Every line the writer emits gets two more fields at its end: `seq`, its
//! position in the chain (from 0), and `prev`, the SHA-256 (hex) of the
//! previous line exactly as written, newline included (`null` on the
//! first). A chain begins at each server start (and after a failed write,
//! see below), with a `chain_start` entry naming a random chain id and the
//! signing key's fingerprint (SHA-256 of the Ed25519 public key; `null`
//! when unsigned):
//!
//! ```json
//! {"time":"…","event":"chain_start","chain":"9f3c…","key":"5d1e…","seq":0,"prev":null}
//! {"time":"…","event":"authorization",…,"seq":1,"prev":"a41b…"}
//! {"time":"…","event":"checkpoint","chain":"9f3c…","signature":"…","seq":2,"prev":"07c2…"}
//! {"time":"…","event":"chain_end","chain":"9f3c…","signature":"…","seq":3,"prev":"5be0…"}
//! ```
//!
//! A `checkpoint` signs, with the server's Ed25519 key, the chain id, its
//! own `seq` and its `prev` (see [`signed_message`]); `prev` commits to
//! every line before it. A `chain_end` is a final checkpoint, signed under
//! its own domain, written at a clean shutdown: only a chain that ends with
//! one is proven whole. So [`verify`] sorts every chain into one of:
//!
//! - **complete**: it ends with a valid `chain_end`; every entry is signed;
//! - **open**: the file's last chain, without an end: a server still
//!   running, or one that crashed or was killed; its tail is unproven;
//! - **unterminated**: any other chain without an end: a crash, a cut, or
//!   entries appended by someone else;
//! - **unverifiable**: unsigned, or signed by a key the verifier wasn't
//!   given;
//! - **broken**: a link, a sequence number or a signature doesn't check:
//!   something was edited, inserted, deleted or reordered.
//!
//! Anyone who can write the file can append lines, `chain_start` included
//! (it isn't signed, and the key's fingerprint is public), but not a
//! signature: appended to a running server's log, the forged run breaks at
//! the server's next line; appended to a stopped server's, it's an open
//! chain with nothing signed. Cutting a chain short leaves it open or
//! unterminated. Neither passes as complete.
//!
//! A failed write may leave a partial line. The writer then ends that line
//! (a newline) and starts a new chain on its next write, so the incident
//! shows as an unterminated chain with a damaged last line, and everything
//! after it verifies as usual. A damaged line is tolerated only as the last
//! line of a chain: anywhere else it breaks the chain.
//!
//! What it can't show: a whole chain, one server run, removed from a file
//! that holds several. That needs the log shipped off the host as it's
//! written.

use std::collections::HashMap;
use std::io::{self, BufRead, Read};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// A checkpoint after at most this many entries.
pub const CHECKPOINT_EVERY: u64 = 256;

/// The longest line the verifier reads, newline included; longer ones are
/// damage (entries are far smaller), and never held in memory whole.
pub const MAX_LINE: usize = 1024 * 1024;

type Hash = [u8; 32];

fn hash(line: &[u8]) -> Hash {
    Sha256::digest(line).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0; N];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// The fingerprint `chain_start` names a key by: SHA-256 of the public
/// key's 32 bytes, hex.
pub fn key_fingerprint(key: &VerifyingKey) -> String {
    hex(&hash(key.as_bytes()))
}

/// What a signature says the chain has reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seal {
    /// Everything up to here; more may follow.
    Checkpoint,
    /// Everything, and nothing follows: the chain is complete.
    End,
}

impl Seal {
    /// First in the signed bytes, so a checkpoint can't pass for an end
    /// (or the reverse), and the key signs nothing else that could be
    /// mistaken for either.
    fn domain(self) -> &'static [u8] {
        match self {
            Self::Checkpoint => b"ferritor audit checkpoint v1\0",
            Self::End => b"ferritor audit chain end v1\0",
        }
    }

    fn event(self) -> &'static str {
        match self {
            Self::Checkpoint => "checkpoint",
            Self::End => "chain_end",
        }
    }
}

/// The bytes a checkpoint's or a chain end's signature covers.
pub fn signed_message(seal: Seal, chain: &[u8; 16], seq: u64, prev: &Hash) -> Vec<u8> {
    [seal.domain(), chain, &seq.to_be_bytes(), prev].concat()
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("OS random number generator failed")]
    Rng(#[from] getrandom::Error),
    #[error("an audit entry must be one JSON object followed by a newline")]
    NotAnObject,
    #[error("encoding an audit chain entry failed")]
    Encode(#[source] serde_json::Error),
}

/// The writer's side: the chain being written. One per server start, and a
/// new one after a chain end or a failed write ([`Chain::needs_start`]).
pub struct Chain {
    id: [u8; 16],
    signer: Option<SigningKey>,
    /// The `seq` the next line gets.
    next: u64,
    /// The hash of the last line written; `None` before the first.
    prev: Option<Hash>,
    /// Lines written since the last checkpoint (or the start).
    unsigned: u64,
    /// Its `chain_end` is written: nothing more goes in it.
    ended: bool,
    /// A line failed to write: it can't go on (the file may hold part of
    /// that line), so the next write starts a new chain.
    failed: bool,
}

#[derive(Serialize)]
struct Start<'a> {
    time: &'a str,
    event: &'static str,
    chain: String,
    key: Option<String>,
}

#[derive(Serialize)]
struct Signed<'a> {
    time: &'a str,
    event: &'static str,
    chain: String,
    signature: String,
}

impl Chain {
    /// A chain with a random id, not started yet; checkpoints and its end
    /// are signed with `signer`, and there are none without one.
    pub fn new(signer: Option<SigningKey>) -> Result<Self, ChainError> {
        let mut id = [0; 16];
        getrandom::fill(&mut id)?;
        Ok(Self {
            id,
            signer,
            next: 0,
            prev: None,
            unsigned: 0,
            ended: false,
            failed: false,
        })
    }

    /// Whether the next line must be a new chain's start ([`Chain::start`]):
    /// nothing written yet, the chain ended, or a write failed.
    pub fn needs_start(&self) -> bool {
        self.prev.is_none() || self.ended || self.failed
    }

    /// The `chain_start` of a fresh chain (a new id, seq 0), to write
    /// before any other line; the chain so far, if any, is left as it is.
    pub fn start(&mut self, time: &str) -> Result<Vec<u8>, ChainError> {
        if self.prev.is_some() {
            getrandom::fill(&mut self.id)?;
        }
        self.next = 0;
        self.prev = None;
        self.unsigned = 0;
        self.ended = false;
        self.failed = false;
        let start = Start {
            time,
            event: "chain_start",
            chain: hex(&self.id),
            key: self
                .signer
                .as_ref()
                .map(|key| key_fingerprint(&key.verifying_key())),
        };
        self.encode(&start)
    }

    /// `line` (one JSON object and a newline) with this chain's `seq` and
    /// `prev` appended. Call [`Chain::written`] once it's written.
    pub fn link(&self, line: &[u8]) -> Result<Vec<u8>, ChainError> {
        let body = line
            .strip_suffix(b"}\n")
            .filter(|body| body.len() > 1 && body.starts_with(b"{"))
            .ok_or(ChainError::NotAnObject)?;
        let prev = self
            .prev
            .map_or_else(|| "null".to_owned(), |prev| format!("\"{}\"", hex(&prev)));
        let mut linked = body.to_vec();
        linked.extend_from_slice(format!(",\"seq\":{},\"prev\":{prev}}}\n", self.next).as_bytes());
        Ok(linked)
    }

    /// `line`, as returned by [`Chain::start`], [`Chain::link`] or
    /// [`Chain::seal`] (with that `seal`), has been written in full: the
    /// next line links to it.
    pub fn written(&mut self, line: &[u8], seal: Option<Seal>) {
        // `start` reset `prev`; the start line itself is the first link.
        self.prev = Some(hash(line));
        self.next += 1;
        match seal {
            None => self.unsigned += 1,
            Some(Seal::Checkpoint) => self.unsigned = 0,
            Some(Seal::End) => {
                self.unsigned = 0;
                self.ended = true;
            }
        }
    }

    /// A line failed to write (perhaps partly): the chain can't go on.
    pub fn write_failed(&mut self) {
        self.failed = true;
    }

    /// Whether enough has been written since the last checkpoint that one
    /// is due now.
    pub fn checkpoint_due(&self) -> bool {
        self.signer.is_some() && !self.needs_start() && self.unsigned >= CHECKPOINT_EVERY
    }

    /// A signed checkpoint covering everything written so far (`None` with
    /// nothing new to cover), or the chain's end (always, once started).
    /// `None` without a signing key, or with no chain to seal.
    pub fn seal(&self, seal: Seal, time: &str) -> Result<Option<Vec<u8>>, ChainError> {
        let (Some(signer), Some(prev)) = (&self.signer, &self.prev) else {
            return Ok(None);
        };
        if self.needs_start() || (seal == Seal::Checkpoint && self.unsigned == 0) {
            return Ok(None);
        }
        let signature = signer.sign(&signed_message(seal, &self.id, self.next, prev));
        let signed = Signed {
            time,
            event: seal.event(),
            chain: hex(&self.id),
            signature: hex(&signature.to_bytes()),
        };
        self.encode(&signed).map(Some)
    }

    fn encode(&self, entry: &impl Serialize) -> Result<Vec<u8>, ChainError> {
        let mut line = serde_json::to_vec(entry).map_err(ChainError::Encode)?;
        line.push(b'\n');
        self.link(&line)
    }
}

/// Where verification stopped trusting a chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// 1-based line number in the input.
    pub line: usize,
    pub what: String,
}

/// What a chain amounts to; see the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainState {
    Complete,
    Open,
    Unterminated,
    Unverifiable(String),
    Broken(Problem),
}

/// One chain (one server run, or part of one) as the verifier found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainReport {
    pub chain: String,
    /// The line of its `chain_start`.
    pub first_line: usize,
    /// Its lines, `chain_start` included.
    pub entries: u64,
    /// The `seq` of the last checkpoint (or end) that verified, if any.
    pub signed_through: Option<u64>,
    /// Lines after that (or the start): linked, but no signature covers
    /// them.
    pub unsigned_tail: u64,
    /// Its last line, damaged by a failed or interrupted write, if it was.
    pub damaged_last_line: Option<Problem>,
    pub state: ChainState,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub chains: Vec<ChainReport>,
    /// The first line found outside any chain (before the first
    /// `chain_start`, or a damaged one after a `chain_end`), if there were
    /// any.
    pub stray: Option<Problem>,
}

/// The whole log, in one word: what a script should act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// At least one chain, every one complete: every entry is signed.
    Proven,
    /// Nothing failed a check, but not everything is signed: an open,
    /// unterminated or unverifiable chain, lines outside any chain, or no
    /// chain at all.
    Unproven,
    /// A check failed somewhere.
    Broken,
}

impl Report {
    pub fn verdict(&self) -> Verdict {
        if self
            .chains
            .iter()
            .any(|c| matches!(c.state, ChainState::Broken(_)))
        {
            Verdict::Broken
        } else if self.stray.is_none()
            && !self.chains.is_empty()
            && self.chains.iter().all(|c| c.state == ChainState::Complete)
        {
            Verdict::Proven
        } else {
            Verdict::Unproven
        }
    }
}

/// The verifier's state for the chain being read.
struct Reading {
    report: ChainReport,
    id: [u8; 16],
    key: Option<VerifyingKey>,
    next: u64,
    prev: Hash,
    ended: bool,
    problem: Option<Problem>,
    unverifiable: Option<String>,
    /// A damaged line, tolerated only if it's the chain's last.
    damaged: Option<Problem>,
}

impl Reading {
    fn finish(mut self, last: bool) -> ChainReport {
        self.report.damaged_last_line = self.damaged;
        self.report.state = match (self.problem, self.unverifiable) {
            (Some(problem), _) => ChainState::Broken(problem),
            (None, Some(why)) => ChainState::Unverifiable(why),
            (None, None) if self.ended => ChainState::Complete,
            (None, None) if last => ChainState::Open,
            (None, None) => ChainState::Unterminated,
        };
        self.report
    }
}

/// Checks every chain in `input` (an audit log, as written). A chain must
/// be signed by one of `keys`, the one its `chain_start` names: a log
/// spanning a key change needs both.
pub fn verify(mut input: impl BufRead, keys: &[VerifyingKey]) -> io::Result<Report> {
    let keys: HashMap<String, VerifyingKey> =
        keys.iter().map(|k| (key_fingerprint(k), *k)).collect();
    let mut report = Report::default();
    let mut current: Option<Reading> = None;
    let mut line = Vec::new();
    let mut number = 0;
    while let Some(too_long) = next_line(&mut input, &mut line)? {
        number += 1;
        let parsed = if too_long {
            Err(format!("a line longer than {MAX_LINE} bytes"))
        } else {
            parse(&line)
        };
        if let Ok(entry) = &parsed
            && entry.event.as_deref() == Some("chain_start")
        {
            if let Some(done) = current.take() {
                report.chains.push(done.finish(false));
            }
            current = Some(start(entry, &line, number, &keys));
            continue;
        }
        let Some(reading) = current.as_mut() else {
            report.stray.get_or_insert(Problem {
                line: number,
                what: "entries before any chain_start".to_owned(),
            });
            continue;
        };
        // After its end a chain takes nothing more, damage included: it
        // isn't the chain's last line (that's its chain_end) but outside
        // any chain, unproven. A writer can leave one (a later chain_start
        // that failed mid-write), so it isn't broken; a parsable entry
        // there is (below).
        if reading.ended && parsed.is_err() {
            report.stray.get_or_insert(Problem {
                line: number,
                what: "damaged lines after a chain_end".to_owned(),
            });
            continue;
        }
        reading.report.entries += 1;
        if reading.problem.is_some() || reading.unverifiable.is_some() {
            continue;
        }
        // A line after a damaged one: the damage wasn't a chain's last
        // line, so it's no failed write the writer recovered from.
        if let Some(damaged) = reading.damaged.take() {
            reading.problem = Some(damaged);
            continue;
        }
        let entry = match parsed {
            Ok(entry) => entry,
            Err(what) => {
                reading.damaged = Some(Problem { line: number, what });
                continue;
            }
        };
        if reading.ended {
            reading.problem = Some(Problem {
                line: number,
                what: "an entry after its chain_end".to_owned(),
            });
            continue;
        }
        match follow(reading, &entry) {
            Ok(()) => {
                reading.prev = hash(&line);
                reading.next += 1;
            }
            Err(what) => reading.problem = Some(Problem { line: number, what }),
        }
    }
    if let Some(done) = current {
        report.chains.push(done.finish(true));
    }
    Ok(report)
}

/// The next line into `line`, newline included, keeping at most
/// [`MAX_LINE`] bytes: `Some(true)` if it was longer (the rest is skipped,
/// never buffered), `None` at the end of the input.
fn next_line(input: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<Option<bool>> {
    line.clear();
    let limit = u64::try_from(MAX_LINE).unwrap_or(u64::MAX);
    if input.by_ref().take(limit).read_until(b'\n', line)? == 0 {
        return Ok(None);
    }
    if line.ends_with(b"\n") || line.len() < MAX_LINE {
        return Ok(Some(false));
    }
    loop {
        let buffer = input.fill_buf()?;
        if buffer.is_empty() {
            break;
        }
        match buffer.iter().position(|&b| b == b'\n') {
            Some(at) => {
                input.consume(at + 1);
                break;
            }
            None => {
                let all = buffer.len();
                input.consume(all);
            }
        }
    }
    Ok(Some(true))
}

/// The fields the verifier reads; everything else is the entry's own.
#[derive(serde::Deserialize)]
struct Entry {
    event: Option<String>,
    seq: Option<u64>,
    prev: Option<String>,
    chain: Option<String>,
    key: Option<String>,
    signature: Option<String>,
}

fn parse(line: &[u8]) -> Result<Entry, String> {
    if !line.ends_with(b"\n") {
        return Err("an incomplete line (cut off mid-write?)".to_owned());
    }
    serde_json::from_slice(line).map_err(|_| "not a JSON object".to_owned())
}

fn start(
    entry: &Entry,
    line: &[u8],
    number: usize,
    keys: &HashMap<String, VerifyingKey>,
) -> Reading {
    let id = entry.chain.as_deref().and_then(unhex::<16>);
    let malformed = entry.seq != Some(0) || entry.prev.is_some() || id.is_none();
    let key = entry.key.as_deref().and_then(|k| keys.get(k)).copied();
    let unverifiable = match entry.key.as_deref() {
        _ if malformed => None,
        None => Some("not signed (a server without a signing key)".to_owned()),
        Some(fingerprint) if key.is_none() => Some(format!(
            "signed by a key not given (fingerprint {fingerprint})"
        )),
        Some(_) => None,
    };
    Reading {
        report: ChainReport {
            chain: entry.chain.clone().unwrap_or_default(),
            first_line: number,
            entries: 1,
            signed_through: None,
            unsigned_tail: 1,
            damaged_last_line: None,
            state: ChainState::Open,
        },
        id: id.unwrap_or_default(),
        key,
        next: 1,
        prev: hash(line),
        ended: false,
        problem: malformed.then(|| Problem {
            line: number,
            what: "a malformed chain_start".to_owned(),
        }),
        unverifiable,
        damaged: None,
    }
}

/// Checks one line against the chain so far.
fn follow(reading: &mut Reading, entry: &Entry) -> Result<(), String> {
    if entry.seq != Some(reading.next) {
        return Err(match entry.seq {
            Some(seq) => format!(
                "seq {seq} where {} was due: entries are missing, inserted or reordered",
                reading.next
            ),
            None => "an entry without seq".to_owned(),
        });
    }
    if entry.prev.as_deref().and_then(unhex::<32>) != Some(reading.prev) {
        return Err("prev doesn't match the line before: one of the two was changed".to_owned());
    }
    let seal = match entry.event.as_deref() {
        Some("checkpoint") => Some(Seal::Checkpoint),
        Some("chain_end") => Some(Seal::End),
        _ => None,
    };
    if let Some(seal) = seal {
        let signature = entry
            .signature
            .as_deref()
            .and_then(unhex::<64>)
            .map(|bytes| Signature::from_bytes(&bytes));
        // The chain id from this chain's own start; the entry's `chain`
        // field is informational. One copied from another chain (the same
        // key) fails on its `prev` alone, which commits to that chain's
        // start; the signed id is a second binding.
        let message = signed_message(seal, &reading.id, reading.next, &reading.prev);
        let valid = match (signature, reading.key) {
            (Some(signature), Some(key)) => key.verify_strict(&message, &signature).is_ok(),
            _ => false,
        };
        if !valid {
            return Err(format!("a {} whose signature doesn't verify", seal.event()));
        }
        reading.report.signed_through = Some(reading.next);
        reading.report.unsigned_tail = 0;
        reading.ended = seal == Seal::End;
        return Ok(());
    }
    reading.report.unsigned_tail += 1;
    // The writer checkpoints after at most CHECKPOINT_EVERY lines, so a
    // longer run was appended by someone else, unless a checkpoint failed
    // to write (which also starts a new chain, so it can't be this one).
    if reading.report.unsigned_tail > CHECKPOINT_EVERY {
        return Err(format!(
            "more than {CHECKPOINT_EVERY} entries without a checkpoint: appended by someone else"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Writes a log the way the server's writer does.
    struct Log {
        chain: Chain,
        lines: Vec<Vec<u8>>,
        n: usize,
    }

    impl Log {
        fn new(signer: Option<SigningKey>) -> Self {
            let mut log = Self {
                chain: Chain::new(signer).unwrap(),
                lines: Vec::new(),
                n: 0,
            };
            log.start();
            log
        }

        fn start(&mut self) {
            let line = self.chain.start("t").unwrap();
            self.chain.written(&line, None);
            self.lines.push(line);
        }

        /// `count` entries, checkpointing where the writer would.
        fn entries(&mut self, count: usize) -> &mut Self {
            for _ in 0..count {
                self.n += 1;
                let entry = format!(
                    "{{\"time\":\"t\",\"event\":\"authorization\",\"n\":{}}}\n",
                    self.n
                );
                let line = self.chain.link(entry.as_bytes()).unwrap();
                self.chain.written(&line, None);
                self.lines.push(line);
                if self.chain.checkpoint_due() {
                    self.seal(Seal::Checkpoint);
                }
            }
            self
        }

        fn seal(&mut self, seal: Seal) -> &mut Self {
            if let Some(line) = self.chain.seal(seal, "t").unwrap() {
                self.chain.written(&line, Some(seal));
                self.lines.push(line);
            }
            self
        }

        fn checkpoint(&mut self) -> &mut Self {
            self.seal(Seal::Checkpoint)
        }

        fn end(&mut self) -> &mut Self {
            self.seal(Seal::End)
        }
    }

    /// start, 5 entries, checkpoint (seq 6), 5 entries, end (seq 12).
    fn complete() -> Vec<Vec<u8>> {
        let mut log = Log::new(Some(key(1)));
        log.entries(5).checkpoint().entries(5).end();
        log.lines
    }

    fn check(lines: &[Vec<u8>], keys: &[SigningKey]) -> Report {
        let keys: Vec<VerifyingKey> = keys.iter().map(SigningKey::verifying_key).collect();
        verify(lines.concat().as_slice(), &keys).unwrap()
    }

    fn broken(report: &Report) -> Option<&str> {
        report.chains.iter().find_map(|c| match &c.state {
            ChainState::Broken(problem) => Some(problem.what.as_str()),
            _ => None,
        })
    }

    /// Replaces line `i`'s `prev` with the hash of line `i - 1`, as a forger
    /// who recomputes the links would.
    fn relink(lines: &mut [Vec<u8>], from: usize) {
        for i in from..lines.len() {
            let text = String::from_utf8(lines[i].clone()).unwrap();
            let at = text.rfind(",\"prev\":").unwrap();
            lines[i] = format!(
                "{},\"prev\":\"{}\"}}\n",
                &text[..at],
                hex(&hash(&lines[i - 1]))
            )
            .into_bytes();
        }
    }

    #[test]
    fn a_complete_chain_is_proven() {
        let report = check(&complete(), &[key(1)]);
        assert_eq!(report.verdict(), Verdict::Proven, "{report:?}");
        let chain = &report.chains[0];
        assert_eq!(chain.state, ChainState::Complete);
        assert_eq!(
            (chain.entries, chain.signed_through, chain.unsigned_tail),
            (13, Some(12), 0)
        );
    }

    #[test]
    fn every_line_ends_with_its_seq_and_the_previous_hash() {
        let lines = complete();
        let first = String::from_utf8(lines[0].clone()).unwrap();
        assert!(
            first.starts_with("{\"time\":\"t\",\"event\":\"chain_start\",\"chain\":\""),
            "{first}"
        );
        assert!(first.ends_with(",\"seq\":0,\"prev\":null}\n"), "{first}");
        let second = String::from_utf8(lines[1].clone()).unwrap();
        assert!(
            second.ends_with(&format!(
                ",\"seq\":1,\"prev\":\"{}\"}}\n",
                hex(&hash(&lines[0]))
            )),
            "{second}"
        );
        let last = String::from_utf8(lines[12].clone()).unwrap();
        assert!(last.contains("\"event\":\"chain_end\""), "{last}");
    }

    #[test]
    fn an_edit_a_deletion_an_insertion_or_a_swap_breaks_the_chain() {
        let lines = complete();
        let changed = |f: &dyn Fn(&mut Vec<Vec<u8>>)| {
            let mut lines = lines.clone();
            f(&mut lines);
            let report = check(&lines, &[key(1)]);
            assert_eq!(report.verdict(), Verdict::Broken, "{report:?}");
            broken(&report).map(str::to_owned).unwrap_or_default()
        };
        let edit = |l: &mut Vec<Vec<u8>>| {
            l[3] = String::from_utf8(l[3].clone())
                .unwrap()
                .replace("authorization", "authorizatio_")
                .into_bytes();
        };
        assert!(changed(&edit).starts_with("prev doesn't match"));
        // With every later link recomputed: the next signature fails.
        let recomputed = changed(&|l| {
            edit(l);
            relink(l, 4);
        });
        assert!(
            recomputed.contains("checkpoint whose signature doesn't verify"),
            "{recomputed}"
        );
        assert!(changed(&|l| drop(l.remove(2))).starts_with("seq 3 where 2"));
        changed(&|l| l.insert(2, l[2].clone()));
        changed(&|l| l.swap(2, 3));
        // Removing a checkpoint (relinked, renumbered by hand is the same
        // as forging): the end's signature no longer verifies.
        let removed = changed(&|l| {
            l.remove(6);
            for (seq, line) in l.iter_mut().enumerate().skip(6) {
                let text = String::from_utf8(line.clone()).unwrap();
                let at = text.rfind(",\"seq\":").unwrap();
                *line = format!("{},\"seq\":{seq},\"prev\":\"\"}}\n", &text[..at]).into_bytes();
            }
            relink(l, 6);
        });
        assert!(
            removed.contains("chain_end whose signature doesn't verify"),
            "{removed}"
        );
    }

    /// A signature only counts where it was made: not from another chain
    /// (the same key, the same seq), and a checkpoint can't pass for an end
    /// or the reverse.
    #[test]
    fn a_signature_from_elsewhere_does_not_verify() {
        let lines = complete();
        let other = complete();
        let mut replayed = lines.clone();
        replayed[6] = other[6].clone();
        relink(&mut replayed, 6);
        let report = check(&replayed, &[key(1)]);
        assert!(
            broken(&report)
                .unwrap()
                .contains("signature doesn't verify"),
            "{report:?}"
        );

        // The checkpoint at seq 6 relabelled as the chain's end, cut there.
        let mut faked_end = lines[..7].to_vec();
        faked_end[6] = String::from_utf8(faked_end[6].clone())
            .unwrap()
            .replace("\"checkpoint\"", "\"chain_end\"")
            .into_bytes();
        let report = check(&faked_end, &[key(1)]);
        assert!(
            broken(&report)
                .unwrap()
                .contains("chain_end whose signature"),
            "{report:?}"
        );

        // The end relabelled as a checkpoint, entries appended after it.
        let mut not_ended = lines.clone();
        not_ended[12] = String::from_utf8(not_ended[12].clone())
            .unwrap()
            .replace("\"chain_end\"", "\"checkpoint\"")
            .into_bytes();
        let report = check(&not_ended, &[key(1)]);
        assert!(
            broken(&report)
                .unwrap()
                .contains("checkpoint whose signature"),
            "{report:?}"
        );
    }

    /// Anyone can write a chain_start with the right fingerprint (it isn't
    /// signed) and link entries after it, but never sign them: after a
    /// stopped server's log that's an open chain, nothing signed; inside a
    /// running server's, the server's next line breaks it.
    #[test]
    fn a_forged_run_is_never_proven() {
        let mut forger = Log::new(Some(key(1)));
        forger.chain.signer = None;
        forger.entries(255);
        let mut appended = complete();
        appended.extend(forger.lines.clone());
        let report = check(&appended, &[key(1)]);
        assert_eq!(report.verdict(), Verdict::Unproven, "{report:?}");
        assert_eq!(report.chains[0].state, ChainState::Complete);
        assert_eq!(report.chains[1].state, ChainState::Open);
        assert_eq!(report.chains[1].signed_through, None);

        let mut server = Log::new(Some(key(1)));
        server.entries(3);
        let mut lines = server.lines.clone();
        lines.extend(forger.lines);
        server.entries(1);
        lines.push(server.lines.last().unwrap().clone());
        let report = check(&lines, &[key(1)]);
        assert_eq!(report.verdict(), Verdict::Broken, "{report:?}");
    }

    /// Cutting a log short, even at a checkpoint, leaves an open chain (the
    /// file's last) or an unterminated one: unproven, never complete.
    #[test]
    fn a_cut_is_never_proven() {
        let lines = complete();
        let cut = check(&lines[..7], &[key(1)]);
        assert_eq!(cut.verdict(), Verdict::Unproven);
        assert_eq!(cut.chains[0].state, ChainState::Open);
        assert_eq!(
            (cut.chains[0].signed_through, cut.chains[0].unsigned_tail),
            (Some(6), 0)
        );

        let mut spliced = lines[..9].to_vec();
        spliced.extend(complete());
        let report = check(&spliced, &[key(1)]);
        assert_eq!(report.verdict(), Verdict::Unproven);
        assert_eq!(report.chains[0].state, ChainState::Unterminated);
        assert_eq!(report.chains[0].unsigned_tail, 2);
        assert_eq!(report.chains[1].state, ChainState::Complete);
    }

    #[test]
    fn an_entry_after_the_end_breaks_the_chain() {
        let mut lines = complete();
        let mut log = Log::new(Some(key(1)));
        log.entries(1);
        lines.push(log.lines[1].clone());
        relink(&mut lines, 13);
        let report = check(&lines, &[key(1)]);
        assert!(
            broken(&report).unwrap().contains("after its chain_end"),
            "{report:?}"
        );
    }

    /// Damage after a chain_end isn't that chain's last line (its end is):
    /// it's outside any chain, so the log is unproven, never proven. Found
    /// by fuzzing: a forged entry appended without its newline passed.
    #[test]
    fn damage_after_the_end_is_never_proven() {
        let forged = b"{\"time\":\"t\",\"event\":\"authorization\",\"decision\":\"allow\"}";
        for tail in [forged.as_slice(), b"not json\n", b"{\"event\":\"chain_st"] {
            let mut lines = complete();
            lines.push(tail.to_vec());
            let report = check(&lines, &[key(1)]);
            assert_eq!(report.verdict(), Verdict::Unproven, "{report:?}");
            assert_eq!(report.chains[0].state, ChainState::Complete);
            assert_eq!(report.stray.as_ref().map(|p| p.line), Some(14));
        }

        // What a writer leaves when the next run's chain_start fails
        // mid-write: unproven, the next chain verifies.
        let mut lines = complete();
        let mut next = Log::new(Some(key(1)));
        lines.push([&next.lines[0][..20], b"\n"].concat());
        next.entries(2).end();
        lines.extend(next.lines);
        let report = check(&lines, &[key(1)]);
        assert_eq!(report.verdict(), Verdict::Unproven, "{report:?}");
        assert!(
            report
                .chains
                .iter()
                .all(|c| c.state == ChainState::Complete)
        );
    }

    /// A key change needs a restart, so a new chain: with both keys given,
    /// a log across it is proven; with one, the other chain is unverifiable.
    /// Unsigned is unverifiable too.
    #[test]
    fn each_chain_is_checked_with_the_key_it_names() {
        let mut lines = complete();
        let mut rotated = Log::new(Some(key(2)));
        rotated.entries(3).end();
        lines.extend(rotated.lines);
        assert_eq!(check(&lines, &[key(1), key(2)]).verdict(), Verdict::Proven);
        let one = check(&lines, &[key(1)]);
        assert_eq!(one.verdict(), Verdict::Unproven);
        assert!(matches!(
            &one.chains[1].state,
            ChainState::Unverifiable(why) if why.contains("a key not given")
        ));

        let mut unsigned = Log::new(None);
        unsigned.entries(3).end();
        let report = check(&unsigned.lines, &[key(1)]);
        assert!(matches!(
            &report.chains[0].state,
            ChainState::Unverifiable(why) if why.contains("not signed")
        ));
    }

    /// What the writer leaves after a failed write: a partial line, ended
    /// with a newline, then a new chain. The cut-off chain is unterminated
    /// with a damaged last line; the next one verifies.
    #[test]
    fn a_failed_write_damages_only_its_own_chain() {
        let mut log = Log::new(Some(key(1)));
        log.entries(3);
        let mut lines = log.lines.clone();
        let partial = log.chain.link(b"{\"event\":\"authorization\"}\n").unwrap();
        log.chain.write_failed();
        lines.push([&partial[..10], b"\n"].concat());
        assert!(log.chain.needs_start());
        let first = log.lines.len();
        log.start();
        log.entries(2).end();
        lines.extend_from_slice(&log.lines[first..]);

        let report = check(&lines, &[key(1)]);
        assert_eq!(report.verdict(), Verdict::Unproven, "{report:?}");
        assert_eq!(report.chains[0].state, ChainState::Unterminated);
        assert_eq!(
            report.chains[0].damaged_last_line.as_ref().map(|p| p.line),
            Some(5)
        );
        assert_eq!(report.chains[1].state, ChainState::Complete);
        assert_ne!(report.chains[0].chain, report.chains[1].chain);

        // Cut off at the very end (a crash mid-write): open, damaged.
        let mut crashed = log.lines[..first].to_vec();
        crashed.push(partial[..10].to_vec());
        let report = check(&crashed, &[key(1)]);
        assert_eq!(report.chains[0].state, ChainState::Open);
        assert!(report.chains[0].damaged_last_line.is_some());

        // Damage anywhere else is no failed write.
        let mut damaged = complete();
        damaged[3] = b"not json\n".to_vec();
        assert!(
            broken(&check(&damaged, &[key(1)]))
                .unwrap()
                .contains("not a JSON object")
        );
    }

    /// A line too long for any entry is damage, and isn't read whole.
    #[test]
    fn an_overlong_line_is_damage() {
        let mut lines = complete();
        lines.insert(3, [vec![b'x'; MAX_LINE + 10], b"\n".to_vec()].concat());
        let report = check(&lines, &[key(1)]);
        assert!(
            broken(&report).unwrap().contains("longer than"),
            "{report:?}"
        );
        // The line after it is read as a line of its own.
        assert_eq!(report.chains[0].entries, 14);
    }

    #[test]
    fn the_writer_checkpoints_by_itself_and_a_longer_unsigned_run_is_appended() {
        let total = usize::try_from(3 * CHECKPOINT_EVERY).unwrap();
        let mut log = Log::new(Some(key(1)));
        log.entries(total).end();
        assert_eq!(check(&log.lines, &[key(1)]).verdict(), Verdict::Proven);

        // As many unsigned lines as the writer ever leaves (the start
        // counts) are open; one more is appended by someone else.
        let mut forger = Log::new(Some(key(1)));
        forger.chain.signer = None;
        forger.entries(usize::try_from(CHECKPOINT_EVERY - 1).unwrap());
        assert_eq!(check(&forger.lines, &[key(1)]).verdict(), Verdict::Unproven);
        forger.entries(1);
        let report = check(&forger.lines, &[key(1)]);
        assert!(
            broken(&report).unwrap().contains("without a checkpoint"),
            "{report:?}"
        );
    }

    #[test]
    fn nothing_or_stray_lines_are_unproven() {
        assert_eq!(check(&[], &[key(1)]).verdict(), Verdict::Unproven);
        let mut lines = complete();
        lines.insert(0, b"{\"event\":\"authorization\"}\n".to_vec());
        let report = check(&lines, &[key(1)]);
        assert_eq!(report.stray.as_ref().map(|p| p.line), Some(1));
        assert_eq!(report.verdict(), Verdict::Unproven);
    }

    #[test]
    fn a_second_end_or_a_checkpoint_after_it_is_nothing() {
        let mut log = Log::new(Some(key(1)));
        log.entries(1).end();
        let lines = log.lines.len();
        log.end().checkpoint();
        assert_eq!(log.lines.len(), lines);
        assert!(log.chain.needs_start());
    }

    #[test]
    fn only_a_json_object_line_is_linked() {
        let chain = Chain::new(None).unwrap();
        for line in [&b"{}\n"[..], b"[1]\n", b"{\"a\":1}", b"x\n"] {
            assert!(matches!(chain.link(line), Err(ChainError::NotAnObject)));
        }
    }
}
