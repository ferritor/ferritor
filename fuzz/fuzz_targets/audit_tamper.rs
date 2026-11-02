//! The audit verifier against a forger: real logs, written by `Chain` as
//! the server's writer does, then edited (lines deleted, repeated, moved,
//! inserted, cut, bits flipped). Unedited, every chain must be judged as
//! written; edited, the log may never pass as proven unless it's still
//! made of the genuine chains.
#![no_main]

use arbitrary::Arbitrary;
use ed25519_dalek::SigningKey;
use ferritor_core::audit_chain::{Chain, ChainState, Seal, verify};
use ferritor_fuzz::{AUDIT_KEY, assert_proven_only_if_genuine, chains};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Plan {
    chains: Vec<ChainPlan>,
    edits: Vec<Edit>,
}

#[derive(Arbitrary, Debug)]
struct ChainPlan {
    signed: bool,
    steps: Vec<Step>,
    end: bool,
}

#[derive(Arbitrary, Debug)]
enum Step {
    /// An entry, with this event name and detail.
    Entry(String, String),
    /// `n` plain entries at once: past `CHECKPOINT_EVERY`, the writer's own
    /// checkpoints.
    Many(u16),
    Checkpoint,
}

#[derive(Arbitrary, Debug)]
enum Edit {
    Delete(u16),
    Copy { from: u16, to: u16 },
    Swap(u16, u16),
    Flip { line: u16, at: u16, bit: u8 },
    Insert { at: u16, line: Vec<u8> },
    Truncate { line: u16, len: u16 },
}

/// The events the verifier reads; an entry's own is never one of them.
const RESERVED: [&str; 3] = ["chain_start", "checkpoint", "chain_end"];

struct Written {
    lines: Vec<Vec<u8>>,
    signed: bool,
    ended: bool,
}

/// The server's writer, without the file: `Chain` and the lines it wrote.
struct Writer {
    chain: Chain,
    lines: Vec<Vec<u8>>,
}

impl Writer {
    fn emit(&mut self, line: Vec<u8>, seal: Option<Seal>) {
        self.chain.written(&line, seal);
        self.lines.push(line);
    }

    fn seal(&mut self, seal: Seal) -> bool {
        match self.chain.seal(seal, "t").unwrap() {
            Some(line) => {
                self.emit(line, Some(seal));
                true
            }
            None => false,
        }
    }

    fn entry(&mut self, event: &str, detail: &str) {
        let event = if RESERVED.contains(&event) {
            "authorization"
        } else {
            event
        };
        let mut body =
            serde_json::to_vec(&serde_json::json!({"time": "t", "event": event, "detail": detail}))
                .unwrap();
        body.push(b'\n');
        let line = self.chain.link(&body).unwrap();
        self.emit(line, None);
        if self.chain.checkpoint_due() {
            self.seal(Seal::Checkpoint);
        }
    }
}

fn write(plan: &ChainPlan, key: &SigningKey) -> Written {
    let mut writer = Writer {
        chain: Chain::new(plan.signed.then(|| key.clone())).unwrap(),
        lines: Vec::new(),
    };
    let start = writer.chain.start("t").unwrap();
    writer.emit(start, None);
    let mut entries = 0usize;
    for step in &plan.steps {
        match step {
            Step::Entry(event, detail) => {
                entries += 1;
                writer.entry(event, detail);
            }
            Step::Many(n) => {
                for _ in 0..(*n % 300) {
                    entries += 1;
                    writer.entry("authorization", "");
                }
            }
            Step::Checkpoint => {
                writer.seal(Seal::Checkpoint);
            }
        }
        if entries > 600 {
            break;
        }
    }
    let ended = plan.end && writer.seal(Seal::End);
    Written {
        lines: writer.lines,
        signed: plan.signed,
        ended,
    }
}

fn edit(lines: &mut Vec<Vec<u8>>, edit: &Edit) {
    let at = |i: u16, len: usize| usize::from(i) % len.max(1);
    match *edit {
        _ if lines.is_empty() => {
            if let Edit::Insert { line, .. } = edit {
                lines.push(line.clone());
            }
        }
        Edit::Delete(i) => {
            let i = at(i, lines.len());
            lines.remove(i);
        }
        Edit::Copy { from, to } => {
            let line = lines[at(from, lines.len())].clone();
            let to = at(to, lines.len() + 1);
            lines.insert(to, line);
        }
        Edit::Swap(i, j) => {
            let (i, j) = (at(i, lines.len()), at(j, lines.len()));
            lines.swap(i, j);
        }
        Edit::Flip {
            line,
            at: byte,
            bit,
        } => {
            let i = at(line, lines.len());
            let line = &mut lines[i];
            if !line.is_empty() {
                let byte = at(byte, line.len());
                line[byte] ^= 1 << (bit % 8);
            }
        }
        Edit::Insert { at: i, ref line } => {
            let i = at(i, lines.len() + 1);
            lines.insert(i, line.clone());
        }
        Edit::Truncate { line, len } => {
            let i = at(line, lines.len());
            let line = &mut lines[i];
            let len = usize::from(len) % (line.len() + 1);
            line.truncate(len);
        }
    }
}

fuzz_target!(|plan: Plan| {
    let key = SigningKey::from_bytes(&AUDIT_KEY);
    let written: Vec<Written> = plan.chains.iter().take(4).map(|c| write(c, &key)).collect();
    let mut lines: Vec<Vec<u8>> = written.iter().flat_map(|w| w.lines.clone()).collect();
    let keys = [key.verifying_key()];

    if plan.edits.is_empty() {
        // As written: each chain judged by how it was written.
        let report = verify(lines.concat().as_slice(), &keys).unwrap();
        assert_eq!(report.chains.len(), written.len());
        assert!(report.stray.is_none());
        for (i, (chain, w)) in report.chains.iter().zip(&written).enumerate() {
            let last = i + 1 == written.len();
            let expected = match (w.signed, w.ended) {
                (false, _) => None,
                (true, true) => Some(ChainState::Complete),
                (true, false) if last => Some(ChainState::Open),
                (true, false) => Some(ChainState::Unterminated),
            };
            match expected {
                None => assert!(
                    matches!(chain.state, ChainState::Unverifiable(_)),
                    "{:?}",
                    chain.state
                ),
                Some(state) => assert_eq!(chain.state, state),
            }
            assert_eq!(chain.entries, w.lines.len() as u64);
        }
        return;
    }

    let genuine: Vec<Vec<Vec<u8>>> = written.iter().map(|w| w.lines.clone()).collect();
    for e in plan.edits.iter().take(16) {
        edit(&mut lines, e);
    }
    let log = lines.concat();
    let report = verify(log.as_slice(), &keys).unwrap();
    assert_proven_only_if_genuine(&log, &report, &genuine);
    // Splitting is the verifier's too.
    let _ = chains(&log);
});
