//! What the fuzz targets share: the audit verifier's oracle.

use serde::Deserialize;
use ferritor_core::audit_chain::{MAX_LINE, Report, Verdict};

/// The fixed test key the genuine logs are signed with (seeds included).
/// Public, but the fuzzer can't compute Ed25519 signatures with it: every
/// valid signature it meets was made by a real writer.
pub const AUDIT_KEY: [u8; 32] = [7; 32];

/// `log` as lines, each with its newline (the last perhaps without).
pub fn lines(log: &[u8]) -> Vec<&[u8]> {
    log.split_inclusive(|&b| b == b'\n').collect()
}

/// The fields as the verifier reads them (`audit_chain::Entry`): the same
/// types, so the same lines parse.
#[derive(Deserialize, PartialEq, Eq, Debug)]
struct Entry {
    event: Option<String>,
    seq: Option<u64>,
    prev: Option<String>,
    chain: Option<String>,
    key: Option<String>,
    signature: Option<String>,
}

fn entry(line: &[u8]) -> Option<Entry> {
    if !line.ends_with(b"\n") || line.len() > MAX_LINE {
        return None;
    }
    serde_json::from_slice(line).ok()
}

fn is_start(line: &[u8]) -> bool {
    entry(line).is_some_and(|e| e.event.as_deref() == Some("chain_start"))
}

/// A `chain_end`'s `event`, `seq`, `prev` and `signature`.
type Sealed = (Option<String>, Option<u64>, Option<String>, Option<String>);

/// The fields a `chain_end` line's signature and position vouch for, as
/// the verifier decodes them (hex in either case).
fn sealed(line: &[u8]) -> Option<Sealed> {
    let lower = |hex: Option<String>| hex.map(|h| h.to_ascii_lowercase());
    entry(line).map(|e| (e.event, e.seq, lower(e.prev), lower(e.signature)))
}

/// `log` split into chains at each `chain_start`; lines before the first
/// are the first element's.
pub fn chains(log: &[u8]) -> Vec<Vec<&[u8]>> {
    let mut chains: Vec<Vec<&[u8]>> = vec![Vec::new()];
    for line in lines(log) {
        if is_start(line) {
            chains.push(Vec::new());
        }
        if let Some(chain) = chains.last_mut() {
            chain.push(line);
        }
    }
    if chains.first().is_some_and(Vec::is_empty) {
        chains.remove(0);
    }
    chains
}

/// The verifier must never call a log proven unless it's made of genuine
/// complete chains (in any order, any number of times: a whole chain
/// removed, or one repeated, is documented as undetectable). A genuine
/// chain is matched line for line, but for its `chain_end`'s spelling and
/// unsigned fields (`time`, `chain`, one added, hex case): nothing after
/// that line hashes it, and its signature covers only the chain id, `seq`
/// and `prev`.
pub fn assert_proven_only_if_genuine(log: &[u8], report: &Report, genuine: &[Vec<Vec<u8>>]) {
    if report.verdict() != Verdict::Proven {
        return;
    }
    let found = chains(log);
    assert_eq!(
        found.len(),
        report.chains.len(),
        "chains counted differently"
    );
    for chain in found {
        let matches = genuine.iter().any(|g| {
            !g.is_empty()
                && g.len() == chain.len()
                && g.iter()
                    .zip(&chain)
                    .take(g.len() - 1)
                    .all(|(a, b)| a.as_slice() == *b)
                && match (g.last(), chain.last()) {
                    (Some(a), Some(b)) => sealed(a).is_some() && sealed(a) == sealed(b),
                    _ => false,
                }
        });
        assert!(
            matches,
            "a proven chain no writer wrote:\n{}",
            String::from_utf8_lossy(&chain.concat())
        );
    }
}
