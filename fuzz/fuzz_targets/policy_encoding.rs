//! The messages the stored policies' HMACs cover (`row_message`,
//! `set_message`): length-prefixed and domain-tagged, so two different rows
//! (or sets) never encode alike. A collision would let a row's MAC vouch
//! for another row.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ferritor_core::policy::{RowFields, SetEntry, row_message, set_message};

#[derive(Arbitrary, Debug, PartialEq, Eq)]
struct Row {
    name: String,
    identity: String,
    actions: Vec<String>,
    paths: Vec<String>,
    all_paths: bool,
    version: u32,
    description: String,
}

impl Row {
    fn message(&self) -> Vec<u8> {
        row_message(&RowFields {
            name: &self.name,
            identity: &self.identity,
            actions: &self.actions,
            paths: &self.paths,
            all_paths: self.all_paths,
            version: self.version,
            description: &self.description,
        })
    }
}

/// A set entry: name, version, MAC.
type Entry = (String, u32, Vec<u8>);

#[derive(Arbitrary, Debug)]
struct Set {
    revision: u64,
    entries: Vec<Entry>,
}

impl Set {
    fn message(&self) -> Vec<u8> {
        let entries: Vec<SetEntry<'_>> = self
            .entries
            .iter()
            .map(|(name, version, mac)| SetEntry {
                name,
                version: *version,
                mac,
            })
            .collect();
        set_message(self.revision, &entries)
    }

    /// What the message is meant to cover: the revision, and the entries in
    /// name order (names are unique in a stored set; with duplicates, a
    /// stable sort keeps their order, as the encoder does).
    fn meaning(&self) -> (u64, Vec<&Entry>) {
        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        (self.revision, entries)
    }
}

/// The second row: any other, or the first with a field boundary moved
/// (bytes from the end of one field to the start of the next, an item from
/// one list to the other): the near-misses a missing length prefix or count
/// would let collide.
#[derive(Arbitrary, Debug)]
enum Twin {
    Other(Row),
    Shift { field: u8, bytes: u8 },
    MoveItem,
}

fn shifted(a: &Row, field: u8, bytes: u8) -> Row {
    let mut fields: Vec<String> = [a.name.clone(), a.identity.clone()]
        .into_iter()
        .chain(a.actions.iter().cloned())
        .chain(a.paths.iter().cloned())
        .chain([a.description.clone()])
        .collect();
    let i = usize::from(field) % (fields.len() - 1);
    let from = &fields[i];
    let mut at = from.len().saturating_sub(usize::from(bytes));
    while !from.is_char_boundary(at) {
        at += 1;
    }
    let moved = fields[i].split_off(at);
    fields[i + 1].insert_str(0, &moved);
    let mut rest = fields.into_iter();
    let mut take = |n: usize| -> Vec<String> { rest.by_ref().take(n).collect() };
    let head = take(2);
    let actions = take(a.actions.len());
    let paths = take(a.paths.len());
    let description = take(1);
    Row {
        name: head[0].clone(),
        identity: head[1].clone(),
        actions,
        paths,
        all_paths: a.all_paths,
        version: a.version,
        description: description[0].clone(),
    }
}

fn twin(a: &Row, twin: Twin) -> Row {
    match twin {
        Twin::Other(row) => row,
        Twin::Shift { field, bytes } => shifted(a, field, bytes),
        Twin::MoveItem => {
            let mut b = Row {
                name: a.name.clone(),
                identity: a.identity.clone(),
                actions: a.actions.clone(),
                paths: a.paths.clone(),
                all_paths: a.all_paths,
                version: a.version,
                description: a.description.clone(),
            };
            match b.actions.pop() {
                Some(item) => b.paths.insert(0, item),
                None => b.actions.extend(b.paths.drain(..1.min(b.paths.len()))),
            }
            b
        }
    }
}

fuzz_target!(|input: (Row, Twin, Set, Set)| {
    let (a, other, s, t) = input;
    let b = twin(&a, other);
    assert_eq!(a.message() == b.message(), a == b, "{a:?} / {b:?}");
    assert_eq!(s.message() == t.message(), s.meaning() == t.meaning());
    // A row's message never passes for a set's, nor the reverse.
    assert_ne!(a.message(), s.message());
});
