//! Labels: keys, values, `key=value` pairs and changes. Whatever is
//! accepted holds to the rules as documented, and nothing is rewritten.
#![no_main]

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use ferritor_core::labels::{
    self, LabelError, MAX_DESCRIPTION_LEN, MAX_KEY_LEN, MAX_LABELS, MAX_VALUE_LEN, check_change,
    check_key, check_namespace, check_namespace_change, check_value, parse_pair,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    key: String,
    value: String,
    pair: String,
    set: BTreeMap<String, String>,
    remove: Vec<String>,
}

/// The rule, restated from the module docs:
/// `([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]`, 1 to `max` characters.
fn label_shape(s: &str, max: usize) -> bool {
    let bytes = s.as_bytes();
    (1..=max).contains(&s.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(b))
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
}

/// The shape, and of the reserved keys (`ferritor.` and on) only
/// `ferritor.rotation`.
fn key_ok(key: &str) -> bool {
    label_shape(key, MAX_KEY_LEN) && (!key.starts_with("ferritor.") || key == "ferritor.rotation")
}

/// By the key: `description` printable ASCII without a space at either end,
/// up to `MAX_DESCRIPTION_LEN`; `contact` the shape's alphabet with `@` and
/// `#`, beginning with a letter, digit or `#`; `owner` the shape's alphabet
/// with `/`, no `//`; `ferritor.rotation` `true` only; any other key the
/// shape.
fn value_ok(key: &str, value: &str) -> bool {
    let bytes = value.as_bytes();
    match key {
        "description" => {
            (1..=MAX_DESCRIPTION_LEN).contains(&value.len())
                && bytes.iter().all(|b| (b' '..=b'~').contains(b))
                && bytes[0] != b' '
                && bytes[bytes.len() - 1] != b' '
        }
        "contact" => {
            (1..=MAX_VALUE_LEN).contains(&value.len())
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.@#".contains(b))
                && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'#')
                && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        }
        "owner" => {
            (1..=MAX_VALUE_LEN).contains(&value.len())
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(b))
                && bytes[0].is_ascii_alphanumeric()
                && bytes[bytes.len() - 1].is_ascii_alphanumeric()
                && !value.contains("//")
        }
        "ferritor.rotation" => value == "true",
        _ => label_shape(value, MAX_VALUE_LEN),
    }
}

fuzz_target!(|input: Input| {
    assert_eq!(
        check_key(&input.key).is_ok(),
        key_ok(&input.key),
        "{:?}",
        input.key
    );
    assert_eq!(
        check_value(&input.key, &input.value).is_ok(),
        value_ok(&input.key, &input.value),
        "{:?}={:?}",
        input.key,
        input.value
    );

    // Split at the first `=`, both halves checked, nothing lost.
    match parse_pair(&input.pair) {
        Ok((key, value)) => {
            assert_eq!(format!("{key}={value}"), input.pair);
            // Split at the first `=`: never one in the key; in the value
            // only where its key allows one (a description).
            assert!(!key.contains('='));
            assert!(
                !value.contains('=') || key == "description",
                "{key}={value}"
            );
            assert!(key_ok(&key) && value_ok(&key, &value));
        }
        Err(LabelError::NotAPair(_)) => assert!(!input.pair.contains('=')),
        Err(_) => {
            let (key, value) = input.pair.split_once('=').unwrap();
            assert!(!(key_ok(key) && value_ok(key, value)), "{:?}", input.pair);
        }
    }

    let set_ok =
        input.set.len() <= MAX_LABELS && input.set.iter().all(|(k, v)| key_ok(k) && value_ok(k, v));
    assert_eq!(labels::check(&input.set).is_ok(), set_ok);
    // A key to remove needs the shape alone: removing adds no label, so a
    // reserved key stored before the rules can still go.
    let change_ok = !(input.set.is_empty() && input.remove.is_empty())
        && set_ok
        && input
            .remove
            .iter()
            .all(|k| label_shape(k, MAX_KEY_LEN) && !input.set.contains_key(k));
    assert_eq!(check_change(&input.set, &input.remove).is_ok(), change_ok);

    // A namespace's: the same, and no reserved key set.
    let unreserved = |k: &String| !k.starts_with("ferritor.");
    assert_eq!(
        check_namespace(&input.set).is_ok(),
        set_ok && input.set.keys().all(unreserved)
    );
    assert_eq!(
        check_namespace_change(&input.set, &input.remove).is_ok(),
        change_ok && input.set.keys().all(unreserved)
    );
});
