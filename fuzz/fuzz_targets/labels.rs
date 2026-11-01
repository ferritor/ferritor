//! Labels: keys, values, `key=value` pairs and changes. Whatever is
//! accepted holds to the rules as documented, and nothing is rewritten.
#![no_main]

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ferritor_core::labels::{
    self, LabelError, MAX_KEY_LEN, MAX_LABELS, MAX_VALUE_LEN, check_change, check_key, check_value,
    parse_pair,
};

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

fn key_ok(key: &str) -> bool {
    label_shape(key, MAX_KEY_LEN)
}

fn value_ok(value: &str) -> bool {
    label_shape(value, MAX_VALUE_LEN)
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
        value_ok(&input.value),
        "{:?}",
        input.value
    );

    // Split at the first `=`, both halves checked, nothing lost.
    match parse_pair(&input.pair) {
        Ok((key, value)) => {
            assert_eq!(format!("{key}={value}"), input.pair);
            assert!(!key.contains('=') && !value.contains('='));
            assert!(key_ok(&key) && value_ok(&value));
        }
        Err(LabelError::NotAPair(_)) => assert!(!input.pair.contains('=')),
        Err(_) => {
            let (key, value) = input.pair.split_once('=').unwrap();
            assert!(!(key_ok(key) && value_ok(value)), "{:?}", input.pair);
        }
    }

    let set_ok =
        input.set.len() <= MAX_LABELS && input.set.iter().all(|(k, v)| key_ok(k) && value_ok(v));
    assert_eq!(labels::check(&input.set).is_ok(), set_ok);
    let change_ok = !(input.set.is_empty() && input.remove.is_empty())
        && set_ok
        && input
            .remove
            .iter()
            .all(|k| key_ok(k) && !input.set.contains_key(k));
    assert_eq!(check_change(&input.set, &input.remove).is_ok(), change_ok);
});
