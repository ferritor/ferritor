//! Labels: custom key/value metadata on a secret path (`team=a`,
//! `project=b`). Plain metadata, **not encrypted**: readable by anyone
//! allowed to list the path, so never put a secret in one.
//!
//! Keys and values share one rule: ASCII letters, digits, `-`, `_` and
//! `.`, beginning and ending with a letter or digit, never empty, at most
//! [`MAX_KEY_LEN`] (or [`MAX_VALUE_LEN`]) characters, so
//! `([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]`. Nothing invisible or
//! confusable fits. A path holds at most [`MAX_LABELS`]. Like paths,
//! invalid input is refused, never rewritten.
//!
//! **Reserved keys.** Keys starting with `ferritor.` ([`RESERVED_PREFIX`])
//! are ferritor's own, and only those it knows are allowed, so a typo is an
//! error rather than a label silently ignored:
//! - [`ROTATION`] (`ferritor.rotation`), on a secret's path only: `true`
//!   says the secret must be rotated (a new version) within the server's
//!   `rotation_max_age_days`, and counts it in the rotation reminders.
//!   Only `true` is stored: absent is off, and `false` is refused (remove
//!   the label instead), so no write stores something other than what was
//!   sent.
//!
//! A namespace takes no reserved key at all ([`check_namespace`]): it never
//! rotates, its secrets do.
//!
//! **Metadata keys.** Three plain keys take wider values than the rule
//! above, for who to ask about a secret; every other key keeps it:
//! - [`DESCRIPTION`] (`description`): printable ASCII, spaces included
//!   (`' '` to `'~'`), not beginning or ending with a space, at most
//!   [`MAX_DESCRIPTION_LEN`] characters.
//! - [`CONTACT`] (`contact`): the rule's alphabet and `@` and `#` (an
//!   email address, a chat channel), beginning with a letter, a digit or
//!   `#`, ending with a letter or digit.
//! - [`OWNER`] (`owner`): the rule, like any key.
//!
//! Still nothing invisible or confusable fits, and like every label they're
//! readable by anyone who may list the path: a contact may be personal
//! data.
//! Shared by the server (which checks everything it stores) and the CLI
//! (which checks `key=value` arguments before sending them).

use std::collections::BTreeMap;

/// The most labels one path may hold.
pub const MAX_LABELS: usize = 64;
/// The longest label key (ASCII, so bytes and characters alike).
pub const MAX_KEY_LEN: usize = 63;
/// The longest label value, but [`DESCRIPTION`]'s.
pub const MAX_VALUE_LEN: usize = 63;
/// The longest [`DESCRIPTION`].
pub const MAX_DESCRIPTION_LEN: usize = 255;

/// Who a secret belongs to: a team or a person, by the usual rule.
pub const OWNER: &str = "owner";
/// Who to ask about it: an email address or a chat channel.
pub const CONTACT: &str = "contact";
/// What it is, in a few words.
pub const DESCRIPTION: &str = "description";

/// The most a path's labels can take, raw: every key and value at its
/// longest, one of them a [`DESCRIPTION`] at its longest. The transports'
/// message limits are sized from it (with the largest value), so a put with
/// the most labels fits through both APIs.
pub const MAX_LABELS_SIZE: usize =
    MAX_LABELS * (MAX_KEY_LEN + MAX_VALUE_LEN) + (MAX_DESCRIPTION_LEN - MAX_VALUE_LEN);

/// What every reserved key starts with: ferritor's own keys.
pub const RESERVED_PREFIX: &str = "ferritor.";
/// The rotation flag: `true` on a secret that must be rotated on schedule.
pub const ROTATION: &str = "ferritor.rotation";
/// The one value [`ROTATION`] takes.
pub const ROTATION_ON: &str = "true";

/// A path's labels, ordered by key.
pub type Labels = BTreeMap<String, String>;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum LabelError {
    #[error("a label key is empty")]
    EmptyKey,
    #[error("label key `{0}` is longer than {MAX_KEY_LEN} characters")]
    KeyTooLong(String),
    #[error(
        "label key `{key}` contains {char:?}; only ASCII letters, digits, `-`, `_` and `.` are \
         allowed"
    )]
    InvalidKeyChar { key: String, char: char },
    #[error("label key `{0}` must begin and end with a letter or digit")]
    KeyEnds(String),
    #[error("the value of label `{0}` is empty")]
    EmptyValue(String),
    #[error("the value of label `{0}` is longer than {max} characters", max = max_value_len(.0))]
    ValueTooLong(String),
    #[error("the value of label `{key}` contains {char:?}; {allowed}", allowed = value_alphabet(.key))]
    InvalidValueChar { key: String, char: char },
    #[error("the value of label `{0}` must {rule}", rule = value_ends(.0))]
    ValueEnds(String),
    #[error("{count} labels; a path holds at most {MAX_LABELS}")]
    TooMany { count: usize },
    #[error("label `{0}` is both set and removed")]
    SetAndRemoved(String),
    #[error("`{0}` is not a `key=value` label")]
    NotAPair(String),
    #[error("a label change must set or remove at least one label")]
    NothingToChange,
    #[error(
        "label key `{0}` is reserved: keys starting with `ferritor.` are ferritor's own, and the \
         only one is `ferritor.rotation`"
    )]
    UnknownReserved(String),
    #[error(
        "`ferritor.rotation` is `true` or absent: remove the label to turn rotation reminders off"
    )]
    RotationFalse,
    #[error("`ferritor.rotation` takes only `true`, not `{0}`")]
    RotationValue(String),
    #[error("label `{0}` is a secret's: a namespace takes no `ferritor.` label (it never rotates)")]
    ReservedOnNamespace(String),
}

/// What a key and a value share: the alphabet, and letters or digits at
/// both ends. The first character outside the alphabet, or `Err(None)` for
/// a bad end.
fn shape(s: &str) -> Result<(), Option<char>> {
    if let Some(c) = s
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    {
        return Err(Some(c));
    }
    let edge = |b: Option<&u8>| b.is_some_and(u8::is_ascii_alphanumeric);
    if !edge(s.as_bytes().first()) || !edge(s.as_bytes().last()) {
        return Err(None);
    }
    Ok(())
}

/// Checks a label key: its shape, and, if it's reserved, that it's one
/// ferritor knows.
pub fn check_key(key: &str) -> Result<(), LabelError> {
    check_key_shape(key)?;
    if key.starts_with(RESERVED_PREFIX) && key != ROTATION {
        return Err(LabelError::UnknownReserved(key.to_owned()));
    }
    Ok(())
}

/// A key's shape alone: what a key to remove needs. Removing never adds a
/// label, so an unknown `ferritor.` key stored before the reserved keys
/// existed can still be removed.
fn check_key_shape(key: &str) -> Result<(), LabelError> {
    if key.is_empty() {
        return Err(LabelError::EmptyKey);
    }
    if key.len() > MAX_KEY_LEN {
        return Err(LabelError::KeyTooLong(key.to_owned()));
    }
    shape(key).map_err(|bad| match bad {
        Some(char) => LabelError::InvalidKeyChar {
            key: key.to_owned(),
            char,
        },
        None => LabelError::KeyEnds(key.to_owned()),
    })
}

/// The longest value `key` takes.
pub fn max_value_len(key: &str) -> usize {
    if key == DESCRIPTION {
        MAX_DESCRIPTION_LEN
    } else {
        MAX_VALUE_LEN
    }
}

fn value_alphabet(key: &str) -> &'static str {
    match key {
        DESCRIPTION => "only printable ASCII is allowed (letters, digits, punctuation, spaces)",
        CONTACT => "only ASCII letters, digits, `-`, `_`, `.`, `@` and `#` are allowed",
        _ => "only ASCII letters, digits, `-`, `_` and `.` are allowed",
    }
}

fn value_ends(key: &str) -> &'static str {
    match key {
        DESCRIPTION => "not begin or end with a space",
        CONTACT => "begin with a letter, a digit or `#`, and end with a letter or digit",
        _ => "begin and end with a letter or digit",
    }
}

/// A value's shape by its key: the first character outside its alphabet,
/// or `Err(None)` for a bad end.
fn value_shape(key: &str, value: &str) -> Result<(), Option<char>> {
    match key {
        DESCRIPTION => {
            if let Some(c) = value.chars().find(|c| !(' '..='~').contains(c)) {
                return Err(Some(c));
            }
            if value.starts_with(' ') || value.ends_with(' ') {
                return Err(None);
            }
            Ok(())
        }
        CONTACT => {
            if let Some(c) = value
                .chars()
                .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '#')))
            {
                return Err(Some(c));
            }
            let bytes = value.as_bytes();
            let first = bytes
                .first()
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'#');
            let last = bytes.last().is_some_and(u8::is_ascii_alphanumeric);
            if first && last { Ok(()) } else { Err(None) }
        }
        _ => shape(value),
    }
}

/// Checks a label's value: by its key's rule (`key` names it in the error).
pub fn check_value(key: &str, value: &str) -> Result<(), LabelError> {
    if value.is_empty() {
        return Err(LabelError::EmptyValue(key.to_owned()));
    }
    if value.len() > max_value_len(key) {
        return Err(LabelError::ValueTooLong(key.to_owned()));
    }
    value_shape(key, value).map_err(|bad| match bad {
        Some(char) => LabelError::InvalidValueChar {
            key: key.to_owned(),
            char,
        },
        None => LabelError::ValueEnds(key.to_owned()),
    })?;
    match (key, value) {
        (ROTATION, ROTATION_ON) => Ok(()),
        (ROTATION, "false") => Err(LabelError::RotationFalse),
        (ROTATION, other) => Err(LabelError::RotationValue(other.to_owned())),
        _ => Ok(()),
    }
}

/// Checks every key and value, and that there are at most [`MAX_LABELS`].
pub fn check(labels: &Labels) -> Result<(), LabelError> {
    if labels.len() > MAX_LABELS {
        return Err(LabelError::TooMany {
            count: labels.len(),
        });
    }
    for (key, value) in labels {
        check_key(key)?;
        check_value(key, value)?;
    }
    Ok(())
}

/// Checks a change: labels to set, and keys to remove (each a key of the
/// right shape, none in both, and at least one of either: an empty change
/// would only clutter the audit log). The reserved keys' rules apply to
/// what's set only: removing can't add a label. How many the path then
/// holds is checked where it's stored.
pub fn check_change(set: &Labels, remove: &[String]) -> Result<(), LabelError> {
    if set.is_empty() && remove.is_empty() {
        return Err(LabelError::NothingToChange);
    }
    check(set)?;
    for key in remove {
        check_key_shape(key)?;
        if set.contains_key(key) {
            return Err(LabelError::SetAndRemoved(key.clone()));
        }
    }
    Ok(())
}

/// [`check`] for a namespace's labels: no reserved key at all.
pub fn check_namespace(labels: &Labels) -> Result<(), LabelError> {
    check(labels)?;
    refuse_reserved(labels.keys())
}

/// [`check_change`] for a namespace's labels: no reserved key set. One may
/// be removed (one stored before the reserved keys existed).
pub fn check_namespace_change(set: &Labels, remove: &[String]) -> Result<(), LabelError> {
    check_change(set, remove)?;
    refuse_reserved(set.keys())
}

fn refuse_reserved<'a>(keys: impl IntoIterator<Item = &'a String>) -> Result<(), LabelError> {
    match keys
        .into_iter()
        .find(|key| key.starts_with(RESERVED_PREFIX))
    {
        Some(key) => Err(LabelError::ReservedOnNamespace(key.clone())),
        None => Ok(()),
    }
}

/// Whether `labels` has the rotation flag on.
pub fn rotates(labels: &Labels) -> bool {
    labels
        .get(ROTATION)
        .is_some_and(|value| value == ROTATION_ON)
}

/// Parses `key=value` (split at the first `=`, so the key never holds one;
/// the value only where its key's rule allows, a `description`), and checks
/// both.
pub fn parse_pair(pair: &str) -> Result<(String, String), LabelError> {
    let (key, value) = pair
        .split_once('=')
        .ok_or_else(|| LabelError::NotAPair(pair.to_owned()))?;
    check_key(key)?;
    check_value(key, value)?;
    Ok((key.to_owned(), value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_values_are_checked_not_rewritten() {
        for ok in ["team", "a", "app.example.com", "a_b-c.1", "A9"] {
            assert_eq!(check_key(ok), Ok(()), "{ok}");
            assert_eq!(check_value("k", ok), Ok(()), "{ok}");
        }
        assert_eq!(check_key(""), Err(LabelError::EmptyKey));
        assert_eq!(
            check_value("k", ""),
            Err(LabelError::EmptyValue("k".to_owned()))
        );
        for (bad, char) in [
            ("team name", ' '),
            ("tëam", 'ë'),
            ("app.example.com/name", '/'),
            ("a=b", '='),
            ("zero\u{200B}width", '\u{200B}'),
            ("a\u{202E}b", '\u{202E}'),
            ("ok\u{E0041}", '\u{E0041}'),
            ("a\nb", '\n'),
        ] {
            assert!(
                matches!(check_key(bad), Err(LabelError::InvalidKeyChar { char: c, .. }) if c == char),
                "{bad:?}"
            );
            assert!(
                matches!(check_value("k", bad), Err(LabelError::InvalidValueChar { char: c, .. }) if c == char),
                "{bad:?}"
            );
        }
        for bad in ["-a", "a-", ".a", "a.", "_", "_a_"] {
            assert_eq!(check_key(bad), Err(LabelError::KeyEnds(bad.to_owned())));
            assert_eq!(
                check_value("k", bad),
                Err(LabelError::ValueEnds("k".to_owned()))
            );
        }
        let longest = "k".repeat(MAX_KEY_LEN);
        assert_eq!(check_key(&longest), Ok(()));
        assert!(matches!(
            check_key(&format!("{longest}k")),
            Err(LabelError::KeyTooLong(_))
        ));
        let longest = "v".repeat(MAX_VALUE_LEN);
        assert_eq!(check_value("k", &longest), Ok(()));
        assert_eq!(
            check_value("k", &format!("{longest}v")),
            Err(LabelError::ValueTooLong("k".to_owned()))
        );
    }

    #[test]
    fn a_path_holds_at_most_64() {
        let labels =
            |n: usize| -> Labels { (0..n).map(|i| (format!("k{i}"), "v".to_owned())).collect() };
        assert_eq!(check(&labels(MAX_LABELS)), Ok(()));
        assert_eq!(
            check(&labels(MAX_LABELS + 1)),
            Err(LabelError::TooMany {
                count: MAX_LABELS + 1
            })
        );
    }

    #[test]
    fn a_change_never_sets_and_removes_one_key() {
        let set = Labels::from([("team".to_owned(), "a".to_owned())]);
        assert_eq!(check_change(&set, &["project".to_owned()]), Ok(()));
        assert_eq!(
            check_change(&set, &["team".to_owned()]),
            Err(LabelError::SetAndRemoved("team".to_owned()))
        );
        assert!(check_change(&set, &["bad key".to_owned()]).is_err());
        assert_eq!(
            check_change(&Labels::new(), &[]),
            Err(LabelError::NothingToChange)
        );
    }

    /// `ferritor.rotation` is the one reserved key, and takes `true` only;
    /// `false` is refused with its own hint. Any other `ferritor.` key is
    /// refused, a near miss included. A namespace takes none.
    #[test]
    fn the_rotation_flag_is_true_or_absent() {
        assert_eq!(check_key(ROTATION), Ok(()));
        assert_eq!(check_value(ROTATION, "true"), Ok(()));
        assert_eq!(
            check_value(ROTATION, "false"),
            Err(LabelError::RotationFalse)
        );
        for other in ["yes", "True", "1", "on"] {
            assert_eq!(
                check_value(ROTATION, other),
                Err(LabelError::RotationValue(other.to_owned())),
                "{other}"
            );
        }
        for typo in [
            "ferritor.rotate",
            "ferritor.rotation2",
            "ferritor.owner",
            "ferritor.x",
        ] {
            assert_eq!(
                check_key(typo),
                Err(LabelError::UnknownReserved(typo.to_owned())),
                "{typo}"
            );
        }
        // Not reserved: the prefix is `ferritor.`, dot included.
        assert_eq!(check_key("ferritor"), Ok(()));
        assert_eq!(check_key("ferritorx.rotation"), Ok(()));
        let flagged = Labels::from([(ROTATION.to_owned(), "true".to_owned())]);
        assert_eq!(check(&flagged), Ok(()));
        assert!(rotates(&flagged));
        assert!(!rotates(&Labels::new()));
        assert_eq!(
            check_namespace(&flagged),
            Err(LabelError::ReservedOnNamespace(ROTATION.to_owned()))
        );
        assert_eq!(
            check_namespace_change(&flagged, &[]),
            Err(LabelError::ReservedOnNamespace(ROTATION.to_owned()))
        );
        // Removing never adds a label: a reserved key stored before the
        // rules (`ferritor.owner`, say) can still be removed, on a path or
        // a namespace, though it can't be set.
        let legacy = ["ferritor.owner".to_owned()];
        assert_eq!(check_change(&Labels::new(), &legacy), Ok(()));
        assert_eq!(check_namespace_change(&Labels::new(), &legacy), Ok(()));
        assert_eq!(
            check_namespace_change(&Labels::new(), &[ROTATION.to_owned()]),
            Ok(())
        );
        assert_eq!(
            parse_pair("ferritor.rotation=true"),
            Ok((ROTATION.to_owned(), "true".to_owned()))
        );
        assert_eq!(
            parse_pair("ferritor.rotation=false"),
            Err(LabelError::RotationFalse)
        );
    }

    /// `description` takes printable ASCII and spaces, up to 255
    /// characters; `contact` `@` and `#`; `owner` and every other key only
    /// the usual rule. Nothing invisible or non-ASCII fits any of them.
    #[test]
    fn the_metadata_keys_take_their_own_values() {
        for ok in [
            "the billing database's password",
            "rotated by: ops (see RUNBOOK.md #4)",
            "a",
        ] {
            assert_eq!(check_value(DESCRIPTION, ok), Ok(()), "{ok}");
        }
        let longest = "d".repeat(MAX_DESCRIPTION_LEN);
        assert_eq!(check_value(DESCRIPTION, &longest), Ok(()));
        assert_eq!(
            check_value(DESCRIPTION, &format!("{longest}d")),
            Err(LabelError::ValueTooLong(DESCRIPTION.to_owned()))
        );
        for (bad, char) in [
            ("tab\there", '\t'),
            ("caf\u{e9}", '\u{e9}'),
            ("a\u{200B}b", '\u{200B}'),
        ] {
            assert!(
                matches!(check_value(DESCRIPTION, bad), Err(LabelError::InvalidValueChar { char: c, .. }) if c == char),
                "{bad:?}"
            );
        }
        for bad in [" padded", "padded "] {
            assert_eq!(
                check_value(DESCRIPTION, bad),
                Err(LabelError::ValueEnds(DESCRIPTION.to_owned()))
            );
        }
        for ok in [
            "alice@example.com",
            "#billing-oncall",
            "ops_team.lead@corp.example",
        ] {
            assert_eq!(check_value(CONTACT, ok), Ok(()), "{ok}");
        }
        assert!(matches!(
            check_value(CONTACT, "alice smith"),
            Err(LabelError::InvalidValueChar { char: ' ', .. })
        ));
        for bad in ["@alice", "alice@", "-x"] {
            assert_eq!(
                check_value(CONTACT, bad),
                Err(LabelError::ValueEnds(CONTACT.to_owned())),
                "{bad}"
            );
        }
        // Not wider for any other key: owner, or a look-alike.
        for key in [OWNER, "team", "descriptions"] {
            assert!(check_value(key, "two words").is_err(), "{key}");
            assert!(check_value(key, "a@b").is_err(), "{key}");
        }
        assert_eq!(check_value(OWNER, "billing-team"), Ok(()));
        // As a CLI argument: `description="two words"` arrives as one.
        assert_eq!(
            parse_pair("description=two words"),
            Ok((DESCRIPTION.to_owned(), "two words".to_owned()))
        );
        // The messages say each key's own rule.
        let message = check_value(CONTACT, "a b").unwrap_err().to_string();
        assert!(message.contains("`@` and `#`"), "{message}");
        let message = check_value(DESCRIPTION, &format!("{longest}d"))
            .unwrap_err()
            .to_string();
        assert!(message.contains("255"), "{message}");
    }

    #[test]
    fn pairs_split_at_the_equals_sign() {
        assert_eq!(
            parse_pair("team=a"),
            Ok(("team".to_owned(), "a".to_owned()))
        );
        // Split at the first `=`: a value holds another only where its key
        // allows one (a description), and neither half may be empty.
        assert!(matches!(
            parse_pair("query=a=b"),
            Err(LabelError::InvalidValueChar { char: '=', .. })
        ));
        assert_eq!(
            parse_pair("description=a=b"),
            Ok((DESCRIPTION.to_owned(), "a=b".to_owned()))
        );
        assert_eq!(
            parse_pair("empty="),
            Err(LabelError::EmptyValue("empty".to_owned()))
        );
        assert_eq!(
            parse_pair("team"),
            Err(LabelError::NotAPair("team".to_owned()))
        );
        assert_eq!(parse_pair("=a"), Err(LabelError::EmptyKey));
    }
}
