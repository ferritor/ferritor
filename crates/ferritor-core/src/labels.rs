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
//! Shared by the server (which checks everything it stores) and the CLI
//! (which checks `key=value` arguments before sending them).

use std::collections::BTreeMap;

/// The most labels one path may hold.
pub const MAX_LABELS: usize = 64;
/// The longest label key (ASCII, so bytes and characters alike).
pub const MAX_KEY_LEN: usize = 63;
/// The longest label value.
pub const MAX_VALUE_LEN: usize = 63;

/// The most a path's labels can take, raw: every key and value at its
/// longest. The transports' message limits are sized from it (with the
/// largest value), so a put with the most labels fits through both APIs.
pub const MAX_LABELS_SIZE: usize = MAX_LABELS * (MAX_KEY_LEN + MAX_VALUE_LEN);

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
    #[error("the value of label `{0}` is longer than {MAX_VALUE_LEN} characters")]
    ValueTooLong(String),
    #[error(
        "the value of label `{key}` contains {char:?}; only ASCII letters, digits, `-`, `_` and \
         `.` are allowed"
    )]
    InvalidValueChar { key: String, char: char },
    #[error("the value of label `{0}` must begin and end with a letter or digit")]
    ValueEnds(String),
    #[error("{count} labels; a path holds at most {MAX_LABELS}")]
    TooMany { count: usize },
    #[error("label `{0}` is both set and removed")]
    SetAndRemoved(String),
    #[error("`{0}` is not a `key=value` label")]
    NotAPair(String),
    #[error("a label change must set or remove at least one label")]
    NothingToChange,
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

/// Checks a label key.
pub fn check_key(key: &str) -> Result<(), LabelError> {
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

/// Checks a label's value (`key` only names it in the error).
pub fn check_value(key: &str, value: &str) -> Result<(), LabelError> {
    if value.is_empty() {
        return Err(LabelError::EmptyValue(key.to_owned()));
    }
    if value.len() > MAX_VALUE_LEN {
        return Err(LabelError::ValueTooLong(key.to_owned()));
    }
    shape(value).map_err(|bad| match bad {
        Some(char) => LabelError::InvalidValueChar {
            key: key.to_owned(),
            char,
        },
        None => LabelError::ValueEnds(key.to_owned()),
    })
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

/// Checks a change: labels to set, and keys to remove (each a valid key,
/// none in both, and at least one of either: an empty change would only
/// clutter the audit log). How many the path then holds is checked where
/// it's stored.
pub fn check_change(set: &Labels, remove: &[String]) -> Result<(), LabelError> {
    if set.is_empty() && remove.is_empty() {
        return Err(LabelError::NothingToChange);
    }
    check(set)?;
    for key in remove {
        check_key(key)?;
        if set.contains_key(key) {
            return Err(LabelError::SetAndRemoved(key.clone()));
        }
    }
    Ok(())
}

/// Parses `key=value` (split at the first `=`; neither half may hold
/// another), and checks both.
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

    #[test]
    fn pairs_split_at_the_equals_sign() {
        assert_eq!(
            parse_pair("team=a"),
            Ok(("team".to_owned(), "a".to_owned()))
        );
        // Neither half may hold a `=`, nor be empty.
        assert!(matches!(
            parse_pair("query=a=b"),
            Err(LabelError::InvalidValueChar { char: '=', .. })
        ));
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
