//! Secret paths. Ciphertext AAD binds the exact bytes of the path, so every
//! path must have exactly one spelling: `a/b`, `/a/b` and `a//b` would
//! otherwise be three different secrets. Non-canonical input is rejected
//! rather than rewritten, so what's stored is always what the caller sent.
//!
//! Canonical form: one or more segments joined by `/`, each made of ASCII
//! letters, digits, `.`, `_` and `-`, and not `.` or `..`. Restricting to
//! ASCII also rules out Unicode look-alikes and NFC/NFD variants of the same
//! name.

use std::fmt;
use std::str::FromStr;

pub const MAX_LEN: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretPath(String);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("secret path is empty")]
    Empty,
    #[error("secret path is longer than {MAX_LEN} bytes")]
    TooLong,
    #[error("secret path has an empty segment (leading, trailing or doubled `/`)")]
    EmptySegment,
    #[error("secret path segment `{0}` is reserved")]
    ReservedSegment(String),
    #[error(
        "secret path contains {0:?}; only ASCII letters, digits, `.`, `_`, `-` and `/` are allowed"
    )]
    InvalidChar(char),
}

impl SecretPath {
    pub fn parse(path: &str) -> Result<Self, PathError> {
        if path.is_empty() {
            return Err(PathError::Empty);
        }
        if path.len() > MAX_LEN {
            return Err(PathError::TooLong);
        }
        for segment in path.split('/') {
            if segment.is_empty() {
                return Err(PathError::EmptySegment);
            }
            if segment == "." || segment == ".." {
                return Err(PathError::ReservedSegment(segment.to_owned()));
            }
            if let Some(c) = segment
                .chars()
                .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
            {
                return Err(PathError::InvalidChar(c));
            }
        }
        Ok(Self(path.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The namespace the path belongs to: its first segment (whether it's
    /// a registered namespace is the server's business).
    pub fn namespace(&self) -> Namespace {
        let first = self.0.split('/').next().unwrap_or(&self.0);
        Namespace(first.to_owned())
    }

    /// Whether `self` is strictly below `parent`, by whole segments:
    /// `a/b/c` is under `a/b`, but `a/bc` is not.
    pub fn is_under(&self, parent: &SecretPath) -> bool {
        self.0
            .strip_prefix(parent.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    }

    /// Half-open byte range `[lo, hi)` holding exactly the paths [`is_under`]
    /// `self`: `self/` up to `self0`, `0` being the byte after `/`. For
    /// listing with `path >= lo AND path < hi`, which uses the index on
    /// `paths.path` even in generic prepared-statement plans, unlike
    /// `starts_with`. Only correct because `paths.path` is `COLLATE "C"`
    /// (byte order); under a locale collation it returns wrong rows.
    ///
    /// [`is_under`]: Self::is_under
    pub fn descendant_range(&self) -> (String, String) {
        (format!("{}/", self.0), format!("{}0", self.0))
    }
}

/// A namespace name: one segment of a secret path (the first), under the
/// same rules. Every secret belongs to the namespace named by its path's
/// first segment, and each namespace has its own KEKs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Namespace(String);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NamespaceError {
    #[error("a namespace is one path segment, without `/`")]
    NotOneSegment,
    #[error("invalid namespace name")]
    Invalid(#[source] PathError),
}

impl Namespace {
    pub fn parse(name: &str) -> Result<Self, NamespaceError> {
        let path = SecretPath::parse(name).map_err(NamespaceError::Invalid)?;
        if path.as_str().contains('/') {
            return Err(NamespaceError::NotOneSegment);
        }
        Ok(Self(path.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The namespace as a path: listing below it lists the namespace.
    pub fn as_path(&self) -> SecretPath {
        SecretPath(self.0.clone())
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SecretPath {
    type Err = PathError;

    fn from_str(path: &str) -> Result<Self, PathError> {
        Self::parse(path)
    }
}

impl AsRef<str> for SecretPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn a_namespace_is_the_first_segment_and_one_segment() {
        let path = SecretPath::parse("billing/eu/db").unwrap();
        assert_eq!(path.namespace().as_str(), "billing");
        assert_eq!(
            SecretPath::parse("solo").unwrap().namespace().as_str(),
            "solo"
        );
        assert_eq!(Namespace::parse("billing").unwrap().as_str(), "billing");
        assert_eq!(Namespace::parse("a/b"), Err(NamespaceError::NotOneSegment));
        assert!(matches!(
            Namespace::parse(""),
            Err(NamespaceError::Invalid(_))
        ));
        assert!(matches!(
            Namespace::parse(".."),
            Err(NamespaceError::Invalid(_))
        ));
        assert_eq!(
            Namespace::parse("billing").unwrap().as_path().as_str(),
            "billing"
        );
    }

    #[test]
    fn accepts_canonical_paths() {
        for path in ["a", "a/b", "prod/db-password", "x.y_z/1/A-b.c", "a/.hidden"] {
            assert_eq!(SecretPath::parse(path).unwrap().as_str(), path);
        }
    }

    #[test]
    fn rejects_non_canonical_spellings() {
        for path in ["/a/b", "a/b/", "a//b", "/", "//"] {
            assert_eq!(SecretPath::parse(path), Err(PathError::EmptySegment));
        }
        assert_eq!(SecretPath::parse(""), Err(PathError::Empty));
        assert!(matches!(
            SecretPath::parse("a/../b"),
            Err(PathError::ReservedSegment(_))
        ));
        assert!(matches!(
            SecretPath::parse("./a"),
            Err(PathError::ReservedSegment(_))
        ));
    }

    #[test]
    fn rejects_characters_outside_the_set() {
        for (path, c) in [
            ("a b", ' '),
            ("a%", '%'),
            ("a\\b", '\\'),
            ("caf\u{e9}", '\u{e9}'),
            ("a\0", '\0'),
        ] {
            assert_eq!(SecretPath::parse(path), Err(PathError::InvalidChar(c)));
        }
    }

    #[test]
    fn rejects_overlong_paths() {
        assert!(SecretPath::parse(&"a".repeat(MAX_LEN)).is_ok());
        assert_eq!(
            SecretPath::parse(&"a".repeat(MAX_LEN + 1)),
            Err(PathError::TooLong)
        );
    }

    #[test]
    fn is_under_matches_whole_segments() {
        let p = |s| SecretPath::parse(s).unwrap();
        assert!(p("a/b/c").is_under(&p("a/b")));
        assert!(p("a/b/c").is_under(&p("a")));
        assert!(!p("a/bc").is_under(&p("a/b")));
        assert!(!p("a/b").is_under(&p("a/b")));
        assert!(!p("a").is_under(&p("a/b")));
    }

    fn path() -> impl Strategy<Value = SecretPath> {
        "[a-c0/._-]{1,3}(/[a-c0/._-]{1,3}){0,3}"
            .prop_filter_map("non-canonical", |s| SecretPath::parse(&s).ok())
    }

    proptest! {
        /// `String` orders by bytes, like `COLLATE "C"`. The small alphabet
        /// (with `0` and `.`/`-`, which sort around `/`) makes near-misses
        /// such as `a/b` vs `a/b0` vs `a/b.c` common.
        #[test]
        fn descendant_range_matches_is_under(child in path(), parent in path()) {
            let (lo, hi) = parent.descendant_range();
            let in_range = child.as_str() >= lo.as_str() && child.as_str() < hi.as_str();
            prop_assert_eq!(in_range, child.is_under(&parent));
        }

        /// Whatever parses is already canonical: no leading, trailing or
        /// doubled separators survive.
        #[test]
        fn parsed_paths_are_canonical(path in "[a-z/._%-]{0,12}") {
            if let Ok(parsed) = SecretPath::parse(&path) {
                let s = parsed.as_str();
                prop_assert!(!s.starts_with('/') && !s.ends_with('/') && !s.contains("//"));
                prop_assert!(s.split('/').all(|seg| seg != "." && seg != ".."));
            }
        }
    }
}
