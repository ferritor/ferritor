//! Stored policies: the rules applications get through the API, kept in the
//! keys database (the server's `policy_store`), shared with the CLI so a
//! file is checked locally by the same rules before anything is sent.
//!
//! A stored policy grants **secret actions only** ([`SecretAction`]): admin
//! actions are granted in `ferritor.toml` alone, so the API can never create an
//! admin. Each policy names one identity, its actions and its scope (path
//! prefixes, whole segments, or every path), plus a description.
//!
//! Integrity: every stored row carries an HMAC (under the policy key, see
//! `crypto::PolicyKey`) over [`row_message`], and the set one over
//! [`set_message`]. The encodings are length-prefixed and domain-tagged, so
//! no two different rows (or sets) encode alike.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::path::{PathError, SecretPath};

/// At most this many paths in one policy.
pub const MAX_PATHS: usize = 64;
/// A description's limit, in bytes.
pub const MAX_DESCRIPTION: usize = 1024;
/// At most this many stored policies.
pub const MAX_STORED: usize = 10_000;
/// At most this many policies in one apply: all of them, so the repair (an
/// apply with prune, the whole set) is always possible.
pub const MAX_APPLY: usize = MAX_STORED;
/// An apply's largest message, in bytes, on either API: what the transport
/// limits are sized from. 10 000 typical policies (a few hundred bytes each)
/// fit easily.
pub const MAX_APPLY_BYTES: usize = 16 * 1024 * 1024;

/// What a stored policy may grant: the secret actions, spelled as in
/// `ferritor.toml` and the audit log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretAction {
    Read,
    Write,
    Delete,
    List,
    Label,
}

/// The admin actions' names (the server's `authz::Action`, `is_admin`), only
/// so a stored policy naming one is refused with a reason, not as unknown.
pub const ADMIN_ACTIONS: &[&str] = &[
    "status",
    "init",
    "unseal",
    "seal",
    "rekey",
    "rotate",
    "rewrap",
    "purge",
    "destroy_kek",
    "namespace",
    "policy",
    "identity",
];

impl SecretAction {
    pub const ALL: [Self; 5] = [
        Self::Read,
        Self::Write,
        Self::Delete,
        Self::List,
        Self::Label,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Label => "label",
        }
    }

    /// A secret action by name; an admin action or anything else is an error
    /// saying which.
    pub fn parse(name: &str) -> Result<Self, PolicyError> {
        Self::ALL
            .into_iter()
            .find(|action| action.name() == name)
            .ok_or_else(|| {
                if ADMIN_ACTIONS.contains(&name) {
                    PolicyError::AdminAction(name.to_owned())
                } else {
                    PolicyError::UnknownAction(name.to_owned())
                }
            })
    }
}

impl fmt::Display for SecretAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl<'de> Deserialize<'de> for SecretAction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Self::parse(&name).map_err(serde::de::Error::custom)
    }
}

/// A stored policy as written: in an API request, a file, the JSON API.
/// Unknown fields are refused, so a misspelled key can't silently drop a
/// restriction.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    /// Secret-path rules (`apps/billing-read`); never `config:…`, which names
    /// the config rules.
    pub name: String,
    /// The `<name>` of a `ferritor://<name>` client certificate identity.
    pub identity: String,
    pub actions: Vec<SecretAction>,
    /// Path prefixes (whole segments); exactly one of `paths` and
    /// `all_paths`.
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub all_paths: bool,
    #[serde(default)]
    pub description: String,
}

/// Where a policy's actions apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// At or under these prefixes.
    Paths(BTreeSet<SecretPath>),
    All,
}

impl Scope {
    /// Whether `path` (a secret, or a listing's prefix) is covered.
    pub fn covers(&self, path: &SecretPath) -> bool {
        match self {
            Self::All => true,
            Self::Paths(prefixes) => prefixes.iter().any(|q| path == q || path.is_under(q)),
        }
    }
}

/// A [`PolicySpec`] that passed [`PolicySpec::validate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub name: SecretPath,
    pub identity: SecretPath,
    pub actions: BTreeSet<SecretAction>,
    pub scope: Scope,
    pub description: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy name `{name}` is invalid (secret-path rules)")]
    BadName {
        name: String,
        #[source]
        source: PathError,
    },
    #[error("identity `{identity}` is not a valid name")]
    BadIdentity {
        identity: String,
        #[source]
        source: PathError,
    },
    #[error("path `{path}` is not a valid secret path")]
    BadPath {
        path: String,
        #[source]
        source: PathError,
    },
    #[error("unknown action `{0}` (a stored policy grants read, write, delete, list, label)")]
    UnknownAction(String),
    #[error(
        "`{0}` is an admin action: only the config rules (ferritor.toml) grant those; a stored \
         policy grants read, write, delete, list, label"
    )]
    AdminAction(String),
    #[error("no actions")]
    NoActions,
    #[error("no scope: give `paths`, or `all_paths = true`")]
    NoScope,
    #[error("`all_paths` and `paths` together; choose one")]
    AllAndPaths,
    #[error("{count} paths; a policy holds at most {MAX_PATHS}")]
    TooManyPaths { count: usize },
    #[error("description of {size} bytes; at most {MAX_DESCRIPTION}")]
    DescriptionTooLong { size: usize },
    #[error(
        "the description holds {0:?}; only printable ASCII (letters, digits, spaces, \
         punctuation), newlines and tabs are allowed"
    )]
    DescriptionChar(char),
}

impl PolicySpec {
    pub fn validate(&self) -> Result<Policy, PolicyError> {
        let name = SecretPath::parse(&self.name).map_err(|source| PolicyError::BadName {
            name: self.name.clone(),
            source,
        })?;
        let identity =
            SecretPath::parse(&self.identity).map_err(|source| PolicyError::BadIdentity {
                identity: self.identity.clone(),
                source,
            })?;
        if self.actions.is_empty() {
            return Err(PolicyError::NoActions);
        }
        if self.paths.len() > MAX_PATHS {
            return Err(PolicyError::TooManyPaths {
                count: self.paths.len(),
            });
        }
        let scope = match (self.all_paths, self.paths.is_empty()) {
            (true, false) => return Err(PolicyError::AllAndPaths),
            (false, true) => return Err(PolicyError::NoScope),
            (true, true) => Scope::All,
            (false, false) => Scope::Paths(
                self.paths
                    .iter()
                    .map(|path| {
                        SecretPath::parse(path).map_err(|source| PolicyError::BadPath {
                            path: path.clone(),
                            source,
                        })
                    })
                    .collect::<Result<_, _>>()?,
            ),
        };
        if self.description.len() > MAX_DESCRIPTION {
            return Err(PolicyError::DescriptionTooLong {
                size: self.description.len(),
            });
        }
        // People decide by it (`ferritor policy list`): plain ASCII hides
        // nothing (no invisible, bidirectional or look-alike characters).
        if let Some(c) = self.description.chars().find(|&c| !description_char(c)) {
            return Err(PolicyError::DescriptionChar(c));
        }
        Ok(Policy {
            name,
            identity,
            actions: self.actions.iter().copied().collect(),
            scope,
            description: self.description.clone(),
        })
    }
}

/// What a description may hold: printable ASCII (space to `~`), newlines
/// and tabs.
fn description_char(c: char) -> bool {
    matches!(c, ' '..='~' | '\n' | '\t')
}

impl Policy {
    /// The canonical form, as stored: actions and paths sorted, no
    /// duplicates. Two specs that grant the same come out equal.
    pub fn spec(&self) -> PolicySpec {
        let (paths, all_paths) = match &self.scope {
            Scope::All => (Vec::new(), true),
            Scope::Paths(paths) => (paths.iter().map(ToString::to_string).collect(), false),
        };
        PolicySpec {
            name: self.name.to_string(),
            identity: self.identity.to_string(),
            actions: self.actions.iter().copied().collect(),
            paths,
            all_paths,
            description: self.description.clone(),
        }
    }
}

/// A row's fields as stored, for [`row_message`]: strings, not parsed types,
/// so a row naming an action this binary doesn't know still encodes (and
/// verifies) exactly as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowFields<'a> {
    pub name: &'a str,
    pub identity: &'a str,
    /// Sorted, as stored.
    pub actions: &'a [String],
    /// Sorted, as stored.
    pub paths: &'a [String],
    pub all_paths: bool,
    pub version: u32,
    pub description: &'a str,
}

/// One entry of the set, for [`set_message`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetEntry<'a> {
    pub name: &'a str,
    pub version: u32,
    pub mac: &'a [u8],
}

fn put(message: &mut Vec<u8>, bytes: &[u8]) {
    // A field is at most a few KiB: a u32 length always fits; saturate
    // rather than wrap if it ever didn't (the MAC then simply fails).
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(bytes);
}

fn put_list(message: &mut Vec<u8>, items: &[String]) {
    let count = u32::try_from(items.len()).unwrap_or(u32::MAX);
    message.extend_from_slice(&count.to_be_bytes());
    for item in items {
        put(message, item.as_bytes());
    }
}

/// What a row's MAC covers: every field but the timestamps (the description
/// too: people decide by it).
pub fn row_message(row: &RowFields<'_>) -> Vec<u8> {
    let mut message = b"ferritor.policy.v1\0".to_vec();
    put(&mut message, row.name.as_bytes());
    put(&mut message, row.identity.as_bytes());
    put_list(&mut message, row.actions);
    put_list(&mut message, row.paths);
    message.push(u8::from(row.all_paths));
    message.extend_from_slice(&row.version.to_be_bytes());
    put(&mut message, row.description.as_bytes());
    message
}

/// What the set's MAC covers: the revision and every row by name, version
/// and MAC, sorted by name. A row added, removed or swapped in from
/// elsewhere changes it.
pub fn set_message(revision: u64, entries: &[SetEntry<'_>]) -> Vec<u8> {
    let mut sorted: Vec<&SetEntry<'_>> = entries.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(b.name));
    let mut message = b"ferritor.policy-set.v1\0".to_vec();
    message.extend_from_slice(&revision.to_be_bytes());
    let count = u32::try_from(sorted.len()).unwrap_or(u32::MAX);
    message.extend_from_slice(&count.to_be_bytes());
    for entry in sorted {
        put(&mut message, entry.name.as_bytes());
        message.extend_from_slice(&entry.version.to_be_bytes());
        put(&mut message, entry.mac);
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> PolicySpec {
        PolicySpec {
            name: "apps/billing-read".to_owned(),
            identity: "apps/billing".to_owned(),
            actions: vec![SecretAction::List, SecretAction::Read, SecretAction::Read],
            paths: vec!["billing".to_owned(), "billing".to_owned()],
            all_paths: false,
            description: "billing app, read only".to_owned(),
        }
    }

    #[test]
    fn a_valid_spec_normalizes() {
        let policy = spec().validate().unwrap();
        let canonical = policy.spec();
        assert_eq!(canonical.actions, [SecretAction::Read, SecretAction::List]);
        assert_eq!(canonical.paths, ["billing"]);
        assert!(
            policy
                .scope
                .covers(&SecretPath::parse("billing/db").unwrap())
        );
        assert!(!policy.scope.covers(&SecretPath::parse("billing2").unwrap()));
    }

    #[test]
    fn invalid_specs_are_refused_with_a_reason() {
        type Change = fn(&mut PolicySpec);
        let cases: [(Change, &str); 11] = [
            (|s| s.name = "config:x".to_owned(), "policy name"),
            (|s| s.identity = "/x".to_owned(), "identity"),
            (|s| s.actions.clear(), "no actions"),
            (|s| s.paths.clear(), "no scope"),
            (|s| s.all_paths = true, "choose one"),
            (|s| s.paths.push("a//b".to_owned()), "secret path"),
            // Printable ASCII only: no controls, nothing invisible, no emoji.
            (|s| s.description = "a\u{7}".to_owned(), "printable ASCII"),
            (
                |s| s.description = "read \u{202e}only".to_owned(),
                "printable ASCII",
            ),
            (
                |s| s.description = "ok\u{e0041}".to_owned(),
                "printable ASCII",
            ),
            (
                |s| s.description = "\u{26a0}\u{fe0f} prod".to_owned(),
                "printable ASCII",
            ),
            (|s| s.description = "déjà vu".to_owned(), "printable ASCII"),
        ];
        for (change, expected) in cases {
            let mut s = spec();
            change(&mut s);
            let error = s.validate().unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
        for ok in ["line one\n\tline two: ok (see #42), 100% ~fine~", ""] {
            let mut s = spec();
            s.description = ok.to_owned();
            assert!(s.validate().is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn admin_and_unknown_actions_say_which() {
        assert!(matches!(
            SecretAction::parse("rekey"),
            Err(PolicyError::AdminAction(_))
        ));
        assert!(matches!(
            SecretAction::parse("raed"),
            Err(PolicyError::UnknownAction(_))
        ));
        let file = r#"{"name": "a", "identity": "a", "actions": ["seal"], "all_paths": true}"#;
        let error = serde_json::from_str::<PolicySpec>(file)
            .unwrap_err()
            .to_string();
        assert!(error.contains("admin action"), "{error}");
        let typo = r#"{"name": "a", "identity": "a", "actions": ["read"], "all_path": true}"#;
        assert!(serde_json::from_str::<PolicySpec>(typo).is_err());
    }

    #[test]
    fn encodings_tell_every_field_apart() {
        let actions = ["read".to_owned()];
        let paths = ["billing".to_owned()];
        let row = RowFields {
            name: "a",
            identity: "b",
            actions: &actions,
            paths: &paths,
            all_paths: false,
            version: 1,
            description: "",
        };
        let base = row_message(&row);
        // The same bytes moved between fields must not encode alike.
        let moved = RowFields {
            name: "ab",
            identity: "",
            ..row.clone()
        };
        assert_ne!(base, row_message(&moved));
        for changed in [
            RowFields {
                version: 2,
                ..row.clone()
            },
            RowFields {
                description: "x",
                ..row.clone()
            },
            RowFields {
                all_paths: true,
                ..row.clone()
            },
        ] {
            assert_ne!(base, row_message(&changed));
        }
        let entries = [
            SetEntry {
                name: "b",
                version: 1,
                mac: &[1],
            },
            SetEntry {
                name: "a",
                version: 1,
                mac: &[2],
            },
        ];
        let reversed = [entries[1].clone(), entries[0].clone()];
        assert_eq!(set_message(3, &entries), set_message(3, &reversed));
        assert_ne!(set_message(3, &entries), set_message(4, &entries));
        assert_ne!(set_message(3, &entries), set_message(3, &entries[..1]));
    }
}
