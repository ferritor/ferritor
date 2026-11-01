//! A static policy from `[[policy]]` entries in `ferritor.toml`: who (a
//! `ferritor://<name>` client certificate identity) may do which actions, and
//! for secret actions, under which paths.
//!
//! ```toml
//! [[policy]]
//! identity = "ops/alice"
//! actions = ["status", "unseal", "seal", "rekey", "rotate", "rewrap"]
//!
//! [[policy]]
//! identity = "apps/billing"
//! actions = ["read", "list"]
//! paths = ["billing"]   # whole segments: billing/db yes, billing2 no
//! ```
//!
//! What `list` means: metadata, never values: the paths below a prefix
//! with their latest versions, and a path's history (`ListVersions`: every
//! version still stored, deleted ones included), so a metadata-only
//! identity (a dashboard) needs no `read`. The audit log records a history
//! as `list` on the path, so "who read this secret?" is answered by the
//! `read` entries alone. Like every path grant, `paths = ["billing"]`
//! covers the secret named exactly `billing` too, so its history is visible,
//! even though a listing of the prefix `billing` shows only what's strictly
//! below it.
//!
//! What `write` means: storing a new version, restoring a deleted one, and
//! with a version limit (`max_versions`) also pushing the oldest live
//! version out (it's marked deleted, then purged after the retention). So a
//! caller with `write` but not `delete` on a path can still remove its
//! history, `max_versions` puts at a time; withholding `delete` protects the
//! current secret, not old versions.
//!
//! Deliberately strict: an unknown action is a startup error (from parsing),
//! and so is anything ambiguous. A rule without `paths` grants no secret
//! access at all; everything is `all_paths = true`, never an accident.
//! [`Caller::Unauthenticated`] is always refused, so even a handshake bug
//! can't turn into access.

use std::collections::HashSet;

use ferritor_core::path::{PathError, SecretPath};
use serde::{Deserialize, Serialize};

use crate::authz::{Action, Authorizer, Caller, Denied, Target};

/// One `[[policy]]` entry as written. Serialize only for the fingerprint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Optional, for listing and checks (`config:<name>`; unnamed rules are
    /// `config:<n>`, by position from 1). Secret-path rules, unique.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The `<name>` of a `ferritor://<name>` client certificate identity.
    pub identity: String,
    pub actions: Vec<Action>,
    /// Path prefixes (whole segments) the secret actions apply to.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Secret actions apply everywhere. Exclusive with `paths`.
    #[serde(default)]
    pub all_paths: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy rule {index}: identity `{identity}` is not a valid name")]
    BadIdentity {
        index: usize,
        identity: String,
        #[source]
        source: PathError,
    },
    #[error("policy rule {index}: path `{path}` is not a valid secret path")]
    BadPath {
        index: usize,
        path: String,
        #[source]
        source: PathError,
    },
    #[error("policy rule {index}: no actions")]
    NoActions { index: usize },
    #[error("policy rule {index}: name `{name}` is not a valid name")]
    BadName {
        index: usize,
        name: String,
        #[source]
        source: PathError,
    },
    #[error("policy rule {index}: name `{name}` is used by another rule")]
    DuplicateName { index: usize, name: String },
    #[error("policy rule {index}: `all_paths = true` and `paths` together; choose one")]
    AllAndPaths { index: usize },
    #[error("the policy could not be fingerprinted")]
    Fingerprint(#[source] serde_json::Error),
}

#[derive(Debug)]
enum Scope {
    /// Under these prefixes (possibly none: no secret access).
    Paths(Vec<SecretPath>),
    All,
}

impl Scope {
    fn covers(&self, target: Target<'_>) -> bool {
        let within = |p: &SecretPath| match self {
            Self::All => true,
            Self::Paths(prefixes) => prefixes.iter().any(|q| p == q || p.is_under(q)),
        };
        match target {
            Target::Path(p) | Target::Below(p) => within(p),
            Target::All => matches!(self, Self::All),
            Target::System => false,
        }
    }
}

#[derive(Debug)]
struct Grant {
    /// `config:<name>`, or `config:<n>`.
    name: String,
    identity: SecretPath,
    actions: HashSet<Action>,
    scope: Scope,
}

#[derive(Debug)]
pub struct Policy {
    grants: Vec<Grant>,
    rules: Vec<Rule>,
}

/// The prefix that marks a config rule's name: a stored policy's name can't
/// hold `:`, so the two never collide.
pub const CONFIG_PREFIX: &str = "config:";

/// What the audit log says about the policy in force: how many rules, and
/// which ones (a fingerprint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyInfo {
    pub rules: usize,
    pub fingerprint: String,
}

impl PolicyInfo {
    /// The fingerprint is SHA-256 over the parsed rules as JSON, in their
    /// order: reformatting `ferritor.toml` or reordering keys doesn't change
    /// it, any change to a rule does. Every audited decision falls between
    /// two entries naming the policy it ran under (`policy_loaded` at
    /// startup, `policy_reload` after).
    ///
    /// Serializing these types can't fail in practice, but if it ever did,
    /// a fingerprint of nothing would silently name no policy: it's an
    /// error instead (a startup error, or a failed reload).
    pub fn of(rules: &[Rule]) -> Result<Self, PolicyError> {
        let json = serde_json::to_vec(rules).map_err(PolicyError::Fingerprint)?;
        Ok(Self {
            rules: rules.len(),
            fingerprint: crate::fingerprint(&json),
        })
    }
}

impl Policy {
    pub fn new(rules: &[Rule]) -> Result<Self, PolicyError> {
        let mut names = HashSet::new();
        let grants = rules
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                let name = match &rule.name {
                    Some(name) => {
                        SecretPath::parse(name).map_err(|source| PolicyError::BadName {
                            index,
                            name: name.clone(),
                            source,
                        })?;
                        if !names.insert(name.clone()) {
                            return Err(PolicyError::DuplicateName {
                                index,
                                name: name.clone(),
                            });
                        }
                        format!("{CONFIG_PREFIX}{name}")
                    }
                    None => format!("{CONFIG_PREFIX}{}", index + 1),
                };
                let identity = SecretPath::parse(&rule.identity).map_err(|source| {
                    PolicyError::BadIdentity {
                        index,
                        identity: rule.identity.clone(),
                        source,
                    }
                })?;
                if rule.actions.is_empty() {
                    return Err(PolicyError::NoActions { index });
                }
                let scope = match (rule.all_paths, rule.paths.is_empty()) {
                    (true, false) => return Err(PolicyError::AllAndPaths { index }),
                    (true, true) => Scope::All,
                    (false, _) => Scope::Paths(
                        rule.paths
                            .iter()
                            .map(|path| {
                                SecretPath::parse(path).map_err(|source| PolicyError::BadPath {
                                    index,
                                    path: path.clone(),
                                    source,
                                })
                            })
                            .collect::<Result<_, _>>()?,
                    ),
                };
                Ok(Grant {
                    name,
                    identity,
                    actions: rule.actions.iter().copied().collect(),
                    scope,
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            grants,
            rules: rules.to_vec(),
        })
    }

    /// Every rule with its qualified name (`config:…`), in order.
    pub fn rules(&self) -> impl Iterator<Item = (&str, &Rule)> {
        self.grants
            .iter()
            .map(|grant| grant.name.as_str())
            .zip(&self.rules)
    }

    /// The rules that grant `identity` `action` on `target`, by qualified
    /// name.
    pub fn granting(&self, identity: &SecretPath, action: Action, target: Target<'_>) -> Vec<&str> {
        self.grants
            .iter()
            .filter(|grant| grant.grants(identity, action, target))
            .map(|grant| grant.name.as_str())
            .collect()
    }
}

impl Grant {
    fn grants(&self, identity: &SecretPath, action: Action, target: Target<'_>) -> bool {
        self.identity == *identity
            && self.actions.contains(&action)
            && match target {
                // Admin actions are about the server; paths don't apply.
                Target::System => action.is_admin(),
                _ => !action.is_admin() && self.scope.covers(target),
            }
    }
}

impl Authorizer for Policy {
    fn authorize(&self, caller: &Caller, action: Action, target: Target<'_>) -> Result<(), Denied> {
        let Caller::Identity(identity) = caller else {
            return Err(Denied::new(caller, action, target));
        };
        let granted = self
            .grants
            .iter()
            .any(|grant| grant.grants(identity, action, target));
        if granted {
            Ok(())
        } else {
            Err(Denied::new(caller, action, target))
        }
    }

    fn as_policy(&self) -> Option<&Policy> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(toml: &str) -> Result<Policy, String> {
        #[derive(Deserialize)]
        struct File {
            policy: Vec<Rule>,
        }
        let file: File = toml::from_str(toml).map_err(|e| e.to_string())?;
        Policy::new(&file.policy).map_err(|e| e.to_string())
    }

    fn who(name: &str) -> Caller {
        Caller::Identity(SecretPath::parse(name).unwrap())
    }

    fn p(path: &str) -> SecretPath {
        SecretPath::parse(path).unwrap()
    }

    fn allowed(policy: &Policy, caller: &Caller, action: Action, target: Target<'_>) -> bool {
        policy.authorize(caller, action, target).is_ok()
    }

    const POLICY: &str = r#"
        [[policy]]
        identity = "ops/alice"
        actions = ["status", "seal", "rekey"]

        [[policy]]
        identity = "apps/billing"
        actions = ["read", "list"]
        paths = ["billing", "shared/rates"]

        [[policy]]
        identity = "ops/root"
        actions = ["read", "write", "delete", "list"]
        all_paths = true
    "#;

    #[test]
    fn grants_follow_identity_action_and_whole_segment_prefixes() {
        let policy = policy(POLICY).unwrap();
        let billing = who("apps/billing");

        assert!(allowed(
            &policy,
            &billing,
            Action::Read,
            Target::Path(&p("billing"))
        ));
        assert!(allowed(
            &policy,
            &billing,
            Action::Read,
            Target::Path(&p("billing/db"))
        ));
        assert!(allowed(
            &policy,
            &billing,
            Action::Read,
            Target::Path(&p("shared/rates"))
        ));
        // Whole segments: a sibling that merely shares the prefix text.
        assert!(!allowed(
            &policy,
            &billing,
            Action::Read,
            Target::Path(&p("billing2/db"))
        ));
        assert!(!allowed(
            &policy,
            &billing,
            Action::Read,
            Target::Path(&p("shared"))
        ));
        // Not granted that action, or no such identity.
        assert!(!allowed(
            &policy,
            &billing,
            Action::Write,
            Target::Path(&p("billing/db"))
        ));
        assert!(!allowed(
            &policy,
            &who("apps/other"),
            Action::Read,
            Target::Path(&p("billing/db"))
        ));

        // Listing: inside a prefix yes; above it or everything, no.
        assert!(allowed(
            &policy,
            &billing,
            Action::List,
            Target::Below(&p("billing"))
        ));
        assert!(!allowed(
            &policy,
            &billing,
            Action::List,
            Target::Below(&p("shared"))
        ));
        assert!(!allowed(&policy, &billing, Action::List, Target::All));
        // A path's history is `list` on the path itself: within the prefix.
        assert!(allowed(
            &policy,
            &billing,
            Action::List,
            Target::Path(&p("billing/db"))
        ));
        assert!(!allowed(
            &policy,
            &billing,
            Action::List,
            Target::Path(&p("billing2"))
        ));
        assert!(allowed(
            &policy,
            &who("ops/root"),
            Action::List,
            Target::All
        ));
    }

    #[test]
    fn admin_actions_are_about_the_server_only() {
        let policy = policy(POLICY).unwrap();
        let alice = who("ops/alice");
        assert!(
            policy
                .authorize(&alice, Action::Seal, Target::System)
                .is_ok()
        );
        assert!(
            policy
                .authorize(&alice, Action::Rotate, Target::System)
                .is_err()
        );
        // Secret actions never on the server target, admin ones never on paths.
        let root = who("ops/root");
        assert!(
            policy
                .authorize(&root, Action::Read, Target::System)
                .is_err()
        );
        assert!(
            policy
                .authorize(&alice, Action::Seal, Target::Path(&p("billing")))
                .is_err()
        );
    }

    #[test]
    fn unauthenticated_callers_are_always_refused() {
        let policy = policy(POLICY).unwrap();
        for action in [Action::Status, Action::Read, Action::List] {
            assert!(
                policy
                    .authorize(&Caller::Unauthenticated, action, Target::System)
                    .is_err()
            );
        }
    }

    /// No paths means no secret access, not "everything".
    #[test]
    fn a_rule_without_paths_grants_no_secrets() {
        let policy = policy(
            r#"
            [[policy]]
            identity = "apps/x"
            actions = ["read", "list"]
            "#,
        )
        .unwrap();
        let x = who("apps/x");
        assert!(
            policy
                .authorize(&x, Action::Read, Target::Path(&p("a")))
                .is_err()
        );
        assert!(policy.authorize(&x, Action::List, Target::All).is_err());
    }

    #[test]
    fn bad_rules_are_startup_errors() {
        let rule = |body: &str| policy(&format!("[[policy]]\nidentity = \"ops/a\"\n{body}"));
        let unknown = rule("actions = [\"sael\"]").unwrap_err();
        assert!(unknown.contains("unknown variant `sael`"), "{unknown}");
        assert!(rule("actions = []").unwrap_err().contains("no actions"));
        assert!(
            rule("actions = [\"read\"]\nall_paths = true\npaths = [\"a\"]")
                .unwrap_err()
                .contains("choose one")
        );
        assert!(
            rule("actions = [\"read\"]\npaths = [\"/a\"]")
                .unwrap_err()
                .contains("not a valid secret path")
        );
        assert!(
            rule("actions = [\"read\"]\npath = [\"a\"]")
                .unwrap_err()
                .contains("unknown field `path`")
        );
        let bad_identity =
            policy("[[policy]]\nidentity = \"ferritor://ops/a\"\nactions = [\"read\"]");
        assert!(bad_identity.unwrap_err().contains("not a valid name"));
    }
}
