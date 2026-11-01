//! Authorization: who may do what to which secrets, and which admin
//! operations. Every secret operation asks an [`Authorizer`] before touching
//! any data, and every `SystemService` call before anything else (before it
//! queues for the admin lock, so a refused caller never waits). They ask
//! through `audit::Gate`, which records every decision.
//!
//! Two authorizers: `policy::Policy` in secured mode, where callers are
//! [`Caller::Identity`] from their client certificate, and [`AllowAll`] in
//! dev mode, where every caller is [`Caller::Unauthenticated`] and the server
//! only listens on loopback (see `config`).
//!
//! Rekey nonces: `RekeyCancel` needs nothing but the nonce, so cancel takes
//! the same [`Action::Rekey`] permission as starting one, and every reply
//! carrying a status shows a rekey's nonce only to callers who may rekey
//! (others still see phase and progress). Seal also discards a rekey, so it
//! too is for operators, not applications.

use std::fmt;

use ferritor_core::path::SecretPath;
use ferritor_core::policy::SecretAction;
use serde::{Deserialize, Serialize};

/// Who is calling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    /// No client certificate: only possible without TLS, which the server
    /// allows only on loopback. A policy-based authorizer refuses it.
    Unauthenticated,
    /// The `ferritor://<name>` identity in the caller's client certificate.
    Identity(SecretPath),
}

impl fmt::Display for Caller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated => f.write_str("unauthenticated caller"),
            Self::Identity(name) => write!(f, "caller `{name}`"),
        }
    }
}

/// Spelled in `ferritor.toml` policies and the audit log in snake case:
/// `read`, `rekey`, ….
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Read,
    Write,
    Delete,
    List,
    /// Change a path's labels (custom metadata; reading them is `List`).
    Label,
    /// Read the seal status.
    Status,
    Init,
    /// Submit (or reset) unseal shares.
    Unseal,
    Seal,
    /// Start, submit to, verify or cancel a rekey; also see its nonce.
    Rekey,
    Rotate,
    Rewrap,
    /// Remove deleted secret versions past their retention for good.
    Purge,
    /// Destroy a retired KEK version: irreversible (see `destroy`).
    DestroyKek,
    /// Create, inspect, label and delete namespaces (deleting one also
    /// needs `DestroyKek`: it destroys the namespace's KEKs).
    Namespace,
    /// Manage the stored policies (see `policies`): granted in the config
    /// only, since a stored policy can't grant an admin action.
    Policy,
    /// Create, rotate and inspect the workload-identity issuing CA (see
    /// `identity`).
    Identity,
}

impl Action {
    /// As spelled in policies and the audit log (`read`, `rekey`, …).
    pub fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Label => "label",
            Self::Status => "status",
            Self::Init => "init",
            Self::Unseal => "unseal",
            Self::Seal => "seal",
            Self::Rekey => "rekey",
            Self::Rotate => "rotate",
            Self::Rewrap => "rewrap",
            Self::Purge => "purge",
            Self::DestroyKek => "destroy_kek",
            Self::Namespace => "namespace",
            Self::Policy => "policy",
            Self::Identity => "identity",
        }
    }

    /// About the server itself ([`Target::System`]), not secrets.
    pub fn is_admin(self) -> bool {
        self.secret().is_none()
    }

    /// The secret action this is, if it is one: what a stored policy may
    /// grant.
    pub fn secret(self) -> Option<SecretAction> {
        match self {
            Self::Read => Some(SecretAction::Read),
            Self::Write => Some(SecretAction::Write),
            Self::Delete => Some(SecretAction::Delete),
            Self::List => Some(SecretAction::List),
            Self::Label => Some(SecretAction::Label),
            _ => None,
        }
    }

    /// By name, as policies spell it.
    pub fn parse(name: &str) -> Option<Self> {
        ALL_ACTIONS.into_iter().find(|action| action.name() == name)
    }
}

/// Every action.
pub const ALL_ACTIONS: [Action; 17] = [
    Action::Read,
    Action::Write,
    Action::Delete,
    Action::List,
    Action::Label,
    Action::Status,
    Action::Init,
    Action::Unseal,
    Action::Seal,
    Action::Rekey,
    Action::Rotate,
    Action::Rewrap,
    Action::Purge,
    Action::DestroyKek,
    Action::Namespace,
    Action::Policy,
    Action::Identity,
];

impl From<SecretAction> for Action {
    fn from(action: SecretAction) -> Self {
        match action {
            SecretAction::Read => Self::Read,
            SecretAction::Write => Self::Write,
            SecretAction::Delete => Self::Delete,
            SecretAction::List => Self::List,
            SecretAction::Label => Self::Label,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Label => "label",
            Self::Status => "read the status of",
            Self::Init => "initialize",
            Self::Unseal => "unseal",
            Self::Seal => "seal",
            Self::Rekey => "rekey",
            Self::Rotate => "rotate the KEK of",
            Self::Rewrap => "rewrap the DEKs of",
            Self::Purge => "purge deleted secrets of",
            Self::DestroyKek => "destroy a KEK of",
            Self::Namespace => "manage the namespaces of",
            Self::Policy => "manage the policies of",
            Self::Identity => "manage the workload-identity CA of",
        })
    }
}

/// The secrets an action applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target<'a> {
    /// One path (read, write, delete; list for its history).
    Path(&'a SecretPath),
    /// Everything strictly below a path (list with a prefix).
    Below(&'a SecretPath),
    /// Every secret (list without a prefix).
    All,
    /// The server itself: admin operations.
    System,
}

impl fmt::Display for Target<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => write!(f, "`{path}`"),
            Self::Below(path) => write!(f, "secrets under `{path}`"),
            Self::All => f.write_str("all secrets"),
            Self::System => f.write_str("the server"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{caller} may not {action} {target}")]
pub struct Denied {
    pub caller: Caller,
    pub action: Action,
    pub target: String,
}

impl Denied {
    pub fn new(caller: &Caller, action: Action, target: Target<'_>) -> Self {
        Self {
            caller: caller.clone(),
            action,
            target: target.to_string(),
        }
    }
}

/// Decides whether `caller` may perform `action` on `target`.
///
/// Synchronous on purpose: it runs on every request and should evaluate
/// policy already in memory, not query a database.
pub trait Authorizer: Send + Sync + 'static {
    fn authorize(&self, caller: &Caller, action: Action, target: Target<'_>) -> Result<(), Denied>;

    /// The config rules, if this is them: for listing them next to the
    /// stored policies, and for checks that say which rule granted what.
    fn as_policy(&self) -> Option<&crate::policy::Policy> {
        None
    }
}

/// What the stored policies (`policies`) say about a secret request the
/// config rules didn't allow: implemented by `seal::Seal`, which holds the
/// verified set next to the keyring.
pub trait StoredPolicies: Send + Sync + 'static {
    fn decide(&self, identity: &SecretPath, action: SecretAction, target: Target<'_>) -> Stored;
}

/// The stored policies' answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stored {
    Allowed,
    Denied,
    /// Not in force: the server is sealed.
    Sealed,
    /// Not in force: unsealed, but the stored set didn't verify.
    Unverified,
}

/// Allows everything: dev mode only (plaintext, loopback only). Never built
/// when TLS is configured; see `config`.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize(&self, _: &Caller, _: Action, _: Target<'_>) -> Result<(), Denied> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Metrics and the audit log must name an action the way policies do.
    #[test]
    fn an_action_is_named_as_policies_spell_it() {
        for action in ALL_ACTIONS {
            assert_eq!(Action::parse(action.name()), Some(action));
            assert_eq!(
                serde_json::to_value(action).unwrap(),
                serde_json::json!(action.name())
            );
        }
    }

    /// A stored policy names an admin action only to be refused, with a
    /// reason: core's list of their names must match.
    #[test]
    fn core_knows_every_admin_action_by_name() {
        let admin: Vec<&str> = ALL_ACTIONS
            .into_iter()
            .filter(|a| a.is_admin())
            .map(Action::name)
            .collect();
        assert_eq!(admin, ferritor_core::policy::ADMIN_ACTIONS);
        for action in ALL_ACTIONS {
            assert_eq!(
                action.secret().map(Action::from),
                (!action.is_admin()).then_some(action)
            );
        }
    }
}
