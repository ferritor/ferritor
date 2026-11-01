//! The stored policies in force: verifying what the keys database holds
//! against the policy key, and the verified set the [`Gate`] asks (through
//! `Seal`, which publishes it next to the keyring).
//!
//! A snapshot (key, state and rows, one REPEATABLE READ read) verifies only
//! if the policy key opens under this server's root key, every row's MAC
//! checks, the set's MAC checks over the revision and every row, and the
//! revision isn't below the highest this process has verified. Anything else
//! is [`Unverified`], with the reason: never a partial set, never a silent
//! fresh start.
//!
//! [`Gate`]: crate::audit::Gate

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ferritor_core::crypto::{PolicyKey, RootKey};
use ferritor_core::path::SecretPath;
use ferritor_core::policy::{self, RowFields, Scope, SecretAction, SetEntry};
use ferritor_datastore::Datastore;
use ferritor_keystore::{PolicySnapshot, StoredPolicy};
use time::OffsetDateTime;

use crate::authz::Target;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Which revision floor ([`RevisionFloor`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Floor {
    /// The stored policies' (`policy_revision_floor`).
    Policies,
    /// The workload-identity issuing keys' (`issuing_revision_floor`).
    IssuingKeys,
}

/// The highest revision any server wrote of a set signed in the keys
/// database (the stored policies, the issuing keys), kept outside it (the
/// data database's `policy_revision_floor` and `issuing_revision_floor`),
/// so a keys-database writer alone can't roll a set back (an older signed
/// set written back, or everything wiped): a server that never saw the
/// newer revision (a restarted one) still refuses it. `Seal` reads them
/// through this, so it never holds the data database itself.
pub trait RevisionFloor: Send + Sync {
    fn read(&self, floor: Floor) -> BoxFuture<'_, Result<u64, String>>;
    /// Raises it to `revision` (never lowers it).
    fn raise(&self, floor: Floor, revision: u64) -> BoxFuture<'_, Result<(), String>>;
}

impl RevisionFloor for Datastore {
    fn read(&self, floor: Floor) -> BoxFuture<'_, Result<u64, String>> {
        Box::pin(async move {
            match floor {
                Floor::Policies => self.policy_revision_floor().await,
                Floor::IssuingKeys => self.issuing_revision_floor().await,
            }
            .map_err(|e| crate::error_chain(&e))
        })
    }

    fn raise(&self, floor: Floor, revision: u64) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            match floor {
                Floor::Policies => self.raise_policy_revision_floor(revision).await,
                Floor::IssuingKeys => self.raise_issuing_revision_floor(revision).await,
            }
            .map_err(|e| crate::error_chain(&e))
        })
    }
}

/// Why a stored set isn't in force.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unverified {
    /// The policy key is gone while policies exist: cleared in the database.
    KeyMissing,
    /// The policy key doesn't open under this root key: changed.
    KeyUnusable,
    /// A row's MAC doesn't check: changed in the database.
    Row(String),
    /// The set's MAC doesn't check: a row added or removed, or one from
    /// another set.
    Set,
    /// A revision below one this process verified: an older set put back.
    Rollback { seen: u64, found: u64 },
    /// Couldn't be read (the keys database didn't answer, say); retried by
    /// the next refresh.
    Unreadable(String),
}

impl Unverified {
    /// For metrics and the audit log.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Rollback { .. } => "rollback",
            Self::Unreadable(_) => "failed",
            _ => "integrity",
        }
    }

    /// What a reporter compares: the same condition gives the same key,
    /// whatever the database said this time.
    pub fn report_key(&self) -> String {
        match self {
            Self::KeyMissing => "key_missing".into(),
            Self::KeyUnusable => "key_unusable".into(),
            // Another row failing means another edit: a new alarm.
            Self::Row(name) => format!("row:{name}"),
            Self::Set => "set".into(),
            Self::Rollback { seen, found } => format!("rollback:{seen}:{found}"),
            // The detail (a timeout, a refused connection, …) varies from
            // one attempt to the next; the condition doesn't.
            Self::Unreadable(_) => "unreadable".into(),
        }
    }

    /// Whether only a repair (`apply` with `prune`) may write over it.
    pub fn needs_repair(&self) -> bool {
        !matches!(self, Self::Unreadable(_))
    }
}

impl fmt::Display for Unverified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyMissing => f.write_str(
                "the policy key is missing while stored policies exist (cleared in the keys \
                 database)",
            ),
            Self::KeyUnusable => f.write_str(
                "the policy key doesn't open under the root key (changed in the keys database)",
            ),
            Self::Row(name) => write!(
                f,
                "policy `{name}` doesn't verify (changed in the keys database)"
            ),
            Self::Set => f.write_str(
                "the policy set doesn't verify (a policy added or removed in the keys database)",
            ),
            Self::Rollback { seen, found } => write!(
                f,
                "the stored policy set is at revision {found}, below revision {seen} this server \
                 already verified: an older set was put back (a restored backup, a failover)"
            ),
            Self::Unreadable(why) => write!(f, "the stored policies couldn't be read: {why}"),
        }
    }
}

/// One verified stored policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub name: String,
    pub identity: SecretPath,
    /// The secret actions it grants this binary knows.
    pub actions: BTreeSet<SecretAction>,
    pub scope: Scope,
    pub description: String,
    pub version: u32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// A verified set: what the stored policies grant, by identity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredSet {
    pub revision: u64,
    /// By name.
    pub policies: Vec<Verified>,
    by_identity: HashMap<SecretPath, Vec<usize>>,
    /// The set's MAC, as a fingerprint for the audit log.
    pub fingerprint: String,
}

impl StoredSet {
    fn new(revision: u64, policies: Vec<Verified>, fingerprint: String) -> Self {
        let mut by_identity: HashMap<SecretPath, Vec<usize>> = HashMap::new();
        for (index, policy) in policies.iter().enumerate() {
            by_identity
                .entry(policy.identity.clone())
                .or_default()
                .push(index);
        }
        Self {
            revision,
            policies,
            by_identity,
            fingerprint,
        }
    }

    /// The policies that grant `identity` `action` on `target`, by name.
    pub fn granting<'a>(
        &'a self,
        identity: &SecretPath,
        action: SecretAction,
        target: Target<'_>,
    ) -> impl Iterator<Item = &'a Verified> + 'a {
        let covers = |scope: &Scope| match target {
            Target::Path(p) | Target::Below(p) => scope.covers(p),
            Target::All => matches!(scope, Scope::All),
            Target::System => false,
        };
        let matching: Vec<&Verified> = self
            .by_identity
            .get(identity)
            .into_iter()
            .flatten()
            .filter_map(|&index| self.policies.get(index))
            .filter(|p| p.actions.contains(&action) && covers(&p.scope))
            .collect();
        matching.into_iter()
    }

    pub fn allows(&self, identity: &SecretPath, action: SecretAction, target: Target<'_>) -> bool {
        self.granting(identity, action, target).next().is_some()
    }

    pub fn get(&self, name: &str) -> Option<&Verified> {
        self.policies.iter().find(|p| p.name == name)
    }
}

/// The stored policies as a server sees them.
#[derive(Clone, Debug, Default)]
pub enum PolicyView {
    /// Sealed (or before the first unseal): not in force.
    #[default]
    Sealed,
    /// Unsealed, but no set verified: not in force.
    Unverified(Unverified),
    Loaded(Arc<StoredSet>),
}

/// A row's fields as stored, for its MAC.
pub fn row_fields(row: &StoredPolicy) -> RowFields<'_> {
    RowFields {
        name: &row.name,
        identity: &row.identity,
        actions: &row.actions,
        paths: &row.paths,
        all_paths: row.all_paths,
        version: row.version,
        description: &row.description,
    }
}

/// What a snapshot's key is: none ever written, a usable key, or a reason
/// it isn't usable.
pub enum KeyState {
    /// Nothing was ever written: revision 0, no key, no set MAC, no rows.
    /// The revision decides: every write raises it (and creates the key),
    /// so key, MAC and rows all missing at a later revision were wiped in
    /// the keys database, which is `KeyMissing`, never a fresh start.
    Fresh,
    Usable(PolicyKey),
    Broken(Unverified),
}

pub fn key_state(root: &RootKey, snapshot: &PolicySnapshot) -> KeyState {
    match &snapshot.wrapped_key {
        None if snapshot.state.revision == 0
            && snapshot.state.mac.is_none()
            && snapshot.policies.is_empty() =>
        {
            KeyState::Fresh
        }
        None => KeyState::Broken(Unverified::KeyMissing),
        Some(wrapped) => match root.unwrap_policy_key(wrapped) {
            Ok(key) => KeyState::Usable(key),
            Err(_) => KeyState::Broken(Unverified::KeyUnusable),
        },
    }
}

/// Verifies `snapshot` (see the module docs). `seen` is the highest
/// revision this process verified.
pub fn verify(
    root: &RootKey,
    snapshot: &PolicySnapshot,
    seen: u64,
) -> Result<StoredSet, Unverified> {
    let found = snapshot.state.revision;
    if found < seen {
        return Err(Unverified::Rollback { seen, found });
    }
    let key = match key_state(root, snapshot) {
        KeyState::Fresh => return Ok(StoredSet::new(found, Vec::new(), String::new())),
        KeyState::Broken(why) => return Err(why),
        KeyState::Usable(key) => key,
    };
    for row in &snapshot.policies {
        if !key.verify(&policy::row_message(&row_fields(row)), &row.mac) {
            return Err(Unverified::Row(row.name.clone()));
        }
    }
    let entries: Vec<SetEntry<'_>> = snapshot
        .policies
        .iter()
        .map(|row| SetEntry {
            name: &row.name,
            version: row.version,
            mac: &row.mac,
        })
        .collect();
    let message = policy::set_message(found, &entries);
    let set_mac = snapshot.state.mac.as_deref().ok_or(Unverified::Set)?;
    if !key.verify(&message, set_mac) {
        return Err(Unverified::Set);
    }
    let policies = snapshot
        .policies
        .iter()
        .map(parse_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StoredSet::new(
        found,
        policies,
        crate::fingerprint(&message),
    ))
}

/// A verified row as a grant. Its MAC checked, so a server wrote it:
/// unknown action names (a newer server's) are ignored with a warning,
/// which fails safe; anything else unparsable is an integrity failure.
fn parse_row(row: &StoredPolicy) -> Result<Verified, Unverified> {
    let broken = || Unverified::Row(row.name.clone());
    let identity = SecretPath::parse(&row.identity).map_err(|_| broken())?;
    let mut actions = BTreeSet::new();
    for name in &row.actions {
        match SecretAction::parse(name) {
            Ok(action) => {
                actions.insert(action);
            }
            Err(e) => tracing::warn!(
                policy = %row.name,
                action = %name,
                reason = %e,
                "stored policy names an action this server doesn't grant from the database; \
                 ignored"
            ),
        }
    }
    let scope = if row.all_paths {
        Scope::All
    } else {
        Scope::Paths(
            row.paths
                .iter()
                .map(|p| SecretPath::parse(p))
                .collect::<Result<_, _>>()
                .map_err(|_| broken())?,
        )
    };
    Ok(Verified {
        name: row.name.clone(),
        identity,
        actions,
        scope,
        description: row.description.clone(),
        version: row.version,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// What a write stores for `policy` at `version`: its fields as strings, in
/// the canonical order, with their MAC.
pub fn sealed_row(
    key: &PolicyKey,
    policy: &policy::Policy,
    version: u32,
) -> Result<ferritor_keystore::NewPolicy, ferritor_core::crypto::CryptoError> {
    let spec = policy.spec();
    let actions: Vec<String> = spec.actions.iter().map(|a| a.name().to_owned()).collect();
    let fields = RowFields {
        name: &spec.name,
        identity: &spec.identity,
        actions: &actions,
        paths: &spec.paths,
        all_paths: spec.all_paths,
        version,
        description: &spec.description,
    };
    let mac = key.mac(&policy::row_message(&fields))?.to_vec();
    Ok(ferritor_keystore::NewPolicy {
        name: spec.name,
        identity: spec.identity,
        actions,
        paths: spec.paths,
        all_paths: spec.all_paths,
        description: spec.description,
        version,
        mac,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One condition, one key: another row or another revision is another
    /// alarm, another database error isn't.
    #[test]
    fn a_report_key_names_the_condition_not_its_wording() {
        let key = |u: Unverified| u.report_key();
        assert_ne!(
            key(Unverified::Row("a".to_owned())),
            key(Unverified::Row("b".to_owned()))
        );
        assert_ne!(
            key(Unverified::Rollback { seen: 3, found: 1 }),
            key(Unverified::Rollback { seen: 3, found: 2 })
        );
        assert_eq!(
            key(Unverified::Unreadable("timed out".to_owned())),
            key(Unverified::Unreadable("connection refused".to_owned()))
        );
        assert_ne!(key(Unverified::KeyMissing), key(Unverified::KeyUnusable));
    }
}
