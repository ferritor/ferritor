//! Stored policies over the API (`PolicyService`, `/v1/policies`): put,
//! delete, apply, get, list and check. One implementation for both APIs, as
//! `secrets` is for secrets: every call asks for the `policy` action (on the
//! server) before anything else, and every write records its outcome.
//!
//! Writes go through the keys database's `policy_state` lock
//! (`Keystore::begin_policy_write`) and build on the set as it is under that
//! lock, **only if it verifies** (`policy_store::verify`): signing a new set
//! over rows nobody vouched for would launder whatever was changed. Over an
//! unverified set, only `apply` with `prune` is allowed, since it replaces
//! the whole set with what the caller sends; if the policy key itself is
//! gone or won't open, that repair creates a new one (audited as such). The
//! first write ever creates the key, but only while nothing was ever stored
//! (`policy_store::KeyState::Fresh`).
//!
//! A write's revision is one past the higher of the stored one and the
//! highest this server verified or found as the policy revision floor
//! (`policy_store::RevisionFloor`, read first), so writing through a server
//! that saw a newer set lifts every server past a rollback, and a repair
//! after a rolled-back keys database lands above the floor. After the keys
//! database commits, the write raises the floor to its revision; if that
//! fails, the write stands (it's committed), and the next server to verify
//! the set raises the floor to it (`Seal::catch_up_policy_floor`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ferritor_core::crypto::{CryptoError, PolicyKey};
use ferritor_core::path::SecretPath;
use ferritor_core::policy::{
    self, MAX_APPLY, MAX_STORED, Policy, PolicyError, PolicySpec, Scope, SetEntry,
};
use ferritor_keystore::{KeystoreError, NewPolicy, PolicyChanges};
use serde_json::json;
use time::OffsetDateTime;

use crate::audit::{AuditError, Gate, Outcome, Refused};
use crate::authz::{Action, Caller, Denied, Target};
use crate::policy::CONFIG_PREFIX;
use crate::policy_store::{self, KeyState, PolicyView, Unverified, Verified};
use crate::seal::{Seal, SealError};

/// Listing's page size when the caller gives none, and its cap.
pub const DEFAULT_PAGE_SIZE: u32 = 100;
pub const MAX_PAGE_SIZE: u32 = 1000;

#[derive(Debug, thiserror::Error)]
pub enum PoliciesError {
    #[error("policy `{name}`")]
    Invalid {
        name: String,
        #[source]
        source: PolicyError,
    },
    /// Anything else about the request that's wrong (a duplicate name in an
    /// apply, too many policies, an unknown action in a check).
    #[error("{0}")]
    Request(String),
    #[error("there is no policy `{0}`")]
    NotFound(String),
    #[error(
        "policy `{name}` is at version {}, not {expected}",
        current.map_or_else(|| "none (it doesn't exist)".to_owned(), |v| v.to_string())
    )]
    VersionMismatch {
        name: String,
        expected: u32,
        current: Option<u32>,
    },
    #[error("the stored policies are at revision {current}, not {expected}")]
    RevisionMismatch { expected: u64, current: u64 },
    #[error("permission denied")]
    Denied(#[source] Denied),
    #[error("{}", ferritor_core::messages::UNAUDITED)]
    Unaudited(#[source] AuditError),
    #[error("{}", ferritor_core::messages::SEALED)]
    Sealed,
    #[error(
        "the stored policies don't verify: {0}. Only `ferritor policy apply --prune` with the whole \
         set from its source of truth replaces them"
    )]
    Unverified(Unverified),
    /// For a write: the outcome is unknown, it may have committed.
    #[error("the keys database did not respond in time")]
    KeysTimeout,
    /// Over one of the caller's rate limits (see `ratelimit`).
    #[error("rate limited ({}): too many requests from this caller; retry later", .0.limit.name())]
    Limited(crate::ratelimit::Refused),
    /// No call slot under the server-wide cap came free in time.
    #[error("the server is busy: no call slot came free in time; retry later")]
    Overloaded,
    /// The policy revision floor (data database) couldn't be read before a
    /// write: nothing was written.
    #[error("the policy revision floor couldn't be read: {0}")]
    RevisionFloor(String),
    #[error("keys database failure")]
    Keys(#[source] KeystoreError),
    #[error("crypto failure")]
    Crypto(#[source] CryptoError),
    #[error(transparent)]
    Seal(SealError),
}

impl From<KeystoreError> for PoliciesError {
    fn from(e: KeystoreError) -> Self {
        match e {
            KeystoreError::Timeout => Self::KeysTimeout,
            other => Self::Keys(other),
        }
    }
}

impl From<SealError> for PoliciesError {
    fn from(e: SealError) -> Self {
        match e {
            SealError::Sealed => Self::Sealed,
            SealError::KeysTimeout => Self::KeysTimeout,
            other => Self::Seal(other),
        }
    }
}

impl From<CryptoError> for PoliciesError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<Refused> for PoliciesError {
    fn from(e: Refused) -> Self {
        match e {
            Refused::Denied(denied) => Self::Denied(denied),
            Refused::Unaudited(e) => Self::Unaudited(e),
            // `policy` is an admin action: the config rules decide it alone.
            Refused::Sealed => Self::Sealed,
            Refused::PolicyUnverified => Self::Unverified(Unverified::Set),
            Refused::Limited(refused) => Self::Limited(refused),
            Refused::Overloaded => Self::Overloaded,
        }
    }
}

type Result<T, E = PoliciesError> = std::result::Result<T, E>;

/// Where a rule comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `[[policy]]` in `ferritor.toml`: read-only here.
    Config,
    Stored,
}

impl Source {
    pub fn name(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Stored => "stored",
        }
    }
}

/// A rule as listed: a stored policy or a config rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Stored: its name; config: `config:<name>` or `config:<n>`.
    pub name: String,
    pub source: Source,
    pub identity: String,
    pub actions: Vec<String>,
    pub paths: Vec<String>,
    pub all_paths: bool,
    pub description: String,
    /// Stored only.
    pub version: Option<u32>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}

/// Whether the stored policies are in force, for a listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredState {
    Loaded { revision: u64 },
    Sealed,
    Unverified,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub entries: Vec<Entry>,
    /// Empty when there's no next page.
    pub next_page_token: String,
    pub stored: StoredState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    pub version: u32,
    pub revision: u64,
    /// `false`: replaced an existing policy.
    pub created: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deleted {
    /// `false`: there was no such policy (nothing written).
    pub deleted: bool,
    pub revision: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Applied {
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub deleted: Vec<String>,
    pub unchanged: Vec<String>,
    /// The revision now (or, for a dry run, what it would be).
    pub revision: u64,
    pub dry_run: bool,
    /// It replaced a set that didn't verify (the repair).
    pub replaced_unverified: bool,
    /// It created a new policy key (the repair, over a missing or broken
    /// one).
    pub new_policy_key: bool,
}

/// What a check found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    pub allowed: bool,
    /// The rules that grant it, by name (config rules qualified).
    pub granted_by: Vec<String>,
    /// `false` in dev mode: nothing is enforced there (everyone may do
    /// everything), whatever the rules say.
    pub enforced: bool,
    /// Why the stored policies couldn't answer, if they couldn't.
    pub undecided: Option<Undecided>,
}

/// Why the stored policies couldn't answer a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Undecided {
    Sealed,
    Unverified,
}

impl Undecided {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Unverified => "unverified",
        }
    }
}

/// What one write does.
enum Write {
    Put {
        policy: Policy,
        expected_version: Option<u32>,
    },
    Delete {
        name: String,
        expected_version: Option<u32>,
    },
    Apply {
        policies: Vec<Policy>,
        expected_revision: Option<u64>,
        prune: bool,
        dry_run: bool,
    },
}

enum WriteResult {
    Put(Written),
    Delete(Deleted),
    Apply(Applied),
}

pub struct Policies {
    seal: Arc<Seal>,
    gate: Arc<Gate>,
}

/// Whether a verified stored policy grants exactly what `policy` does.
fn same(stored: &Verified, policy: &Policy) -> bool {
    stored.identity == policy.identity
        && stored.actions == policy.actions
        && stored.scope == policy.scope
        && stored.description == policy.description
}

fn validate(spec: &PolicySpec) -> Result<Policy> {
    spec.validate().map_err(|source| PoliciesError::Invalid {
        name: spec.name.clone(),
        source,
    })
}

impl Policies {
    pub fn new(seal: Arc<Seal>, gate: Arc<Gate>) -> Self {
        Self { seal, gate }
    }

    /// The gate it asks, for the transports to name the caller.
    pub fn gate(&self) -> &Gate {
        &self.gate
    }

    async fn authorize(&self, caller: &Caller) -> Result<()> {
        Ok(self
            .gate
            .check(caller, Action::Policy, Target::System)
            .await?)
    }

    fn record(&self, caller: &Caller, operation: &'static str, outcome: Outcome) {
        self.gate
            .outcome(caller, Action::Policy, Target::System, operation, outcome);
    }

    /// Creates or replaces `spec`. `expected_version`: `Some(0)` only
    /// creates, `Some(n)` only replaces version `n`.
    pub async fn put(
        &self,
        caller: &Caller,
        spec: &PolicySpec,
        expected_version: Option<u32>,
    ) -> Result<Written> {
        self.authorize(caller).await?;
        let result = match validate(spec) {
            Ok(policy) => {
                self.write(Write::Put {
                    policy,
                    expected_version,
                })
                .await
            }
            Err(e) => Err(e),
        };
        let result = result.and_then(|written| match written {
            WriteResult::Put(written) => Ok(written),
            _ => Err(mismatched()),
        });
        self.record(
            caller,
            "policy_put",
            match &result {
                Ok(written) => Outcome::Succeeded(json!({
                    "name": spec.name,
                    "identity": spec.identity,
                    "actions": spec.actions,
                    "paths": spec.paths,
                    "all_paths": spec.all_paths,
                    "description": spec.description,
                    "version": written.version,
                    "revision": written.revision,
                    "created": written.created,
                })),
                Err(e) => failed(e, json!({"name": spec.name})),
            },
        );
        result
    }

    /// Deletes `name`; `deleted: false` if there's none (idempotent).
    pub async fn delete(
        &self,
        caller: &Caller,
        name: &str,
        expected_version: Option<u32>,
    ) -> Result<Deleted> {
        self.authorize(caller).await?;
        let result = self
            .write(Write::Delete {
                name: name.to_owned(),
                expected_version,
            })
            .await
            .and_then(|written| match written {
                WriteResult::Delete(deleted) => Ok(deleted),
                _ => Err(mismatched()),
            });
        self.record(
            caller,
            "policy_delete",
            match &result {
                Ok(done) => Outcome::Succeeded(json!({
                    "name": name,
                    "deleted": done.deleted,
                    "revision": done.revision,
                })),
                Err(e) => failed(e, json!({"name": name})),
            },
        );
        result
    }

    /// Makes the stored set match `specs` (see the module docs). A dry run
    /// writes nothing and records nothing beyond its authorization.
    pub async fn apply(
        &self,
        caller: &Caller,
        specs: &[PolicySpec],
        expected_revision: Option<u64>,
        prune: bool,
        dry_run: bool,
    ) -> Result<Applied> {
        self.authorize(caller).await?;
        let result = self
            .apply_unrecorded(specs, expected_revision, prune, dry_run)
            .await;
        if !dry_run {
            self.record(
                caller,
                "policy_apply",
                match &result {
                    Ok(done) => {
                        let mut details = json!({
                            "created": done.created,
                            "updated": done.updated,
                            "deleted": done.deleted,
                            "unchanged": done.unchanged.len(),
                            "revision": done.revision,
                            "prune": prune,
                        });
                        if done.replaced_unverified {
                            details["replaced_unverified"] = json!(true);
                        }
                        if done.new_policy_key {
                            details["new_policy_key"] = json!(true);
                        }
                        Outcome::Succeeded(details)
                    }
                    Err(e) => failed(e, json!({"policies": specs.len(), "prune": prune})),
                },
            );
        }
        result
    }

    async fn apply_unrecorded(
        &self,
        specs: &[PolicySpec],
        expected_revision: Option<u64>,
        prune: bool,
        dry_run: bool,
    ) -> Result<Applied> {
        if specs.len() > MAX_APPLY {
            return Err(PoliciesError::Request(format!(
                "{} policies; an apply carries at most {MAX_APPLY}",
                specs.len()
            )));
        }
        let mut names = BTreeSet::new();
        let mut policies = Vec::with_capacity(specs.len());
        for spec in specs {
            let policy = validate(spec)?;
            if !names.insert(policy.name.to_string()) {
                return Err(PoliciesError::Request(format!(
                    "policy `{}` is given twice",
                    policy.name
                )));
            }
            policies.push(policy);
        }
        match self
            .write(Write::Apply {
                policies,
                expected_revision,
                prune,
                dry_run,
            })
            .await?
        {
            WriteResult::Apply(applied) => Ok(applied),
            _ => Err(mismatched()),
        }
    }

    /// The one write path (see the module docs).
    async fn write(&self, op: Write) -> Result<WriteResult> {
        let epoch = self.seal.unsealed_epoch()?;
        let (root, generation) = self.seal.policy_write_context(epoch)?;
        // The floor before the keys database's snapshot (see
        // `Seal::sync_policy_floor`): verify and the new revision both
        // build on it.
        self.seal
            .sync_policy_floor()
            .await
            .map_err(PoliciesError::RevisionFloor)?;
        let pending = self.seal.keystore().begin_policy_write(generation).await?;
        let snapshot = pending.snapshot.clone();
        let seen = self.seal.policy_revision_seen();
        let verified = policy_store::verify(&root, &snapshot, seen);
        let repair = matches!(op, Write::Apply { prune: true, .. }) && verified.is_err();
        if let Err(why) = &verified
            && !repair
        {
            return Err(PoliciesError::Unverified(why.clone()));
        }
        let (key, new_wrapped_key) = match policy_store::key_state(&root, &snapshot) {
            KeyState::Usable(key) => (key, None),
            KeyState::Fresh => {
                let key = PolicyKey::generate()?;
                let wrapped = root.wrap_policy_key(&key)?;
                (key, Some(wrapped))
            }
            KeyState::Broken(_) => {
                // Only a repair gets here (anything else returned above).
                tracing::error!(
                    "replacing the stored policies with a new policy key: the old one was missing \
                     or didn't open"
                );
                let key = PolicyKey::generate()?;
                let wrapped = root.wrap_policy_key(&key)?;
                (key, Some(wrapped))
            }
        };
        let new_policy_key = new_wrapped_key.is_some() && repair;
        // What's stored now, by name: verified, or (a repair) as raw rows,
        // whose only use is to keep version numbers going up.
        let current: BTreeMap<String, Option<Verified>> = match &verified {
            Ok(set) => set
                .policies
                .iter()
                .map(|p| (p.name.clone(), Some(p.clone())))
                .collect(),
            Err(_) => snapshot
                .policies
                .iter()
                .map(|p| (p.name.clone(), None))
                .collect(),
        };
        let raw_versions: BTreeMap<&str, u32> = snapshot
            .policies
            .iter()
            .map(|p| (p.name.as_str(), p.version))
            .collect();
        let next_version = |name: &str| -> Result<u32> {
            raw_versions
                .get(name)
                .map_or(Some(1), |v| v.checked_add(1))
                .ok_or_else(|| {
                    PoliciesError::Request(format!("policy `{name}`: versions exhausted"))
                })
        };

        let mut upsert: Vec<NewPolicy> = Vec::new();
        let mut delete: Vec<String> = Vec::new();
        let mut result;
        match op {
            Write::Put {
                policy,
                expected_version,
            } => {
                let name = policy.name.to_string();
                let existing = raw_versions.get(name.as_str()).copied();
                if let Some(expected) = expected_version {
                    let matches = match (expected, existing) {
                        (0, None) => true,
                        (expected, Some(current)) => expected == current,
                        (_, None) => false,
                    };
                    if !matches {
                        return Err(PoliciesError::VersionMismatch {
                            name,
                            expected,
                            current: existing,
                        });
                    }
                }
                if existing.is_none() && current.len() >= MAX_STORED {
                    return Err(PoliciesError::Request(format!(
                        "{MAX_STORED} policies are stored; that's the most"
                    )));
                }
                let version = next_version(&name)?;
                upsert.push(policy_store::sealed_row(&key, &policy, version)?);
                result = WriteResult::Put(Written {
                    version,
                    revision: 0,
                    created: existing.is_none(),
                });
            }
            Write::Delete {
                name,
                expected_version,
            } => {
                let Some(&existing) = raw_versions.get(name.as_str()) else {
                    // Nothing to delete: nothing written.
                    return Ok(WriteResult::Delete(Deleted {
                        deleted: false,
                        revision: snapshot.state.revision,
                    }));
                };
                if let Some(expected) = expected_version
                    && expected != existing
                {
                    return Err(PoliciesError::VersionMismatch {
                        name,
                        expected,
                        current: Some(existing),
                    });
                }
                delete.push(name);
                result = WriteResult::Delete(Deleted {
                    deleted: true,
                    revision: 0,
                });
            }
            Write::Apply {
                policies,
                expected_revision,
                prune,
                dry_run,
            } => {
                if let Some(expected) = expected_revision
                    && expected != snapshot.state.revision
                {
                    return Err(PoliciesError::RevisionMismatch {
                        expected,
                        current: snapshot.state.revision,
                    });
                }
                let mut applied = Applied {
                    dry_run,
                    replaced_unverified: repair,
                    new_policy_key,
                    ..Applied::default()
                };
                let listed: BTreeSet<String> =
                    policies.iter().map(|p| p.name.to_string()).collect();
                for policy in &policies {
                    let name = policy.name.to_string();
                    match current.get(&name) {
                        // Verified and the same: left as it is.
                        Some(Some(stored)) if same(stored, policy) => applied.unchanged.push(name),
                        found => {
                            let version = next_version(&name)?;
                            upsert.push(policy_store::sealed_row(&key, policy, version)?);
                            if found.is_some() {
                                applied.updated.push(name);
                            } else {
                                applied.created.push(name);
                            }
                        }
                    }
                }
                if prune {
                    for name in current.keys().filter(|name| !listed.contains(*name)) {
                        delete.push(name.clone());
                        applied.deleted.push(name.clone());
                    }
                }
                let remaining = current.len() - applied.deleted.len() + applied.created.len();
                if remaining > MAX_STORED {
                    return Err(PoliciesError::Request(format!(
                        "{remaining} policies would be stored; at most {MAX_STORED}"
                    )));
                }
                result = WriteResult::Apply(applied);
            }
        }

        let revision = snapshot
            .state
            .revision
            .max(seen)
            .checked_add(1)
            .ok_or_else(|| PoliciesError::Request("revisions exhausted".to_owned()))?;
        // The set after this write: what's kept as stored, and what's new.
        let changed: BTreeSet<&str> = upsert
            .iter()
            .map(|p| p.name.as_str())
            .chain(delete.iter().map(String::as_str))
            .collect();
        let kept = snapshot
            .policies
            .iter()
            .filter(|p| !changed.contains(p.name.as_str()))
            .map(|p| SetEntry {
                name: &p.name,
                version: p.version,
                mac: &p.mac,
            });
        let added = upsert.iter().map(|p| SetEntry {
            name: &p.name,
            version: p.version,
            mac: &p.mac,
        });
        let entries: Vec<SetEntry<'_>> = kept.chain(added).collect();
        let set_mac = key.mac(&policy::set_message(revision, &entries))?.to_vec();
        drop(entries);
        match &mut result {
            WriteResult::Put(w) => w.revision = revision,
            WriteResult::Delete(d) => d.revision = revision,
            WriteResult::Apply(a) => {
                a.revision = revision;
                if a.dry_run {
                    // Nothing written: the transaction ends with `pending`.
                    return Ok(result);
                }
            }
        }
        pending
            .commit(PolicyChanges {
                upsert,
                delete,
                revision,
                mac: set_mac,
                new_wrapped_key,
            })
            .await?;
        self.seal.note_policy_revision(revision);
        // Committed: the floor follows. Failing that, the write stands, and
        // the next server to verify the set raises the floor to it.
        if let Err(e) = self.seal.raise_policy_floor(revision).await {
            tracing::warn!(
                revision,
                error = %e,
                "stored the policies but couldn't raise the policy revision floor; the next \
                 server to verify them will"
            );
        }
        // In force here at once; other servers follow within their refresh.
        if let Err(e) = self.seal.refresh_policies(true).await {
            tracing::warn!(
                error = %crate::error_chain(&e),
                "stored the policies but couldn't reload them; the next refresh will"
            );
        }
        Ok(result)
    }

    /// One rule by name: `config:…` for a config rule, else a stored policy
    /// (in force, so the server must be unsealed and the set verified).
    pub async fn get(&self, caller: &Caller, name: &str) -> Result<Entry> {
        self.authorize(caller).await?;
        if name.starts_with(CONFIG_PREFIX) {
            return self
                .config_entries()
                .into_iter()
                .find(|entry| entry.name == name)
                .ok_or_else(|| PoliciesError::NotFound(name.to_owned()));
        }
        match self.seal.policy_view() {
            PolicyView::Loaded(set) => set
                .get(name)
                .map(stored_entry)
                .ok_or_else(|| PoliciesError::NotFound(name.to_owned())),
            PolicyView::Sealed => Err(PoliciesError::Sealed),
            PolicyView::Unverified(why) => Err(PoliciesError::Unverified(why)),
        }
    }

    /// Config rules and (when in force) stored policies, by name, paged by
    /// name like secrets; `identity` filters.
    pub async fn list(
        &self,
        caller: &Caller,
        identity: Option<&str>,
        page_size: u32,
        page_token: &str,
    ) -> Result<Page> {
        self.authorize(caller).await?;
        let after = if page_token.is_empty() {
            None
        } else {
            Some(
                decode_token(page_token)
                    .ok_or_else(|| PoliciesError::Request("invalid page token".to_owned()))?,
            )
        };
        let size = match page_size {
            0 => DEFAULT_PAGE_SIZE,
            n => n.min(MAX_PAGE_SIZE),
        };
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        let mut entries = self.config_entries();
        let view = self.seal.policy_view();
        let stored = match &view {
            PolicyView::Loaded(set) => {
                entries.extend(set.policies.iter().map(stored_entry));
                StoredState::Loaded {
                    revision: set.revision,
                }
            }
            PolicyView::Sealed => StoredState::Sealed,
            PolicyView::Unverified(_) => StoredState::Unverified,
        };
        entries.retain(|entry| identity.is_none_or(|wanted| entry.identity == wanted));
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut page: Vec<Entry> = entries
            .into_iter()
            .filter(|entry| {
                after
                    .as_deref()
                    .is_none_or(|after| entry.name.as_str() > after)
            })
            .take(size.saturating_add(1))
            .collect();
        let next_page_token = if page.len() > size {
            page.truncate(size);
            page.last()
                .map(|e| encode_token(&e.name))
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Page {
            entries: page,
            next_page_token,
            stored,
        })
    }

    /// Whether `identity` may do `action` (on `path`, for a secret action),
    /// and which rules grant it. Nothing else is revealed.
    pub async fn check(
        &self,
        caller: &Caller,
        identity: &str,
        action: &str,
        path: Option<&str>,
    ) -> Result<Checked> {
        self.authorize(caller).await?;
        let identity = SecretPath::parse(identity)
            .map_err(|e| PoliciesError::Request(format!("identity `{identity}`: {e}")))?;
        let action = Action::parse(action)
            .ok_or_else(|| PoliciesError::Request(format!("unknown action `{action}`")))?;
        let path = path
            .filter(|p| !p.is_empty())
            .map(SecretPath::parse)
            .transpose()
            .map_err(|e| PoliciesError::Request(format!("path: {e}")))?;
        let target = match (&path, action.is_admin()) {
            (_, true) => Target::System,
            (Some(path), false) => Target::Path(path),
            (None, false) => Target::All,
        };
        let config = self.gate.config_policy();
        let config_policy = config.as_policy();
        let mut granted_by: Vec<String> = config_policy
            .map(|p| p.granting(&identity, action, target))
            .unwrap_or_default()
            .into_iter()
            .map(str::to_owned)
            .collect();
        let mut undecided = None;
        if let Some(secret) = action.secret() {
            match self.seal.policy_view() {
                PolicyView::Loaded(set) => granted_by.extend(
                    set.granting(&identity, secret, target)
                        .map(|p| p.name.clone()),
                ),
                PolicyView::Sealed => undecided = Some(Undecided::Sealed),
                PolicyView::Unverified(_) => undecided = Some(Undecided::Unverified),
            }
        }
        Ok(Checked {
            allowed: !granted_by.is_empty(),
            granted_by,
            enforced: config_policy.is_some(),
            undecided,
        })
    }

    fn config_entries(&self) -> Vec<Entry> {
        let config = self.gate.config_policy();
        let Some(policy) = config.as_policy() else {
            return Vec::new();
        };
        policy
            .rules()
            .map(|(name, rule)| Entry {
                name: name.to_owned(),
                source: Source::Config,
                identity: rule.identity.clone(),
                actions: rule.actions.iter().map(|a| a.name().to_owned()).collect(),
                paths: rule.paths.clone(),
                all_paths: rule.all_paths,
                description: String::new(),
                version: None,
                created_at: None,
                updated_at: None,
            })
            .collect()
    }
}

fn stored_entry(policy: &Verified) -> Entry {
    let (paths, all_paths) = match &policy.scope {
        Scope::All => (Vec::new(), true),
        Scope::Paths(paths) => (paths.iter().map(ToString::to_string).collect(), false),
    };
    Entry {
        name: policy.name.clone(),
        source: Source::Stored,
        identity: policy.identity.to_string(),
        actions: policy.actions.iter().map(|a| a.name().to_owned()).collect(),
        paths,
        all_paths,
        description: policy.description.clone(),
        version: Some(policy.version),
        created_at: Some(policy.created_at),
        updated_at: Some(policy.updated_at),
    }
}

/// A failed write's outcome: `unknown` when it may have landed.
fn failed(e: &PoliciesError, details: serde_json::Value) -> Outcome {
    let error = crate::error_chain(e);
    match e {
        PoliciesError::KeysTimeout => Outcome::Unknown(error),
        _ => Outcome::Failed {
            error,
            details: Some(details),
        },
    }
}

/// A write answered with another kind of result than it was: a bug, never
/// a made-up answer.
fn mismatched() -> PoliciesError {
    PoliciesError::Request(
        "internal error: a policy write answered for another operation".to_owned(),
    )
}

fn encode_token(name: &str) -> String {
    name.bytes().map(|b| format!("{b:02x}")).collect()
}

fn decode_token(token: &str) -> Option<String> {
    if !token.len().is_multiple_of(2) {
        return None;
    }
    let bytes = (0..token.len())
        .step_by(2)
        .map(|i| {
            token
                .get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()?;
    String::from_utf8(bytes).ok()
}
