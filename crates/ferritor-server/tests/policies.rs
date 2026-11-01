//! Stored policies against real keys and data databases (one each per test,
//! see `ferritor-testkit`): writes, enforcement next to the config rules,
//! sealed and unverified answers, integrity and rollback, the policy key's
//! life cycle, rekey and propagation between servers.

use std::sync::Arc;
use std::time::Duration;

use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::Labels;
use ferritor_core::path::SecretPath;
use ferritor_core::policy::{PolicySpec, SecretAction};
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{Action, Caller, StoredPolicies, Target};
use ferritor_server::namespaces::Namespaces;
use ferritor_server::policies::{Policies, PoliciesError, Source, StoredState};
use ferritor_server::policy::{Policy, Rule};
use ferritor_server::policy_store::{PolicyView, Unverified};
use ferritor_server::seal::{PolicyRefresh, RekeyPhase, Seal, SealError};
use ferritor_server::secrets::{Secrets, SecretsError};
use ferritor_testkit::{Captured, TestDatabase, TestResult};
use serde_json::Value;

fn who(name: &str) -> TestResult<Caller> {
    Ok(Caller::Identity(SecretPath::parse(name)?))
}

/// The config rules: an operator with every admin action and full secret
/// access, and a monitor that may only read the status.
fn config() -> TestResult<Policy> {
    use Action as A;
    Ok(Policy::new(&[
        Rule {
            name: Some("ops-admin".to_owned()),
            identity: "ops/admin".to_owned(),
            actions: vec![
                A::Status,
                A::Init,
                A::Unseal,
                A::Seal,
                A::Rekey,
                A::Namespace,
                A::Policy,
                A::Read,
                A::Write,
                A::List,
                A::Delete,
            ],
            paths: vec![],
            all_paths: true,
        },
        Rule {
            name: None,
            identity: "ops/monitor".to_owned(),
            actions: vec![A::Status],
            paths: vec![],
            all_paths: false,
        },
    ])?)
}

fn billing_read() -> PolicySpec {
    PolicySpec {
        name: "apps/billing-read".to_owned(),
        identity: "apps/billing".to_owned(),
        actions: vec![SecretAction::Read, SecretAction::List],
        paths: vec!["billing".to_owned()],
        all_paths: false,
        description: "billing app, read only".to_owned(),
    }
}

fn spec(name: &str, identity: &str, actions: &[SecretAction], paths: &[&str]) -> PolicySpec {
    PolicySpec {
        name: name.to_owned(),
        identity: identity.to_owned(),
        actions: actions.to_vec(),
        paths: paths.iter().map(|p| (*p).to_owned()).collect(),
        all_paths: false,
        description: String::new(),
    }
}

/// A server on its own databases (or another's: [`Env::second_server`]).
struct Server {
    seal: Arc<Seal>,
    gate: Arc<Gate>,
    audit: Captured,
    secrets: Secrets,
    policies: Policies,
}

impl Server {
    fn new(keys: &TestDatabase, data: &TestDatabase) -> TestResult<Self> {
        // As `main` builds it: the policy revision floor in the data
        // database.
        let seal = Arc::new(
            Seal::new(Keystore::new(keys.pool().clone()))
                .with_revision_floor(Arc::new(Datastore::new(data.pool().clone()))),
        );
        let audit = Captured::default();
        let gate = Arc::new(Gate::new(
            Arc::new(config()?),
            AuditLog::new(audit.clone(), Duration::from_secs(5))?,
        ));
        gate.use_stored_policies(Arc::clone(&seal) as Arc<dyn StoredPolicies>);
        Ok(Self {
            secrets: Secrets::new(
                Arc::clone(&seal),
                Datastore::new(data.pool().clone()),
                Arc::clone(&gate),
            ),
            policies: Policies::new(Arc::clone(&seal), Arc::clone(&gate)),
            seal,
            gate,
            audit,
        })
    }

    async fn unseal(&self, shares: &[Vec<u8>]) -> TestResult<()> {
        for share in shares {
            self.seal.unseal(share, false).await?;
        }
        Ok(())
    }

    /// Audit entries of one event, as JSON.
    fn entries(&self, event: &str) -> TestResult<Vec<Value>> {
        let mut found = Vec::new();
        for line in self.audit.lines() {
            let entry: Value = serde_json::from_str(&line)?;
            if entry["event"] == event {
                found.push(entry);
            }
        }
        Ok(found)
    }
}

struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    shares: Vec<Vec<u8>>,
    server: Server,
    admin: Caller,
    app: Caller,
}

impl Env {
    async fn new() -> TestResult<Self> {
        let keys = TestDatabase::new(
            "KEYS_DATABASE_URL",
            "ferritor_server_test",
            &ferritor_keystore::MIGRATOR,
        )
        .await?;
        let data = TestDatabase::new(
            "DATA_DATABASE_URL",
            "ferritor_server_test",
            &ferritor_datastore::MIGRATOR,
        )
        .await?;
        let server = Server::new(&keys, &data)?;
        let shares: Vec<Vec<u8>> = server
            .seal
            .init(ShareParams::new(3, 2)?)
            .await?
            .iter()
            .map(|s| s.to_bytes().to_vec())
            .collect();
        server.unseal(&shares[..2]).await?;
        let namespaces = Namespaces::new(
            Arc::clone(&server.seal),
            Datastore::new(data.pool().clone()),
        );
        for name in ["billing", "other"] {
            namespaces.create(name, &Labels::new()).await?;
        }
        let admin = who("ops/admin")?;
        server.secrets.put(&admin, "billing/db", b"bill").await?;
        server.secrets.put(&admin, "other/db", b"other").await?;
        Ok(Self {
            keys,
            data,
            shares,
            server,
            admin,
            app: who("apps/billing")?,
        })
    }

    /// Another server on the same databases, unsealed now.
    async fn second_server(&self) -> TestResult<Server> {
        let server = Server::new(&self.keys, &self.data)?;
        server.unseal(&self.shares[..2]).await?;
        Ok(server)
    }

    async fn reseal(&self) -> TestResult<()> {
        self.server.seal.seal().await;
        self.server.unseal(&self.shares[..2]).await
    }

    async fn sql(&self, statement: &'static str) -> TestResult<()> {
        sqlx::query(statement).execute(self.keys.pool()).await?;
        Ok(())
    }

    async fn destroy(self) -> TestResult<()> {
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

async fn reads(server: &Server, caller: &Caller, path: &str) -> Result<(), SecretsError> {
    server.secrets.get(caller, path, None).await.map(drop)
}

/// A stored grant allows what it names, next to the config rules; taken
/// away, the next request is denied. Put is check-and-set by version, and
/// delete is idempotent.
#[tokio::test]
async fn a_stored_policy_grants_until_it_is_deleted() {
    let env = Env::new().await.unwrap();
    let s = &env.server;
    assert!(matches!(
        reads(s, &env.app, "billing/db").await,
        Err(SecretsError::Denied(_))
    ));

    let written = s
        .policies
        .put(&env.admin, &billing_read(), Some(0))
        .await
        .unwrap();
    assert_eq!(
        (written.version, written.revision, written.created),
        (1, 1, true)
    );
    reads(s, &env.app, "billing/db").await.unwrap();
    // Only what it names: not another namespace, not a write.
    assert!(matches!(
        reads(s, &env.app, "other/db").await,
        Err(SecretsError::Denied(_))
    ));
    assert!(matches!(
        s.secrets.put(&env.app, "billing/db", b"x").await,
        Err(SecretsError::Denied(_))
    ));

    // Check-and-set.
    assert!(matches!(
        s.policies.put(&env.admin, &billing_read(), Some(0)).await,
        Err(PoliciesError::VersionMismatch {
            expected: 0,
            current: Some(1),
            ..
        })
    ));
    let mut wider = billing_read();
    wider.actions.push(SecretAction::Write);
    let replaced = s.policies.put(&env.admin, &wider, Some(1)).await.unwrap();
    assert_eq!((replaced.version, replaced.created), (2, false));
    s.secrets.put(&env.app, "billing/db", b"x").await.unwrap();
    assert!(matches!(
        s.policies
            .delete(&env.admin, "apps/billing-read", Some(1))
            .await,
        Err(PoliciesError::VersionMismatch { .. })
    ));

    let deleted = s
        .policies
        .delete(&env.admin, "apps/billing-read", Some(2))
        .await
        .unwrap();
    assert!(deleted.deleted);
    assert!(matches!(
        reads(s, &env.app, "billing/db").await,
        Err(SecretsError::Denied(_))
    ));
    let again = s
        .policies
        .delete(&env.admin, "apps/billing-read", None)
        .await
        .unwrap();
    assert!(!again.deleted);

    // Only callers with `policy` (a config grant) manage them.
    assert!(matches!(
        s.policies.put(&env.app, &billing_read(), None).await,
        Err(PoliciesError::Denied(_))
    ));
    // Every write's outcome, with what it stored.
    let outcomes = s.entries("outcome").unwrap();
    let put = outcomes
        .iter()
        .find(|e| e["operation"] == "policy_put" && e["result"] == "succeeded")
        .unwrap();
    assert_eq!(
        (&put["details"]["name"], &put["details"]["version"]),
        (&Value::from("apps/billing-read"), &Value::from(1))
    );
    env.destroy().await.unwrap();
}

/// Apply makes the stored set match a list, all or nothing: creates,
/// updates, leaves the same alone, and with prune deletes the rest. A dry
/// run changes nothing; one invalid policy or a stale revision refuses the
/// whole call.
#[tokio::test]
async fn apply_makes_the_stored_set_match() {
    let env = Env::new().await.unwrap();
    let p = &env.server.policies;
    let read = SecretAction::Read;
    p.put(
        &env.admin,
        &spec("a", "apps/a", &[read], &["billing"]),
        None,
    )
    .await
    .unwrap();
    p.put(
        &env.admin,
        &spec("b", "apps/b", &[read], &["billing"]),
        None,
    )
    .await
    .unwrap();

    let wanted = [
        spec("a", "apps/a", &[read], &["billing"]),
        spec("b", "apps/b", &[read], &["other"]),
        spec("c", "apps/c", &[read], &["other"]),
    ];
    let dry = p
        .apply(&env.admin, &wanted, None, false, true)
        .await
        .unwrap();
    assert!(dry.dry_run);
    assert_eq!(
        (dry.created, dry.updated),
        (vec!["c".to_owned()], vec!["b".to_owned()])
    );
    assert_eq!(
        env.server.seal.keystore().policy_revision().await.unwrap(),
        2
    );

    let mut invalid = wanted.to_vec();
    invalid.push(spec("d", "apps/d", &[read], &["a//b"]));
    let refused = p.apply(&env.admin, &invalid, None, true, false).await;
    assert!(matches!(refused, Err(PoliciesError::Invalid { ref name, .. }) if name == "d"));
    let mut twice = wanted.to_vec();
    twice.push(spec("a", "apps/x", &[read], &["other"]));
    assert!(matches!(
        p.apply(&env.admin, &twice, None, false, false).await,
        Err(PoliciesError::Request(_))
    ));
    assert!(matches!(
        p.apply(&env.admin, &wanted, Some(1), false, false).await,
        Err(PoliciesError::RevisionMismatch {
            expected: 1,
            current: 2
        })
    ));
    assert_eq!(
        env.server.seal.keystore().policy_revision().await.unwrap(),
        2
    );

    let applied = p
        .apply(&env.admin, &wanted[1..], Some(2), true, false)
        .await
        .unwrap();
    assert_eq!(
        (
            applied.created,
            applied.updated,
            applied.deleted,
            applied.unchanged,
            applied.revision
        ),
        (
            vec!["c".to_owned()],
            vec!["b".to_owned()],
            vec!["a".to_owned()],
            vec![],
            3
        )
    );
    let again = p
        .apply(&env.admin, &wanted[1..], None, true, false)
        .await
        .unwrap();
    assert_eq!(again.unchanged, ["b", "c"]);
    let listed = p.list(&env.admin, None, 0, "").await.unwrap();
    let names: Vec<(&str, Source)> = listed
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e.source))
        .collect();
    assert_eq!(
        names,
        [
            ("b", Source::Stored),
            ("c", Source::Stored),
            ("config:2", Source::Config),
            ("config:ops-admin", Source::Config),
        ]
    );
    assert_eq!(listed.stored, StoredState::Loaded { revision: 4 });
    env.destroy().await.unwrap();
}

/// Sealed is not denied: a secret request only a stored policy could
/// allow is SEALED, audited as such, whether or not one would; an admin
/// call the config rules don't allow is a plain denial. Unseal brings the
/// stored grants back with the keyring.
#[tokio::test]
async fn a_sealed_server_answers_sealed_not_denied() {
    let env = Env::new().await.unwrap();
    let s = &env.server;
    s.policies
        .put(&env.admin, &billing_read(), None)
        .await
        .unwrap();
    s.seal.seal().await;

    for caller in [&env.app, &who("apps/nobody").unwrap()] {
        assert!(matches!(
            reads(s, caller, "billing/db").await,
            Err(SecretsError::Sealed)
        ));
    }
    let unseal = s.gate.check(&env.app, Action::Unseal, Target::System).await;
    assert!(matches!(
        unseal,
        Err(ferritor_server::audit::Refused::Denied(_))
    ));
    let decisions: Vec<(String, String)> = s
        .entries("authorization")
        .unwrap()
        .iter()
        .rev()
        .take(3)
        .map(|e| {
            (
                e["action"].as_str().unwrap_or_default().to_owned(),
                e["decision"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        decisions,
        [
            ("unseal".to_owned(), "denied".to_owned()),
            ("read".to_owned(), "sealed".to_owned()),
            ("read".to_owned(), "sealed".to_owned()),
        ]
    );

    s.unseal(&env.shares[..2]).await.unwrap();
    reads(s, &env.app, "billing/db").await.unwrap();
    env.destroy().await.unwrap();
}

/// A row changed in the database: the running server keeps the set it
/// verified (and catches the change with a full refresh even without a new
/// revision); a reseal finds nothing verified, so what only the stored
/// policies decide is POLICY_UNVERIFIED while the config rules still work,
/// puts and deletes are refused, and only `apply --prune` repairs.
#[tokio::test]
async fn a_tampered_set_is_never_in_force_and_only_a_prune_repairs_it() {
    let env = Env::new().await.unwrap();
    let s = &env.server;
    s.policies
        .put(&env.admin, &billing_read(), None)
        .await
        .unwrap();
    // Widened behind ferritor's back, without touching the revision.
    env.sql("UPDATE policies SET paths = '{billing,other}'")
        .await
        .unwrap();
    assert!(matches!(
        s.seal.refresh_policies(false).await.unwrap(),
        PolicyRefresh::Unchanged
    ));
    assert!(matches!(
        s.seal.refresh_policies(true).await.unwrap(),
        PolicyRefresh::Failed {
            reason: Unverified::Row(_),
            kept: true
        }
    ));
    // Still the verified set: billing, not other.
    reads(s, &env.app, "billing/db").await.unwrap();
    assert!(matches!(
        reads(s, &env.app, "other/db").await,
        Err(SecretsError::Denied(_))
    ));

    env.reseal().await.unwrap();
    assert!(matches!(
        s.seal.policy_view(),
        PolicyView::Unverified(Unverified::Row(_))
    ));
    assert!(matches!(
        reads(s, &env.app, "billing/db").await,
        Err(SecretsError::PolicyUnverified)
    ));
    reads(s, &env.admin, "other/db").await.unwrap();
    assert!(matches!(
        s.policies.put(&env.admin, &billing_read(), None).await,
        Err(PoliciesError::Unverified(_))
    ));
    assert!(matches!(
        s.policies
            .apply(&env.admin, &[billing_read()], None, false, false)
            .await,
        Err(PoliciesError::Unverified(_))
    ));

    let repaired = s
        .policies
        .apply(&env.admin, &[billing_read()], None, true, false)
        .await
        .unwrap();
    assert!(repaired.replaced_unverified && !repaired.new_policy_key);
    assert_eq!(repaired.updated, ["apps/billing-read"]);
    reads(s, &env.app, "billing/db").await.unwrap();
    assert!(matches!(
        reads(s, &env.app, "other/db").await,
        Err(SecretsError::Denied(_))
    ));
    let apply = s
        .entries("outcome")
        .unwrap()
        .into_iter()
        .rfind(|e| e["operation"] == "policy_apply")
        .unwrap();
    assert_eq!(apply["details"]["replaced_unverified"], true);
    env.destroy().await.unwrap();
}

/// Rows added or removed behind the server's back fail the set's MAC.
#[tokio::test]
async fn a_row_inserted_or_deleted_in_sql_fails_the_set() {
    let env = Env::new().await.unwrap();
    let s = &env.server;
    let read = SecretAction::Read;
    s.policies
        .put(
            &env.admin,
            &spec("a", "apps/a", &[read], &["billing"]),
            None,
        )
        .await
        .unwrap();
    s.policies
        .put(
            &env.admin,
            &spec("b", "apps/b", &[read], &["billing"]),
            None,
        )
        .await
        .unwrap();
    for statement in [
        // A copy of a's row (its MAC valid for a) under another name.
        "INSERT INTO policies (name, identity, actions, paths, all_paths, description, version, mac)
         SELECT 'c', identity, actions, paths, all_paths, description, version, mac
         FROM policies WHERE name = 'a'",
        "DELETE FROM policies WHERE name = 'c'",
        "DELETE FROM policies WHERE name = 'b'",
    ] {
        env.sql(statement).await.unwrap();
        let refresh = s.seal.refresh_policies(true).await.unwrap();
        if statement.starts_with("DELETE FROM policies WHERE name = 'c'") {
            // Back as it was: verifies again.
            assert!(matches!(refresh, PolicyRefresh::Loaded { .. }), "{refresh:?}");
        } else {
            assert!(
                matches!(refresh, PolicyRefresh::Failed { kept: true, .. }),
                "{statement}: {refresh:?}"
            );
        }
    }
    env.destroy().await.unwrap();
}

/// A cleared policy key is an integrity failure, never a fresh start; a
/// corrupted one too, and it refuses a rekey before anything is committed.
/// Only the repair (an apply with prune) creates a new key.
#[tokio::test]
async fn a_cleared_or_corrupted_policy_key_is_repaired_only_by_a_prune() {
    let env = Env::new().await.unwrap();
    let s = &env.server;
    s.policies
        .put(&env.admin, &billing_read(), None)
        .await
        .unwrap();

    env.sql("UPDATE seal_config SET wrapped_policy_key = NULL")
        .await
        .unwrap();
    env.reseal().await.unwrap();
    assert!(matches!(
        s.seal.policy_view(),
        PolicyView::Unverified(Unverified::KeyMissing)
    ));
    assert!(matches!(
        s.policies.put(&env.admin, &billing_read(), None).await,
        Err(PoliciesError::Unverified(Unverified::KeyMissing))
    ));
    let repaired = s
        .policies
        .apply(&env.admin, &[billing_read()], None, true, false)
        .await
        .unwrap();
    assert!(repaired.replaced_unverified && repaired.new_policy_key);
    reads(s, &env.app, "billing/db").await.unwrap();

    env.sql("UPDATE seal_config SET wrapped_policy_key = '\\x00'")
        .await
        .unwrap();
    assert!(matches!(
        s.seal.rekey_start(ShareParams::new(3, 2).unwrap()).await,
        Err(SealError::PolicyKeyUnusable)
    ));
    let repaired = s
        .policies
        .apply(&env.admin, &[billing_read()], None, true, false)
        .await
        .unwrap();
    assert!(repaired.new_policy_key);
    s.seal
        .rekey_start(ShareParams::new(3, 2).unwrap())
        .await
        .unwrap();
    env.destroy().await.unwrap();
}

/// Key, set MAC and rows all wiped in the keys database, the revision left
/// alone (so no rollback): that's no fresh start, which only revision 0 is.
/// A running server keeps its verified set and alarms; a starting one has
/// none in force. Neither adopts the empty set.
#[tokio::test]
async fn a_wiped_set_past_revision_zero_is_missing_its_key_not_fresh() {
    let env = Env::new().await.unwrap();
    let s = &env.server;
    let read = SecretAction::Read;
    for name in ["a", "b"] {
        s.policies
            .put(&env.admin, &spec(name, "apps/x", &[read], &["other"]), None)
            .await
            .unwrap();
    }
    s.policies
        .put(&env.admin, &billing_read(), None)
        .await
        .unwrap();
    for statement in [
        "UPDATE seal_config SET wrapped_policy_key = NULL",
        "DELETE FROM policies",
        "UPDATE policy_state SET mac = NULL",
    ] {
        env.sql(statement).await.unwrap();
    }

    // The once-a-minute full check (a poll sees the same revision, 3, and
    // reads nothing).
    assert!(matches!(
        s.seal.refresh_policies(true).await.unwrap(),
        PolicyRefresh::Failed {
            reason: Unverified::KeyMissing,
            kept: true
        }
    ));
    reads(s, &env.app, "billing/db").await.unwrap();

    let started = env.second_server().await.unwrap();
    assert!(matches!(
        started.seal.policy_view(),
        PolicyView::Unverified(Unverified::KeyMissing)
    ));
    assert!(matches!(
        started
            .policies
            .put(&env.admin, &billing_read(), None)
            .await,
        Err(PoliciesError::Unverified(Unverified::KeyMissing))
    ));
    env.destroy().await.unwrap();
}

/// Put back an older, validly signed set while sealed (a restored backup,
/// or a keys-database writer on purpose): the same process refuses it at
/// unseal, and so does a restarted one, which never saw the newer revision
/// but finds it as the floor in the data database: nothing in force. A
/// write through a server lifts the set past it, and every server follows.
#[tokio::test]
async fn a_rollback_is_caught_across_a_reseal_and_a_write_lifts_past_it() {
    let env = Env::new().await.unwrap();
    let s = &env.server;
    let read = SecretAction::Read;
    s.policies
        .put(
            &env.admin,
            &spec("a", "apps/a", &[read], &["billing"]),
            None,
        )
        .await
        .unwrap();
    // The backup: revision 1.
    env.sql("CREATE TABLE saved_policies AS SELECT * FROM policies")
        .await
        .unwrap();
    env.sql("CREATE TABLE saved_state AS SELECT * FROM policy_state")
        .await
        .unwrap();
    s.policies
        .put(&env.admin, &billing_read(), None)
        .await
        .unwrap();

    s.seal.seal().await;
    for statement in [
        "DELETE FROM policies",
        "INSERT INTO policies SELECT * FROM saved_policies",
        "UPDATE policy_state SET (revision, mac) = (SELECT revision, mac FROM saved_state)",
    ] {
        env.sql(statement).await.unwrap();
    }
    s.unseal(&env.shares[..2]).await.unwrap();
    assert!(matches!(
        s.seal.policy_view(),
        PolicyView::Unverified(Unverified::Rollback { seen: 2, found: 1 })
    ));
    // A restarted process too, by the floor.
    let restarted = env.second_server().await.unwrap();
    assert!(matches!(
        restarted.seal.policy_view(),
        PolicyView::Unverified(Unverified::Rollback { seen: 2, found: 1 })
    ));
    assert!(matches!(
        reads(&restarted, &env.app, "billing/db").await,
        Err(SecretsError::PolicyUnverified)
    ));

    // The repair through the server that saw revision 2 lands at 3.
    let repaired = s
        .policies
        .apply(
            &env.admin,
            &[spec("a", "apps/a", &[read], &["billing"]), billing_read()],
            None,
            true,
            false,
        )
        .await
        .unwrap();
    assert_eq!(repaired.revision, 3);
    assert!(matches!(
        restarted.seal.refresh_policies(false).await.unwrap(),
        PolicyRefresh::Loaded {
            revision: 3,
            changed: true,
            ..
        }
    ));
    reads(&restarted, &env.app, "billing/db").await.unwrap();
    env.destroy().await.unwrap();
}

/// Everything wiped back to revision 0 (key, set MAC, rows and revision),
/// which is what a fresh start looks like: a restarted server, which never
/// saw a revision, still refuses it, by the floor every write raised in
/// the data database. Nothing in force, never an empty set.
#[tokio::test]
async fn a_wipe_to_revision_zero_is_a_rollback_by_the_floor() {
    let env = Env::new().await.unwrap();
    let s = &env.server;
    s.policies
        .put(&env.admin, &billing_read(), None)
        .await
        .unwrap();
    s.policies
        .put(
            &env.admin,
            &spec("a", "apps/a", &[SecretAction::Read], &["other"]),
            None,
        )
        .await
        .unwrap();
    let floor: i64 = sqlx::query_scalar("SELECT revision FROM policy_revision_floor")
        .fetch_one(env.data.pool())
        .await
        .unwrap();
    assert_eq!(floor, 2, "every write raises the floor");

    s.seal.seal().await;
    for statement in [
        "UPDATE seal_config SET wrapped_policy_key = NULL",
        "DELETE FROM policies",
        "UPDATE policy_state SET (revision, mac) = (0, NULL)",
    ] {
        env.sql(statement).await.unwrap();
    }
    let restarted = env.second_server().await.unwrap();
    assert!(matches!(
        restarted.seal.policy_view(),
        PolicyView::Unverified(Unverified::Rollback { seen: 2, found: 0 })
    ));
    assert!(matches!(
        reads(&restarted, &env.app, "billing/db").await,
        Err(SecretsError::PolicyUnverified)
    ));
    // The repair lands above the floor, and every server takes it.
    let repaired = restarted
        .policies
        .apply(&env.admin, &[billing_read()], None, true, false)
        .await
        .unwrap();
    assert_eq!(repaired.revision, 3);
    reads(&restarted, &env.app, "billing/db").await.unwrap();
    env.destroy().await.unwrap();
}

/// A raise a write missed (it failed, or a data-database failover lost it)
/// is caught up by the next server to verify the set, so a rollback to the
/// revision just below is refused, by a restarted server too.
#[tokio::test]
async fn a_missed_floor_raise_is_caught_up_by_the_next_load() {
    let env = Env::new().await.unwrap();
    let s = &env.server;
    s.policies
        .put(
            &env.admin,
            &spec("a", "apps/a", &[SecretAction::Read], &["other"]),
            None,
        )
        .await
        .unwrap();
    // The backup: revision 1.
    env.sql("CREATE TABLE saved_policies AS SELECT * FROM policies")
        .await
        .unwrap();
    env.sql("CREATE TABLE saved_state AS SELECT * FROM policy_state")
        .await
        .unwrap();
    s.policies
        .put(&env.admin, &billing_read(), None)
        .await
        .unwrap();
    let floor = || async {
        sqlx::query_scalar::<_, i64>("SELECT revision FROM policy_revision_floor")
            .fetch_one(env.data.pool())
            .await
            .unwrap()
    };
    let lose_the_raise = || async {
        sqlx::query("UPDATE policy_revision_floor SET revision = 1")
            .execute(env.data.pool())
            .await
            .unwrap();
    };
    // The write's raise to 2, lost (a data-database failover).
    lose_the_raise().await;

    // The server that raised it once, still running, raises it again at
    // its next load: it goes by the floor as read now, not as it was.
    s.seal.refresh_policies(true).await.unwrap();
    assert_eq!(floor().await, 2);

    // So does another server that verifies revision 2.
    lose_the_raise().await;
    let other = env.second_server().await.unwrap();
    assert!(matches!(other.seal.policy_view(), PolicyView::Loaded(set) if set.revision == 2));
    assert_eq!(floor().await, 2);

    // So revision 1 put back is refused by a server started after it.
    for statement in [
        "DELETE FROM policies",
        "INSERT INTO policies SELECT * FROM saved_policies",
        "UPDATE policy_state SET (revision, mac) = (SELECT revision, mac FROM saved_state)",
    ] {
        env.sql(statement).await.unwrap();
    }
    let restarted = env.second_server().await.unwrap();
    assert!(matches!(
        restarted.seal.policy_view(),
        PolicyView::Unverified(Unverified::Rollback { seen: 2, found: 1 })
    ));
    env.destroy().await.unwrap();
}

/// A change through one server reaches another at its next poll: a grant,
/// and its revocation. The other server also follows a repair that replaced
/// the policy key.
#[tokio::test]
async fn changes_reach_other_servers_at_their_next_refresh() {
    let env = Env::new().await.unwrap();
    let other = env.second_server().await.unwrap();
    env.server
        .policies
        .put(&env.admin, &billing_read(), None)
        .await
        .unwrap();
    assert!(matches!(
        reads(&other, &env.app, "billing/db").await,
        Err(SecretsError::Denied(_))
    ));
    other.seal.refresh_policies(false).await.unwrap();
    reads(&other, &env.app, "billing/db").await.unwrap();

    env.server
        .policies
        .delete(&env.admin, "apps/billing-read", None)
        .await
        .unwrap();
    other.seal.refresh_policies(false).await.unwrap();
    assert!(matches!(
        reads(&other, &env.app, "billing/db").await,
        Err(SecretsError::Denied(_))
    ));

    // A repair with a new key elsewhere: adopted with the set.
    env.sql("UPDATE seal_config SET wrapped_policy_key = NULL")
        .await
        .unwrap();
    env.server.seal.refresh_policies(true).await.unwrap();
    let repaired = env
        .server
        .policies
        .apply(&env.admin, &[billing_read()], None, true, false)
        .await
        .unwrap();
    assert!(repaired.new_policy_key);
    assert!(matches!(
        other.seal.refresh_policies(false).await.unwrap(),
        PolicyRefresh::Loaded { changed: true, .. }
    ));
    reads(&other, &env.app, "billing/db").await.unwrap();
    env.destroy().await.unwrap();
}

/// A rekey re-wraps the policy key, even one created by another server
/// since this one last refreshed: the stored policies still verify after
/// the commit and after a reseal with the new shares.
#[tokio::test]
async fn a_rekey_keeps_the_stored_policies_verifiable() {
    let env = Env::new().await.unwrap();
    let other = env.second_server().await.unwrap();
    // Created through the other server: this one never loaded the key.
    other
        .policies
        .put(&env.admin, &billing_read(), None)
        .await
        .unwrap();

    let seal = &env.server.seal;
    let nonce = seal
        .rekey_start(ShareParams::new(3, 2).unwrap())
        .await
        .unwrap()
        .nonce;
    let mut progress = None;
    for share in &env.shares[..2] {
        progress = Some(seal.rekey_submit(&nonce, share).await.unwrap());
    }
    let new_shares: Vec<Vec<u8>> = progress
        .unwrap()
        .new_shares
        .iter()
        .map(|s| s.to_bytes().to_vec())
        .collect();
    let mut done = None;
    for share in &new_shares[..2] {
        done = Some(seal.rekey_verify(&nonce, share).await.unwrap());
    }
    assert_eq!(done.unwrap().phase, RekeyPhase::Complete);
    assert!(matches!(
        seal.refresh_policies(true).await.unwrap(),
        PolicyRefresh::Loaded { .. }
    ));
    seal.seal().await;
    env.server.unseal(&new_shares[..2]).await.unwrap();
    assert!(matches!(seal.policy_view(), PolicyView::Loaded(_)));
    reads(&env.server, &env.app, "billing/db").await.unwrap();
    env.destroy().await.unwrap();
}

/// Get and check: config rules by their qualified names, stored policies
/// by theirs; check says which rules grant, and what couldn't be decided
/// while sealed.
#[tokio::test]
async fn get_and_check_name_the_rules() {
    let env = Env::new().await.unwrap();
    let p = &env.server.policies;
    p.put(&env.admin, &billing_read(), None).await.unwrap();

    let config_rule = p.get(&env.admin, "config:ops-admin").await.unwrap();
    assert_eq!(
        (config_rule.source, config_rule.identity.as_str()),
        (Source::Config, "ops/admin")
    );
    let stored = p.get(&env.admin, "apps/billing-read").await.unwrap();
    assert_eq!(
        (stored.source, stored.version, stored.description.as_str()),
        (Source::Stored, Some(1), "billing app, read only")
    );
    assert!(matches!(
        p.get(&env.admin, "nope").await,
        Err(PoliciesError::NotFound(_))
    ));
    // `:` can't be in a stored policy's name.
    let mut bad = billing_read();
    bad.name = "config:mine".to_owned();
    assert!(matches!(
        p.put(&env.admin, &bad, None).await,
        Err(PoliciesError::Invalid { .. })
    ));

    let checked = p
        .check(&env.admin, "apps/billing", "read", Some("billing/db"))
        .await
        .unwrap();
    assert_eq!(
        (checked.allowed, checked.granted_by, checked.enforced),
        (true, vec!["apps/billing-read".to_owned()], true)
    );
    let admin_rotate = p
        .check(&env.admin, "ops/monitor", "status", None)
        .await
        .unwrap();
    assert_eq!(admin_rotate.granted_by, ["config:2"]);
    let denied = p
        .check(&env.admin, "apps/billing", "write", Some("billing/db"))
        .await
        .unwrap();
    assert!(!denied.allowed);

    env.server.seal.seal().await;
    let sealed = p
        .check(&env.admin, "apps/billing", "read", Some("billing/db"))
        .await
        .unwrap();
    assert_eq!(
        (sealed.allowed, sealed.undecided),
        (false, Some(ferritor_server::policies::Undecided::Sealed))
    );
    assert!(matches!(
        p.get(&env.admin, "apps/billing-read").await,
        Err(PoliciesError::Sealed)
    ));
    // Config rules are listed sealed or not.
    let listed = p.list(&env.admin, None, 0, "").await.unwrap();
    assert_eq!(listed.stored, StoredState::Sealed);
    assert_eq!(listed.entries.len(), 2);
    env.destroy().await.unwrap();
}
