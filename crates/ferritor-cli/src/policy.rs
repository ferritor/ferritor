//! `ferritor policy`: the stored policies over `PolicyService`. A file for
//! `apply` is parsed and validated here with the server's own rule types
//! (`ferritor_core::policy`), so a typo is refused before anything is sent.

use std::io::{self, Read, Write};
use std::path::Path;

use anyhow::Context;
use ferritor_core::policy::{PolicySpec, SecretAction};
use ferritor_core::proto::v1 as pb;
use ferritor_core::proto::v1::policy_service_client::PolicyServiceClient;
use serde::Deserialize;

use crate::cli::PolicyCommand;
use crate::run::{answer, utc};

pub type PolicyClient = PolicyServiceClient<ferritor_client::Transport>;

/// `ferritor policy check` found the action not allowed: exit status 1,
/// after the verdict on stdout.
#[derive(Debug, thiserror::Error)]
#[error("not allowed")]
pub struct NotAllowed;

/// A policy file: TOML `[[policy]]` entries, or the JSON API's apply body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlFile {
    #[serde(default)]
    policy: Vec<PolicySpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonFile {
    policies: Vec<PolicySpec>,
}

/// Reads and validates the policies in `path` (`-`: stdin). JSON if the
/// name ends in `.json`, or (stdin) if it starts with `{`; TOML otherwise.
pub fn read_policy_file(path: &Path) -> anyhow::Result<Vec<PolicySpec>> {
    let stdin = path == Path::new("-");
    let text = if stdin {
        let mut text = String::new();
        io::stdin()
            .read_to_string(&mut text)
            .context("reading the policies from stdin")?;
        text
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
    };
    let json = if stdin {
        text.trim_start().starts_with('{')
    } else {
        path.extension().is_some_and(|e| e == "json")
    };
    let what = if stdin {
        "stdin".to_owned()
    } else {
        path.display().to_string()
    };
    let specs = if json {
        serde_json::from_str::<JsonFile>(&text)
            .with_context(|| format!("{what} isn't a valid policy file (JSON)"))?
            .policies
    } else {
        toml::from_str::<TomlFile>(&text)
            .with_context(|| format!("{what} isn't a valid policy file (TOML)"))?
            .policy
    };
    let mut names = std::collections::BTreeSet::new();
    for spec in &specs {
        spec.validate()
            .with_context(|| format!("{what}: policy `{}`", spec.name))?;
        anyhow::ensure!(
            names.insert(spec.name.clone()),
            "{what}: policy `{}` is given twice",
            spec.name
        );
    }
    Ok(specs)
}

fn proto_action(action: SecretAction) -> pb::SecretAction {
    match action {
        SecretAction::Read => pb::SecretAction::Read,
        SecretAction::Write => pb::SecretAction::Write,
        SecretAction::Delete => pb::SecretAction::Delete,
        SecretAction::List => pb::SecretAction::List,
        SecretAction::Label => pb::SecretAction::Label,
    }
}

fn proto_spec(spec: &PolicySpec) -> pb::PolicySpec {
    pb::PolicySpec {
        name: spec.name.clone(),
        identity: spec.identity.clone(),
        actions: spec
            .actions
            .iter()
            .map(|a| proto_action(*a).into())
            .collect(),
        paths: spec.paths.clone(),
        all_paths: spec.all_paths,
        description: spec.description.clone(),
    }
}

fn scope(entry: &pb::PolicyEntry) -> String {
    if entry.all_paths {
        "all paths".to_owned()
    } else if entry.paths.is_empty() {
        "no paths".to_owned()
    } else {
        entry.paths.join(", ")
    }
}

fn source(entry: &pb::PolicyEntry) -> &'static str {
    match entry.source() {
        pb::PolicySource::Config => "config",
        pb::PolicySource::Stored => "stored",
        pb::PolicySource::Unspecified => "unknown",
    }
}

fn list_of(names: &[String]) -> String {
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    }
}

pub async fn policy_command(
    mut client: PolicyClient,
    command: &PolicyCommand,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    match command {
        PolicyCommand::List { identity } => {
            let mut token = String::new();
            let state = loop {
                let reply = answer(
                    client
                        .list_policies(pb::ListPoliciesRequest {
                            identity: identity.clone().unwrap_or_default(),
                            page_size: 0,
                            page_token: token,
                        })
                        .await,
                )?;
                for entry in &reply.policies {
                    writeln!(
                        out,
                        "{}\t{}\t{}\t{}\t{}",
                        entry.name,
                        source(entry),
                        entry.identity,
                        entry.actions.join(","),
                        scope(entry)
                    )?;
                }
                if reply.next_page_token.is_empty() {
                    break reply.stored();
                }
                token = reply.next_page_token;
            };
            match state {
                pb::StoredPolicyState::Sealed => eprintln!(
                    "Sealed: stored policies aren't in force, only the config rules are listed."
                ),
                pb::StoredPolicyState::Unverified => eprintln!(
                    "The stored policies don't verify: only the config rules are listed. Re-apply \
                     them from their source of truth (`ferritor policy apply --prune`)."
                ),
                _ => {}
            }
        }
        PolicyCommand::Get { name } => {
            let reply = answer(
                client
                    .get_policy(pb::GetPolicyRequest { name: name.clone() })
                    .await,
            )?;
            let entry = reply.policy.context("no policy in the reply")?;
            writeln!(out, "name: {}", entry.name)?;
            writeln!(out, "source: {}", source(&entry))?;
            writeln!(out, "identity: {}", entry.identity)?;
            writeln!(out, "actions: {}", entry.actions.join(", "))?;
            writeln!(out, "paths: {}", scope(&entry))?;
            if !entry.description.is_empty() {
                writeln!(out, "description: {}", entry.description)?;
            }
            if let Some(version) = entry.version {
                writeln!(out, "version: {version}")?;
            }
            if let Some(at) = entry.created_at_unix {
                writeln!(out, "created: {}", utc(at))?;
            }
            if let Some(at) = entry.updated_at_unix {
                writeln!(out, "updated: {}", utc(at))?;
            }
        }
        PolicyCommand::Put {
            name,
            identity,
            actions,
            paths,
            all_paths,
            description,
            expected_version,
        } => {
            let spec = PolicySpec {
                name: name.clone(),
                identity: identity.clone(),
                actions: actions.clone(),
                paths: paths.clone(),
                all_paths: *all_paths,
                description: description.clone(),
            };
            spec.validate()
                .with_context(|| format!("policy `{name}`"))?;
            let reply = answer(
                client
                    .put_policy(pb::PutPolicyRequest {
                        policy: Some(proto_spec(&spec)),
                        expected_version: *expected_version,
                    })
                    .await,
            )?;
            let verb = if reply.created { "created" } else { "replaced" };
            writeln!(out, "{verb} {name} version {}", reply.version)?;
            writeln!(out, "revision: {}", reply.revision)?;
        }
        PolicyCommand::Delete {
            name,
            expected_version,
        } => {
            let reply = answer(
                client
                    .delete_policy(pb::DeletePolicyRequest {
                        name: name.clone(),
                        expected_version: *expected_version,
                    })
                    .await,
            )?;
            if reply.deleted {
                writeln!(out, "deleted {name}")?;
            } else {
                writeln!(out, "there was no policy {name}")?;
            }
            writeln!(out, "revision: {}", reply.revision)?;
        }
        PolicyCommand::Apply {
            file,
            prune,
            dry_run,
            expected_revision,
        } => {
            let specs = read_policy_file(file)?;
            let reply = answer(
                client
                    .apply_policies(pb::ApplyPoliciesRequest {
                        policies: specs.iter().map(proto_spec).collect(),
                        expected_revision: *expected_revision,
                        prune: *prune,
                        dry_run: *dry_run,
                    })
                    .await,
            )?;
            if reply.dry_run {
                writeln!(out, "dry run: nothing was changed")?;
            }
            writeln!(out, "created: {}", list_of(&reply.created))?;
            writeln!(out, "updated: {}", list_of(&reply.updated))?;
            writeln!(out, "deleted: {}", list_of(&reply.deleted))?;
            writeln!(out, "unchanged: {}", reply.unchanged.len())?;
            writeln!(out, "revision: {}", reply.revision)?;
            if reply.replaced_unverified {
                eprintln!(
                    "The stored set didn't verify, and this replaced it{}. Find out who changed \
                     the keys database (the audit log has every change through ferritor).",
                    if reply.new_policy_key {
                        ", with a new policy key"
                    } else {
                        ""
                    }
                );
            }
        }
        PolicyCommand::Check {
            identity,
            action,
            path,
        } => {
            let reply = answer(
                client
                    .check_access(pb::CheckAccessRequest {
                        identity: identity.clone(),
                        action: action.clone(),
                        path: path.clone().unwrap_or_default(),
                    })
                    .await,
            )?;
            if reply.allowed {
                writeln!(out, "allowed by {}", reply.granted_by.join(", "))?;
            } else {
                writeln!(out, "not allowed")?;
            }
            if !reply.undecided.is_empty() {
                eprintln!(
                    "The stored policies couldn't answer ({}): only the config rules were \
                     checked.",
                    reply.undecided
                );
            }
            if !reply.enforced {
                eprintln!(
                    "Not enforced (dev mode): everyone may do everything on this server, \
                     whatever the rules say."
                );
            }
            if !reply.allowed {
                return Err(NotAllowed.into());
            }
        }
    }
    Ok(())
}
