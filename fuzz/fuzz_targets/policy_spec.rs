//! `PolicySpec::validate`: from a JSON API body, a TOML policy file, or the
//! fields directly. A policy that validates holds to every rule, its
//! canonical form (`Policy::spec`, what's stored and signed) is a fixed
//! point, and it survives the JSON round trip unchanged.
#![no_main]

use arbitrary::Arbitrary;
use ferritor_core::path::SecretPath;
use ferritor_core::policy::{MAX_DESCRIPTION, MAX_PATHS, PolicySpec, Scope, SecretAction};
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

/// The JSON API's apply body and `ferritor policy apply -f x.json`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonFile {
    policies: Vec<PolicySpec>,
}

/// `ferritor policy apply -f x.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlFile {
    #[serde(default)]
    policy: Vec<PolicySpec>,
}

#[derive(Arbitrary, Debug)]
enum Input {
    Json(String),
    Toml(String),
    Fields {
        name: String,
        identity: String,
        /// Indices into `SecretAction::ALL`.
        actions: Vec<u8>,
        paths: Vec<String>,
        all_paths: bool,
        description: String,
    },
}

fn specs(input: Input) -> Vec<PolicySpec> {
    match input {
        Input::Json(text) => {
            let mut specs: Vec<PolicySpec> = serde_json::from_str::<JsonFile>(&text)
                .map(|f| f.policies)
                .unwrap_or_default();
            specs.extend(serde_json::from_str::<PolicySpec>(&text).ok());
            specs
        }
        Input::Toml(text) => toml::from_str::<TomlFile>(&text)
            .map(|f| f.policy)
            .unwrap_or_default(),
        Input::Fields {
            name,
            identity,
            actions,
            paths,
            all_paths,
            description,
        } => vec![PolicySpec {
            name,
            identity,
            actions: actions
                .iter()
                .map(|&i| SecretAction::ALL[usize::from(i) % SecretAction::ALL.len()])
                .collect(),
            paths,
            all_paths,
            description,
        }],
    }
}

fn check(spec: &PolicySpec) {
    let Ok(policy) = spec.validate() else {
        return;
    };
    assert!(SecretPath::parse(&spec.name).is_ok() && SecretPath::parse(&spec.identity).is_ok());
    assert!(!spec.actions.is_empty());
    assert!(spec.paths.len() <= MAX_PATHS);
    assert_ne!(spec.all_paths, !spec.paths.is_empty());
    assert!(spec.description.len() <= MAX_DESCRIPTION);
    // Printable ASCII, newlines and tabs.
    assert!(
        spec.description
            .bytes()
            .all(|b| b.is_ascii_graphic() || matches!(b, b' ' | b'\n' | b'\t'))
    );
    match &policy.scope {
        Scope::All => assert!(spec.all_paths),
        Scope::Paths(prefixes) => {
            for path in &spec.paths {
                let path = SecretPath::parse(path).unwrap();
                assert!(prefixes.contains(&path) && policy.scope.covers(&path));
            }
        }
    }

    // The canonical form: sorted, no duplicates, the same grants, a fixed
    // point.
    let canonical = policy.spec();
    assert!(canonical.actions.is_sorted() && canonical.paths.is_sorted());
    assert!(canonical.actions.windows(2).all(|w| w[0] != w[1]));
    assert!(canonical.paths.windows(2).all(|w| w[0] != w[1]));
    let again = canonical.validate().unwrap();
    assert_eq!(again, policy);
    assert_eq!(again.spec(), canonical);

    // What the JSON API answers, read back, is the same policy.
    let json = serde_json::to_string(&canonical).unwrap();
    assert_eq!(
        serde_json::from_str::<PolicySpec>(&json).unwrap(),
        canonical
    );
}

fuzz_target!(|input: Input| {
    for spec in specs(input) {
        check(&spec);
    }
});
