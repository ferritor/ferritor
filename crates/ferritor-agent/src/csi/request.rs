//! A `MountRequest` as the driver sends it, checked. `attributes` is one
//! JSON object of strings: the `SecretProviderClass`'s `parameters` (ours:
//! `prefix` or `objects`, `onRevoked`, `filePermission`), merged with the
//! kubelet's volume attributes (`csi.storage.k8s.io/pod.*`, the pod's
//! tokens under `csi.storage.k8s.io/serviceAccount.tokens`).

use std::collections::{BTreeMap, HashSet};

use ferritor_core::path::SecretPath;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use super::proto::MountRequest;
use crate::config::OnRevoked;

const TOKENS: &str = "csi.storage.k8s.io/serviceAccount.tokens";
const POD_NAMESPACE: &str = "csi.storage.k8s.io/pod.namespace";
const POD_NAME: &str = "csi.storage.k8s.io/pod.name";
/// Ours, in the `SecretProviderClass`'s `parameters`.
const OURS: [&str; 4] = ["prefix", "objects", "onRevoked", "filePermission"];
/// The driver's own, beside the kubelet's (`csi.storage.k8s.io/…`).
const THE_DRIVERS: [&str; 1] = ["secretProviderClass"];

/// What the volume holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// Every live secret below the prefix, its file named by the path below
    /// it (subdirectories for deeper paths).
    Prefix(SecretPath),
    /// Exactly these, each to its file.
    Objects(Vec<Object>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub path: SecretPath,
    pub file: String,
}

/// One volume, as asked for.
pub struct Volume {
    /// The volume's path on the node: what identifies it across refreshes.
    pub target: String,
    /// `namespace/name`, for logs.
    pub pod: String,
    pub token: Zeroizing<String>,
    pub source: Source,
    pub on_revoked: OnRevoked,
    /// Every file's mode.
    pub mode: u32,
}

#[derive(Deserialize)]
struct Token {
    token: String,
    #[serde(rename = "expirationTimestamp")]
    expiration: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObject {
    path: String,
    file: Option<String>,
}

/// A file name the driver accepts (one relative path, no `..` element,
/// not starting with `..`) and that can't collide with the driver's own
/// (`..data` and the generations: they start with `..`).
fn file_name_ok(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && !part.starts_with(".."))
}

/// The file a secret below `prefix` goes to: its path below the prefix.
pub fn file_below(prefix: &SecretPath, path: &SecretPath) -> Option<String> {
    let rest = path
        .as_str()
        .strip_prefix(prefix.as_str())?
        .strip_prefix('/')?;
    file_name_ok(rest).then(|| rest.to_owned())
}

/// The token for `audience` from the pod's tokens, and when it expires.
fn token(
    attributes: &BTreeMap<String, String>,
    audience: &str,
) -> Result<(Zeroizing<String>, Option<OffsetDateTime>), String> {
    let Some(tokens) = attributes.get(TOKENS) else {
        return Err(format!(
            "no service account token: the driver's CSIDriver needs tokenRequests with audience \
             {audience:?} (and requiresRepublish)"
        ));
    };
    let tokens: BTreeMap<String, Token> =
        serde_json::from_str(tokens).map_err(|_| "the pod's tokens aren't JSON".to_owned())?;
    let Some(token) = tokens.get(audience) else {
        return Err(format!(
            "no token with audience {audience:?} among the pod's: add it to the CSIDriver's \
             tokenRequests"
        ));
    };
    let expires = token
        .expiration
        .as_deref()
        .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok());
    Ok((Zeroizing::new(token.token.clone()), expires))
}

/// Parses and checks `request`, every mistake refused with what's wrong.
/// Also returns when the token expires, if the kubelet said.
pub fn parse(
    request: &MountRequest,
    audience: &str,
) -> Result<(Volume, Option<OffsetDateTime>), String> {
    let attributes: BTreeMap<String, String> = serde_json::from_str(&request.attributes)
        .map_err(|_| "the volume's attributes aren't a JSON object of strings".to_owned())?;
    for key in attributes.keys() {
        if !key.contains('/')
            && !OURS.contains(&key.as_str())
            && !THE_DRIVERS.contains(&key.as_str())
        {
            return Err(format!(
                "unknown parameter {key:?} (ferritor takes {})",
                OURS.join(", ")
            ));
        }
    }
    let (token, expires) = token(&attributes, audience)?;
    let source = match (attributes.get("prefix"), attributes.get("objects")) {
        (Some(prefix), None) => Source::Prefix(
            SecretPath::parse(prefix).map_err(|e| format!("prefix {prefix:?}: {e}"))?,
        ),
        (None, Some(objects)) => Source::Objects(objects_from(objects)?),
        (Some(_), Some(_)) => return Err("prefix or objects, not both".to_owned()),
        (None, None) => return Err("no prefix and no objects: nothing to mount".to_owned()),
    };
    let on_revoked = match attributes.get("onRevoked").map(String::as_str) {
        None | Some("keep") => OnRevoked::Keep,
        Some("remove") => OnRevoked::Remove,
        Some(other) => return Err(format!("onRevoked {other:?}: keep or remove")),
    };
    let mode = match attributes.get("filePermission") {
        Some(mode) => u32::from_str_radix(mode.trim_start_matches("0o"), 8)
            .ok()
            .filter(|mode| *mode <= 0o777)
            .ok_or_else(|| format!("filePermission {mode:?}: an octal mode, like \"0440\""))?,
        // The driver's own default, as it sends it (a JSON number).
        None => serde_json::from_str::<u32>(&request.permission)
            .ok()
            .filter(|mode| *mode <= 0o777)
            .unwrap_or(0o644),
    };
    let pod = format!(
        "{}/{}",
        attributes.get(POD_NAMESPACE).map_or("?", String::as_str),
        attributes.get(POD_NAME).map_or("?", String::as_str)
    );
    Ok((
        Volume {
            target: request.target_path.clone(),
            pod,
            token,
            source,
            on_revoked,
            mode,
        },
        expires,
    ))
}

fn objects_from(objects: &str) -> Result<Vec<Object>, String> {
    let raw: Vec<RawObject> = serde_json::from_str(objects)
        .map_err(|e| format!("objects: a JSON list of {{\"path\": …, \"file\": …}} ({e})"))?;
    if raw.is_empty() {
        return Err("objects is empty: nothing to mount".to_owned());
    }
    let mut files = HashSet::new();
    let mut out = Vec::with_capacity(raw.len());
    for object in raw {
        let path = SecretPath::parse(&object.path)
            .map_err(|e| format!("objects: path {:?}: {e}", object.path))?;
        let file = object.file.unwrap_or_else(|| {
            path.as_str()
                .rsplit('/')
                .next()
                .unwrap_or(path.as_str())
                .to_owned()
        });
        if !file_name_ok(&file) {
            return Err(format!(
                "objects: file {file:?}: a relative name, no element '..' or starting with '..'"
            ));
        }
        if !files.insert(file.clone()) {
            return Err(format!("objects: two secrets name the file {file:?}"));
        }
        out.push(Object { path, file });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(parameters: &[(&str, &str)]) -> MountRequest {
        let mut attributes: BTreeMap<String, String> = parameters
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        attributes.insert("secretProviderClass".to_owned(), "billing-api".to_owned());
        attributes.insert(POD_NAMESPACE.to_owned(), "billing".to_owned());
        attributes.insert(POD_NAME.to_owned(), "api-1".to_owned());
        attributes.entry(TOKENS.to_owned()).or_insert_with(|| {
            r#"{"ferritor":{"token":"t0k3n","expirationTimestamp":"2026-10-25T12:00:00Z"}}"#
                .to_owned()
        });
        MountRequest {
            attributes: serde_json::to_string(&attributes).unwrap(),
            secrets: String::new(),
            target_path: "/var/lib/kubelet/pods/u/volumes/x".to_owned(),
            permission: "420".to_owned(),
            current_object_version: Vec::new(),
        }
    }

    #[test]
    fn a_prefix_volume_parses_with_the_drivers_permission() {
        let (volume, expires) = parse(&request(&[("prefix", "billing/api")]), "ferritor").unwrap();
        assert_eq!(
            volume.source,
            Source::Prefix(SecretPath::parse("billing/api").unwrap())
        );
        assert_eq!(volume.mode, 0o644);
        assert_eq!(volume.on_revoked, OnRevoked::Keep);
        assert_eq!(volume.pod, "billing/api-1");
        assert_eq!(*volume.token, "t0k3n");
        assert_eq!(
            expires.map(OffsetDateTime::unix_timestamp),
            Some(1_792_929_600)
        );
    }

    #[test]
    fn objects_name_their_files() {
        let objects = r#"[{"path": "billing/api/db-password"},
                         {"path": "billing/shared/redis-password", "file": "redis"}]"#;
        let (volume, _) = parse(
            &request(&[
                ("objects", objects),
                ("onRevoked", "remove"),
                ("filePermission", "0440"),
            ]),
            "ferritor",
        )
        .unwrap();
        let Source::Objects(objects) = volume.source else {
            panic!("objects")
        };
        let files: Vec<&str> = objects.iter().map(|o| o.file.as_str()).collect();
        assert_eq!(files, ["db-password", "redis"]);
        assert_eq!(volume.mode, 0o440);
        assert_eq!(volume.on_revoked, OnRevoked::Remove);
    }

    #[test]
    fn files_below_a_prefix_keep_their_subdirectories() {
        let prefix = SecretPath::parse("billing/api").unwrap();
        let file = |path: &str| file_below(&prefix, &SecretPath::parse(path).unwrap());
        assert_eq!(file("billing/api/db").as_deref(), Some("db"));
        assert_eq!(file("billing/api/tls/cert").as_deref(), Some("tls/cert"));
        // The driver's own names start with "..".
        assert_eq!(file("billing/api/..data"), None);
        assert_eq!(file("billing/apix/db"), None);
    }

    #[test]
    fn mistakes_are_refused_saying_what() {
        let two = r#"[{"path": "a/x/db"}, {"path": "a/y/db"}]"#;
        for (parameters, says) in [
            (vec![], "nothing to mount"),
            (vec![("prefix", "a"), ("objects", "[]")], "not both"),
            (vec![("objects", two)], "two secrets name the file"),
            (vec![("objects", "[]")], "objects is empty"),
            (vec![("objects", "- path: a/b")], "a JSON list"),
            (
                vec![("objects", r#"[{"path": "a/b", "file": "../x"}]"#)],
                "relative name",
            ),
            (vec![("prefix", "a//b")], "prefix"),
            (
                vec![("prefix", "a"), ("onRevoked", "drop")],
                "keep or remove",
            ),
            (vec![("prefix", "a"), ("filePermission", "rw")], "octal"),
            (vec![("prefix", "a"), ("prefx", "a")], "unknown parameter"),
            (
                vec![("prefix", "a"), (TOKENS, "{}")],
                "no token with audience",
            ),
        ] {
            let error = parse(&request(&parameters), "ferritor").err().unwrap();
            assert!(error.contains(says), "{parameters:?} => {error}");
        }
        let mut no_tokens = request(&[("prefix", "a")]);
        no_tokens.attributes = r#"{"prefix": "a"}"#.to_owned();
        assert!(
            parse(&no_tokens, "ferritor")
                .err()
                .unwrap()
                .contains("tokenRequests")
        );
    }
}
