//! From a verified token's claims to a ferritor identity: an issuer's
//! mappings, tried in order. The first whose `require` holds decides; its
//! template, filled from claims, is the identity, or, if it doesn't fill,
//! the token gets none (never a later, broader mapping instead).
//!
//! A template's first segment is the issuer's name, literally, so an issuer
//! only ever names identities under it. Each claim fills a whole segment
//! (a `/` or the end on both sides), never part of one: claim values may
//! contain `-`, `.` and `_`, so two in one segment (`{ns}-{sa}`) would map
//! `a-b` + `c` and `a` + `b-c` to the same identity. Its value must be text
//! that fits in one segment: no `/`, so a claim can't add segments, and the
//! whole is then checked as a path, so it can't be `.` or `..`.

use std::collections::BTreeMap;

use ferritor_core::path::SecretPath;
use serde_json::{Map, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    Literal(String),
    /// A claim, by dotted path (`kubernetes.io.serviceaccount.name`).
    Claim(String),
}

/// `k8s-prod/{kubernetes.io.namespace}/{kubernetes.io.serviceaccount.name}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    parts: Vec<Part>,
}

/// One mapping: a template and the claims it requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub template: Template,
    /// Claims that must hold one of the listed values, by dotted path.
    pub require: Vec<(String, Vec<String>)>,
}

/// A token mapped to an identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapped {
    pub identity: SecretPath,
    /// Which mapping (from 0).
    pub mapping: usize,
    /// The claims the mapping read, with their values (for the audit log:
    /// they're what made the identity, never secret).
    pub claims: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MapError {
    #[error("no mapping of the issuer matches the token's claims")]
    NoMapping,
    #[error("claim {0} is missing, or not a string")]
    Missing(String),
    #[error("claim {0} doesn't fit in one path segment (letters, digits, '.', '_', '-')")]
    NotASegment(String),
    #[error("the mapped identity isn't a valid path")]
    InvalidIdentity,
}

fn segment_text(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl Template {
    /// Parses `template` for issuer `issuer`: its first segment must be
    /// the issuer's name, literally, followed by at least one more.
    pub fn parse(template: &str, issuer: &str) -> Result<Self, String> {
        let mut parts = Vec::new();
        let mut rest = template;
        while !rest.is_empty() {
            match rest.find('{') {
                None => {
                    parts.push(Part::Literal(rest.to_owned()));
                    break;
                }
                Some(open) => {
                    if open > 0 {
                        parts.push(Part::Literal(rest[..open].to_owned()));
                    }
                    let after = &rest[open + 1..];
                    let close = after
                        .find('}')
                        .ok_or_else(|| format!("{template:?}: a '{{' without '}}'"))?;
                    let claim = &after[..close];
                    let valid = !claim.is_empty()
                        && claim.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':')
                        });
                    if !valid {
                        return Err(format!("{template:?}: claim name {claim:?}"));
                    }
                    parts.push(Part::Claim(claim.to_owned()));
                    rest = &after[close + 1..];
                }
            }
        }
        if parts
            .iter()
            .any(|p| matches!(p, Part::Literal(l) if l.contains('}')))
        {
            return Err(format!("{template:?}: a '}}' without '{{'"));
        }
        // The issuer's name, then a '/', literally.
        let prefix = format!("{issuer}/");
        match parts.first() {
            Some(Part::Literal(first)) if first.starts_with(&prefix) => {}
            _ => {
                return Err(format!(
                    "{template:?}: must start with the issuer's name and a '/' ({prefix:?}), \
                     literally: an issuer names identities under its own prefix only"
                ));
            }
        }
        // Each claim a whole segment: a '/' (or the start, which the prefix
        // rules out) before it and a '/' or the end after it.
        for (i, part) in parts.iter().enumerate() {
            let Part::Claim(claim) = part else { continue };
            let after_slash =
                matches!(parts.get(i.wrapping_sub(1)), Some(Part::Literal(l)) if l.ends_with('/'));
            let before_slash = match parts.get(i + 1) {
                None => true,
                Some(Part::Literal(l)) => l.starts_with('/'),
                Some(Part::Claim(_)) => false,
            };
            if !after_slash || !before_slash {
                return Err(format!(
                    "{template:?}: claim {claim:?} must fill a whole segment (a '/' or the end \
                     on both sides): sharing one with another claim or text, two different \
                     tokens could map to the same identity"
                ));
            }
        }
        let template = Self { parts };
        // Every literal must make a valid path with placeholder values.
        let sample: String = template
            .parts
            .iter()
            .map(|p| match p {
                Part::Literal(l) => l.as_str(),
                Part::Claim(_) => "x",
            })
            .collect();
        let path = SecretPath::parse(&sample)
            .map_err(|e| format!("{template_str:?}: not a path: {e}", template_str = sample))?;
        if !path.as_str().contains('/') {
            return Err(format!(
                "{sample:?}: needs a segment after the issuer's name"
            ));
        }
        Ok(template)
    }
}

/// A claim by dotted path, as text. Claim names may contain dots
/// themselves (`kubernetes.io`), so at each level the longest key that
/// matches the path's next dotted pieces is taken.
pub fn claim<'a>(claims: &'a Map<String, Value>, path: &str) -> Option<&'a str> {
    let pieces: Vec<&str> = path.split('.').collect();
    let mut object = claims;
    let mut at = 0;
    loop {
        let found = (at + 1..=pieces.len())
            .rev()
            .find_map(|end| object.get(&pieces[at..end].join(".")).map(|v| (end, v)));
        let (end, value) = found?;
        if end == pieces.len() {
            return value.as_str();
        }
        object = value.as_object()?;
        at = end;
    }
}

/// Maps `claims` by `mappings`, in order.
pub fn map(mappings: &[Mapping], claims: &Map<String, Value>) -> Result<Mapped, MapError> {
    let (index, mapping) = mappings
        .iter()
        .enumerate()
        .find(|(_, mapping)| {
            mapping.require.iter().all(|(name, allowed)| {
                claim(claims, name).is_some_and(|value| allowed.iter().any(|a| a == value))
            })
        })
        .ok_or(MapError::NoMapping)?;
    let mut used = BTreeMap::new();
    for (name, _) in &mapping.require {
        if let Some(value) = claim(claims, name) {
            used.insert(name.clone(), value.to_owned());
        }
    }
    let mut identity = String::new();
    for part in &mapping.template.parts {
        match part {
            Part::Literal(literal) => identity.push_str(literal),
            Part::Claim(name) => {
                let value = claim(claims, name).ok_or_else(|| MapError::Missing(name.clone()))?;
                if !segment_text(value) {
                    return Err(MapError::NotASegment(name.clone()));
                }
                identity.push_str(value);
                used.insert(name.clone(), value.to_owned());
            }
        }
    }
    let identity = SecretPath::parse(&identity).map_err(|_| MapError::InvalidIdentity)?;
    Ok(Mapped {
        identity,
        mapping: index,
        claims: used,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn claims() -> Map<String, Value> {
        match json!({
            "sub": "system:serviceaccount:billing:api",
            "kubernetes.io": {"namespace": "billing", "serviceaccount": {"name": "api"}},
            "repository": "acme/shop",
            "repository_owner": "acme",
            "dots": "..",
            "dot": ".",
            "number": 7,
        }) {
            Value::Object(object) => object,
            _ => unreachable!(),
        }
    }

    fn mapping(template: &str, require: &[(&str, &[&str])]) -> Mapping {
        Mapping {
            template: Template::parse(template, "k8s").unwrap(),
            require: require
                .iter()
                .map(|(name, values)| {
                    (
                        (*name).to_owned(),
                        values.iter().map(|v| (*v).to_owned()).collect(),
                    )
                })
                .collect(),
        }
    }

    /// Claims by dotted path, through keys with dots in them.
    #[test]
    fn claims_are_found_by_dotted_path() {
        let claims = claims();
        assert_eq!(claim(&claims, "kubernetes.io.namespace"), Some("billing"));
        assert_eq!(
            claim(&claims, "kubernetes.io.serviceaccount.name"),
            Some("api")
        );
        assert_eq!(
            claim(&claims, "sub"),
            Some("system:serviceaccount:billing:api")
        );
        assert_eq!(
            claim(&claims, "kubernetes.io"),
            None,
            "an object isn't text"
        );
        assert_eq!(claim(&claims, "number"), None, "a number isn't text");
        assert_eq!(claim(&claims, "kubernetes.io.missing"), None);
    }

    /// The Kubernetes mapping: namespace and service account.
    #[test]
    fn a_kubernetes_token_maps_to_namespace_and_service_account() {
        let mappings = [mapping(
            "k8s/{kubernetes.io.namespace}/{kubernetes.io.serviceaccount.name}",
            &[("kubernetes.io.namespace", &["billing", "shop"])],
        )];
        let mapped = map(&mappings, &claims()).unwrap();
        assert_eq!(mapped.identity.as_str(), "k8s/billing/api");
        assert_eq!(mapped.mapping, 0);
        assert_eq!(
            mapped.claims.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "kubernetes.io.namespace",
                "kubernetes.io.serviceaccount.name"
            ]
        );
    }

    /// The first mapping whose requirements hold decides; none: no
    /// identity; its template not filling: no identity, never a later one.
    #[test]
    fn the_first_matching_mapping_decides() {
        let narrow = mapping(
            "k8s/billing/{kubernetes.io.serviceaccount.name}",
            &[("kubernetes.io.namespace", &["billing"])],
        );
        let other = mapping(
            "k8s/other/{sub}",
            &[("kubernetes.io.namespace", &["other"])],
        );
        assert_eq!(
            map(&[other.clone(), narrow.clone()], &claims())
                .unwrap()
                .mapping,
            1
        );
        assert_eq!(map(&[other], &claims()), Err(MapError::NoMapping));
        // Matches, but `sub` has ':' in it: refused, not passed to the next.
        let broken = mapping("k8s/x/{sub}", &[("kubernetes.io.namespace", &["billing"])]);
        assert_eq!(
            map(&[broken, narrow], &claims()),
            Err(MapError::NotASegment("sub".to_owned()))
        );
    }

    /// A claim's value stays in its segment: a '/' (which would add segments),
    /// '.' and '..' (which would climb), a missing claim: no identity.
    #[test]
    fn a_claim_cannot_add_segments_or_climb() {
        for (template, error) in [
            (
                "k8s/{repository}",
                MapError::NotASegment("repository".to_owned()),
            ),
            ("k8s/{dots}/x", MapError::InvalidIdentity),
            ("k8s/{dot}", MapError::InvalidIdentity),
            ("k8s/{missing}", MapError::Missing("missing".to_owned())),
            ("k8s/{number}", MapError::Missing("number".to_owned())),
        ] {
            assert_eq!(
                map(&[mapping(template, &[])], &claims()),
                Err(error),
                "{template}"
            );
        }
    }

    /// A claim fills a whole segment, never part of one: `{ns}-{sa}` would
    /// map namespace `a-b` with account `c`, and `a` with `b-c`, to the same
    /// `k8s/a-b-c`, one identity for two tenants. Text next to a claim is
    /// refused too: the rule is "a claim is a segment".
    #[test]
    fn a_claim_is_a_whole_segment() {
        for template in [
            "k8s/{kubernetes.io.namespace}-{kubernetes.io.serviceaccount.name}",
            "k8s/{a}{b}",
            "k8s/{repository_owner}-deploy",
            "k8s/deploy-{repository_owner}",
            "k8s/x{sub}/y",
        ] {
            let refused = Template::parse(template, "k8s").unwrap_err();
            assert!(refused.contains("whole segment"), "{template}: {refused}");
        }
        for template in [
            "k8s/{kubernetes.io.namespace}/{kubernetes.io.serviceaccount.name}",
            "k8s/{sub}/deploy",
            "k8s/ci/{sub}",
        ] {
            assert!(Template::parse(template, "k8s").is_ok(), "{template}");
        }
    }

    /// Templates must start with the issuer's own name, literally, and
    /// have a segment after it.
    #[test]
    fn templates_stay_under_their_issuers_prefix() {
        for template in [
            "{sub}/x",
            "ops/{sub}",
            "k8sx/{sub}",
            "k8s",
            "k8s/",
            "k8s/{a",
            "k8s/a}",
            "k8s/{}",
            "k8s/{a/b}",
            "k8s//{sub}",
            "/k8s/{sub}",
        ] {
            assert!(Template::parse(template, "k8s").is_err(), "{template}");
        }
        assert!(Template::parse("k8s/{sub}", "k8s").is_ok());
        assert!(Template::parse("k8s/fixed", "k8s").is_ok());
    }
}
