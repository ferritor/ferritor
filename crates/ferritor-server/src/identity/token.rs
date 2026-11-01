//! Verifying a platform token: a JWT in JWS compact form (RFC 7515, 7519),
//! signed by one of the configured issuers.
//!
//! In this order, and nothing trusted before its step: the issuer is picked
//! by the token's `iss`; the signature is checked with the key the header
//! names, among that issuer's keys only, and only with the algorithm the
//! key's type allows (`jwk`); then the claims: `aud` names this issuer's
//! audience for ferritor, `exp` is ahead, `nbf` and `iat` aren't, and the token
//! is no older than the issuer allows. Clocks may differ by [`SKEW`].

use std::time::Duration;

use base64::Engine as _;
use serde_json::{Map, Value};

use super::jwk::{Algorithm, BASE64URL, Jwks};

/// How far the issuer's clock and ours may differ, either way.
pub const SKEW: i64 = 30;
/// The largest token accepted (Kubernetes' are about a kilobyte).
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// What a token is checked against: one issuer's identity and its keys.
pub struct IssuerKeys<'a> {
    /// The `iss` its tokens carry, exactly.
    pub iss: &'a str,
    /// What `aud` must contain: the audience its tokens for ferritor are
    /// minted with.
    pub audience: &'a str,
    /// The oldest a token may be (by `iat`), whatever its `exp`.
    pub max_age: Duration,
    pub keys: &'a Jwks,
}

/// A verified token.
#[derive(Clone, Debug, PartialEq)]
pub struct Verified {
    /// Which of the issuers signed it.
    pub issuer: usize,
    /// `exp` and `iat`, unix seconds.
    pub expires: i64,
    pub issued: i64,
    /// Every claim, for the mapping.
    pub claims: Map<String, Value>,
}

/// Why a token was refused. Never carries the token, nor a claim's value.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("not a JWT: {0}")]
    Malformed(&'static str),
    #[error("signature algorithm {0:?} isn't accepted (RS256, ES256, EdDSA)")]
    Algorithm(String),
    #[error("the token has critical header parameters, which ferritor doesn't understand")]
    Critical,
    #[error("no configured issuer has this token's iss")]
    UnknownIssuer,
    /// `issuer`: which (from 0), whose keys may need fetching again.
    #[error("the issuer has no key matching the token's kid")]
    UnknownKey { issuer: usize },
    #[error("the token says {alg}, but the key it names is for {key}")]
    KeyMismatch {
        alg: &'static str,
        key: &'static str,
    },
    #[error("the signature doesn't verify")]
    Signature,
    #[error("the token isn't for ferritor (its aud lacks the issuer's audience)")]
    Audience,
    #[error("the token has expired")]
    Expired,
    #[error("the token isn't valid yet (nbf)")]
    NotYetValid,
    #[error("the token claims to be issued in the future (iat)")]
    IssuedInFuture,
    #[error("the token is older than the issuer allows (iat)")]
    TooOld,
    #[error("the token lacks {0}")]
    Missing(&'static str),
}

fn decode_json(part: &str, what: &'static str) -> Result<Map<String, Value>, TokenError> {
    let bytes = BASE64URL
        .decode(part)
        .map_err(|_| TokenError::Malformed(what))?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(object)) => Ok(object),
        _ => Err(TokenError::Malformed(what)),
    }
}

/// A NumericDate claim: integer seconds (fractions aren't used by the
/// issuers ferritor knows, and refusing them keeps the arithmetic exact).
fn seconds(claims: &Map<String, Value>, name: &'static str) -> Result<Option<i64>, TokenError> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or(TokenError::Malformed("a time claim isn't whole seconds")),
    }
}

/// Verifies `token` against `issuers` at `now` (unix seconds).
pub fn verify(token: &str, issuers: &[IssuerKeys<'_>], now: i64) -> Result<Verified, TokenError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::Malformed("too large"));
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TokenError::Malformed("not three dot-separated parts"));
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(TokenError::Malformed("an empty part"));
    }
    let header_fields = decode_json(header, "the header isn't base64url JSON")?;
    let alg = match header_fields.get("alg") {
        Some(Value::String(alg)) => {
            Algorithm::parse(alg).ok_or_else(|| TokenError::Algorithm(alg.clone()))?
        }
        _ => return Err(TokenError::Missing("an alg header")),
    };
    if header_fields.contains_key("crit") {
        return Err(TokenError::Critical);
    }
    let kid = match header_fields.get("kid") {
        None => None,
        Some(Value::String(kid)) => Some(kid.as_str()),
        Some(_) => return Err(TokenError::Malformed("kid isn't a string")),
    };
    let claims = decode_json(payload, "the payload isn't base64url JSON")?;

    // The issuer, by `iss`; the key, among that issuer's only.
    let iss = match claims.get("iss") {
        Some(Value::String(iss)) => iss,
        _ => return Err(TokenError::Missing("iss")),
    };
    let (index, issuer) = issuers
        .iter()
        .enumerate()
        .find(|(_, issuer)| issuer.iss == iss)
        .ok_or(TokenError::UnknownIssuer)?;
    let key = issuer
        .keys
        .key(kid)
        .ok_or(TokenError::UnknownKey { issuer: index })?;
    if key.algorithm() != alg {
        return Err(TokenError::KeyMismatch {
            alg: alg.name(),
            key: key.algorithm().name(),
        });
    }
    let signature = BASE64URL
        .decode(signature)
        .map_err(|_| TokenError::Malformed("the signature isn't base64url"))?;
    let signed = &token[..header.len() + 1 + payload.len()];
    if !key.verifies(signed.as_bytes(), &signature) {
        return Err(TokenError::Signature);
    }

    // Only now are the claims the issuer's.
    let for_ferritor = match claims.get("aud") {
        Some(Value::String(aud)) => aud == issuer.audience,
        Some(Value::Array(auds)) => auds.iter().any(|aud| aud.as_str() == Some(issuer.audience)),
        _ => false,
    };
    if !for_ferritor {
        return Err(TokenError::Audience);
    }
    let expires = seconds(&claims, "exp")?.ok_or(TokenError::Missing("exp"))?;
    if now >= expires.saturating_add(SKEW) {
        return Err(TokenError::Expired);
    }
    if let Some(not_before) = seconds(&claims, "nbf")?
        && now.saturating_add(SKEW) < not_before
    {
        return Err(TokenError::NotYetValid);
    }
    let issued = seconds(&claims, "iat")?.ok_or(TokenError::Missing("iat"))?;
    if issued > now.saturating_add(SKEW) {
        return Err(TokenError::IssuedInFuture);
    }
    let max_age = i64::try_from(issuer.max_age.as_secs()).unwrap_or(i64::MAX);
    if now.saturating_sub(issued) > max_age {
        return Err(TokenError::TooOld);
    }
    Ok(Verified {
        issuer: index,
        expires,
        issued,
        claims,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::json;

    use super::super::jwk::tests::TestKey;
    use super::*;

    pub(crate) const ISS: &str = "https://kubernetes.default.svc.cluster.local";
    pub(crate) const NOW: i64 = 1_800_000_000;

    /// A token with `header` and `claims`, signed by `key` (the header's
    /// `alg` as given, so tests can lie in it).
    pub(crate) fn token(key: &TestKey, header: &Value, claims: &Value) -> String {
        let b64 = |v: &Value| BASE64URL.encode(serde_json::to_vec(v).unwrap());
        let signing = format!("{}.{}", b64(header), b64(claims));
        let signing = signing.replace('=', "");
        let signature = BASE64URL.encode(key.sign(signing.as_bytes()));
        format!("{signing}.{}", signature.trim_end_matches('='))
    }

    pub(crate) fn claims() -> Value {
        json!({
            "iss": ISS,
            "aud": ["ferritor"],
            "exp": NOW + 3600,
            "iat": NOW - 60,
            "nbf": NOW - 60,
            "sub": "system:serviceaccount:billing:api",
            "kubernetes.io": {"namespace": "billing", "serviceaccount": {"name": "api"}},
        })
    }

    pub(crate) fn header(key: &TestKey, kid: &str) -> Value {
        json!({"alg": key.alg(), "kid": kid, "typ": "JWT"})
    }

    fn jwks(keys: &[(&TestKey, &str)]) -> Jwks {
        let keys: Vec<Value> = keys.iter().map(|(key, kid)| key.jwk(kid)).collect();
        Jwks::parse(&serde_json::to_vec(&json!({ "keys": keys })).unwrap()).unwrap()
    }

    fn issuer(keys: &Jwks) -> IssuerKeys<'_> {
        IssuerKeys {
            iss: ISS,
            audience: "ferritor",
            max_age: Duration::from_secs(3600),
            keys,
        }
    }

    fn check(token: &str, keys: &Jwks, now: i64) -> Result<Verified, TokenError> {
        verify(token, &[issuer(keys)], now)
    }

    /// A token from each key type verifies, and gives its claims.
    #[test]
    fn a_good_token_from_each_key_type_verifies() {
        for key in [TestKey::rsa(), TestKey::p256(), TestKey::ed25519()] {
            let keys = jwks(&[(&key, "k1")]);
            let verified = check(&token(&key, &header(&key, "k1"), &claims()), &keys, NOW)
                .unwrap_or_else(|e| panic!("{}: {e}", key.alg()));
            assert_eq!(verified.issuer, 0);
            assert_eq!(verified.expires, NOW + 3600);
            assert_eq!(verified.claims["sub"], "system:serviceaccount:billing:api");
        }
    }

    /// The signature: tampering with any part, another key, another
    /// issuer's key, an unknown kid: refused.
    #[test]
    fn a_signature_must_be_the_issuers() {
        let key = TestKey::p256();
        let other = TestKey::p256();
        let keys = jwks(&[(&key, "k1")]);
        let good = token(&key, &header(&key, "k1"), &claims());

        let mut tampered_claims = claims();
        tampered_claims["kubernetes.io"]["namespace"] = "admin".into();
        let b64 = |v: &Value| {
            BASE64URL
                .encode(serde_json::to_vec(v).unwrap())
                .replace('=', "")
        };
        let parts: Vec<&str> = good.split('.').collect();
        let swapped = format!("{}.{}.{}", parts[0], b64(&tampered_claims), parts[2]);
        assert_eq!(check(&swapped, &keys, NOW), Err(TokenError::Signature));

        let by_other = token(&other, &header(&other, "k1"), &claims());
        assert_eq!(check(&by_other, &keys, NOW), Err(TokenError::Signature));
        let unknown_kid = token(&key, &header(&key, "k2"), &claims());
        assert_eq!(
            check(&unknown_kid, &keys, NOW),
            Err(TokenError::UnknownKey { issuer: 0 })
        );

        // Signed by a key of another issuer, with that issuer's iss swapped
        // for ours: the key isn't among ours.
        let elsewhere = jwks(&[(&other, "k9")]);
        let theirs = token(&other, &header(&other, "k9"), &claims());
        assert_eq!(
            check(&theirs, &keys, NOW),
            Err(TokenError::UnknownKey { issuer: 0 })
        );
        assert!(check(&theirs, &elsewhere, NOW).is_ok());
    }

    /// The algorithm is the key's, never the token's choice: `none`, HMAC
    /// (with the public key as its secret, the classic confusion), and an
    /// algorithm that doesn't fit the key are refused before anything is
    /// verified.
    #[test]
    fn the_algorithm_is_the_keys_not_the_tokens() {
        let rsa = TestKey::rsa();
        let ed = TestKey::ed25519();
        let keys = jwks(&[(&rsa, "rsa"), (&ed, "ed")]);
        for alg in ["none", "HS256", "RS384", "PS256", "ES384"] {
            let header = json!({"alg": alg, "kid": "rsa"});
            let refused = check(&token(&rsa, &header, &claims()), &keys, NOW);
            assert_eq!(refused, Err(TokenError::Algorithm(alg.to_owned())), "{alg}");
        }
        // `none` with an empty signature: not even three non-empty parts.
        let b64 = |v: &Value| {
            BASE64URL
                .encode(serde_json::to_vec(v).unwrap())
                .replace('=', "")
        };
        let unsigned = format!("{}.{}.", b64(&json!({"alg": "none"})), b64(&claims()));
        assert!(matches!(
            check(&unsigned, &keys, NOW),
            Err(TokenError::Malformed(_))
        ));
        // An Ed25519 signature claiming RS256 on the Ed25519 key's kid.
        let lying = token(&ed, &json!({"alg": "RS256", "kid": "ed"}), &claims());
        assert_eq!(
            check(&lying, &keys, NOW),
            Err(TokenError::KeyMismatch {
                alg: "RS256",
                key: "EdDSA"
            })
        );
        let critical = token(
            &rsa,
            &json!({"alg": "RS256", "kid": "rsa", "crit": ["exp"]}),
            &claims(),
        );
        assert_eq!(check(&critical, &keys, NOW), Err(TokenError::Critical));
        // Several keys: a token without kid names none of them.
        let no_kid = token(&rsa, &json!({"alg": "RS256"}), &claims());
        assert_eq!(
            check(&no_kid, &keys, NOW),
            Err(TokenError::UnknownKey { issuer: 0 })
        );
    }

    /// The claims, each against its rule, with the skew either way.
    #[test]
    fn the_claims_are_checked_with_the_skew() {
        let key = TestKey::ed25519();
        let keys = jwks(&[(&key, "k1")]);
        let with = |change: &dyn Fn(&mut Value)| {
            let mut claims = claims();
            change(&mut claims);
            token(&key, &header(&key, "k1"), &claims)
        };
        let cases: Vec<(String, Result<(), TokenError>)> = vec![
            (with(&|c| c["aud"] = "ferritor".into()), Ok(())),
            (
                with(&|c| c["aud"] = json!(["vault", "other"])),
                Err(TokenError::Audience),
            ),
            (
                with(&|c| {
                    c.as_object_mut().unwrap().remove("aud");
                }),
                Err(TokenError::Audience),
            ),
            (
                with(&|c| c["iss"] = "https://elsewhere".into()),
                Err(TokenError::UnknownIssuer),
            ),
            (
                with(&|c| c["exp"] = (NOW - SKEW).into()),
                Err(TokenError::Expired),
            ),
            (with(&|c| c["exp"] = (NOW - SKEW + 1).into()), Ok(())),
            (
                with(&|c| {
                    c.as_object_mut().unwrap().remove("exp");
                }),
                Err(TokenError::Missing("exp")),
            ),
            (
                with(&|c| c["exp"] = 1.5e9.into()),
                Err(TokenError::Malformed("a time claim isn't whole seconds")),
            ),
            (
                with(&|c| c["nbf"] = (NOW + SKEW + 1).into()),
                Err(TokenError::NotYetValid),
            ),
            (with(&|c| c["nbf"] = (NOW + SKEW).into()), Ok(())),
            (
                with(&|c| c["iat"] = (NOW + SKEW + 1).into()),
                Err(TokenError::IssuedInFuture),
            ),
            (
                with(&|c| c["iat"] = (NOW - 3601).into()),
                Err(TokenError::TooOld),
            ),
            (with(&|c| c["iat"] = (NOW - 3600).into()), Ok(())),
            (
                with(&|c| {
                    c.as_object_mut().unwrap().remove("iat");
                }),
                Err(TokenError::Missing("iat")),
            ),
        ];
        for (i, (token, expected)) in cases.into_iter().enumerate() {
            assert_eq!(check(&token, &keys, NOW).map(drop), expected, "case {i}");
        }
    }

    /// Shapes that aren't a JWT at all.
    #[test]
    fn malformed_tokens_are_refused() {
        let keys = jwks(&[(&TestKey::ed25519(), "k1")]);
        for token in ["", "a.b", "a.b.c.d", "!!.b.c", "e30.e30.AA"] {
            assert!(check(token, &keys, NOW).is_err(), "{token:?}");
        }
        let huge = "a".repeat(MAX_TOKEN_BYTES + 1);
        assert_eq!(
            check(&huge, &keys, NOW),
            Err(TokenError::Malformed("too large"))
        );
    }
}
