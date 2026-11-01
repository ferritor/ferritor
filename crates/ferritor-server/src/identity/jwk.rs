//! A token issuer's public keys (a JWKS, RFC 7517), and verifying a
//! signature with one of them. Each key is bound to the one algorithm its
//! type allows (RSA: RS256, P-256: ES256, Ed25519: EdDSA), so a token can't
//! choose how its signature is checked: an `alg` that doesn't fit the key
//! it names is refused, `none` and HMAC never fit anything.

use base64::Engine as _;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ED25519, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents,
    UnparsedPublicKey,
};
use serde::Deserialize;

/// The most keys a JWKS may hold, and its largest size: an issuer's set is
/// a handful of keys, rotated.
pub const MAX_KEYS: usize = 64;
pub const MAX_JWKS_BYTES: usize = 256 * 1024;

/// base64url, with or without padding (JWKs in the wild have both).
pub(crate) const BASE64URL: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// The signature algorithms a token may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Rs256,
    Es256,
    EdDsa,
}

impl Algorithm {
    /// The JOSE name (`alg`), if it's one of these; `none`, `HS256` and
    /// everything else are refused.
    pub fn parse(alg: &str) -> Option<Self> {
        Some(match alg {
            "RS256" => Self::Rs256,
            "ES256" => Self::Es256,
            "EdDSA" => Self::EdDsa,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum KeyMaterial {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// The uncompressed point: 0x04, x, y.
    P256(Vec<u8>),
    Ed25519(Vec<u8>),
}

/// One public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub kid: Option<String>,
    material: KeyMaterial,
}

impl Key {
    /// The one algorithm this key verifies.
    pub fn algorithm(&self) -> Algorithm {
        match self.material {
            KeyMaterial::Rsa { .. } => Algorithm::Rs256,
            KeyMaterial::P256(_) => Algorithm::Es256,
            KeyMaterial::Ed25519(_) => Algorithm::EdDsa,
        }
    }

    /// Whether `signature` is this key's over `message`.
    pub fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        match &self.material {
            KeyMaterial::Rsa { n, e } => RsaPublicKeyComponents { n, e }
                .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok(),
            KeyMaterial::P256(point) => UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                .verify(message, signature)
                .is_ok(),
            KeyMaterial::Ed25519(x) => UnparsedPublicKey::new(&ED25519, x)
                .verify(message, signature)
                .is_ok(),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JwksError {
    #[error("the key set is larger than {MAX_JWKS_BYTES} bytes")]
    TooLarge,
    #[error("the key set isn't a JWKS (a JSON object with \"keys\"): {0}")]
    Malformed(String),
    #[error("the key set has more than {MAX_KEYS} keys")]
    TooManyKeys,
    #[error("the key set has no key ferritor can use (RSA of 2048 bits or more, P-256, Ed25519)")]
    NoUsableKey,
    #[error("two keys share the kid {0:?}")]
    DuplicateKid(String),
    #[error("key {kid:?}: {reason}")]
    BadKey { kid: Option<String>, reason: String },
}

/// An issuer's keys.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Jwks {
    keys: Vec<Key>,
}

#[derive(Deserialize)]
struct RawJwks {
    keys: Vec<RawJwk>,
}

#[derive(Deserialize)]
struct RawJwk {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    alg: Option<String>,
    crv: Option<String>,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

fn field(raw: &RawJwk, name: &str, value: Option<&String>) -> Result<Vec<u8>, String> {
    let value = value.ok_or_else(|| format!("{} key without {name}", raw.kty))?;
    BASE64URL
        .decode(value)
        .map_err(|_| format!("{name} isn't base64url"))
}

impl Jwks {
    /// Parses a JWKS. Keys ferritor can't use (another type or curve, an
    /// encryption key, an `alg` that doesn't fit the key) are skipped, as
    /// an issuer may publish them for others; one that claims to be usable
    /// but is broken is an error, as is a set with no usable key.
    pub fn parse(bytes: &[u8]) -> Result<Self, JwksError> {
        if bytes.len() > MAX_JWKS_BYTES {
            return Err(JwksError::TooLarge);
        }
        let raw: RawJwks =
            serde_json::from_slice(bytes).map_err(|e| JwksError::Malformed(e.to_string()))?;
        if raw.keys.len() > MAX_KEYS {
            return Err(JwksError::TooManyKeys);
        }
        let mut keys: Vec<Key> = Vec::new();
        for raw in raw.keys {
            let Some(material) = material(&raw).map_err(|reason| JwksError::BadKey {
                kid: raw.kid.clone(),
                reason,
            })?
            else {
                continue;
            };
            let key = Key {
                kid: raw.kid.clone(),
                material,
            };
            if let Some(alg) = &raw.alg
                && Algorithm::parse(alg) != Some(key.algorithm())
            {
                // Published for another algorithm (`RS384`, say): not ours.
                continue;
            }
            if let Some(kid) = &key.kid
                && keys.iter().any(|k| k.kid.as_deref() == Some(kid))
            {
                return Err(JwksError::DuplicateKid(kid.clone()));
            }
            keys.push(key);
        }
        if keys.is_empty() {
            return Err(JwksError::NoUsableKey);
        }
        Ok(Self { keys })
    }

    /// The key a token's header names: by `kid`; without one, the only
    /// key there is (an issuer with several keys must say which).
    pub fn key(&self, kid: Option<&str>) -> Option<&Key> {
        match kid {
            Some(kid) => self.keys.iter().find(|k| k.kid.as_deref() == Some(kid)),
            None => match self.keys.as_slice() {
                [only] => Some(only),
                _ => None,
            },
        }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// A key's material, `None` for a key ferritor doesn't use.
fn material(raw: &RawJwk) -> Result<Option<KeyMaterial>, String> {
    if raw.usage.as_deref().is_some_and(|usage| usage != "sig") {
        return Ok(None);
    }
    Ok(Some(match (raw.kty.as_str(), raw.crv.as_deref()) {
        ("RSA", _) => {
            let n = field(raw, "n", raw.n.as_ref())?;
            let e = field(raw, "e", raw.e.as_ref())?;
            let n = n.strip_prefix(&[0][..]).unwrap_or(&n).to_vec();
            if n.len() * 8 < 2048 {
                return Err(format!("an RSA key of {} bits: at least 2048", n.len() * 8));
            }
            KeyMaterial::Rsa { n, e }
        }
        ("EC", Some("P-256")) => {
            let x = field(raw, "x", raw.x.as_ref())?;
            let y = field(raw, "y", raw.y.as_ref())?;
            if x.len() != 32 || y.len() != 32 {
                return Err("a P-256 key's x and y are 32 bytes each".to_owned());
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            KeyMaterial::P256(point)
        }
        ("OKP", Some("Ed25519")) => {
            let x = field(raw, "x", raw.x.as_ref())?;
            if x.len() != 32 {
                return Err("an Ed25519 key's x is 32 bytes".to_owned());
            }
            KeyMaterial::Ed25519(x)
        }
        _ => return Ok(None),
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _,
        RSA_PKCS1_SHA256, RsaKeyPair,
    };

    use super::*;

    /// A fixed 2048-bit RSA key for tests (ring can't generate RSA keys);
    /// test-only, used nowhere else.
    const RSA_PKCS8: &[u8] = include_bytes!("../../tests/fixtures/jwt-test-rsa.pk8");

    /// A key pair for tests: its JWK, and signing.
    pub(crate) enum TestKey {
        Rsa(RsaKeyPair),
        P256(EcdsaKeyPair),
        Ed25519(Ed25519KeyPair),
    }

    impl TestKey {
        pub(crate) fn rsa() -> Self {
            Self::Rsa(RsaKeyPair::from_pkcs8(RSA_PKCS8).unwrap())
        }

        pub(crate) fn p256() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            Self::P256(
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap(),
            )
        }

        pub(crate) fn ed25519() -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Self::Ed25519(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
        }

        pub(crate) fn alg(&self) -> &'static str {
            match self {
                Self::Rsa(_) => "RS256",
                Self::P256(_) => "ES256",
                Self::Ed25519(_) => "EdDSA",
            }
        }

        /// The public key as a JWK.
        pub(crate) fn jwk(&self, kid: &str) -> serde_json::Value {
            let b64 = |bytes: &[u8]| BASE64URL.encode(bytes).trim_end_matches('=').to_owned();
            match self {
                Self::Rsa(pair) => {
                    let public = ring::rsa::PublicKeyComponents::<Vec<u8>>::from(pair.public());
                    serde_json::json!({
                        "kty": "RSA", "kid": kid, "use": "sig",
                        "n": b64(&public.n),
                        "e": b64(&public.e),
                    })
                }
                Self::P256(pair) => {
                    let point = pair.public_key().as_ref();
                    serde_json::json!({
                        "kty": "EC", "crv": "P-256", "kid": kid,
                        "x": b64(&point[1..33]), "y": b64(&point[33..65]),
                    })
                }
                Self::Ed25519(pair) => serde_json::json!({
                    "kty": "OKP", "crv": "Ed25519", "kid": kid,
                    "x": b64(pair.public_key().as_ref()),
                }),
            }
        }

        pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
            let rng = SystemRandom::new();
            match self {
                Self::Rsa(pair) => {
                    let mut signature = vec![0; pair.public().modulus_len()];
                    pair.sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature)
                        .unwrap();
                    signature
                }
                Self::P256(pair) => pair.sign(&rng, message).unwrap().as_ref().to_vec(),
                Self::Ed25519(pair) => pair.sign(message).as_ref().to_vec(),
            }
        }
    }

    fn jwks(keys: &[serde_json::Value]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "keys": keys })).unwrap()
    }

    /// Each key type verifies its own signatures, and only with its own
    /// algorithm; a signature by another key doesn't verify.
    #[test]
    fn each_key_verifies_its_own_signatures_only() {
        let keys = [TestKey::rsa(), TestKey::p256(), TestKey::ed25519()];
        let set = Jwks::parse(&jwks(&[
            keys[0].jwk("rsa"),
            keys[1].jwk("ec"),
            keys[2].jwk("ed"),
        ]))
        .unwrap();
        assert_eq!(set.len(), 3);
        for (key, kid) in keys.iter().zip(["rsa", "ec", "ed"]) {
            let public = set.key(Some(kid)).unwrap();
            assert_eq!(public.algorithm().name(), key.alg());
            assert!(public.verifies(b"message", &key.sign(b"message")));
            assert!(!public.verifies(b"other message", &key.sign(b"message")));
        }
        let ec = set.key(Some("ec")).unwrap();
        assert!(!ec.verifies(b"message", &keys[2].sign(b"message")));
        // Several keys: a kid is needed.
        assert!(set.key(None).is_none());
        assert!(set.key(Some("missing")).is_none());
    }

    /// Keys for other uses or algorithms are skipped; broken ones, too few
    /// RSA bits, duplicate kids and a set with nothing usable are refused.
    #[test]
    fn unusable_keys_are_skipped_and_broken_ones_refused() {
        let ed = TestKey::ed25519();
        let only = Jwks::parse(&jwks(&[
            serde_json::json!({"kty": "oct", "k": "c2VjcmV0"}),
            serde_json::json!({"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"}),
            serde_json::json!({"kty": "RSA", "use": "enc", "n": "AQAB", "e": "AQAB"}),
            {
                let mut jwk = TestKey::rsa().jwk("rs384");
                jwk["alg"] = "RS384".into();
                jwk
            },
            ed.jwk("ed"),
        ]))
        .unwrap();
        assert_eq!(only.len(), 1);
        // One key: it's used without a kid.
        assert!(only.key(None).is_some());

        assert_eq!(
            Jwks::parse(&jwks(&[serde_json::json!({"kty": "oct", "k": "c2VjcmV0"})])),
            Err(JwksError::NoUsableKey)
        );
        assert_eq!(
            Jwks::parse(&jwks(&[ed.jwk("same"), TestKey::p256().jwk("same")])),
            Err(JwksError::DuplicateKid("same".to_owned()))
        );
        let small =
            serde_json::json!({"kty": "RSA", "n": BASE64URL.encode([0xff; 128]), "e": "AQAB"});
        assert!(matches!(
            Jwks::parse(&jwks(&[small])),
            Err(JwksError::BadKey { .. })
        ));
        let short = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "AAAA"});
        assert!(matches!(
            Jwks::parse(&jwks(&[short])),
            Err(JwksError::BadKey { .. })
        ));
        assert!(matches!(Jwks::parse(b"[]"), Err(JwksError::Malformed(_))));
        assert_eq!(
            Jwks::parse(&vec![b' '; MAX_JWKS_BYTES + 1]),
            Err(JwksError::TooLarge)
        );
    }
}
