//! A token issuer for the workload-identity tests: an Ed25519 key, its
//! JWKS in a file, and tokens it signs (`EdDSA`, kid `k1`).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::TestResult;

/// The `iss` of every token.
pub const ISS: &str = "https://ci.example";
/// Their `aud`.
pub const AUDIENCE: &str = "ferritor";

pub struct TokenIssuer {
    key: Ed25519KeyPair,
    /// Its JWKS, removed on drop.
    pub jwks: PathBuf,
}

impl TokenIssuer {
    /// A new key, its JWKS written in `dir`.
    pub fn new(dir: &Path) -> TestResult<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| e.to_string())?;
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|e| e.to_string())?;
        let jwks = dir.join(format!(
            "ferritor-jwks-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let set = json!({"keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": "k1",
            "x": URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
        }]});
        std::fs::write(&jwks, serde_json::to_vec(&set)?)?;
        Ok(Self { key, jwks })
    }

    /// A token with `claims` on top of valid `iss`, `aud`, `iat` and `exp`
    /// (ten minutes).
    pub fn token(&self, claims: &Value) -> TestResult<String> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut body = json!({"iss": ISS, "aud": AUDIENCE, "iat": now, "exp": now + 600});
        if let (Some(body), Some(extra)) = (body.as_object_mut(), claims.as_object()) {
            body.extend(extra.clone());
        }
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"k1","typ":"JWT"}"#);
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&body)?);
        let signing = format!("{header}.{body}");
        let signature = URL_SAFE_NO_PAD.encode(self.key.sign(signing.as_bytes()).as_ref());
        Ok(format!("{signing}.{signature}"))
    }
}

impl Drop for TokenIssuer {
    fn drop(&mut self) {
        std::fs::remove_file(&self.jwks).ok();
    }
}
