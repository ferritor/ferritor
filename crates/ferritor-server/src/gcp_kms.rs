//! Auto-unseal with Google Cloud KMS ([`GcpKms`], the `gcp-kms` feature): the
//! root key wrapped by `encrypt` under the configured key, unwrapped by
//! `decrypt` on that key (Cloud KMS finds the version from the ciphertext,
//! and refuses one of another key), both bound to the generation by the
//! additional authenticated data, [`aad`]. Unlike AWS's encryption context,
//! the AAD isn't logged, and IAM can't require it: it binds a wrap to its
//! generation, but can't narrow what the key may be used for.
//!
//! Credentials come from Google's Application Default Credentials (GKE
//! Workload Identity, a VM's service account, `GOOGLE_APPLICATION_CREDENTIALS`,
//! `gcloud auth application-default login` with or without impersonation),
//! never from ferritor's config. The two calls go over KMS's REST API with
//! reqwest, on rustls with ring, as the rest of ferritor. Each call ends
//! within [`CALL_TIMEOUT`], its retries (at most [`MAX_ATTEMPTS`]) included,
//! so the backoff between start attempts stays ferritor's.
//!
//! Cloud KMS has no aliases: the configured resource name is the key, so
//! [`AutoUnseal::key_id`] makes no call (and the server's role needs no
//! permission to read the key's metadata).

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use axum::http::Extensions;
use axum::http::header::CONTENT_TYPE;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use ferritor_core::crypto::RootKey;
use google_cloud_auth::credentials::{CacheableResource, Credentials};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::auto_unseal::{AutoUnseal, AutoUnsealError, GCP_KMS, GcpKmsConfig, Wrapped};

/// The longest one call may take, attempts included.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// Attempts per call: the first and one retry.
pub const MAX_ATTEMPTS: u32 = 2;
/// The pause before the retry, so a throttled call isn't retried at once.
pub const RETRY_PAUSE: Duration = Duration::from_millis(200);
/// Cloud KMS's public endpoint, unless the config names another.
pub const DEFAULT_ENDPOINT: &str = "https://cloudkms.googleapis.com";
/// The OAuth scope the access tokens are asked for.
const SCOPE: &str = "https://www.googleapis.com/auth/cloudkms";

type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Where a [`GcpKms`] gets its credentials: tried at each attempt until it
/// gives some, its error text then a `Denied` attempt.
pub type CredentialsSource = Box<dyn Fn() -> Result<Credentials, String> + Send + Sync>;

/// Why a [`GcpKms`] couldn't be made (at startup).
#[derive(Debug, thiserror::Error)]
pub enum GcpKmsError {
    #[error("building the HTTP client")]
    Http(#[source] reqwest::Error),
}

/// See the module docs.
pub struct GcpKms {
    http: reqwest::Client,
    source: CredentialsSource,
    /// Once the source gave them: kept, they refresh their own tokens.
    credentials: Mutex<Option<Credentials>>,
    /// As configured: every call names it.
    key_name: String,
    /// Without a trailing `/`.
    endpoint: String,
}

impl GcpKms {
    /// A client for `config`'s key, with Application Default Credentials.
    /// Nothing is read or called yet: credentials are loaded at the first
    /// attempt, so a credentials file that's missing or unreadable (a
    /// secret mounted late) is that attempt's `denied`, looked at again,
    /// never a server that won't start (the shares still unseal it).
    pub fn new(config: &GcpKmsConfig) -> Result<Self, GcpKmsError> {
        Self::with_credentials(
            config,
            Box::new(|| {
                google_cloud_auth::credentials::Builder::default()
                    .with_scopes([SCOPE])
                    .build()
                    .map_err(|e| crate::error_chain(&e))
            }),
        )
    }

    /// With credentials from `source` (a test double's: anonymous).
    pub fn with_credentials(
        config: &GcpKmsConfig,
        source: CredentialsSource,
    ) -> Result<Self, GcpKmsError> {
        install_crypto_provider();
        let http = reqwest::Client::builder()
            .timeout(CALL_TIMEOUT / MAX_ATTEMPTS)
            .build()
            .map_err(GcpKmsError::Http)?;
        let endpoint = config
            .endpoint
            .as_deref()
            .unwrap_or(DEFAULT_ENDPOINT)
            .trim_end_matches('/')
            .to_owned();
        Ok(Self {
            http,
            source,
            credentials: Mutex::new(None),
            key_name: config.key_name.clone(),
            endpoint,
        })
    }

    /// The credentials, loaded from the source the first time it gives
    /// some.
    fn credentials(&self) -> Result<Credentials, AutoUnsealError> {
        let mut held = self
            .credentials
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(credentials) = held.as_ref() {
            return Ok(credentials.clone());
        }
        let credentials = (self.source)().map_err(|e| {
            AutoUnsealError::Denied(format!("loading Google Cloud credentials: {e}"))
        })?;
        *held = Some(credentials.clone());
        Ok(credentials)
    }

    /// One call, `method` (`encrypt`, `decrypt`) on the key with `body`
    /// (JSON), retried once after [`RETRY_PAUSE`] if the service was
    /// unavailable, all within [`CALL_TIMEOUT`].
    async fn call<T: DeserializeOwned>(
        &self,
        method: &'static str,
        body: Bytes,
    ) -> Result<T, AutoUnsealError> {
        let attempts = async {
            let mut last = String::new();
            for attempt in 0..MAX_ATTEMPTS {
                if attempt > 0 {
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
                match self.attempt(method, body.clone()).await {
                    Err(AutoUnsealError::Unavailable(error)) => last = error,
                    done => return done,
                }
            }
            Err(AutoUnsealError::Unavailable(last))
        };
        tokio::time::timeout(CALL_TIMEOUT, attempts)
            .await
            .unwrap_or_else(|_| {
                Err(AutoUnsealError::Unavailable(format!(
                    "Cloud KMS {method}: no answer within {CALL_TIMEOUT:?}"
                )))
            })
    }

    async fn attempt<T: DeserializeOwned>(
        &self,
        method: &'static str,
        body: Bytes,
    ) -> Result<T, AutoUnsealError> {
        let headers = match self.credentials()?.headers(Extensions::new()).await {
            Ok(CacheableResource::New { data, .. }) => data,
            Ok(CacheableResource::NotModified) => {
                return Err(AutoUnsealError::Unavailable(
                    "Google Cloud credentials answered without headers".to_owned(),
                ));
            }
            Err(e) => {
                let text = format!("Google Cloud credentials: {}", crate::error_chain(&e));
                return Err(if e.is_transient() {
                    AutoUnsealError::Unavailable(text)
                } else {
                    AutoUnsealError::Denied(text)
                });
            }
        };
        let url = format!("{}/v1/{}:{method}", self.endpoint, self.key_name);
        let unavailable = |e: reqwest::Error| {
            AutoUnsealError::Unavailable(format!("Cloud KMS {method}: {}", crate::error_chain(&e)))
        };
        let response = self
            .http
            .post(url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(unavailable)?;
        let status = response.status().as_u16();
        let answer = Zeroizing::new(response.bytes().await.map_err(unavailable)?.to_vec());
        if !(200..300).contains(&status) {
            return Err(classify(method, status, &answer));
        }
        serde_json::from_slice(&answer).map_err(|e| {
            AutoUnsealError::Unavailable(format!("Cloud KMS {method}: an unreadable answer: {e}"))
        })
    }
}

/// A request body of `fields` (names and base64 values, which JSON never
/// escapes), wiped when the last copy is dropped: the encrypt's carries
/// the root key. What hyper and rustls copy it into is theirs, and the
/// process is undumpable either way.
fn body(fields: &[(&str, &str)]) -> Bytes {
    let mut json = Zeroizing::new(Vec::with_capacity(
        fields
            .iter()
            .map(|(k, v)| k.len() + v.len() + 6)
            .sum::<usize>()
            + 2,
    ));
    json.push(b'{');
    for (i, (name, value)) in fields.iter().enumerate() {
        if i > 0 {
            json.push(b',');
        }
        for part in ["\"", name, "\":\"", value, "\""] {
            json.extend_from_slice(part.as_bytes());
        }
    }
    json.push(b'}');
    Bytes::from_owner(json)
}

/// reqwest and google-cloud-auth are built without a TLS provider of their
/// own (the default would be aws-lc-rs, a C build): they use the process's
/// default, ring, as the rest of ferritor. Setting it again is a no-op.
fn install_crypto_provider() {
    let _already = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

/// The additional authenticated data of a wrap of `generation`'s root key.
pub fn aad(generation: u32) -> String {
    format!("ferritor:purpose=root-key\nferritor:generation={generation}")
}

/// Google's error body: `{"error": {"code", "message", "status"}}`.
#[derive(Deserialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Deserialize)]
struct ErrorDetail {
    #[serde(default)]
    status: String,
    #[serde(default)]
    message: String,
}

/// Sorts a refusal into what a start does with it: a `decrypt` refused as
/// an invalid argument with "Decryption failed" is a ciphertext that isn't
/// the key's (or of another generation, or changed): `Mismatch`, which
/// stops the loop. A refusal by IAM, of credentials, of a key that's
/// missing or not enabled, or of any other request is `Denied`, looked at
/// again (a fix in the project brings the server up).
/// Anything else (throttling, Google failing) is `Unavailable`, retried.
/// The text names what Google said, which may include projects and
/// accounts: shown only to callers who may unseal.
pub fn classify(method: &str, http_status: u16, body: &[u8]) -> AutoUnsealError {
    let (status, message) = serde_json::from_slice::<ErrorBody>(body)
        .map(|b| (b.error.status, b.error.message))
        .unwrap_or_default();
    let text = format!("Cloud KMS {method}: HTTP {http_status} {status}: {message}");
    match (http_status, status.as_str()) {
        (_, "INVALID_ARGUMENT")
            if method == "decrypt" && message.starts_with("Decryption failed") =>
        {
            AutoUnsealError::Mismatch(text)
        }
        (400 | 401 | 403 | 404, _)
        | (
            _,
            "INVALID_ARGUMENT"
            | "FAILED_PRECONDITION"
            | "PERMISSION_DENIED"
            | "UNAUTHENTICATED"
            | "NOT_FOUND",
        ) => AutoUnsealError::Denied(text),
        _ => AutoUnsealError::Unavailable(text),
    }
}

#[derive(Deserialize)]
struct EncryptResponse {
    /// The key version that encrypted.
    name: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptResponse {
    plaintext: Zeroizing<String>,
}

impl AutoUnseal for GcpKms {
    fn provider(&self) -> &'static str {
        GCP_KMS
    }

    fn key_id(&self) -> BoxFuture<'_, Result<String, AutoUnsealError>> {
        Box::pin(async move { Ok(self.key_name.clone()) })
    }

    fn wrap<'a>(
        &'a self,
        root: &'a RootKey,
        generation: u32,
    ) -> BoxFuture<'a, Result<Wrapped, AutoUnsealError>> {
        Box::pin(async move {
            let plaintext = Zeroizing::new(STANDARD.encode(root.bytes_for_wrapping()));
            let aad = STANDARD.encode(aad(generation));
            let body = body(&[
                ("plaintext", plaintext.as_str()),
                ("additionalAuthenticatedData", &aad),
            ]);
            let encrypted: EncryptResponse = self.call("encrypt", body).await?;
            // Always a version of the key named: anything else isn't a wrap
            // this key's decrypt would open.
            let ours = encrypted
                .name
                .strip_prefix(&self.key_name)
                .and_then(|rest| rest.strip_prefix("/cryptoKeyVersions/"))
                .is_some_and(|version| !version.is_empty());
            if !ours {
                return Err(AutoUnsealError::Unavailable(format!(
                    "Cloud KMS encrypt answered for {}, not a version of the configured key",
                    encrypted.name
                )));
            }
            let ciphertext = STANDARD.decode(&encrypted.ciphertext).map_err(|e| {
                AutoUnsealError::Unavailable(format!(
                    "Cloud KMS encrypt: a ciphertext that isn't base64: {e}"
                ))
            })?;
            // The version is what must stay enabled while this wrap is the
            // deployment's: logged, as it's nowhere else ferritor shows.
            tracing::info!(
                generation,
                version = encrypted.name,
                "root key wrapped by Cloud KMS: keep this key version enabled until a rekey \
                 moves the wrap"
            );
            Ok(Wrapped {
                key_id: self.key_name.clone(),
                ciphertext,
            })
        })
    }

    fn unwrap<'a>(
        &'a self,
        ciphertext: &'a [u8],
        generation: u32,
    ) -> BoxFuture<'a, Result<RootKey, AutoUnsealError>> {
        Box::pin(async move {
            let ciphertext = STANDARD.encode(ciphertext);
            let aad = STANDARD.encode(aad(generation));
            let body = body(&[
                ("ciphertext", &ciphertext),
                ("additionalAuthenticatedData", &aad),
            ]);
            let decrypted: DecryptResponse = self.call("decrypt", body).await?;
            let plaintext = Zeroizing::new(
                STANDARD
                    .decode(decrypted.plaintext.as_bytes())
                    .map_err(|e| {
                        AutoUnsealError::Unavailable(format!(
                            "Cloud KMS decrypt: a plaintext that isn't base64: {e}"
                        ))
                    })?,
            );
            RootKey::from_unwrapped(&plaintext)
                .map_err(|e| AutoUnsealError::Mismatch(e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What Google answers, sorted as the start loop needs it.
    #[test]
    fn refusals_are_sorted_by_what_fixes_them() {
        let said = |status: &str, message: &str| {
            format!(r#"{{"error": {{"code": 0, "message": "{message}", "status": "{status}"}}}}"#)
        };
        let body = |status: &str| said(status, "m");
        let kind =
            |method: &str, http: u16, body: &str| classify(method, http, body.as_bytes()).result();
        // Cloud KMS's own words for a wrong AAD or a changed ciphertext.
        let failed = said("INVALID_ARGUMENT", "Decryption failed.");
        assert_eq!(kind("decrypt", 400, &failed), "mismatch");
        assert_eq!(kind("encrypt", 400, &failed), "denied");
        assert_eq!(kind("decrypt", 400, &body("INVALID_ARGUMENT")), "denied");
        assert_eq!(kind("decrypt", 400, &body("FAILED_PRECONDITION")), "denied");
        assert_eq!(kind("decrypt", 403, &body("PERMISSION_DENIED")), "denied");
        assert_eq!(kind("encrypt", 401, &body("UNAUTHENTICATED")), "denied");
        assert_eq!(kind("encrypt", 404, &body("NOT_FOUND")), "denied");
        assert_eq!(
            kind("decrypt", 429, &body("RESOURCE_EXHAUSTED")),
            "kms_unavailable"
        );
        assert_eq!(
            kind("decrypt", 503, &body("UNAVAILABLE")),
            "kms_unavailable"
        );
        assert_eq!(
            kind("decrypt", 502, "<html>bad gateway</html>"),
            "kms_unavailable"
        );
        assert_eq!(kind("decrypt", 403, "not json"), "denied");
        let AutoUnsealError::Denied(text) =
            classify("encrypt", 403, body("PERMISSION_DENIED").as_bytes())
        else {
            panic!("not denied");
        };
        assert_eq!(text, "Cloud KMS encrypt: HTTP 403 PERMISSION_DENIED: m");
    }

    /// The AAD names the purpose and the generation, so a wrap opens for
    /// its own generation only.
    #[test]
    fn the_aad_binds_the_generation() {
        assert_eq!(aad(5), "ferritor:purpose=root-key\nferritor:generation=5");
        assert_ne!(aad(5), aad(50));
    }

    /// The request bodies are the JSON they claim to be.
    #[test]
    fn bodies_are_json() {
        let sent = body(&[
            ("plaintext", "AAEC+/8="),
            ("additionalAuthenticatedData", "Zg=="),
        ]);
        let parsed: serde_json::Value = serde_json::from_slice(&sent).unwrap();
        assert_eq!(
            parsed,
            serde_json::json!({"plaintext": "AAEC+/8=", "additionalAuthenticatedData": "Zg=="})
        );
    }
}
