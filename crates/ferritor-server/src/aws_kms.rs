//! Auto-unseal with AWS KMS ([`AwsKms`], the `aws-kms` feature): the root
//! key wrapped by `Encrypt` under the configured key, unwrapped by
//! `Decrypt` naming that key (so a ciphertext of another key is refused by
//! KMS itself), both bound to `{"ferritor:purpose": "root-key",
//! "ferritor:generation": "<n>"}` (the encryption context: logged in
//! CloudTrail, not secret, and what a key policy can require).
//!
//! Credentials come from the SDK's standard chain (the environment, the
//! shared config and Identity Center sessions, EKS Pod Identity or IRSA, an
//! instance profile), never from ferritor's config. Its HTTP client is rustls
//! on ring, as the rest of ferritor. Each call ends within [`CALL_TIMEOUT`],
//! the SDK's own retries (at most [`MAX_ATTEMPTS`]) included, so the
//! backoff between start attempts stays ferritor's.

use std::time::Duration;

use aws_config::BehaviorVersion;
use aws_config::retry::RetryConfig;
use aws_config::timeout::TimeoutConfig;
use aws_sdk_kms::Client;
use aws_sdk_kms::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_kms::primitives::Blob;
use aws_smithy_http_client::tls;
use ferritor_core::crypto::RootKey;
use zeroize::Zeroizing;

use crate::auto_unseal::{AutoUnseal, AutoUnsealError, AwsKmsConfig, Wrapped};

/// The longest one call may take, attempts included.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// Attempts per call: the first and one retry.
pub const MAX_ATTEMPTS: u32 = 2;

type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// See the module docs.
pub struct AwsKms {
    client: Client,
    /// As configured: every call names it.
    key_id: String,
}

impl AwsKms {
    /// A client for `config`'s key, with the SDK's credential chain. Nothing
    /// is called yet: a key that's missing, or credentials that don't work,
    /// show at the first attempt.
    pub async fn new(config: &AwsKmsConfig) -> Self {
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(tls::Provider::Rustls(
                tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();
        let shared = aws_config::defaults(BehaviorVersion::latest())
            .http_client(http)
            .region(aws_config::Region::new(config.region.clone()))
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(CALL_TIMEOUT)
                    .operation_attempt_timeout(CALL_TIMEOUT / MAX_ATTEMPTS)
                    .build(),
            )
            .retry_config(RetryConfig::standard().with_max_attempts(MAX_ATTEMPTS))
            .load()
            .await;
        let mut kms = aws_sdk_kms::config::Builder::from(&shared);
        if let Some(endpoint) = &config.endpoint {
            kms = kms.endpoint_url(endpoint);
        }
        Self {
            client: Client::from_conf(kms.build()),
            key_id: config.key_id.clone(),
        }
    }
}

/// The encryption context of a wrap of `generation`'s root key.
fn context(generation: u32) -> [(&'static str, String); 2] {
    [
        ("ferritor:purpose", "root-key".to_owned()),
        ("ferritor:generation", generation.to_string()),
    ]
}

/// Sorts an SDK error into what a start does with it: a refusal by policy
/// or the key's state is `Denied`, a ciphertext that isn't the key's (or
/// context's) is `Mismatch`, anything else (the network, throttling, KMS
/// failing) is `Unavailable`, retried. The text names what AWS said, which
/// may include accounts and roles: shown only to callers who may unseal.
fn classify<E, R>(error: &SdkError<E, R>) -> AutoUnsealError
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
    R: std::fmt::Debug,
{
    let text = DisplayErrorContext(error).to_string();
    let code = match error {
        SdkError::ServiceError(service) => service.err().code(),
        _ => None,
    };
    match code {
        Some(
            "AccessDeniedException"
            | "DisabledException"
            | "KMSInvalidStateException"
            | "NotFoundException"
            | "InvalidKeyUsageException"
            | "UnrecognizedClientException"
            | "InvalidSignatureException"
            | "ExpiredTokenException",
        ) => AutoUnsealError::Denied(text),
        Some("InvalidCiphertextException" | "IncorrectKeyException") => {
            AutoUnsealError::Mismatch(text)
        }
        _ => AutoUnsealError::Unavailable(text),
    }
}

impl AutoUnseal for AwsKms {
    fn provider(&self) -> &'static str {
        crate::auto_unseal::AWS_KMS
    }

    fn key_id(&self) -> BoxFuture<'_, Result<String, AutoUnsealError>> {
        Box::pin(async move {
            let described = self
                .client
                .describe_key()
                .key_id(&self.key_id)
                .send()
                .await
                .map_err(|e| classify(&e))?;
            described
                .key_metadata()
                .and_then(|key| key.arn())
                .map(str::to_owned)
                .ok_or_else(|| {
                    AutoUnsealError::Unavailable("DescribeKey answered without the key".to_owned())
                })
        })
    }

    fn wrap<'a>(
        &'a self,
        root: &'a RootKey,
        generation: u32,
    ) -> BoxFuture<'a, Result<Wrapped, AutoUnsealError>> {
        Box::pin(async move {
            let mut request = self
                .client
                .encrypt()
                .key_id(&self.key_id)
                .plaintext(Blob::new(root.bytes_for_wrapping().to_vec()));
            for (key, value) in context(generation) {
                request = request.encryption_context(key, value);
            }
            let encrypted = request.send().await.map_err(|e| classify(&e))?;
            match (encrypted.key_id(), encrypted.ciphertext_blob()) {
                (Some(key_id), Some(ciphertext)) => Ok(Wrapped {
                    key_id: key_id.to_owned(),
                    ciphertext: ciphertext.as_ref().to_vec(),
                }),
                _ => Err(AutoUnsealError::Unavailable(
                    "Encrypt answered without a ciphertext or its key".to_owned(),
                )),
            }
        })
    }

    fn unwrap<'a>(
        &'a self,
        ciphertext: &'a [u8],
        generation: u32,
    ) -> BoxFuture<'a, Result<RootKey, AutoUnsealError>> {
        Box::pin(async move {
            let mut request = self
                .client
                .decrypt()
                .key_id(&self.key_id)
                .ciphertext_blob(Blob::new(ciphertext.to_vec()));
            for (key, value) in context(generation) {
                request = request.encryption_context(key, value);
            }
            let decrypted = request.send().await.map_err(|e| classify(&e))?;
            let plaintext =
                Zeroizing::new(decrypted.plaintext.map(Blob::into_inner).ok_or_else(|| {
                    AutoUnsealError::Unavailable("Decrypt answered without a plaintext".into())
                })?);
            RootKey::from_unwrapped(&plaintext)
                .map_err(|e| AutoUnsealError::Mismatch(e.to_string()))
        })
    }
}
