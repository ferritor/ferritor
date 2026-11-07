//! The Google Cloud KMS provider: against a double of KMS's REST API on
//! loopback (always), and against the real service when
//! `FERRITOR_TEST_GCP_KMS_KEY` names a key (its resource name) the caller
//! may use, with Application Default Credentials (`gcloud auth
//! application-default login`, impersonating the server's service account):
//! a developer's own key, never CI's. Otherwise those tests return at once.
#![cfg(feature = "gcp-kms")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferritor_core::crypto::RootKey;
use ferritor_server::auto_unseal::{AutoUnseal, AutoUnsealError, GcpKmsConfig};
use ferritor_server::gcp_kms::GcpKms;
use ferritor_testkit::TestResult;
use serde_json::{Value, json};

const KEY: &str = "projects/p/locations/asia-southeast1/keyRings/ferritor/cryptoKeys/root-key";

/// What the double answers.
#[derive(Clone, Copy)]
enum Mode {
    /// As KMS: a "ciphertext" that is the AAD and the plaintext, opened
    /// only with the same AAD.
    Working,
    /// Every call refused by IAM.
    Denied,
    /// Every call answered 503.
    Down,
}

struct Double {
    mode: Mode,
    calls: AtomicU32,
}

fn refusal(code: StatusCode, status: &str) -> Response {
    refused(code, status, "said the double")
}

/// As Cloud KMS words its refusals.
fn refused(code: StatusCode, status: &str, message: &str) -> Response {
    let body = json!({"error": {"code": code.as_u16(), "message": message, "status": status}});
    (code, Json(body)).into_response()
}

async fn kms(
    State(double): State<Arc<Double>>,
    Path(rest): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    double.calls.fetch_add(1, Ordering::SeqCst);
    match double.mode {
        Mode::Denied => return refusal(StatusCode::FORBIDDEN, "PERMISSION_DENIED"),
        Mode::Down => return refusal(StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE"),
        Mode::Working => {}
    }
    let field = |name: &str| body[name].as_str().unwrap_or_default().to_owned();
    match rest.rsplit_once(':') {
        Some((key, "encrypt")) if key == KEY => {
            let sealed = json!({"aad": field("additionalAuthenticatedData"), "plaintext": field("plaintext")});
            Json(json!({
                "name": format!("{KEY}/cryptoKeyVersions/3"),
                "ciphertext": STANDARD.encode(sealed.to_string()),
            }))
            .into_response()
        }
        Some((key, "decrypt")) if key == KEY => {
            let sealed: Option<Value> = STANDARD
                .decode(field("ciphertext"))
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok());
            match sealed {
                Some(sealed) if sealed["aad"] == body["additionalAuthenticatedData"] => {
                    Json(json!({"plaintext": sealed["plaintext"]})).into_response()
                }
                _ => refused(
                    StatusCode::BAD_REQUEST,
                    "INVALID_ARGUMENT",
                    "Decryption failed.",
                ),
            }
        }
        _ => refusal(StatusCode::NOT_FOUND, "NOT_FOUND"),
    }
}

/// Credentials a double takes: none at all.
fn anonymous() -> ferritor_server::gcp_kms::CredentialsSource {
    Box::new(|| Ok(google_cloud_auth::credentials::anonymous::Builder::new().build()))
}

/// A provider talking to a double in `mode`, and the double.
async fn against_double(mode: Mode) -> TestResult<(GcpKms, Arc<Double>)> {
    against_double_with(mode, anonymous()).await
}

/// The same, with credentials from `source`.
async fn against_double_with(
    mode: Mode,
    source: ferritor_server::gcp_kms::CredentialsSource,
) -> TestResult<(GcpKms, Arc<Double>)> {
    let double = Arc::new(Double {
        mode,
        calls: AtomicU32::new(0),
    });
    let app = axum::Router::new()
        .route("/v1/{*rest}", axum::routing::post(kms))
        .with_state(double.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, app).await });
    let kms = GcpKms::with_credentials(
        &GcpKmsConfig {
            key_name: KEY.to_owned(),
            endpoint: Some(format!("http://{addr}")),
        },
        source,
    )?;
    Ok((kms, double))
}

/// A wrap round-trips under its generation only (the AAD), naming the key
/// (never the version that encrypted); a changed ciphertext is a mismatch.
#[tokio::test]
async fn a_root_key_round_trips_through_the_rest_api() {
    let (kms, _) = against_double(Mode::Working).await.unwrap();
    assert_eq!(kms.key_id().await.unwrap(), KEY);
    let root = RootKey::generate().unwrap();
    let check = root.root_check().unwrap();
    let wrapped = kms.wrap(&root, 5).await.unwrap();
    assert_eq!(wrapped.key_id, KEY);
    kms.unwrap(&wrapped.ciphertext, 5)
        .await
        .unwrap()
        .verify_root_check(&check)
        .unwrap();
    assert!(matches!(
        kms.unwrap(&wrapped.ciphertext, 6).await,
        Err(AutoUnsealError::Mismatch(_))
    ));
    assert!(matches!(
        kms.unwrap(b"not a wrap", 5).await,
        Err(AutoUnsealError::Mismatch(_))
    ));
}

/// A refusal by IAM is `denied` at once, never retried; a service that's
/// down is `kms_unavailable` after the call's two attempts.
#[tokio::test]
async fn refusals_and_outages_are_told_apart() {
    let root = RootKey::generate().unwrap();
    let (kms, double) = against_double(Mode::Denied).await.unwrap();
    assert!(matches!(
        kms.wrap(&root, 1).await,
        Err(AutoUnsealError::Denied(text)) if text.contains("PERMISSION_DENIED")
    ));
    assert_eq!(double.calls.load(Ordering::SeqCst), 1);

    let (kms, double) = against_double(Mode::Down).await.unwrap();
    assert!(matches!(
        kms.unwrap(b"anything", 1).await,
        Err(AutoUnsealError::Unavailable(_))
    ));
    assert_eq!(
        double.calls.load(Ordering::SeqCst),
        ferritor_server::gcp_kms::MAX_ATTEMPTS
    );
}

/// Credentials that can't be loaded yet (a secret mounted late) are a
/// `denied` attempt, never a failure to start, and are tried again at the
/// next attempt: once they load, the provider works.
#[tokio::test]
async fn credentials_are_loaded_at_the_first_attempt_that_can() {
    let mounted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::clone(&mounted);
    let source: ferritor_server::gcp_kms::CredentialsSource = Box::new(move || {
        if seen.load(Ordering::SeqCst) {
            Ok(google_cloud_auth::credentials::anonymous::Builder::new().build())
        } else {
            Err("/var/run/secrets/gcp/key.json: no such file".to_owned())
        }
    });
    let (kms, double) = against_double_with(Mode::Working, source).await.unwrap();
    let root = RootKey::generate().unwrap();
    assert!(matches!(
        kms.wrap(&root, 1).await,
        Err(AutoUnsealError::Denied(text)) if text.contains("no such file")
    ));
    assert_eq!(double.calls.load(Ordering::SeqCst), 0);
    mounted.store(true, Ordering::SeqCst);
    let wrapped = kms.wrap(&root, 1).await.unwrap();
    assert!(kms.unwrap(&wrapped.ciphertext, 1).await.is_ok());
}

/// Nothing listening: unavailable, within the call's timeout.
#[tokio::test]
async fn no_service_is_unavailable() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let kms = GcpKms::with_credentials(
        &GcpKmsConfig {
            key_name: KEY.to_owned(),
            endpoint: Some(format!("http://{addr}")),
        },
        anonymous(),
    )
    .unwrap();
    assert!(matches!(
        kms.unwrap(b"anything", 1).await,
        Err(AutoUnsealError::Unavailable(_))
    ));
}

/// The real service: the same round trip, and Cloud KMS's own refusal of a
/// wrap of another generation or a changed ciphertext as a mismatch.
#[tokio::test]
async fn a_root_key_round_trips_through_gcp_kms() {
    let Ok(key_name) = std::env::var("FERRITOR_TEST_GCP_KMS_KEY") else {
        eprintln!("FERRITOR_TEST_GCP_KMS_KEY isn't set: skipped");
        return;
    };
    let kms = GcpKms::new(&GcpKmsConfig {
        key_name: key_name.clone(),
        endpoint: None,
    })
    .unwrap();
    let root = RootKey::generate().unwrap();
    let check = root.root_check().unwrap();
    let wrapped = kms.wrap(&root, 5).await.unwrap();
    assert_eq!(wrapped.key_id, key_name);
    kms.unwrap(&wrapped.ciphertext, 5)
        .await
        .unwrap()
        .verify_root_check(&check)
        .unwrap();
    assert!(matches!(
        kms.unwrap(&wrapped.ciphertext, 6).await,
        Err(AutoUnsealError::Mismatch(_))
    ));
    let mut tampered = wrapped.ciphertext.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 1;
    assert!(matches!(
        kms.unwrap(&tampered, 5).await,
        Err(AutoUnsealError::Mismatch(_))
    ));
}
