//! The AWS KMS provider against the real service, run only when
//! `FERRITOR_TEST_AWS_KMS_KEY` names a key (its ARN) the caller may use, with
//! credentials from the SDK's usual chain (`AWS_PROFILE`, …): a developer's
//! own key, never CI's without a role set up through OIDC. Otherwise each
//! test returns at once.
#![cfg(feature = "aws-kms")]

use ferritor_core::crypto::RootKey;
use ferritor_server::auto_unseal::{AutoUnseal, AutoUnsealError, AwsKmsConfig};
use ferritor_server::aws_kms::AwsKms;

async fn provider() -> Option<AwsKms> {
    let key_id = std::env::var("FERRITOR_TEST_AWS_KMS_KEY").ok()?;
    let region = key_id.split(':').nth(3)?.to_owned();
    Some(
        AwsKms::new(&AwsKmsConfig {
            key_id,
            region,
            endpoint: None,
        })
        .await,
    )
}

/// The key resolves to its ARN; a wrap round-trips under its generation
/// only (the encryption context), naming the key that made it; a
/// ciphertext that isn't the key's is a mismatch, never a retry.
#[tokio::test]
async fn a_root_key_round_trips_through_aws_kms() {
    let Some(kms) = provider().await else {
        eprintln!("FERRITOR_TEST_AWS_KMS_KEY isn't set: skipped");
        return;
    };
    let arn = kms.key_id().await.unwrap();
    assert!(arn.starts_with("arn:aws:kms:"), "{arn}");

    let root = RootKey::generate().unwrap();
    let check = root.root_check().unwrap();
    let wrapped = kms.wrap(&root, 5).await.unwrap();
    assert_eq!(wrapped.key_id, arn);
    let back = kms.unwrap(&wrapped.ciphertext, 5).await.unwrap();
    back.verify_root_check(&check).unwrap();

    assert!(matches!(
        kms.unwrap(&wrapped.ciphertext, 6).await,
        Err(AutoUnsealError::Mismatch(_))
    ));
    let mut tampered = wrapped.ciphertext.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        kms.unwrap(&tampered, 5).await,
        Err(AutoUnsealError::Mismatch(_))
    ));
}
