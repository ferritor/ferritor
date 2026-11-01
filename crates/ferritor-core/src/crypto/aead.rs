//! AES-256-GCM with a random 96-bit nonce prepended to the ciphertext.
//!
//! Every AAD starts with a fixed label for the ciphertext's purpose, so a
//! ciphertext made for one purpose (say, a wrapped KEK) never decrypts as
//! another (say, the root check) even under the same key.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use zeroize::Zeroizing;

use super::CryptoError;
use super::key::KEY_LEN;

const NONCE_LEN: usize = 12;

#[derive(Clone, Copy, Debug)]
pub(super) enum Purpose {
    RootCheck,
    Kek,
    Dek,
    SecretValue,
    PolicyKey,
    IssuingKey,
    IssuingSet,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Self::RootCheck => b"ferritor.v1.root-check",
            // v2: the context is the namespace and version (v1 had no
            // namespaces); a new label, so the two formats can never meet.
            Self::Kek => b"ferritor.v2.kek",
            Self::Dek => b"ferritor.v1.dek",
            Self::SecretValue => b"ferritor.v1.secret-value",
            Self::PolicyKey => b"ferritor.v1.policy-key",
            Self::IssuingKey => b"ferritor.v1.issuing-key",
            Self::IssuingSet => b"ferritor.v1.issuing-set",
        }
    }
}

/// `label || 0x00 || context`. Labels contain no NUL byte, so the split
/// between label and context is unambiguous.
fn aad(purpose: Purpose, context: &[u8]) -> Vec<u8> {
    let label = purpose.label();
    let mut aad = Vec::with_capacity(label.len() + 1 + context.len());
    aad.extend_from_slice(label);
    aad.push(0);
    aad.extend_from_slice(context);
    aad
}

/// Encrypts `plaintext`, returning `nonce || ciphertext || tag`.
pub(super) fn seal(
    key: &[u8; KEY_LEN],
    purpose: Purpose,
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = Nonce::<Aes256Gcm>::default();
    getrandom::fill(&mut nonce)?;
    let aad = aad(purpose, context);
    let ciphertext = Aes256Gcm::new(key.into())
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Reverses [`seal`]. `purpose` and `context` must match what it was sealed with.
pub(super) fn open(
    key: &[u8; KEY_LEN],
    purpose: Purpose,
    context: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (nonce, ciphertext) = sealed
        .split_at_checked(NONCE_LEN)
        .ok_or(CryptoError::Decrypt)?;
    let nonce = Nonce::<Aes256Gcm>::try_from(nonce).map_err(|_| CryptoError::Decrypt)?;
    let aad = aad(purpose, context);
    Aes256Gcm::new(key.into())
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const KEY: [u8; KEY_LEN] = [7; KEY_LEN];

    proptest! {
        #[test]
        fn round_trips(plaintext: Vec<u8>, context: Vec<u8>) {
            let sealed = seal(&KEY, Purpose::Dek, &context, &plaintext).unwrap();
            let opened = open(&KEY, Purpose::Dek, &context, &sealed).unwrap();
            prop_assert_eq!(&*opened, &plaintext);
        }

        #[test]
        fn rejects_any_flipped_bit(plaintext: Vec<u8>, index: prop::sample::Index, bit in 0u8..8) {
            let mut sealed = seal(&KEY, Purpose::Dek, b"ctx", &plaintext).unwrap();
            let i = index.index(sealed.len());
            sealed[i] ^= 1 << bit;
            prop_assert!(matches!(
                open(&KEY, Purpose::Dek, b"ctx", &sealed),
                Err(CryptoError::Decrypt)
            ));
        }

        #[test]
        fn rejects_truncation(plaintext: Vec<u8>, index: prop::sample::Index) {
            let sealed = seal(&KEY, Purpose::Dek, b"ctx", &plaintext).unwrap();
            let truncated = &sealed[..index.index(sealed.len())];
            prop_assert!(matches!(
                open(&KEY, Purpose::Dek, b"ctx", truncated),
                Err(CryptoError::Decrypt)
            ));
        }
    }

    #[test]
    fn rejects_wrong_context() {
        let sealed = seal(&KEY, Purpose::Dek, b"a", b"secret").unwrap();
        assert!(matches!(
            open(&KEY, Purpose::Dek, b"b", &sealed),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn rejects_wrong_purpose() {
        let sealed = seal(&KEY, Purpose::Kek, b"", b"secret").unwrap();
        assert!(matches!(
            open(&KEY, Purpose::RootCheck, b"", &sealed),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn rejects_wrong_key() {
        let sealed = seal(&KEY, Purpose::Dek, b"", b"secret").unwrap();
        assert!(matches!(
            open(&[8; KEY_LEN], Purpose::Dek, b"", &sealed),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn uses_a_fresh_nonce_each_time() {
        let a = seal(&KEY, Purpose::Dek, b"", b"secret").unwrap();
        let b = seal(&KEY, Purpose::Dek, b"", b"secret").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }
}
