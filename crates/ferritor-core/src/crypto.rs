//! Crypto primitives for the key hierarchy: key types, AES-256-GCM sealing
//! with domain-separated AAD, and Shamir splitting of the root key.

mod aead;
mod key;
mod shamir;

pub use key::{Dek, IssuingRecord, KEY_LEN, Kek, MAC_LEN, PolicyKey, RootKey};
pub use shamir::{Share, ShareParams, combine, split};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("OS random number generator failed")]
    Rng(#[from] getrandom::Error),
    #[error("encryption failed")]
    Encrypt,
    /// Deliberately vague: wrong key, wrong context, truncation and tampering
    /// all look the same.
    #[error("decryption failed: wrong key or context, or the ciphertext was tampered with")]
    Decrypt,
    #[error("expected a {KEY_LEN}-byte key, got {0} bytes")]
    InvalidKeyLength(usize),
    #[error("root key does not match the stored root check")]
    RootCheckMismatch,
    #[error("threshold must be between 2 and the share count, got {threshold} of {shares}")]
    InvalidShareParams { threshold: u8, shares: u8 },
    #[error("malformed share")]
    MalformedShare,
    #[error("share is from generation {found}, but the current generation is {expected}")]
    StaleShare { expected: u32, found: u32 },
    /// `vsss_rs::Error` doesn't implement `std::error::Error`, so it can't be a `#[source]`.
    #[error("secret sharing failed: {0}")]
    Shamir(vsss_rs::Error),
}
