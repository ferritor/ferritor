//! The three key types of the hierarchy. Each is a 32-byte AES-256 key that
//! is zeroized on drop and redacted in `Debug`. Keeping them distinct types
//! means a KEK can only wrap a DEK, the root key only a KEK, and so on.

use std::fmt;

use hmac::{KeyInit, Mac};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::CryptoError;
use super::aead::{self, Purpose};
use crate::path::{Namespace, SecretPath};

pub const KEY_LEN: usize = 32;

/// Known plaintext sealed under the root key and stored as `seal_config.root_check`.
const ROOT_CHECK_PLAINTEXT: &[u8] = b"ferritor root check";

/// The HKDF info of the root commitments' subkey ([`RootKey::root_commitment`]).
const ROOT_COMMITMENT_INFO: &[u8] = b"ferritor.v1.root-commitment";

macro_rules! key_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name(pub(super) [u8; KEY_LEN]);

        impl $name {
            /// Generates a fresh key from the OS RNG.
            pub fn generate() -> Result<Self, CryptoError> {
                let mut key = Self([0; KEY_LEN]);
                getrandom::fill(&mut key.0)?;
                Ok(key)
            }

            pub(super) fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
                if bytes.len() != KEY_LEN {
                    return Err(CryptoError::InvalidKeyLength(bytes.len()));
                }
                let mut key = Self([0; KEY_LEN]);
                key.0.copy_from_slice(bytes);
                Ok(key)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

key_type!(
    /// Reconstructed from Shamir shares at unseal. Lives only in memory.
    RootKey
);
key_type!(
    /// Key-encryption key. Stored in the keys DB, wrapped by the root key.
    Kek
);
key_type!(
    /// Data-encryption key, one per secret version. Stored in the data DB,
    /// wrapped by a KEK.
    Dek
);
key_type!(
    /// Authenticates the stored policies (HMAC-SHA256), so that writing the
    /// keys database can't grant anyone access. Stored there wrapped by the
    /// root key, like a KEK.
    PolicyKey
);

/// An HMAC-SHA256 tag's length.
pub const MAC_LEN: usize = 32;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// HKDF-Expand (RFC 5869) of one block: `HMAC(prk, info || 0x01)`, the
/// first 32 bytes of the output keying material.
fn hkdf_expand_block(prk: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let mut mac =
        HmacSha256::new_from_slice(prk).map_err(|_| CryptoError::InvalidKeyLength(prk.len()))?;
    mac.update(info);
    mac.update(&[1]);
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

/// `version (u32 BE) || path`. The version is fixed-width, so the encoding
/// is unambiguous without a length prefix.
fn secret_context(path: &SecretPath, version: u32) -> Vec<u8> {
    let path = path.as_str();
    let mut context = Vec::with_capacity(4 + path.len());
    context.extend_from_slice(&version.to_be_bytes());
    context.extend_from_slice(path.as_bytes());
    context
}

/// `version (u32 BE) || namespace`: fixed-width first, so unambiguous
/// without a length prefix, as for secrets.
fn kek_context(namespace: &Namespace, version: u32) -> Vec<u8> {
    let name = namespace.as_str();
    let mut context = Vec::with_capacity(4 + name.len());
    context.extend_from_slice(&version.to_be_bytes());
    context.extend_from_slice(name.as_bytes());
    context
}

/// One issuing key as the set's tag covers it ([`RootKey::tag_issuing_set`]):
/// everything that decides whether what it signed is trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuingRecord<'a> {
    pub version: u32,
    /// `active`, `retired` or `revoked`.
    pub state: &'a str,
    /// Unix seconds.
    pub retired_at: Option<i64>,
    /// DER.
    pub certificate: &'a [u8],
}

impl IssuingRecord<'_> {
    /// Version, state (length-prefixed), retirement (a flag and the
    /// seconds), then the certificate: each field's end is unambiguous.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + self.state.len() + 9 + self.certificate.len());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(u8::try_from(self.state.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(self.state.as_bytes());
        match self.retired_at {
            Some(at) => {
                out.push(1);
                out.extend_from_slice(&at.to_be_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&0i64.to_be_bytes());
            }
        }
        out.extend_from_slice(self.certificate);
        out
    }

    /// The revision, the count, then each record length-prefixed.
    fn encode_set(revision: u64, records: &[IssuingRecord<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&revision.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(records.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for record in records {
            let encoded = record.encode();
            out.extend_from_slice(
                &u32::try_from(encoded.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            out.extend_from_slice(&encoded);
        }
        out
    }
}

impl RootKey {
    /// Wraps `kek` for storage as `keks.wrapped_key`, bound to its namespace
    /// and `version`: a KEK row moved to another namespace (or version)
    /// doesn't unwrap.
    pub fn wrap_kek(
        &self,
        namespace: &Namespace,
        version: u32,
        kek: &Kek,
    ) -> Result<Vec<u8>, CryptoError> {
        aead::seal(
            &self.0,
            Purpose::Kek,
            &kek_context(namespace, version),
            &kek.0,
        )
    }

    pub fn unwrap_kek(
        &self,
        namespace: &Namespace,
        version: u32,
        wrapped: &[u8],
    ) -> Result<Kek, CryptoError> {
        let bytes = aead::open(
            &self.0,
            Purpose::Kek,
            &kek_context(namespace, version),
            wrapped,
        )?;
        Kek::from_slice(&bytes)
    }

    /// Wraps the policy key for storage (`seal_config.wrapped_policy_key`).
    /// One per deployment, so no context beyond its purpose.
    pub fn wrap_policy_key(&self, key: &PolicyKey) -> Result<Vec<u8>, CryptoError> {
        aead::seal(&self.0, Purpose::PolicyKey, &[], &key.0)
    }

    pub fn unwrap_policy_key(&self, wrapped: &[u8]) -> Result<PolicyKey, CryptoError> {
        let bytes = aead::open(&self.0, Purpose::PolicyKey, &[], wrapped)?;
        PolicyKey::from_slice(&bytes)
    }

    /// Wraps the workload-identity issuing CA's private key (PKCS#8 DER) for
    /// storage (`issuing_keys.wrapped_key`), bound to its version: a wrapped
    /// key moved to another version's row doesn't unwrap.
    pub fn wrap_issuing_key(&self, version: u32, pkcs8: &[u8]) -> Result<Vec<u8>, CryptoError> {
        aead::seal(&self.0, Purpose::IssuingKey, &version.to_be_bytes(), pkcs8)
    }

    /// The issuing CA's private key (PKCS#8 DER), wiped when dropped.
    pub fn unwrap_issuing_key(
        &self,
        version: u32,
        wrapped: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        aead::open(
            &self.0,
            Purpose::IssuingKey,
            &version.to_be_bytes(),
            wrapped,
        )
    }

    /// Tags the issuing keys as a set (`issuing_set.tag`): its revision and
    /// every key's version, certificate, state and retirement, so a key
    /// added or changed by anyone without the root key (a keys-database
    /// writer) is never trusted, and an older set written back is caught by
    /// its revision. AES-GCM over an empty plaintext: a MAC over the set.
    pub fn tag_issuing_set(
        &self,
        revision: u64,
        records: &[IssuingRecord<'_>],
    ) -> Result<Vec<u8>, CryptoError> {
        aead::seal(
            &self.0,
            Purpose::IssuingSet,
            &IssuingRecord::encode_set(revision, records),
            &[],
        )
    }

    /// Whether `tag` is this root key's for the set.
    pub fn verifies_issuing_set(
        &self,
        revision: u64,
        records: &[IssuingRecord<'_>],
        tag: &[u8],
    ) -> bool {
        aead::open(
            &self.0,
            Purpose::IssuingSet,
            &IssuingRecord::encode_set(revision, records),
            tag,
        )
        .is_ok()
    }

    /// The subkey for root commitments: HKDF-Expand with the root key as the
    /// PRK (it's uniformly random, so HKDF-Extract adds nothing: RFC 5869,
    /// 3.3) and the info `ferritor.v1.root-commitment`. The root key itself is
    /// the AES-GCM key for KEK wraps, so it isn't used directly for a
    /// second primitive.
    fn commitment_key(&self) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
        hkdf_expand_block(&self.0, ROOT_COMMITMENT_INFO)
    }

    fn commitment_mac(&self, generation: u32) -> Result<HmacSha256, CryptoError> {
        let key = self.commitment_key()?;
        let mut mac = HmacSha256::new_from_slice(key.as_slice())
            .map_err(|_| CryptoError::InvalidKeyLength(KEY_LEN))?;
        mac.update(&generation.to_be_bytes());
        Ok(mac)
    }

    /// This root key's commitment for `generation`, stored in the data
    /// database (`root_commitments`): only the holder of this root key can
    /// make it, so a root key substituted in the keys database alone (with
    /// a `root_check` of its own) doesn't match any commitment there.
    pub fn root_commitment(&self, generation: u32) -> Result<[u8; MAC_LEN], CryptoError> {
        Ok(self
            .commitment_mac(generation)?
            .finalize()
            .into_bytes()
            .into())
    }

    /// Whether `mac` is this root key's commitment for `generation`,
    /// compared in constant time.
    pub fn verifies_root_commitment(&self, generation: u32, mac: &[u8]) -> bool {
        self.commitment_mac(generation)
            .is_ok_and(|m| m.verify_slice(mac).is_ok())
    }

    /// The key's bytes, for one purpose only: handing them to a key
    /// management service that wraps them (auto-unseal), which needs the
    /// plaintext. Wiped when dropped; the copies the KMS client and its
    /// transport make aren't.
    pub fn bytes_for_wrapping(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.0)
    }

    /// A root key from bytes a key management service unwrapped (see
    /// [`RootKey::bytes_for_wrapping`]). Check it against `root_check`
    /// before trusting it.
    pub fn from_unwrapped(bytes: &[u8]) -> Result<Self, CryptoError> {
        Self::from_slice(bytes)
    }

    /// Produces a fresh `seal_config.root_check` for this key.
    pub fn root_check(&self) -> Result<Vec<u8>, CryptoError> {
        aead::seal(&self.0, Purpose::RootCheck, &[], ROOT_CHECK_PLAINTEXT)
    }

    /// Confirms this is the key that produced `root_check`, before any KEK is touched.
    pub fn verify_root_check(&self, root_check: &[u8]) -> Result<(), CryptoError> {
        let plaintext = aead::open(&self.0, Purpose::RootCheck, &[], root_check)
            .map_err(|_| CryptoError::RootCheckMismatch)?;
        if plaintext.as_slice() == ROOT_CHECK_PLAINTEXT {
            Ok(())
        } else {
            Err(CryptoError::RootCheckMismatch)
        }
    }
}

impl Kek {
    /// Wraps `dek` for storage as `secrets.wrapped_dek`, bound to the secret's
    /// path and version.
    pub fn wrap_dek(
        &self,
        path: &SecretPath,
        version: u32,
        dek: &Dek,
    ) -> Result<Vec<u8>, CryptoError> {
        aead::seal(
            &self.0,
            Purpose::Dek,
            &secret_context(path, version),
            &dek.0,
        )
    }

    pub fn unwrap_dek(
        &self,
        path: &SecretPath,
        version: u32,
        wrapped: &[u8],
    ) -> Result<Dek, CryptoError> {
        let bytes = aead::open(
            &self.0,
            Purpose::Dek,
            &secret_context(path, version),
            wrapped,
        )?;
        Dek::from_slice(&bytes)
    }
}

impl PolicyKey {
    fn hmac(&self, message: &[u8]) -> Result<HmacSha256, CryptoError> {
        let mut mac = HmacSha256::new_from_slice(&self.0)
            .map_err(|_| CryptoError::InvalidKeyLength(KEY_LEN))?;
        mac.update(message);
        Ok(mac)
    }

    /// HMAC-SHA256 of `message`.
    pub fn mac(&self, message: &[u8]) -> Result<[u8; MAC_LEN], CryptoError> {
        Ok(self.hmac(message)?.finalize().into_bytes().into())
    }

    /// Whether `tag` is `message`'s MAC, compared in constant time.
    pub fn verify(&self, message: &[u8], tag: &[u8]) -> bool {
        self.hmac(message)
            .is_ok_and(|mac| mac.verify_slice(tag).is_ok())
    }
}

impl Dek {
    /// Encrypts a secret value for storage as `secrets.ciphertext`, bound to
    /// its path and version.
    pub fn encrypt(
        &self,
        path: &SecretPath,
        version: u32,
        value: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        aead::seal(
            &self.0,
            Purpose::SecretValue,
            &secret_context(path, version),
            value,
        )
    }

    pub fn decrypt(
        &self,
        path: &SecretPath,
        version: u32,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        aead::open(
            &self.0,
            Purpose::SecretValue,
            &secret_context(path, version),
            ciphertext,
        )
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn path() -> impl Strategy<Value = SecretPath> {
        "[a-z0-9_-]{1,8}(/[a-z0-9_-]{1,8}){0,3}".prop_map(|s| SecretPath::parse(&s).unwrap())
    }

    /// One HKDF-Expand block, against RFC 5869's test case 1 (its PRK is 32
    /// bytes, as a root key is).
    #[test]
    fn hkdf_expand_matches_rfc_5869() {
        let hex = |s: &str| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        let prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let okm = hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");
        assert_eq!(hkdf_expand_block(&prk, &info).unwrap().as_slice(), okm);
    }

    /// A commitment verifies under its root key and generation only, and
    /// isn't a plain HMAC under the root key (a subkey makes it).
    #[test]
    fn a_root_commitment_binds_its_key_and_generation() {
        let root = RootKey::generate().unwrap();
        let other = RootKey::generate().unwrap();
        let mac = root.root_commitment(3).unwrap();
        assert!(root.verifies_root_commitment(3, &mac));
        assert!(!root.verifies_root_commitment(4, &mac));
        assert!(!other.verifies_root_commitment(3, &mac));
        assert!(!root.verifies_root_commitment(3, &mac[..31]));
        let mut plain = HmacSha256::new_from_slice(&root.0).unwrap();
        plain.update(&3u32.to_be_bytes());
        let plain: [u8; MAC_LEN] = plain.finalize().into_bytes().into();
        assert_ne!(plain, mac);
    }

    fn p(path: &str) -> SecretPath {
        SecretPath::parse(path).unwrap()
    }

    /// The issuing key round-trips under its version only, and nothing
    /// wrapped for another purpose opens as one.
    #[test]
    fn an_issuing_key_unwraps_under_its_own_version_only() {
        let root = RootKey::generate().unwrap();
        let pkcs8 = b"a PKCS#8 document".to_vec();
        let wrapped = root.wrap_issuing_key(3, &pkcs8).unwrap();
        assert_eq!(*root.unwrap_issuing_key(3, &wrapped).unwrap(), pkcs8);
        assert!(root.unwrap_issuing_key(4, &wrapped).is_err());
        let other = RootKey::generate().unwrap();
        assert!(other.unwrap_issuing_key(3, &wrapped).is_err());
        let policy = root
            .wrap_policy_key(&PolicyKey::generate().unwrap())
            .unwrap();
        assert!(root.unwrap_issuing_key(0, &policy).is_err());
    }

    /// A set's tag holds for that revision and those records only: any
    /// field changed, a record added, removed or reordered, another
    /// revision or another root key, and it doesn't.
    #[test]
    fn an_issuing_set_tag_covers_every_record_and_the_revision() {
        let root = RootKey::generate().unwrap();
        let first = IssuingRecord {
            version: 1,
            state: "retired",
            retired_at: Some(1_792_800_000),
            certificate: b"a certificate",
        };
        let second = IssuingRecord {
            version: 2,
            state: "active",
            retired_at: None,
            certificate: b"another",
        };
        let set = [first, second];
        let tag = root.tag_issuing_set(7, &set).unwrap();
        assert!(root.verifies_issuing_set(7, &set, &tag));
        assert!(!root.verifies_issuing_set(6, &set, &tag));
        for changed in [
            IssuingRecord {
                version: 3,
                ..first
            },
            IssuingRecord {
                state: "active",
                ..first
            },
            IssuingRecord {
                retired_at: Some(1_792_800_001),
                ..first
            },
            IssuingRecord {
                retired_at: None,
                ..first
            },
            IssuingRecord {
                certificate: b"forged",
                ..first
            },
        ] {
            assert!(
                !root.verifies_issuing_set(7, &[changed, second], &tag),
                "{changed:?}"
            );
        }
        assert!(!root.verifies_issuing_set(7, &[second], &tag));
        assert!(!root.verifies_issuing_set(7, &[second, first], &tag));
        assert!(!root.verifies_issuing_set(7, &[first, second, second], &tag));
        assert!(
            !RootKey::generate()
                .unwrap()
                .verifies_issuing_set(7, &set, &tag)
        );
        // Nothing wrapped for another purpose passes as a tag.
        let wrapped = root.wrap_issuing_key(2, b"").unwrap();
        assert!(!root.verifies_issuing_set(7, &set, &wrapped));
    }

    proptest! {
        #[test]
        fn secret_value_round_trips(path in path(), version: u32, value: Vec<u8>) {
            let dek = Dek::generate().unwrap();
            let ciphertext = dek.encrypt(&path, version, &value).unwrap();
            prop_assert_eq!(&*dek.decrypt(&path, version, &ciphertext).unwrap(), &value);
        }

        #[test]
        fn dek_round_trips_through_kek(path in path(), version: u32) {
            let kek = Kek::generate().unwrap();
            let dek = Dek::generate().unwrap();
            let wrapped = kek.wrap_dek(&path, version, &dek).unwrap();
            prop_assert_eq!(kek.unwrap_dek(&path, version, &wrapped).unwrap().0, dek.0);
        }

        #[test]
        fn kek_round_trips_through_root_key(version: u32) {
            let root = RootKey::generate().unwrap();
            let kek = Kek::generate().unwrap();
            let ns = Namespace::parse("billing").unwrap();
            let wrapped = root.wrap_kek(&ns, version, &kek).unwrap();
            prop_assert_eq!(root.unwrap_kek(&ns, version, &wrapped).unwrap().0, kek.0);
        }
    }

    #[test]
    fn secret_value_is_bound_to_path_and_version() {
        let dek = Dek::generate().unwrap();
        let ciphertext = dek.encrypt(&p("a/b"), 1, b"value").unwrap();
        assert!(dek.decrypt(&p("a/c"), 1, &ciphertext).is_err());
        assert!(dek.decrypt(&p("a/b"), 2, &ciphertext).is_err());
    }

    #[test]
    fn wrapped_dek_is_bound_to_path_and_version() {
        let kek = Kek::generate().unwrap();
        let wrapped = kek
            .wrap_dek(&p("a/b"), 1, &Dek::generate().unwrap())
            .unwrap();
        assert!(kek.unwrap_dek(&p("a/c"), 1, &wrapped).is_err());
        assert!(kek.unwrap_dek(&p("a/b"), 2, &wrapped).is_err());
    }

    /// A KEK row moved to another version or namespace doesn't unwrap.
    #[test]
    fn wrapped_kek_is_bound_to_namespace_and_version() {
        let root = RootKey::generate().unwrap();
        let (billing, other) = (
            Namespace::parse("billing").unwrap(),
            Namespace::parse("other").unwrap(),
        );
        let wrapped = root
            .wrap_kek(&billing, 1, &Kek::generate().unwrap())
            .unwrap();
        assert!(root.unwrap_kek(&billing, 1, &wrapped).is_ok());
        assert!(root.unwrap_kek(&billing, 2, &wrapped).is_err());
        assert!(root.unwrap_kek(&other, 1, &wrapped).is_err());
    }

    #[test]
    fn a_policy_key_round_trips_and_macs_only_what_it_saw() {
        let root = RootKey::generate().unwrap();
        let key = PolicyKey::generate().unwrap();
        let wrapped = root.wrap_policy_key(&key).unwrap();
        let back = root.unwrap_policy_key(&wrapped).unwrap();
        assert_eq!(back.0, key.0);
        assert!(
            RootKey::generate()
                .unwrap()
                .unwrap_policy_key(&wrapped)
                .is_err()
        );
        // Not interchangeable with a KEK wrapped under the same root key.
        let ns = Namespace::parse("app").unwrap();
        let kek = root.wrap_kek(&ns, 1, &Kek::generate().unwrap()).unwrap();
        assert!(root.unwrap_policy_key(&kek).is_err());

        let tag = key.mac(b"policy").unwrap();
        assert!(key.verify(b"policy", &tag));
        assert!(!key.verify(b"policy!", &tag));
        assert!(!key.verify(b"policy", &tag[..31]));
        assert!(!PolicyKey::generate().unwrap().verify(b"policy", &tag));
    }

    #[test]
    fn root_check_accepts_only_its_own_key() {
        let root = RootKey::generate().unwrap();
        let check = root.root_check().unwrap();
        root.verify_root_check(&check).unwrap();
        assert!(matches!(
            RootKey::generate().unwrap().verify_root_check(&check),
            Err(CryptoError::RootCheckMismatch)
        ));
    }

    #[test]
    fn debug_is_redacted() {
        let key = RootKey([0xab; KEY_LEN]);
        assert_eq!(format!("{key:?}"), "RootKey(<redacted>)");
    }
}
