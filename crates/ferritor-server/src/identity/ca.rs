//! The workload-identity issuing CA: its key and self-signed certificate,
//! and the short-lived client certificates it issues for a CSR.
//!
//! A certificate it issues is built by ferritor alone: an empty subject, the
//! one `ferritor://<identity>` URI SAN, `clientAuth` and `digitalSignature`
//! only, a random serial, valid from 30 s ago. The CSR contributes only its
//! public key, and only once its own signature verifies (the requester
//! holds the private key), never a name, an extension or a validity it asks
//! for.
//!
//! The CA has no name constraints: rcgen can't encode one on URIs. What an
//! issued certificate may name is checked by ferritor on every request
//! instead (the identity under its issuer's prefix, the issuer still
//! configured), which is the guarantee either way.

use ferritor_core::path::SecretPath;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData as _, SanType,
    SerialNumber, SubjectPublicKeyInfo,
};
use time::{Duration, OffsetDateTime};
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;
use zeroize::Zeroizing;

/// How long an issuing CA's certificate is valid. Long: ferritor is its only
/// verifier, and a rotation replaces it whenever wanted; it must just
/// outlive any certificate it signs.
pub const CA_VALIDITY: Duration = Duration::days(5 * 365);
/// How far back an issued certificate's `notBefore` is set, for clocks
/// behind ours.
pub const BACKDATE: Duration = Duration::seconds(30);
/// The smallest RSA key accepted in a CSR.
pub const MIN_RSA_BITS: usize = 3072;
/// The largest CSR accepted.
pub const MAX_CSR_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("generating the issuing key")]
    Generate(#[source] rcgen::Error),
    #[error("the stored issuing key or certificate is unusable")]
    Unusable(#[source] rcgen::Error),
    #[error("the stored issuing key doesn't match its certificate")]
    Mismatch,
    #[error("the CSR is invalid: {0}")]
    Csr(&'static str),
    #[error(
        "the CSR's key isn't accepted: {0} (P-256, Ed25519, or RSA of {MIN_RSA_BITS} bits or more)"
    )]
    KeyType(&'static str),
    #[error("signing the certificate")]
    Sign(#[source] rcgen::Error),
}

/// A random, positive 16-byte serial.
fn serial() -> Result<SerialNumber, CaError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| CaError::Generate(rcgen::Error::RingUnspecified))?;
    bytes[0] &= 0x7f;
    bytes[0] |= 0x01;
    Ok(SerialNumber::from_slice(&bytes))
}

/// A new issuing key and its self-signed certificate (DER), for `version`,
/// valid from `now`: the private key as PKCS#8 DER, wiped when dropped.
pub fn generate(
    version: u32,
    now: OffsetDateTime,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CaError> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(CaError::Generate)?;
    let mut params = CertificateParams::default();
    // Certificates go to a verifier by their issuer's name (`tls`), so the
    // name must be this CA's alone: random, so no operators' CA, and no
    // other issuing CA (a version number reused after a restore), has it.
    let mut unique = [0_u8; 8];
    getrandom::fill(&mut unique).map_err(|_| CaError::Generate(rcgen::Error::RingUnspecified))?;
    let mut name = DistinguishedName::new();
    name.push(
        DnType::CommonName,
        format!(
            "ferritor workload identity CA {version} {:016x}",
            u64::from_be_bytes(unique)
        ),
    );
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.not_before = now - Duration::minutes(1);
    params.not_after = now + CA_VALIDITY;
    params.serial_number = Some(serial()?);
    let certificate = params.self_signed(&key).map_err(CaError::Generate)?;
    Ok((
        Zeroizing::new(key.serialize_der()),
        certificate.der().to_vec(),
    ))
}

/// A certificate issued for a CSR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issued {
    /// DER.
    pub certificate: Vec<u8>,
    /// The serial, lowercase hex, for the audit log.
    pub serial: String,
    pub not_after: OffsetDateTime,
}

/// The issuing CA, loaded: its version, certificate, and signing key.
pub struct IssuingCa {
    version: u32,
    certificate: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}

impl std::fmt::Debug for IssuingCa {
    /// Never the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuingCa")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl IssuingCa {
    /// Loads a stored key (PKCS#8 DER) and its certificate (DER), refusing a
    /// key that isn't the certificate's.
    pub fn load(version: u32, pkcs8: &[u8], certificate: &[u8]) -> Result<Self, CaError> {
        let key = KeyPair::try_from(pkcs8).map_err(CaError::Unusable)?;
        let (_, parsed) = X509Certificate::from_der(certificate).map_err(|_| CaError::Mismatch)?;
        if parsed.public_key().raw != key.subject_public_key_info().as_slice() {
            return Err(CaError::Mismatch);
        }
        let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(certificate.to_vec()), key)
            .map_err(CaError::Unusable)?;
        Ok(Self {
            version,
            certificate: certificate.to_vec(),
            issuer,
        })
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    /// The CA certificate, DER.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// Issues a client certificate for `identity` to the key of `csr`
    /// (DER), valid from [`BACKDATE`] before `now` until `not_after`.
    pub fn issue(
        &self,
        csr: &[u8],
        identity: &SecretPath,
        now: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> Result<Issued, CaError> {
        let public_key = csr_public_key(csr)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        let uri = format!("ferritor://{identity}")
            .try_into()
            .map_err(|_| CaError::Csr("an identity that isn't a valid URI"))?;
        params.subject_alt_names = vec![SanType::URI(uri)];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.not_before = now - BACKDATE;
        params.not_after = not_after;
        let serial = serial()?;
        let hex = serial.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        params.serial_number = Some(serial);
        params.use_authority_key_identifier_extension = true;
        let certificate = params
            .signed_by(&public_key, &self.issuer)
            .map_err(CaError::Sign)?;
        Ok(Issued {
            certificate: certificate.der().to_vec(),
            serial: hex,
            not_after,
        })
    }
}

/// The public key of a CSR whose signature verifies, if it's of a type
/// accepted.
fn csr_public_key(csr: &[u8]) -> Result<SubjectPublicKeyInfo, CaError> {
    use x509_parser::certification_request::X509CertificationRequest;

    if csr.len() > MAX_CSR_BYTES {
        return Err(CaError::Csr("too large"));
    }
    let (rest, request) =
        X509CertificationRequest::from_der(csr).map_err(|_| CaError::Csr("not a DER CSR"))?;
    if !rest.is_empty() {
        return Err(CaError::Csr("trailing bytes"));
    }
    request
        .verify_signature()
        .map_err(|_| CaError::Csr("its signature doesn't verify"))?;
    let spki = &request.certification_request_info.subject_pki;
    match spki.parsed() {
        Ok(PublicKey::EC(_)) => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok());
            if curve != Some(x509_parser::oid_registry::OID_EC_P256) {
                return Err(CaError::KeyType("an EC key on another curve than P-256"));
            }
        }
        Ok(PublicKey::RSA(rsa)) => {
            if rsa.key_size() < MIN_RSA_BITS {
                return Err(CaError::KeyType("an RSA key too small"));
            }
        }
        _ if spki.algorithm.algorithm == x509_parser::oid_registry::OID_SIG_ED25519 => {}
        _ => return Err(CaError::KeyType("another key type")),
    }
    SubjectPublicKeyInfo::from_der(spki.raw)
        .map_err(|_| CaError::KeyType("not one rcgen signs for"))
}

#[cfg(test)]
mod tests {
    use rcgen::PKCS_ED25519;
    use x509_parser::extensions::GeneralName;

    use super::*;

    const RSA_2048_PKCS8: &[u8] = include_bytes!("../../tests/fixtures/jwt-test-rsa.pk8");

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn ca() -> IssuingCa {
        let (key, certificate) = generate(1, now()).unwrap();
        IssuingCa::load(1, &key, &certificate).unwrap()
    }

    /// A CSR from `key`, asking for `sans` (which ferritor must ignore).
    fn csr(key: &KeyPair, sans: &[&str]) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = sans
            .iter()
            .map(|s| SanType::URI((*s).try_into().unwrap()))
            .collect();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.serialize_request(key).unwrap().der().to_vec()
    }

    /// The issued certificate: signed by the CA, the one ferritor:// SAN ferritor
    /// chose (never the CSR's), client auth only, not a CA, the CSR's key,
    /// valid from 30 s back to the given end.
    #[test]
    fn an_issued_certificate_is_what_ferritor_says_not_what_the_csr_asks() {
        let ca = ca();
        let (_, ca_cert) = X509Certificate::from_der(ca.certificate()).unwrap();
        assert!(ca_cert.is_ca());
        for alg in [&PKCS_ECDSA_P256_SHA256, &PKCS_ED25519] {
            let key = KeyPair::generate_for(alg).unwrap();
            let request = csr(&key, &["ferritor://ops/alice", "ferritor://k8s/x/y"]);
            let identity = SecretPath::parse("k8s/billing/api").unwrap();
            let end = now() + Duration::hours(1);
            let issued = ca.issue(&request, &identity, now(), end).unwrap();

            let (_, cert) = X509Certificate::from_der(&issued.certificate).unwrap();
            cert.verify_signature(Some(ca_cert.public_key())).unwrap();
            assert_eq!(cert.issuer(), ca_cert.subject());
            assert!(cert.subject().iter().next().is_none(), "an empty subject");
            let sans: Vec<String> = cert
                .subject_alternative_name()
                .unwrap()
                .unwrap()
                .value
                .general_names
                .iter()
                .map(|n| match n {
                    GeneralName::URI(uri) => (*uri).to_owned(),
                    other => format!("{other:?}"),
                })
                .collect();
            assert_eq!(sans, ["ferritor://k8s/billing/api"]);
            let eku = cert.extended_key_usage().unwrap().unwrap().value;
            assert!(eku.client_auth && !eku.server_auth && eku.other.is_empty());
            assert!(!cert.is_ca());
            assert_eq!(
                cert.public_key().raw,
                key.subject_public_key_info().as_slice()
            );
            assert_eq!(
                cert.validity().not_before.timestamp(),
                (now() - BACKDATE).unix_timestamp()
            );
            assert_eq!(cert.validity().not_after.timestamp(), end.unix_timestamp());
            assert_eq!(issued.serial.len(), 32);
        }
    }

    /// A CSR whose signature doesn't verify (no proof of the key), garbage,
    /// and keys of types or sizes not accepted are refused.
    #[test]
    fn a_csr_must_prove_its_key_and_be_of_an_accepted_type() {
        let ca = ca();
        let identity = SecretPath::parse("k8s/a/b").unwrap();
        let end = now() + Duration::hours(1);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut tampered = csr(&key, &[]);
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(matches!(
            ca.issue(&tampered, &identity, now(), end),
            Err(CaError::Csr(_))
        ));
        assert!(matches!(
            ca.issue(b"not a csr", &identity, now(), end),
            Err(CaError::Csr(_))
        ));
        let p384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        assert!(matches!(
            ca.issue(&csr(&p384, &[]), &identity, now(), end),
            Err(CaError::KeyType(_))
        ));
        let rsa = KeyPair::try_from(RSA_2048_PKCS8).unwrap();
        assert!(matches!(
            ca.issue(&csr(&rsa, &[]), &identity, now(), end),
            Err(CaError::KeyType(_))
        ));
    }

    /// A stored key that isn't its certificate's is refused at load.
    /// Two CAs of one version never share a name: certificates are routed
    /// by their issuer's name.
    #[test]
    fn every_ca_has_a_name_of_its_own() {
        let subject = |der: &[u8]| {
            let (_, cert) = X509Certificate::from_der(der).unwrap();
            cert.subject().to_string()
        };
        let (_, first) = generate(1, now()).unwrap();
        let (_, second) = generate(1, now()).unwrap();
        assert!(subject(&first).starts_with("CN=ferritor workload identity CA 1 "));
        assert_ne!(subject(&first), subject(&second));
    }

    #[test]
    fn a_key_must_match_its_certificate() {
        let (key_1, _) = generate(1, now()).unwrap();
        let (_, certificate_2) = generate(2, now()).unwrap();
        assert!(matches!(
            IssuingCa::load(1, &key_1, &certificate_2),
            Err(CaError::Mismatch)
        ));
        let debug = format!("{:?}", ca());
        assert!(!debug.contains("key:"), "{debug}");
    }
}
