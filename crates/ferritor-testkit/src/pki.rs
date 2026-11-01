//! A throwaway certificate authority for TLS tests: certificates are made
//! at run time, so no keys are checked in.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    CrlIssuingDistributionPoint, CrlScope, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SanType, SerialNumber,
};
use time::OffsetDateTime;

use crate::TestResult;

/// A certificate and its private key, PEM-encoded.
pub struct Pem {
    pub cert: String,
    pub key: String,
    /// The certificate's serial number, to revoke it with.
    pub serial: SerialNumber,
}

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    /// The CA certificate, for trust stores.
    pub cert: String,
    /// The last serial number issued, and the last CRL number.
    serials: AtomicU64,
    crl_numbers: AtomicU64,
}

impl Ca {
    /// A CA with rcgen's default name: two of them share it.
    pub fn new() -> TestResult<Self> {
        Self::with_params(CertificateParams::default())
    }

    /// A CA named `name` (its common name).
    pub fn named(name: &str) -> TestResult<Self> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        Self::with_params(params)
    }

    /// A CA named `name` whose certificate's key usage lacks cRLSign: its
    /// CRLs are signed all the same (rcgen checks the issuer's usages, which
    /// here still allow it), as a misconfigured CA's would be.
    pub fn without_crl_sign(name: &str) -> TestResult<Self> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?.pem();
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        Ok(Self {
            issuer: Issuer::new(params, key),
            cert,
            serials: AtomicU64::new(0),
            crl_numbers: AtomicU64::new(0),
        })
    }

    fn with_params(mut params: CertificateParams) -> TestResult<Self> {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?.pem();
        Ok(Self {
            issuer: Issuer::new(params, key),
            cert,
            serials: AtomicU64::new(0),
            crl_numbers: AtomicU64::new(0),
        })
    }

    /// A CRL (PEM) revoking `revoked`, valid until `next_update`, numbered
    /// one past this CA's previous CRL.
    pub fn crl(&self, revoked: &[&Pem], next_update: OffsetDateTime) -> TestResult<String> {
        self.crl_with(revoked, next_update, None)
    }

    /// A CRL covering only user certificates from one distribution point:
    /// a partitioned CRL.
    pub fn partitioned_crl(&self, next_update: OffsetDateTime) -> TestResult<String> {
        let idp = CrlIssuingDistributionPoint {
            distribution_point: CrlDistributionPoint {
                uris: vec!["http://crl.example/users.crl".to_owned()],
            },
            scope: Some(CrlScope::UserCertsOnly),
        };
        self.crl_with(&[], next_update, Some(idp))
    }

    fn crl_with(
        &self,
        revoked: &[&Pem],
        next_update: OffsetDateTime,
        issuing_distribution_point: Option<CrlIssuingDistributionPoint>,
    ) -> TestResult<String> {
        let now = OffsetDateTime::now_utc();
        let params = CertificateRevocationListParams {
            this_update: now.min(next_update) - time::Duration::days(1),
            next_update,
            crl_number: SerialNumber::from(self.crl_numbers.fetch_add(1, Ordering::Relaxed) + 1),
            issuing_distribution_point,
            revoked_certs: revoked
                .iter()
                .map(|pem| RevokedCertParams {
                    serial_number: pem.serial.clone(),
                    revocation_time: now,
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        Ok(params.signed_by(&self.issuer)?.pem()?)
    }

    /// Issues a certificate with these SANs and extended key usages,
    /// expiring at `not_after` if given.
    pub fn issue(
        &self,
        sans: Vec<SanType>,
        usages: Vec<ExtendedKeyUsagePurpose>,
        not_after: Option<OffsetDateTime>,
    ) -> TestResult<Pem> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans;
        params.extended_key_usages = usages;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.use_authority_key_identifier_extension = true;
        let serial = SerialNumber::from(self.serials.fetch_add(1, Ordering::Relaxed) + 1);
        params.serial_number = Some(serial.clone());
        if let Some(not_after) = not_after {
            params.not_after = not_after;
        }
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.issuer)?.pem();
        Ok(Pem {
            cert,
            key: key.serialize_pem(),
            serial,
        })
    }

    /// A server certificate for `localhost` and 127.0.0.1.
    pub fn server(&self) -> TestResult<Pem> {
        self.issue(
            vec![
                SanType::DnsName("localhost".try_into()?),
                SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ],
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            None,
        )
    }

    /// A client certificate with one `ferritor://<name>` identity.
    pub fn client(&self, name: &str) -> TestResult<Pem> {
        self.issue(
            vec![uri(&format!("ferritor://{name}"))?],
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            None,
        )
    }
}

pub fn uri(uri: &str) -> TestResult<SanType> {
    Ok(SanType::URI(uri.try_into()?))
}
