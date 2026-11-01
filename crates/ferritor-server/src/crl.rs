//! Certificate revocation lists for client certificates (`[tls] crl`): one
//! PEM file holding a CRL from each client CA.
//!
//! Checked when loaded, so a bad file is refused at startup or on a reload
//! (the current CRLs stay) instead of failing handshakes later. All but one
//! of the checks mirror what rustls checks at the handshake:
//!
//! - each CRL must be signed by one of the client CA certificates (all of
//!   which must parse: one skipped would escape every other check here,
//!   while rustls still trusted it);
//! - that CA's certificate, if it has a key usage extension, must allow
//!   `cRLSign` (and one that can't be read is refused). This one is
//!   stricter than rustls: it's RFC 5280's rule for a CRL's signer, which
//!   OpenSSL and others enforce, but webpki checks no key usage on a trust
//!   anchor, and every CA in `client_ca` is one;
//! - at most one CRL per CA, and every client CA needs one, since rustls
//!   refuses a certificate whose revocation status it can't determine, so a
//!   CA without a CRL would be one whose certificates all fail;
//! - each CRL must be complete: no issuing distribution point (a
//!   partitioned CRL, covering only some of its CA's certificates, while
//!   [`Crls::check`] treats a CRL as covering them all) and no delta CRL
//!   indicator (only the changes since a base CRL);
//! - no two client CAs may share a name: CRLs are matched to CAs by name,
//!   by rustls too, which takes the first CRL with the name and then fails
//!   on the signature for the other CA's certificates. In a CA key rollover,
//!   give the new CA a distinct name.
//!
//! Only a client certificate itself is checked, never an intermediate:
//! certificates must be issued directly by a configured client CA. So list
//! in `client_ca` only the CAs that issue client certificates: an issuing
//! intermediate goes there, and the CAs above it (the root) stay out, or
//! each would need a CRL of its own, renewed every `nextUpdate` (for an
//! offline root, a signing ceremony each time) for nothing.
//!
//! Used twice: by rustls's verifier at every full handshake, and by
//! [`Crls::check`] on every request ([`crate::tls::identity`]), for the
//! same reason as expiry: an open HTTP/2 connection or a resumed TLS
//! session never sees the verifier again, so a certificate revoked after
//! its handshake would otherwise keep working.
//!
//! A CRL past its `nextUpdate` is still used (rustls's default), only warned
//! about (at load, and once when one in force goes stale while serving:
//! [`StaleWatch`]) and visible as a gauge (`ferritor.tls.crl.next_update`): a
//! CRL publisher that stalls must not lock every client out. Renew the file
//! and send SIGHUP.

use std::collections::{HashMap, HashSet};

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use tokio_rustls::rustls::pki_types::pem::{self, PemObject};
use tokio_rustls::rustls::pki_types::{CertificateDer, CertificateRevocationListDer};
use x509_parser::oid_registry::{
    OID_X509_EXT_DELTA_CRL_INDICATOR, OID_X509_EXT_ISSUER_DISTRIBUTION_POINT,
};
use x509_parser::prelude::{CertificateRevocationList, FromDer, X509Certificate};
use x509_parser::time::ASN1Time;

use crate::tls::IdentityError;

#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    #[error("the CRL file is not valid PEM")]
    Pem(#[source] pem::Error),
    #[error("the CRL file holds no CRL")]
    Empty,
    /// `index` counts from 0; the message, from 1.
    #[error("the CRL at position {} in the file could not be parsed", .index + 1)]
    Unparsable { index: usize },
    /// `index` counts from 0; the message, from 1.
    #[error("the client CA certificate at position {} in client_ca could not be parsed", .index + 1)]
    UnparsableCa { index: usize },
    #[error("the CRL issued by {issuer} is not from a client CA")]
    UnknownIssuer { issuer: String },
    #[error("the CRL issued by {issuer} is not signed by that client CA")]
    BadSignature { issuer: String },
    #[error(
        "the client CA {issuer} may not sign CRLs: its certificate's key usage lacks cRLSign, \
         which RFC 5280 requires of a CRL's signer"
    )]
    NotCrlSigner { issuer: String },
    #[error("the client CA {issuer}'s key usage extension could not be read")]
    UnreadableKeyUsage { issuer: String },
    #[error(
        "the CRL issued by {issuer} has an issuing distribution point: a partitioned CRL, \
         covering only some of its CA's certificates, isn't supported (give one complete CRL \
         per CA)"
    )]
    Partitioned { issuer: String },
    #[error(
        "the CRL issued by {issuer} is a delta CRL, which isn't supported (give one complete \
         CRL per CA)"
    )]
    Delta { issuer: String },
    #[error(
        "two client CAs are named {subject}: CRLs are matched to CAs by name, so with a CRL file \
         each client CA needs a distinct name (in a key rollover, give the new CA a new name)"
    )]
    SameName { subject: String },
    #[error("the CRL file holds more than one CRL issued by {issuer}")]
    Duplicate { issuer: String },
    #[error(
        "no CRL for the client CA {subject}: with a CRL file, every client CA needs one, or none \
         of its certificates would be accepted"
    )]
    Missing { subject: String },
}

/// The CRLs in force: as given, for rustls, and as revoked serial numbers
/// by issuer, for the per-request check.
#[derive(Debug)]
pub struct Crls {
    ders: Vec<CertificateRevocationListDer<'static>>,
    /// Issuer name (DER, compared byte for byte, as rustls does) → serial
    /// numbers (the INTEGER's content octets: DER is canonical, so equal
    /// numbers are equal bytes).
    revoked: HashMap<Vec<u8>, HashSet<Vec<u8>>>,
    info: Vec<CrlInfo>,
}

/// What a CRL is, for the logs and the audit log; never anything of the
/// revoked certificates.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CrlInfo {
    pub issuer: String,
    /// The CRL number, if it has one (decimal): increases with each CRL
    /// its issuer publishes.
    pub number: Option<String>,
    pub this_update: String,
    pub next_update: Option<String>,
    /// How many certificates it revokes.
    pub revoked: usize,
    /// SHA-256 of its DER.
    pub fingerprint: String,
    #[serde(skip)]
    next_update_at: Option<i64>,
}

impl CrlInfo {
    /// When its issuer promised the next CRL (unix seconds): past it, this
    /// one may be missing revocations.
    pub fn next_update_at(&self) -> Option<i64> {
        self.next_update_at
    }

    /// Whether `nextUpdate` has passed.
    pub fn is_stale(&self) -> bool {
        self.is_stale_at(ASN1Time::now().timestamp())
    }

    /// Whether `nextUpdate` was before `now` (unix seconds).
    pub fn is_stale_at(&self, now: i64) -> bool {
        self.next_update_at.is_some_and(|at| at < now)
    }
}

/// Notices CRLs going stale while they're in force, so each is warned
/// about once, when it happens, not only at the next load. Only a CRL seen
/// fresh and then stale counts: one already stale when loaded was warned
/// about by the load itself. Tracks CRLs by fingerprint: a new CRL is
/// watched afresh, while the same file reloaded keeps its state (an
/// unchanged file doesn't re-arm the warning; if it's stale, the reload
/// warns anyway).
///
/// One case goes unwarned: a CRL loaded fresh that goes stale before the
/// next check (within a minute in `main`) is first seen stale, so it never
/// counted as fresh, and the load didn't warn either. Only the gauge shows
/// it. That takes a renewal due within a minute; not worth more code.
#[derive(Debug, Default)]
pub struct StaleWatch {
    /// Fingerprints of the CRLs in force last seen fresh.
    fresh: HashSet<String>,
}

impl StaleWatch {
    /// The CRLs in `crls` (those in force now) that went stale since the
    /// last check at or before `now` (unix seconds).
    pub fn check<'a>(&mut self, crls: &'a [CrlInfo], now: i64) -> Vec<&'a CrlInfo> {
        // Forget CRLs no longer in force.
        self.fresh
            .retain(|fingerprint| crls.iter().any(|crl| &crl.fingerprint == fingerprint));
        crls.iter()
            .filter(|crl| {
                if crl.is_stale_at(now) {
                    self.fresh.remove(&crl.fingerprint)
                } else {
                    self.fresh.insert(crl.fingerprint.clone());
                    false
                }
            })
            .collect()
    }
}

/// As the audit log writes times.
fn rfc3339(at: ASN1Time) -> String {
    at.to_datetime()
        .format(&Rfc3339)
        .unwrap_or_else(|_| at.to_string())
}

impl Crls {
    /// The CRLs in `pem`, checked against the client CA certificates `cas`
    /// as described in the module docs.
    pub fn parse(pem: &[u8], cas: &[CertificateDer<'_>]) -> Result<Self, CrlError> {
        let ders = CertificateRevocationListDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(CrlError::Pem)?;
        if ders.is_empty() {
            return Err(CrlError::Empty);
        }
        let cas = cas
            .iter()
            .enumerate()
            .map(|(index, der)| {
                X509Certificate::from_der(der.as_ref())
                    .map(|(_, cert)| cert)
                    .map_err(|_| CrlError::UnparsableCa { index })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut names = HashSet::new();
        if let Some(ca) = cas.iter().find(|ca| !names.insert(ca.subject().as_raw())) {
            return Err(CrlError::SameName {
                subject: ca.subject().to_string(),
            });
        }
        let mut revoked = HashMap::new();
        let mut info = Vec::with_capacity(ders.len());
        for (index, der) in ders.iter().enumerate() {
            let (_, crl) = CertificateRevocationList::from_der(der.as_ref())
                .map_err(|_| CrlError::Unparsable { index })?;
            let issuer = crl.issuer().to_string();
            let ca = cas
                .iter()
                .find(|ca| ca.subject().as_raw() == crl.issuer().as_raw())
                .ok_or_else(|| CrlError::UnknownIssuer {
                    issuer: issuer.clone(),
                })?;
            // RFC 5280's rule; rustls doesn't check it (see the module docs).
            let usage = ca.key_usage().map_err(|_| CrlError::UnreadableKeyUsage {
                issuer: issuer.clone(),
            })?;
            if usage.is_some_and(|usage| !usage.value.crl_sign()) {
                return Err(CrlError::NotCrlSigner { issuer });
            }
            // Before the signature: refused whoever signed it.
            for extension in crl.extensions() {
                if extension.oid == OID_X509_EXT_ISSUER_DISTRIBUTION_POINT {
                    return Err(CrlError::Partitioned { issuer });
                }
                if extension.oid == OID_X509_EXT_DELTA_CRL_INDICATOR {
                    return Err(CrlError::Delta { issuer });
                }
            }
            crl.verify_signature(ca.public_key())
                .map_err(|_| CrlError::BadSignature {
                    issuer: issuer.clone(),
                })?;
            let serials: HashSet<Vec<u8>> = crl
                .iter_revoked_certificates()
                .map(|entry| entry.raw_serial().to_vec())
                .collect();
            info.push(CrlInfo {
                issuer: issuer.clone(),
                number: crl.crl_number().map(ToString::to_string),
                this_update: rfc3339(crl.last_update()),
                next_update: crl.next_update().map(rfc3339),
                revoked: serials.len(),
                fingerprint: crate::fingerprint(der),
                next_update_at: crl.next_update().map(|at| at.timestamp()),
            });
            if revoked
                .insert(crl.issuer().as_raw().to_vec(), serials)
                .is_some()
            {
                return Err(CrlError::Duplicate { issuer });
            }
        }
        if let Some(ca) = cas
            .iter()
            .find(|ca| !revoked.contains_key(ca.subject().as_raw()))
        {
            return Err(CrlError::Missing {
                subject: ca.subject().to_string(),
            });
        }
        Ok(Self {
            ders,
            revoked,
            info,
        })
    }

    /// The CRLs as given, for rustls's verifier.
    pub fn ders(&self) -> Vec<CertificateRevocationListDer<'static>> {
        self.ders.clone()
    }

    /// One entry per CRL, in file order.
    pub fn info(&self) -> &[CrlInfo] {
        &self.info
    }

    /// Whether `cert` (a client certificate) is revoked. A certificate whose
    /// issuer has no CRL here is refused too, as rustls does: its status is
    /// unknown.
    pub fn check(&self, cert: &X509Certificate<'_>) -> Result<(), IdentityError> {
        match self.revoked.get(cert.issuer().as_raw()) {
            None => Err(IdentityError::RevocationUnknown),
            Some(serials) if serials.contains(cert.raw_serial()) => Err(IdentityError::Revoked),
            Some(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use ferritor_testkit::pki::{Ca, Pem};

    use super::*;

    fn der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    fn check(crls: &Crls, pem: &Pem) -> Result<(), IdentityError> {
        let der = der(&pem.cert);
        crls.check(&X509Certificate::from_der(der.as_ref()).unwrap().1)
    }

    fn day() -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc() + time::Duration::days(1)
    }

    #[test]
    fn a_listed_serial_is_revoked_and_others_are_not() {
        let ca = Ca::new().unwrap();
        let (alice, bob) = (
            ca.client("ops/alice").unwrap(),
            ca.client("ops/bob").unwrap(),
        );
        let crls =
            Crls::parse(ca.crl(&[&bob], day()).unwrap().as_bytes(), &[der(&ca.cert)]).unwrap();
        assert!(check(&crls, &alice).is_ok());
        assert!(matches!(check(&crls, &bob), Err(IdentityError::Revoked)));
        let [info] = crls.info() else {
            panic!("{:?}", crls.info())
        };
        assert_eq!((info.revoked, info.number.as_deref()), (1, Some("1")));
        assert!(!info.is_stale());
    }

    /// A certificate from an issuer without a CRL here has no known status.
    #[test]
    fn a_certificate_from_another_issuer_is_unknown() {
        let (ca, other) = (Ca::named("one").unwrap(), Ca::named("two").unwrap());
        let crls = Crls::parse(ca.crl(&[], day()).unwrap().as_bytes(), &[der(&ca.cert)]).unwrap();
        assert!(matches!(
            check(&crls, &other.client("ops/alice").unwrap()),
            Err(IdentityError::RevocationUnknown)
        ));
    }

    #[test]
    fn a_crl_that_does_not_match_the_client_cas_is_refused() {
        let (one, two) = (Ca::named("one").unwrap(), Ca::named("two").unwrap());
        let cas = [der(&one.cert), der(&two.cert)];
        let crl = |ca: &Ca| ca.crl(&[], day()).unwrap();
        let parse = |pem: &str, cas: &[CertificateDer<'_>]| Crls::parse(pem.as_bytes(), cas);

        assert!(parse(&format!("{}{}", crl(&one), crl(&two)), &cas).is_ok());
        assert!(matches!(parse("", &cas), Err(CrlError::Empty)));
        assert!(matches!(
            parse(&crl(&one), &cas),
            Err(CrlError::Missing { subject }) if subject.contains("two")
        ));
        assert!(matches!(
            parse(&crl(&two), &cas[..1]),
            Err(CrlError::UnknownIssuer { issuer }) if issuer.contains("two")
        ));
        assert!(matches!(
            parse(&format!("{}{}", crl(&one), crl(&one)), &cas[..1]),
            Err(CrlError::Duplicate { .. })
        ));
        // Same name, another key: the name alone proves nothing.
        let impostor = Ca::named("one").unwrap();
        assert!(matches!(
            parse(&crl(&impostor), &cas[..1]),
            Err(CrlError::BadSignature { .. })
        ));
        let garbage = "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n";
        assert!(matches!(
            parse(garbage, &cas[..1]),
            Err(CrlError::Unparsable { index: 0 })
        ));
    }

    /// RFC 5280: a CRL's signer must allow cRLSign. Stricter than rustls,
    /// which checks no key usage on a trust anchor.
    #[test]
    fn a_crl_from_a_ca_that_may_not_sign_crls_is_refused() {
        let ca = Ca::without_crl_sign("clients").unwrap();
        let refused = Crls::parse(ca.crl(&[], day()).unwrap().as_bytes(), &[der(&ca.cert)]);
        assert!(
            matches!(&refused, Err(CrlError::NotCrlSigner { issuer }) if issuer == "CN=clients"),
            "{refused:?}"
        );
    }

    /// A client CA certificate that doesn't parse is an error, not skipped:
    /// skipped, it would escape the missing-CRL and same-name checks while
    /// rustls still trusted it.
    #[test]
    fn an_unparsable_client_ca_is_refused() {
        let ca = Ca::named("clients").unwrap();
        let garbage = CertificateDer::from(b"not a certificate".to_vec());
        let refused = Crls::parse(
            ca.crl(&[], day()).unwrap().as_bytes(),
            &[der(&ca.cert), garbage],
        );
        assert!(
            matches!(refused, Err(CrlError::UnparsableCa { index: 1 })),
            "{refused:?}"
        );
        assert_eq!(
            refused.unwrap_err().to_string(),
            "the client CA certificate at position 2 in client_ca could not be parsed"
        );
    }

    /// Only complete CRLs: a partitioned one covers only some certificates
    /// (rustls then can't tell the others' status), a delta one only
    /// changes.
    #[test]
    fn a_partitioned_or_delta_crl_is_refused() {
        use base64::Engine as _;

        let ca = Ca::named("clients").unwrap();
        let cas = [der(&ca.cert)];
        let partitioned = ca.partitioned_crl(day()).unwrap();
        assert!(matches!(
            Crls::parse(partitioned.as_bytes(), &cas),
            Err(CrlError::Partitioned { .. })
        ));
        // rcgen makes no delta CRLs: turn the CRL number (2.5.29.20) into a
        // delta CRL indicator (2.5.29.27), both an INTEGER. That breaks the
        // signature, but the scope is checked first.
        let complete = ca.crl(&[], day()).unwrap();
        let mut der = CertificateRevocationListDer::from_pem_slice(complete.as_bytes())
            .unwrap()
            .to_vec();
        let number = [0x06, 0x03, 0x55, 0x1d, 0x14];
        let at = der.windows(5).position(|w| w == number).unwrap();
        der[at + 4] = 0x1b;
        let delta = format!(
            "-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----\n",
            base64::engine::general_purpose::STANDARD.encode(&der)
        );
        let refused = Crls::parse(delta.as_bytes(), &cas);
        assert!(
            matches!(refused, Err(CrlError::Delta { .. })),
            "{refused:?}"
        );
    }

    /// CRLs are matched to CAs by name (by rustls too), so two CAs sharing
    /// one can't both work: refused with that reason, not a misleading
    /// signature error.
    #[test]
    fn two_client_cas_with_the_same_name_are_refused() {
        let (old, new) = (Ca::named("clients").unwrap(), Ca::named("clients").unwrap());
        let both = format!(
            "{}{}",
            old.crl(&[], day()).unwrap(),
            new.crl(&[], day()).unwrap()
        );
        let refused = Crls::parse(both.as_bytes(), &[der(&old.cert), der(&new.cert)]);
        assert!(
            matches!(&refused, Err(CrlError::SameName { subject }) if subject == "CN=clients"),
            "{refused:?}"
        );
    }

    /// Warned once, when it goes stale; not again, and not at all for one
    /// already stale when first seen (the load warned about that). A
    /// renewed CRL is watched afresh.
    #[test]
    fn a_crl_going_stale_while_in_force_is_noticed_once() {
        let ca = Ca::new().unwrap();
        let in_an_hour = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
        let crls = Crls::parse(
            ca.crl(&[], in_an_hour).unwrap().as_bytes(),
            &[der(&ca.cert)],
        )
        .unwrap();
        let crls = crls.info();
        let due = crls[0].next_update_at().unwrap();
        let mut watch = StaleWatch::default();

        assert!(watch.check(crls, due - 60).is_empty());
        assert!(watch.check(crls, due).is_empty());
        let stale = watch.check(crls, due + 1);
        assert_eq!(stale, [&crls[0]]);
        assert!(watch.check(crls, due + 60).is_empty());

        // Already stale when first seen: no warning from the watch.
        let mut late = StaleWatch::default();
        assert!(late.check(crls, due + 1).is_empty());

        // Renewed (another fingerprint) and still fresh, then stale again.
        let renewed = Crls::parse(
            ca.crl(&[], in_an_hour).unwrap().as_bytes(),
            &[der(&ca.cert)],
        )
        .unwrap();
        let renewed = renewed.info();
        assert_ne!(renewed[0].fingerprint, crls[0].fingerprint);
        let due = renewed[0].next_update_at().unwrap();
        assert!(watch.check(renewed, due - 60).is_empty());
        assert_eq!(watch.check(renewed, due + 1), [&renewed[0]]);
    }

    #[test]
    fn a_crl_past_its_next_update_is_stale() {
        let ca = Ca::new().unwrap();
        let past = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        let crls = Crls::parse(ca.crl(&[], past).unwrap().as_bytes(), &[der(&ca.cert)]).unwrap();
        assert!(crls.info()[0].is_stale());
    }
}
