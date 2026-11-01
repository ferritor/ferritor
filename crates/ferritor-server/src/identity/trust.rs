//! What the TLS layer trusts of the workload-identity issuing CA
//! ([`crate::tls::WorkloadTrust`]), from the keyring (which issuing CAs
//! there are, and their states) and the `[identity]` config (which issuers,
//! which cutoffs). Read at every handshake and request, so a seal, a
//! rotation, here or on another server once refreshed, and a reload take
//! effect at once.

use std::sync::{Arc, PoisonError, RwLock};

use ferritor_core::path::SecretPath;
use ferritor_keystore::IssuingKeyState;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::{Identity, MAX_LIFETIME};
use crate::seal::Seal;
use crate::tls::{WorkloadCa, WorkloadTrust};

#[derive(Debug, Default)]
struct Admitted {
    /// Configured issuers, with their cutoffs (unix seconds).
    issuers: Vec<(String, Option<i64>)>,
    /// Single identities' cutoffs.
    revoked: Vec<(SecretPath, i64)>,
}

/// See the module docs.
pub struct Trust {
    seal: Arc<Seal>,
    admitted: RwLock<Arc<Admitted>>,
    /// The issuing CAs last seen unsealed: while sealed they're all
    /// untrusted, so a connection opened before the seal is refused as
    /// revoked rather than treated as the operators' PKI's.
    seen: RwLock<Vec<WorkloadCa>>,
}

fn admitted(identity: &Identity) -> Admitted {
    Admitted {
        issuers: identity
            .issuers
            .iter()
            .map(|issuer| (issuer.name.clone(), issuer.not_before))
            .collect(),
        revoked: identity.revoked.clone(),
    }
}

impl Trust {
    pub fn new(seal: Arc<Seal>, identity: &Identity) -> Self {
        Self {
            seal,
            admitted: RwLock::new(Arc::new(admitted(identity))),
            seen: RwLock::new(Vec::new()),
        }
    }

    /// The config's issuers and cutoffs, after a reload (`None`: the
    /// section is gone, so nothing issued is admitted any more).
    pub fn reload(&self, identity: Option<&Identity>) {
        let next = identity.map(admitted).unwrap_or_default();
        *self
            .admitted
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
    }

    fn admitted(&self) -> Arc<Admitted> {
        Arc::clone(&self.admitted.read().unwrap_or_else(PoisonError::into_inner))
    }
}

impl WorkloadTrust for Trust {
    /// Sealed: those last seen, none trusted (nothing issued is trusted
    /// without the keyring).
    fn cas(&self) -> Vec<WorkloadCa> {
        let Ok(keyring) = self.seal.keyring() else {
            let mut seen = self
                .seen
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            for ca in &mut seen {
                ca.trusted = false;
            }
            return seen;
        };
        let now = OffsetDateTime::now_utc();
        let window = time::Duration::try_from(MAX_LIFETIME).unwrap_or(time::Duration::DAY);
        let cas = keyring
            .issuing()
            .stored
            .iter()
            .filter_map(|key| {
                let (_, cert) = X509Certificate::from_der(&key.certificate).ok()?;
                // A retired CA's certificates live at most the longest
                // lifetime past its retirement; then nothing it signed is
                // valid anyway.
                let trusted = match key.state {
                    IssuingKeyState::Active => true,
                    IssuingKeyState::Retired => key.retired_at.is_some_and(|at| now < at + window),
                    IssuingKeyState::Revoked => false,
                };
                Some(WorkloadCa {
                    certificate: key.certificate.clone(),
                    subject: cert.subject().as_raw().to_vec(),
                    trusted,
                })
            })
            .collect::<Vec<_>>();
        // Read first: this runs at every request, and rarely changes.
        if *self.seen.read().unwrap_or_else(PoisonError::into_inner) != cas {
            self.seen
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .clone_from(&cas);
        }
        cas
    }

    fn admits(&self, identity: &SecretPath, issued_at: i64) -> bool {
        let admitted = self.admitted();
        let first = identity.as_str().split('/').next().unwrap_or_default();
        let Some((_, cutoff)) = admitted.issuers.iter().find(|(name, _)| name == first) else {
            // Its issuer is gone from the config: what it got is refused.
            return false;
        };
        if cutoff.is_some_and(|cutoff| issued_at < cutoff) {
            return false;
        }
        !admitted
            .revoked
            .iter()
            .any(|(revoked, cutoff)| revoked == identity && issued_at < *cutoff)
    }
}
