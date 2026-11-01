//! Workload identity (`docs/src/content/docs/guides/workload-identity.md`): a workload proves who it is
//! with a token its platform gives it (a Kubernetes service account token,
//! an OIDC token from CI) and gets a short-lived client certificate in
//! exchange ([`exchange`]). Verifying the token ([`token`], with the
//! issuer's keys, [`jwk`]), mapping its claims to a ferritor identity
//! ([`mapping`]), signing the certificate ([`ca`]), and what the TLS layer
//! then trusts of it ([`trust`]). Which issuers are trusted, and how, is
//! the operators' config (`[identity]`, [`crate::config::IdentitySettings`]).

pub mod ca;
pub mod exchange;
pub mod jwk;
pub mod mapping;
pub mod token;
pub mod trust;

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::Duration;

use mapping::Mapping;

/// The longest an issued certificate may live, and the default.
pub const MAX_LIFETIME: Duration = Duration::from_secs(86_400);
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(3600);
/// The shortest: a certificate is renewed at two thirds of its life, and
/// each renewal is an audited exchange.
pub const MIN_LIFETIME: Duration = Duration::from_secs(60);
/// The default oldest token accepted (by `iat`), and the most allowed.
/// Generous by default: Kubernetes' projected tokens may live a day before
/// the kubelet replaces them; `exp` bounds every token anyway.
pub const DEFAULT_MAX_TOKEN_AGE: Duration = Duration::from_secs(86_400);
pub const MAX_TOKEN_AGE: Duration = Duration::from_secs(31 * 86_400);
/// The default burst of exchanges per identity (one a second refills
/// it), and the most allowed: a deployment of many replicas sharing an
/// identity starts them all at once.
pub const DEFAULT_EXCHANGE_BURST: NonZeroU32 = NonZeroU32::MIN.saturating_add(9);
pub const MAX_EXCHANGE_BURST: u32 = 10_000;

/// Where an issuer's keys come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JwksSource {
    File(PathBuf),
    /// `https://` only; `ca`: a private CA to verify it with (PEM), else
    /// the public web PKI roots.
    Url {
        url: String,
        ca: Option<PathBuf>,
    },
}

/// One trusted token issuer, as configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issuer {
    /// Also the first segment of every identity it maps to.
    pub name: String,
    /// Its tokens' `iss`, exactly.
    pub iss: String,
    /// What their `aud` must contain.
    pub audience: String,
    pub max_token_age: Duration,
    /// Exchanges per identity at once, refilled at one a second.
    pub exchange_burst: NonZeroU32,
    pub jwks: JwksSource,
    pub mappings: Vec<Mapping>,
    /// Its certificates issued before this (unix seconds) are refused.
    pub not_before: Option<i64>,
}

/// `[identity]`, checked: where the exchange listens, how long issued
/// certificates live, whom to trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub listen_addr: SocketAddr,
    pub lifetime: Duration,
    pub issuers: Vec<Issuer>,
    /// Single identities' cutoffs (unix seconds): their certificates issued
    /// before are refused.
    pub revoked: Vec<(ferritor_core::path::SecretPath, i64)>,
}
