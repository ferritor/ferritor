//! Settings: optional `ferritor.toml` in the working directory, overridden by
//! `FERRITOR_*` environment variables (e.g. `FERRITOR_KEYS_DATABASE_URL`; nested
//! keys with `__`, e.g. `FERRITOR_TLS__CERT`). Policies are TOML only.
//!
//! Two modes, and nothing in between:
//! - **dev**: no `[tls]` and no `[[policy]]`. Plaintext (gRPC and the JSON
//!   API), everyone allowed, so only on loopback (`ensure_loopback`).
//! - **secured**: `[tls]` (client certificates required), at least one
//!   `[[policy]]`, and `audit_signing_key` (the audit log's checkpoints are
//!   signed). Any address. The allow-everything authorizer is never built
//!   in this mode.
//!
//! Anything else (TLS without a policy, a policy without TLS) refuses to
//! start.
//!
//! Misspelled settings: an unknown top-level key in `ferritor.toml` refuses to
//! start ([`KNOWN_KEYS`]), as do unknown keys inside `[tls]` and
//! `[[policy]]`. Environment variables get no such check: the CLI's
//! `FERRITOR_ADDR`, `FERRITOR_CA`, `FERRITOR_CERT` and `FERRITOR_KEY` share the prefix
//! and may well be set in the same shell or `.env`, so a misspelled
//! `FERRITOR_…` variable is silently ignored.

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use secrecy::SecretString;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::authz::{AllowAll, Authorizer};
use crate::policy::{self, Policy, PolicyInfo};
use crate::{identity, ratelimit, tls};

#[derive(Debug, Deserialize)]
pub struct Settings {
    /// Where gRPC and the JSON API listen (one port). Loopback only in dev
    /// mode. Defaults to 127.0.0.1:7070.
    pub listen_addr: SocketAddr,
    /// Database URLs can carry a password; `SecretString` redacts them in
    /// `Debug`.
    pub keys_database_url: SecretString,
    pub data_database_url: SecretString,
    /// The most connections each pool opens to its database. A put holds a
    /// data-database connection for its whole transaction, so
    /// `data_database_max_connections` caps the writes in flight; past it,
    /// requests wait for a connection (up to `database_timeout_ms`, then
    /// `UNAVAILABLE`). Every server opens its own pools: keep the sum over
    /// all servers below Postgres's `max_connections`. Default 10 each; at
    /// least 1.
    pub keys_database_max_connections: u32,
    pub data_database_max_connections: u32,
    /// Upper bound on any one database call, client side, plus the pool's
    /// connection-acquire timeout and Postgres's `statement_timeout`.
    /// Default 5000.
    pub database_timeout_ms: u64,
    /// How long to wait for a lock held by another transaction: another put
    /// to the same path, or an unconfirmed rekey commit. Must be below
    /// `database_timeout_ms`, so a busy lock is reported as such rather than
    /// as an unresponsive database. Default 2000.
    pub lock_timeout_ms: u64,
    /// How long a deleted secret version is kept before `Purge` may remove
    /// it for good. Default 30. Until then it can be restored (`ferritor
    /// restore`): this is the window to undo a delete or a trim. 0 makes
    /// every deletion purgeable at once (logged as a warning at startup, in
    /// case it's a mistake).
    pub purge_deleted_after_days: u32,
    /// Live versions kept per secret path: each put marks the older ones
    /// deleted (they're purged after `purge_deleted_after_days`, like any
    /// deletion). 0 keeps every version. Default 10: old secret values
    /// shouldn't linger forever.
    ///
    /// It applies to existing secrets too, on each path's next put: after
    /// lowering it (or upgrading to a version that has it), the first put to
    /// a path with more live versions trims the excess, and a client pinned
    /// to an old version then gets "not found", which can mean "trimmed".
    /// Read at startup (logged there); not reloaded on SIGHUP.
    pub max_versions: u32,
    /// How often an unsealed server reloads its KEKs, to pick up a rotation
    /// or retirement done by another server (see `keyring`). 0 turns the
    /// periodic refresh off; reads still refresh on meeting an unknown KEK,
    /// and SIGHUP refreshes too. Default 60.
    pub keyring_refresh_secs: u64,
    /// How often an unsealed server checks whether the stored policies
    /// changed (one tiny read), reloading them if so: the longest a
    /// revocation through the API takes to reach this server. 0 turns the
    /// poll off (writes through this server, SIGHUP, unseal and the keyring
    /// refresh still reload). Default 5.
    pub policy_refresh_secs: u64,
    /// On the first SIGINT/SIGTERM, how long to keep accepting and serving
    /// while reporting not ready (see `health`) before draining, so a load
    /// balancer stops routing here first: on Kubernetes, a few seconds
    /// (endpoint removal reaches the proxies about when SIGTERM arrives).
    /// A second signal still exits at once. Default 0: drain at once; at
    /// most [`MAX_SHUTDOWN_DELAY_SECS`].
    pub shutdown_delay_secs: u64,
    /// The Ed25519 private key (PKCS#8 PEM, e.g. `openssl genpkey
    /// -algorithm ed25519`) that signs the audit log's checkpoints (see
    /// `audit`), so edits to the log can be detected with the public key
    /// alone (`ferritor audit verify`). Required in secured mode; optional in
    /// dev mode (unsigned there: chained, no checkpoints). Read at startup,
    /// never logged; its fingerprint is in every chain's `chain_start`.
    /// Keep it readable by the server's user only (startup warns
    /// otherwise): whoever can read it can sign forged checkpoints.
    pub audit_signing_key: Option<PathBuf>,
    pub tls: Option<TlsSettings>,
    #[serde(default)]
    pub policy: Vec<policy::Rule>,
    /// Rate limits (see [`RateLimitSettings`]); absent, the defaults.
    #[serde(default)]
    pub rate_limit: RateLimitSettings,
    /// Workload identity (see [`IdentitySettings`]); absent, off.
    pub identity: Option<IdentitySettings>,
    /// How the root key is opened at start ([`SealSettings`]); absent, the
    /// shares alone. Read at startup only.
    #[serde(default)]
    pub seal: SealSettings,
    /// How metrics leave the server ([`MetricsSettings`]); absent, OTLP if
    /// its endpoint variable is set. Read at startup only.
    #[serde(default)]
    pub metrics: MetricsSettings,
}

/// `[metrics]`: `exporter = "otlp"` (pushed to a collector, configured by
/// the standard `OTEL_EXPORTER_OTLP_*` variables, which must name an
/// endpoint), `"prometheus"` (scraped from a listener of its own) or
/// `"none"`. Without `exporter`, OTLP when `OTEL_EXPORTER_OTLP_ENDPOINT`
/// (or its metrics variant) is set, off otherwise. One exporter at a time.
/// Resolved and checked by [`Settings::metrics`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetricsSettings {
    pub exporter: Option<MetricsExporter>,
    /// Prometheus only: where `GET /metrics` is served. Default
    /// [`DEFAULT_METRICS_ADDR`]; never the main listener's or the
    /// exchange's address.
    pub listen_addr: Option<SocketAddr>,
    /// Prometheus only: TLS with the server's certificate (secured mode).
    /// Default: off on a loopback address, on anywhere else, so plaintext
    /// off loopback is only ever asked for.
    pub tls: Option<bool>,
    /// Prometheus over TLS only: the CA (PEM) whose client certificates a
    /// scraper must present. Without it, any scraper that reaches the port
    /// may read the metrics.
    pub client_ca: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MetricsExporter {
    Otlp,
    Prometheus,
    None,
}

/// Where the Prometheus endpoint listens by default: loopback, and OpenTelemetry's
/// usual Prometheus port.
pub const DEFAULT_METRICS_ADDR: &str = ferritor_metrics::DEFAULT_SERVER_ADDR;

/// `[metrics]` resolved by [`Settings::metrics`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Metrics {
    /// No `exporter`: OTLP if the endpoint variable is set, off otherwise.
    OtlpIfConfigured,
    /// `exporter = "otlp"`: the endpoint variable is required.
    Otlp,
    Prometheus(PrometheusListener),
    Off,
}

/// The Prometheus endpoint's listener, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrometheusListener {
    pub addr: SocketAddr,
    /// With the server's certificate; `false`: plaintext.
    pub tls: bool,
    /// Scrapers must present a certificate from this CA (TLS only).
    pub client_ca: Option<PathBuf>,
}

/// `[seal]`: `provider = "shamir"` (the default: operators' shares),
/// `"awskms"` or `"gcpkms"` (auto-unseal: the root key wrapped by AWS KMS
/// or Google Cloud KMS, the shares kept as recovery shares), with the
/// provider's own section (`[seal.awskms]`, `[seal.gcpkms]`). One provider
/// at a time: a section for another is refused.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealSettings {
    pub provider: Option<String>,
    pub awskms: Option<AwsKmsSettings>,
    pub gcpkms: Option<GcpKmsSettings>,
}

/// `[seal.awskms]`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AwsKmsSettings {
    /// The key: its ARN (recommended in production), or an alias ARN.
    pub key_id: String,
    /// Default: the ARN's.
    pub region: Option<String>,
    /// `https://` (a VPC endpoint), or loopback for a test double.
    pub endpoint: Option<String>,
}

/// `[seal.gcpkms]`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GcpKmsSettings {
    /// The key's resource name:
    /// `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`.
    pub key_name: String,
    /// `https://` (Private Service Connect), or loopback for a test double.
    pub endpoint: Option<String>,
}

/// `[identity]`: short-lived client certificates in exchange for a token
/// from a trusted issuer (a Kubernetes cluster, a CI system). Resolved and
/// checked by [`Settings::identity`]. Secured mode only.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentitySettings {
    /// The exchange's own listener (TLS, no client certificate asked).
    pub listen_addr: SocketAddr,
    /// How long an issued certificate lives (never past its token's
    /// `exp`). Default 3600, at least 60, at most 86400.
    pub lifetime_secs: Option<u64>,
    #[serde(default)]
    pub issuer: Vec<IssuerSettings>,
    /// Cutoffs for single identities: their certificates issued before
    /// `not_before` are refused (an emergency; rotate whatever leaked).
    #[serde(default)]
    pub revoke: Vec<RevokeSettings>,
}

/// One `[[identity.revoke]]`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevokeSettings {
    pub identity: String,
    /// RFC 3339.
    pub not_before: String,
}

/// One `[[identity.issuer]]`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuerSettings {
    /// Also the first segment of every identity it maps to.
    pub name: String,
    /// The `iss` of its tokens, exactly.
    pub issuer: String,
    /// What its tokens' `aud` must contain: minted for ferritor.
    pub audience: String,
    /// Its public keys (a JWKS): a file, or an `https://` URL.
    pub jwks_file: Option<PathBuf>,
    pub jwks_url: Option<String>,
    /// The CA (PEM) to verify `jwks_url` with, for a private one; without
    /// it, the public web PKI roots.
    pub jwks_ca: Option<PathBuf>,
    /// Refuse its certificates issued before this (RFC 3339): an
    /// emergency cutoff, applied to open connections on SIGHUP.
    pub not_before: Option<String>,
    /// The oldest a token may be (by `iat`). Default 86400.
    pub max_token_age_secs: Option<u64>,
    /// Exchanges per identity at once (refilled at one a second): raise it
    /// for a deployment of many replicas sharing an identity. Default 10.
    pub exchange_burst: Option<u32>,
    #[serde(default)]
    pub map: Vec<MapSettings>,
}

/// One `[[identity.issuer.map]]`: a template and the claims it requires.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MapSettings {
    pub identity: String,
    #[serde(default)]
    pub require: Vec<RequireSettings>,
}

/// A claim that must hold one of the values. A list of these, not a table
/// keyed by claim name: claim names are case-sensitive and may contain
/// dots (`kubernetes.io.namespace`), which config keys can't keep.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequireSettings {
    pub claim: String,
    pub one_of: Vec<String>,
}

/// `[rate_limit]`: the default limits per identity, the server-wide cap on
/// calls in flight, and identities' own limits (`[[rate_limit.identity]]`),
/// taking priority over the default. Resolved by [`Settings::limits`];
/// every limit but `server_max_in_flight` reloads on SIGHUP.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitSettings {
    /// Calls in flight, all identities together. Default: twice
    /// `data_database_max_connections`, plus 16. Read at startup.
    pub server_max_in_flight: Option<u32>,
    /// Calls in flight per identity. Default: a quarter of the server-wide
    /// cap (at least 1); 0: no limit.
    pub max_in_flight: Option<u32>,
    /// Requests per second per identity. Default 0: no rate limit.
    #[serde(default)]
    pub requests_per_second: u32,
    /// Requests an identity may send at once above its rate. Default:
    /// twice the rate.
    pub burst: Option<u32>,
    /// Watch streams open at once per identity. Default
    /// `watch::DEFAULT_MAX_PER_IDENTITY`; 0: no limit but the server's.
    pub max_watch_streams: Option<u32>,
    #[serde(default)]
    pub identity: Vec<IdentityLimitSettings>,
}

/// One `[[rate_limit.identity]]`: an identity's own limits, exact or by
/// prefix (whole segments); a field left out is the default's.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityLimitSettings {
    pub identity: String,
    pub max_in_flight: Option<u32>,
    pub requests_per_second: Option<u32>,
    pub burst: Option<u32>,
    pub max_watch_streams: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSettings {
    /// The server's certificate and key (PEM).
    pub cert: PathBuf,
    pub key: PathBuf,
    /// The CA (PEM) whose client certificates are accepted.
    pub client_ca: PathBuf,
    /// Optional: a CRL (PEM) from each client CA, revoking client
    /// certificates (see `crl`). Reloaded on SIGHUP. Without it nothing is
    /// revoked.
    pub crl: Option<PathBuf>,
    /// Connections are closed after this long (plus the grace period).
    /// Hygiene only: certificate expiry is enforced on every request, not by
    /// this. Default 3600.
    #[serde(default = "default_max_connection_age_secs")]
    pub max_connection_age_secs: u64,
    /// How long a connection past its age may finish in-flight calls.
    /// Default 30.
    #[serde(default = "default_connection_age_grace_secs")]
    pub connection_age_grace_secs: u64,
}

impl TlsSettings {
    /// The CRL file's contents, if one is set; read again for a reload.
    pub fn crl_pem(&self) -> Result<Option<Vec<u8>>, SecurityError> {
        self.crl.as_deref().map(read).transpose()
    }
}

fn default_max_connection_age_secs() -> u64 {
    3600
}

fn default_connection_age_grace_secs() -> u64 {
    30
}

/// What `main` serves with: who decides access, and TLS if any.
pub struct Security {
    pub authz: Arc<dyn Authorizer>,
    /// The policy's rule count and fingerprint, for the audit log; `None`
    /// in dev mode (allow everything, no policy).
    pub policy: Option<PolicyInfo>,
    pub tls: Option<tls::ServerTls>,
    pub max_connection_age: Duration,
    pub connection_age_grace: Duration,
    /// Signs the audit log's checkpoints; `None` (dev mode only) leaves it
    /// unsigned.
    pub audit_key: Option<SigningKey>,
}

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error(
        "{} is not an Ed25519 private key in PKCS#8 PEM (make one with \
         `openssl genpkey -algorithm ed25519`)",
        .path.display()
    )]
    AuditKey {
        path: PathBuf,
        #[source]
        source: ed25519_dalek::pkcs8::Error,
    },
    #[error(transparent)]
    Policy(#[from] policy::PolicyError),
    #[error("reading {}", .path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("setting up TLS")]
    Tls(#[from] tls::TlsSetupError),
}

impl Settings {
    pub fn load() -> Result<Self, config::ConfigError> {
        let file = config::File::with_name("ferritor").required(false);
        ensure_known_keys(&file)?;
        // The settings file, then the environment over it.
        Self::from_builder(
            config::Config::builder()
                .add_source(file)
                .add_source(environment()),
        )
    }

    /// Defaults, the given sources, then every check that can fail without
    /// touching the filesystem.
    fn from_builder(
        builder: config::ConfigBuilder<config::builder::DefaultState>,
    ) -> Result<Self, config::ConfigError> {
        let settings: Self = builder
            .set_default("listen_addr", "127.0.0.1:7070")?
            .set_default("keys_database_max_connections", 10)?
            .set_default("data_database_max_connections", 10)?
            .set_default("database_timeout_ms", 5000)?
            .set_default("lock_timeout_ms", 2000)?
            .set_default("purge_deleted_after_days", 30)?
            .set_default("max_versions", 10)?
            .set_default("keyring_refresh_secs", 60)?
            .set_default("policy_refresh_secs", 5)?
            .set_default("shutdown_delay_secs", 0)?
            .build()?
            .try_deserialize()?;
        ensure_timeouts(settings.database_timeout_ms, settings.lock_timeout_ms)?;
        ensure_pool_sizes(
            settings.keys_database_max_connections,
            settings.data_database_max_connections,
        )?;
        ensure_shutdown_delay(settings.shutdown_delay_secs)?;
        settings.limits().map_err(config::ConfigError::Message)?;
        settings.identity().map_err(config::ConfigError::Message)?;
        settings.metrics().map_err(config::ConfigError::Message)?;
        match (&settings.tls, settings.policy.is_empty()) {
            (None, true) => ensure_loopback(settings.listen_addr)?,
            (Some(tls), false) => {
                if settings.audit_signing_key.is_none() {
                    return Err(config::ConfigError::Message(
                        "secured mode needs audit_signing_key: the audit log's checkpoints are \
                         signed, so edits to it can be detected"
                            .to_owned(),
                    ));
                }
                if tls.max_connection_age_secs == 0 || tls.connection_age_grace_secs == 0 {
                    return Err(config::ConfigError::Message(
                        "tls.max_connection_age_secs and tls.connection_age_grace_secs must be \
                         above 0"
                            .to_owned(),
                    ));
                }
                Policy::new(&settings.policy)
                    .map_err(|e| config::ConfigError::Message(crate::error_chain(&e)))?;
            }
            (Some(_), true) => {
                return Err(config::ConfigError::Message(
                    "[tls] is set but there is no [[policy]]: with client certificates required, \
                     a policy must say who may do what"
                        .to_owned(),
                ));
            }
            (None, false) => {
                return Err(config::ConfigError::Message(
                    "[[policy]] needs [tls]: without client certificates there are no identities \
                     to match"
                        .to_owned(),
                ));
            }
        }
        Ok(settings)
    }

    pub fn database_timeout(&self) -> Duration {
        Duration::from_millis(self.database_timeout_ms)
    }

    pub fn lock_timeout(&self) -> Duration {
        Duration::from_millis(self.lock_timeout_ms)
    }

    pub fn purge_retention(&self) -> Duration {
        Duration::from_secs(u64::from(self.purge_deleted_after_days) * 24 * 60 * 60)
    }

    /// The authorizer and TLS setup for the mode these settings describe
    /// (already validated by [`Settings::load`]); reads the PEM files.
    pub fn security(&self) -> Result<Security, SecurityError> {
        let audit_key = self
            .audit_signing_key
            .as_deref()
            .map(audit_key)
            .transpose()?;
        let Some(tls_settings) = &self.tls else {
            // Dev mode: loopback only, enforced by `load`.
            return Ok(Security {
                authz: Arc::new(AllowAll),
                policy: None,
                tls: None,
                max_connection_age: Duration::from_secs(default_max_connection_age_secs()),
                connection_age_grace: Duration::from_secs(default_connection_age_grace_secs()),
                audit_key,
            });
        };
        let policy = Policy::new(&self.policy)?;
        let key = Zeroizing::new(read(&tls_settings.key)?);
        Ok(Security {
            authz: Arc::new(policy),
            policy: Some(PolicyInfo::of(&self.policy)?),
            tls: Some(tls::server_tls(
                &read(&tls_settings.cert)?,
                &key,
                &read(&tls_settings.client_ca)?,
                tls_settings.crl_pem()?.as_deref(),
            )?),
            max_connection_age: Duration::from_secs(tls_settings.max_connection_age_secs),
            connection_age_grace: Duration::from_secs(tls_settings.connection_age_grace_secs),
            audit_key,
        })
    }
}

/// The audit signing key at `path`. Warns if others than its owner may
/// read it: whoever can read it can sign forged checkpoints.
fn audit_key(path: &Path) -> Result<SigningKey, SecurityError> {
    let pem = Zeroizing::new(read(path)?);
    if let Some(mode) = shared_mode(path) {
        tracing::warn!(
            path = %path.display(),
            mode = format!("{mode:o}"),
            "the audit signing key is readable by group or others: anyone who can read it can \
             sign forged audit checkpoints (chmod 600 it)"
        );
    }
    // Not UTF-8 can't be PEM: lossy turns it into text that fails to parse.
    let pem = Zeroizing::new(String::from_utf8_lossy(&pem).into_owned());
    SigningKey::from_pkcs8_pem(&pem).map_err(|source| SecurityError::AuditKey {
        path: path.to_owned(),
        source,
    })
}

/// A policy re-read for a reload, ready to swap in.
pub struct ReloadedPolicy {
    pub authz: Arc<dyn Authorizer>,
    pub info: PolicyInfo,
}

/// The server certificate chain and key, as read (PEM).
pub struct CertificatePem {
    pub cert: Vec<u8>,
    pub key: Zeroizing<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error("the settings no longer load")]
    Load(#[source] config::ConfigError),
    /// Adding or removing `[tls]` switches between dev and secured mode,
    /// which needs a restart.
    #[error(
        "the settings now describe {now} mode, but the server runs in {running} mode: \
         changing modes needs a restart"
    )]
    ModeChanged {
        running: &'static str,
        now: &'static str,
    },
    #[error("the policy is invalid")]
    Policy(#[from] policy::PolicyError),
}

impl Settings {
    /// The authorizer to switch to after re-reading the settings (on
    /// SIGHUP): these settings' `[[policy]]`, with its rule count and
    /// fingerprint, or `None` in dev mode (allow everything: nothing to
    /// reload). Other settings take effect on restart, except the server
    /// certificate ([`Settings::certificate`]). `secured` is the mode the
    /// server is running in: a change of mode is refused, since TLS can't be
    /// switched on or off while serving.
    pub fn authz_for_reload(&self, secured: bool) -> Result<Option<ReloadedPolicy>, ReloadError> {
        let mode = |secured| if secured { "secured" } else { "dev" };
        if self.tls.is_some() != secured {
            return Err(ReloadError::ModeChanged {
                running: mode(secured),
                now: mode(self.tls.is_some()),
            });
        }
        if !secured {
            return Ok(None);
        }
        Ok(Some(ReloadedPolicy {
            authz: Arc::new(Policy::new(&self.policy)?),
            info: PolicyInfo::of(&self.policy)?,
        }))
    }

    /// The server certificate chain and key (PEM), read again for a reload;
    /// `None` in dev mode.
    pub fn certificate(&self) -> Result<Option<CertificatePem>, SecurityError> {
        let Some(tls) = &self.tls else {
            return Ok(None);
        };
        Ok(Some(CertificatePem {
            cert: read(&tls.cert)?,
            key: Zeroizing::new(read(&tls.key)?),
        }))
    }
}

/// An RFC 3339 cutoff, as unix seconds.
fn cutoff(text: &str) -> Result<i64, String> {
    time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .map(time::OffsetDateTime::unix_timestamp)
        .map_err(|_| format!("not_before {text:?} isn't an RFC 3339 time (2026-10-24T12:00:00Z)"))
}

/// `[seal.awskms]`, checked.
fn aws_kms(raw: &AwsKmsSettings) -> Result<crate::auto_unseal::AwsKmsConfig, String> {
    if raw.key_id.is_empty() {
        return Err("seal.awskms.key_id must be set (the key's ARN)".to_owned());
    }
    // arn:aws:kms:<region>:<account>:key/<id> (or alias/<name>).
    let arn_region = raw
        .key_id
        .strip_prefix("arn:")
        .and_then(|rest| rest.split(':').nth(2))
        .filter(|region| !region.is_empty());
    let region = match (&raw.region, arn_region) {
        (Some(region), _) => region.clone(),
        (None, Some(region)) => region.to_owned(),
        (None, None) => {
            return Err(
                "seal.awskms.region must be set when key_id isn't an ARN naming one".to_owned(),
            );
        }
    };
    if let Some(endpoint) = &raw.endpoint {
        kms_endpoint("awskms", endpoint)?;
    }
    Ok(crate::auto_unseal::AwsKmsConfig {
        key_id: raw.key_id.clone(),
        region,
        endpoint: raw.endpoint.clone(),
    })
}

/// `[seal.gcpkms]`, checked: the key's full resource name, each part
/// non-empty and in the characters Cloud KMS allows (it goes into the
/// request's URL), never a version.
fn gcp_kms(raw: &GcpKmsSettings) -> Result<crate::auto_unseal::GcpKmsConfig, String> {
    // Letters, digits, `-` and `_`, starting with a letter or digit; a
    // project id may also be domain-scoped (`example.com:p`). Never `/`,
    // `?`, `#`, a `:` elsewhere (`key:encrypt` is a method) or a `..`.
    fn id(part: &str, scoped: bool) -> bool {
        part.starts_with(|c: char| c.is_ascii_alphanumeric())
            && part.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '-' | '_')
                    || (scoped && matches!(c, '.' | ':'))
            })
    }
    let parts: Vec<&str> = raw.key_name.split('/').collect();
    let shaped = matches!(
        parts.as_slice(),
        ["projects", project, "locations", location, "keyRings", ring, "cryptoKeys", key]
            if id(project, true) && [location, ring, key].iter().all(|part| id(part, false))
    );
    if !shaped {
        let version = if raw.key_name.contains("/cryptoKeyVersions/") {
            " (the key, not a version: decrypt finds the version itself)"
        } else {
            ""
        };
        return Err(format!(
            "seal.gcpkms.key_name {:?} must be the key's resource name, \
             projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>{version}",
            raw.key_name
        ));
    }
    if let Some(endpoint) = &raw.endpoint {
        kms_endpoint("gcpkms", endpoint)?;
    }
    Ok(crate::auto_unseal::GcpKmsConfig {
        key_name: raw.key_name.clone(),
        endpoint: raw.endpoint.clone(),
    })
}

/// A KMS endpoint, checked: the root key goes in the wrap's request body,
/// so never in the clear off this host. Loopback as plaintext serving
/// decides it, never by DNS.
fn kms_endpoint(section: &str, endpoint: &str) -> Result<(), String> {
    let uri: axum::http::Uri = endpoint
        .parse()
        .map_err(|_| format!("seal.{section}.endpoint {endpoint:?} isn't a URL"))?;
    let host = uri.host().unwrap_or_default();
    let https = uri.scheme_str() == Some("https");
    if https || (uri.scheme_str() == Some("http") && crate::http::is_loopback_host(host)) {
        Ok(())
    } else {
        Err(format!(
            "seal.{section}.endpoint {endpoint:?} must be https:// (http:// only on loopback: \
             the root key is in the request)"
        ))
    }
}

/// One `[[identity.issuer]]`, checked.
fn issuer(raw: &IssuerSettings) -> Result<identity::Issuer, String> {
    ferritor_core::path::Namespace::parse(&raw.name)
        .map_err(|_| "name must be one path segment (letters, digits, '.', '_', '-')".to_owned())?;
    if raw.issuer.is_empty() || raw.audience.is_empty() {
        return Err("issuer and audience must be set".to_owned());
    }
    let jwks = match (&raw.jwks_file, &raw.jwks_url) {
        (Some(file), None) => identity::JwksSource::File(file.clone()),
        (None, Some(url)) if url.starts_with("https://") => identity::JwksSource::Url {
            url: url.clone(),
            ca: raw.jwks_ca.clone(),
        },
        (None, Some(_)) => return Err("jwks_url must be https://".to_owned()),
        _ => return Err("exactly one of jwks_file and jwks_url".to_owned()),
    };
    if raw.jwks_ca.is_some() && raw.jwks_url.is_none() {
        return Err("jwks_ca is for jwks_url".to_owned());
    }
    let not_before = raw.not_before.as_deref().map(cutoff).transpose()?;
    let max_token_age = raw.max_token_age_secs.map_or(
        identity::DEFAULT_MAX_TOKEN_AGE,
        std::time::Duration::from_secs,
    );
    if max_token_age.is_zero() || max_token_age > identity::MAX_TOKEN_AGE {
        return Err(format!(
            "max_token_age_secs must be between 1 and {}",
            identity::MAX_TOKEN_AGE.as_secs()
        ));
    }
    let exchange_burst = match raw.exchange_burst {
        None => identity::DEFAULT_EXCHANGE_BURST,
        Some(burst) => std::num::NonZeroU32::new(burst)
            .filter(|burst| burst.get() <= identity::MAX_EXCHANGE_BURST)
            .ok_or_else(|| {
                format!(
                    "exchange_burst must be between 1 and {}",
                    identity::MAX_EXCHANGE_BURST
                )
            })?,
    };
    if raw.map.is_empty() {
        return Err("no [[identity.issuer.map]]: its tokens would map to nothing".to_owned());
    }
    let mut mappings = Vec::with_capacity(raw.map.len());
    for map in &raw.map {
        let template = identity::mapping::Template::parse(&map.identity, &raw.name)?;
        let mut require = Vec::with_capacity(map.require.len());
        for r in &map.require {
            if r.claim.is_empty() || r.one_of.is_empty() {
                return Err(format!(
                    "{:?}: a require needs a claim and at least one value",
                    map.identity
                ));
            }
            require.push((r.claim.clone(), r.one_of.clone()));
        }
        mappings.push(identity::mapping::Mapping { template, require });
    }
    Ok(identity::Issuer {
        name: raw.name.clone(),
        iss: raw.issuer.clone(),
        audience: raw.audience.clone(),
        max_token_age,
        exchange_burst,
        jwks,
        mappings,
        not_before,
    })
}

/// The top-level keys of [`Settings`], as written in `ferritor.toml`. Keep in
/// sync with its fields; a test parses a file setting all of them.
pub const KNOWN_KEYS: &[&str] = &[
    "listen_addr",
    "keys_database_url",
    "data_database_url",
    "keys_database_max_connections",
    "data_database_max_connections",
    "database_timeout_ms",
    "lock_timeout_ms",
    "purge_deleted_after_days",
    "max_versions",
    "keyring_refresh_secs",
    "policy_refresh_secs",
    "shutdown_delay_secs",
    "audit_signing_key",
    "tls",
    "policy",
    "rate_limit",
    "identity",
    "seal",
    "metrics",
];

/// Refuses a settings file with a top-level key [`Settings`] doesn't have:
/// otherwise a typo like `listen_adress` would silently fall back to the
/// default. (Serde's
/// `deny_unknown_fields` can't do this on `Settings`: it would also see
/// every `FERRITOR_*` variable, the CLI's included.)
fn ensure_known_keys(file: &impl config::Source) -> Result<(), config::ConfigError> {
    let keys = file.collect()?;
    let mut unknown: Vec<&String> = keys
        .keys()
        .filter(|key| !KNOWN_KEYS.contains(&key.to_lowercase().as_str()))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort();
    let unknown = unknown
        .iter()
        .map(|k| format!("`{k}`"))
        .collect::<Vec<_>>()
        .join(", ");
    Err(config::ConfigError::Message(format!(
        "unknown setting {unknown} in the settings file; known: {}",
        KNOWN_KEYS.join(", ")
    )))
}

/// `FERRITOR_<KEY>` variables, nested keys joined with `__`
/// (`FERRITOR_TLS__CERT`). The prefix separator must be set too: it defaults to
/// the nesting separator, which would make every plain variable like
/// `FERRITOR_KEYS_DATABASE_URL` silently ignored.
fn environment() -> config::Environment {
    config::Environment::with_prefix("FERRITOR")
        .prefix_separator("_")
        .separator("__")
}

fn read(path: &Path) -> Result<Vec<u8>, SecurityError> {
    std::fs::read(path).map_err(|source| SecurityError::Read {
        path: path.to_owned(),
        source,
    })
}

/// The file's permission bits if its group or others have any access to it.
fn shared_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode() & 0o777;
    (mode & 0o077 != 0).then_some(mode)
}

fn ensure_timeouts(database_ms: u64, lock_ms: u64) -> Result<(), config::ConfigError> {
    if lock_ms == 0 || lock_ms >= database_ms {
        return Err(config::ConfigError::Message(format!(
            "lock_timeout_ms ({lock_ms}) must be above 0 and below \
             database_timeout_ms ({database_ms})"
        )));
    }
    Ok(())
}

impl Settings {
    /// `[metrics]`, checked (see [`MetricsSettings`]). The Prometheus
    /// listener is the scrape's alone: on another address than the main
    /// listener and the exchange; over TLS (by default off loopback) only in
    /// secured mode, whose certificate it presents; a client CA only with TLS.
    pub fn metrics(&self) -> Result<Metrics, String> {
        let raw = &self.metrics;
        let listener_set =
            raw.listen_addr.is_some() || raw.tls.is_some() || raw.client_ca.is_some();
        match raw.exporter {
            Some(MetricsExporter::Prometheus) => {}
            _ if listener_set => {
                return Err(
                    "metrics.listen_addr, metrics.tls and metrics.client_ca are for exporter = \
                     \"prometheus\""
                        .to_owned(),
                );
            }
            None => return Ok(Metrics::OtlpIfConfigured),
            Some(MetricsExporter::Otlp) => return Ok(Metrics::Otlp),
            Some(MetricsExporter::None) => return Ok(Metrics::Off),
        }
        let addr = match raw.listen_addr {
            Some(addr) => addr,
            None => DEFAULT_METRICS_ADDR
                .parse()
                .map_err(|e| format!("the default metrics address: {e}"))?,
        };
        if addr == self.listen_addr {
            return Err(
                "metrics.listen_addr must differ from listen_addr: the scrape has a listener of \
                 its own"
                    .to_owned(),
            );
        }
        if self
            .identity
            .as_ref()
            .is_some_and(|identity| identity.listen_addr == addr)
        {
            return Err("metrics.listen_addr must differ from identity.listen_addr".to_owned());
        }
        let tls = raw.tls.unwrap_or(!is_loopback(addr.ip()));
        if tls && self.tls.is_none() {
            return Err(format!(
                "metrics.listen_addr {addr} is served over TLS with the server's certificate, \
                 which needs secured mode ([tls]); listen on a loopback address, or set \
                 metrics.tls = false to serve plaintext there on purpose"
            ));
        }
        if raw.client_ca.is_some() && !tls {
            return Err(
                "metrics.client_ca needs TLS: client certificates are part of the handshake"
                    .to_owned(),
            );
        }
        Ok(Metrics::Prometheus(PrometheusListener {
            addr,
            tls,
            client_ca: raw.client_ca.clone(),
        }))
    }

    /// The rate limits as configured, the defaults filled in (see
    /// [`RateLimitSettings`]), or why they're invalid.
    /// `[identity]`, checked: `None` if it's absent. Secured mode only. Each
    /// issuer's name is the first segment of every identity it maps to, so
    /// names are unique and none may be the first segment of a config
    /// rule's identity (an operator's): an issuer can't mint an operator's
    /// name, nor another issuer's.
    pub fn identity(&self) -> Result<Option<identity::Identity>, String> {
        let Some(raw) = &self.identity else {
            return Ok(None);
        };
        if self.tls.is_none() {
            return Err(
                "[identity] needs secured mode ([tls]): it issues client certificates".to_owned(),
            );
        }
        if raw.listen_addr == self.listen_addr {
            return Err("identity.listen_addr must differ from listen_addr: the exchange has a listener of its own".to_owned());
        }
        let lifetime = raw
            .lifetime_secs
            .map_or(identity::DEFAULT_LIFETIME, std::time::Duration::from_secs);
        if !(identity::MIN_LIFETIME..=identity::MAX_LIFETIME).contains(&lifetime) {
            return Err(format!(
                "identity.lifetime_secs must be between {} and {}",
                identity::MIN_LIFETIME.as_secs(),
                identity::MAX_LIFETIME.as_secs()
            ));
        }
        if raw.issuer.is_empty() {
            return Err("[identity] without an [[identity.issuer]]: nobody to trust".to_owned());
        }
        let operators: Vec<&str> = self
            .policy
            .iter()
            .map(|rule| rule.identity.split('/').next().unwrap_or_default())
            .collect();
        let mut issuers: Vec<identity::Issuer> = Vec::with_capacity(raw.issuer.len());
        for issuer in &raw.issuer {
            let issuer = self::issuer(issuer)
                .map_err(|e| format!("identity.issuer {:?}: {e}", issuer.name))?;
            if operators.contains(&issuer.name.as_str()) {
                return Err(format!(
                    "identity.issuer {:?}: a config rule ([[policy]]) names an identity under {:?}: \
                     an issuer's name is reserved for the identities it maps, so it could \
                     mint an operator's",
                    issuer.name, issuer.name
                ));
            }
            if let Some(other) = issuers
                .iter()
                .find(|o| o.name == issuer.name || o.iss == issuer.iss)
            {
                return Err(format!(
                    "identity.issuer {:?}: the same name or iss as {:?}",
                    issuer.name, other.name
                ));
            }
            issuers.push(issuer);
        }
        let mut revoked = Vec::with_capacity(raw.revoke.len());
        for revoke in &raw.revoke {
            let path = ferritor_core::path::SecretPath::parse(&revoke.identity)
                .map_err(|e| format!("identity.revoke {:?}: {e}", revoke.identity))?;
            let first = path.as_str().split('/').next().unwrap_or_default();
            if !issuers.iter().any(|i| i.name == first) {
                return Err(format!(
                    "identity.revoke {:?}: not under any issuer's name",
                    revoke.identity
                ));
            }
            revoked.push((path, cutoff(&revoke.not_before)?));
        }
        Ok(Some(identity::Identity {
            listen_addr: raw.listen_addr,
            lifetime,
            issuers,
            revoked,
        }))
    }

    /// The auto-unseal provider `[seal]` names, checked: `None` for the
    /// shares alone. Only the named provider's section may be set.
    pub fn auto_unseal(&self) -> Result<Option<crate::auto_unseal::ProviderConfig>, String> {
        use crate::auto_unseal::ProviderConfig;
        let provider = self.seal.provider.as_deref().unwrap_or("shamir");
        let sections = [
            ("awskms", self.seal.awskms.is_some()),
            ("gcpkms", self.seal.gcpkms.is_some()),
        ];
        if let Some((section, _)) = sections
            .iter()
            .find(|(section, set)| *set && *section != provider)
        {
            return Err(format!(
                "[seal.{section}] is set, but seal.provider isn't \"{section}\": set it, or \
                 remove the section (one provider at a time)"
            ));
        }
        let needs = |key: &str| {
            format!("seal.provider = \"{provider}\" needs [seal.{provider}] with {key}")
        };
        match provider {
            "shamir" => Ok(None),
            "awskms" => match &self.seal.awskms {
                Some(aws) => aws_kms(aws).map(|c| Some(ProviderConfig::AwsKms(c))),
                None => Err(needs("key_id")),
            },
            "gcpkms" => match &self.seal.gcpkms {
                Some(gcp) => gcp_kms(gcp).map(|c| Some(ProviderConfig::GcpKms(c))),
                None => Err(needs("key_name")),
            },
            other => Err(format!(
                "seal.provider {other:?} isn't known: \"shamir\" (the default), \"awskms\" or \
                 \"gcpkms\""
            )),
        }
    }

    pub fn limits(&self) -> Result<ratelimit::Limits, String> {
        let r = &self.rate_limit;
        let cap = r.server_max_in_flight.unwrap_or_else(|| {
            self.data_database_max_connections
                .saturating_mul(2)
                .saturating_add(16)
        });
        let cap =
            NonZeroU32::new(cap).ok_or("rate_limit.server_max_in_flight must be at least 1")?;
        let max_in_flight = |max: u32, whose: &str| -> Result<Option<NonZeroU32>, String> {
            if max > cap.get() {
                return Err(format!(
                    "{whose} max_in_flight ({max}) is above rate_limit.server_max_in_flight \
                     ({cap})"
                ));
            }
            Ok(NonZeroU32::new(max))
        };
        let rate = |per_second: u32, burst: Option<u32>, whose: &str| -> Result<_, String> {
            let Some(per_second) = NonZeroU32::new(per_second) else {
                return Ok(None);
            };
            if per_second.get() > ratelimit::MAX_RATE {
                return Err(format!(
                    "{whose} requests_per_second must be at most {} (0: no rate limit)",
                    ratelimit::MAX_RATE
                ));
            }
            let burst = burst.unwrap_or_else(|| per_second.get().saturating_mul(2));
            let burst = NonZeroU32::new(burst)
                .ok_or_else(|| format!("{whose} burst must be at least 1 with a rate"))?;
            Ok(Some(ratelimit::Rate::new(per_second, burst)))
        };
        let max_watch_streams = |max: u32, whose: &str| -> Result<Option<NonZeroU32>, String> {
            if usize::try_from(max).is_ok_and(|max| max > crate::watch::MAX_STREAMS) {
                return Err(format!(
                    "{whose} max_watch_streams ({max}) is above the {} a server serves",
                    crate::watch::MAX_STREAMS
                ));
            }
            Ok(NonZeroU32::new(max))
        };
        let default_max = r.max_in_flight.unwrap_or_else(|| (cap.get() / 4).max(1));
        let default = ratelimit::Quota {
            rate: rate(r.requests_per_second, r.burst, "rate_limit")?,
            max_in_flight: max_in_flight(default_max, "rate_limit")?,
            max_watch_streams: max_watch_streams(
                r.max_watch_streams
                    .unwrap_or(crate::watch::DEFAULT_MAX_PER_IDENTITY),
                "rate_limit",
            )?,
        };
        let mut seen = std::collections::BTreeSet::new();
        let mut overrides = Vec::with_capacity(r.identity.len());
        for entry in &r.identity {
            let whose = format!("rate_limit.identity `{}`", entry.identity);
            let identity = ferritor_core::path::SecretPath::parse(&entry.identity)
                .map_err(|e| format!("{whose}: not a valid identity: {e}"))?;
            if !seen.insert(identity.clone()) {
                return Err(format!("{whose} is given twice"));
            }
            // A rate of its own brings a burst of its own (twice the rate
            // unless given); otherwise the default's rate and burst.
            let quota = ratelimit::Quota {
                rate: match entry.requests_per_second {
                    Some(per_second) => rate(per_second, entry.burst, &whose)?,
                    None => match (default.rate, entry.burst) {
                        (Some(_), Some(burst)) => rate(r.requests_per_second, Some(burst), &whose)?,
                        (rate, _) => rate,
                    },
                },
                max_in_flight: match entry.max_in_flight {
                    Some(max) => max_in_flight(max, &whose)?,
                    None => default.max_in_flight,
                },
                max_watch_streams: match entry.max_watch_streams {
                    Some(max) => max_watch_streams(max, &whose)?,
                    None => default.max_watch_streams,
                },
            };
            overrides.push((identity, quota));
        }
        Ok(ratelimit::Limits::new(cap, default, overrides))
    }
}

fn ensure_pool_sizes(keys: u32, data: u32) -> Result<(), config::ConfigError> {
    if keys == 0 || data == 0 {
        return Err(config::ConfigError::Message(format!(
            "keys_database_max_connections ({keys}) and data_database_max_connections ({data}) \
             must be at least 1"
        )));
    }
    Ok(())
}

/// The longest `shutdown_delay_secs` accepted: load balancers notice within
/// seconds, so anything longer is a mistake (a typo, a script's
/// "infinity"), refused at startup rather than holding every shutdown.
pub const MAX_SHUTDOWN_DELAY_SECS: u64 = 300;

fn ensure_shutdown_delay(secs: u64) -> Result<(), config::ConfigError> {
    if secs > MAX_SHUTDOWN_DELAY_SECS {
        return Err(config::ConfigError::Message(format!(
            "shutdown_delay_secs ({secs}) must be at most {MAX_SHUTDOWN_DELAY_SECS}: a load \
             balancer notices a server that isn't ready within seconds"
        )));
    }
    Ok(())
}

/// Dev mode has no authentication and no TLS: anyone who can reach it can
/// seal the server, rotate the KEK, start a rekey (blocking others from
/// starting one) or submit fake shares (resetting everyone's unseal
/// progress), and real shares cross it in plaintext. So it may only listen
/// on loopback; anything else needs the secured mode.
fn ensure_loopback(addr: SocketAddr) -> Result<(), config::ConfigError> {
    if is_loopback(addr.ip()) {
        return Ok(());
    }
    Err(config::ConfigError::Message(format!(
        "listen_addr {addr} is not loopback: without [tls] and [[policy]] there is no \
         authentication, so it may only listen on 127.0.0.0/8 or ::1"
    )))
}

/// The one loopback rule, for where dev mode may listen and for the hosts
/// it answers (`http::loopback_hosts_only`), so a server can't bind to an
/// address its own requests are then refused for. 127.0.0.0/8, `::1`, and
/// either as an IPv4-mapped IPv6 address (`::ffff:127.0.0.1`): every
/// ferritor binary's (`ferritor_core::net`).
pub use ferritor_core::net::is_loopback;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{Action, Caller, Target};

    const DATABASES: &str = r#"
        keys_database_url = "postgres://k"
        data_database_url = "postgres://d"
    "#;

    /// With the audit signing key secured mode needs: top-level, so before
    /// the table.
    const TLS: &str = r#"
        audit_signing_key = "audit-key.pem"
        [tls]
        cert = "server.pem"
        key = "server-key.pem"
        client_ca = "client-ca.pem"
    "#;

    const POLICY: &str = r#"
        [[policy]]
        identity = "ops/alice"
        actions = ["status", "seal"]
    "#;

    const IDENTITY: &str = r#"
        [identity]
        listen_addr = "127.0.0.1:7071"
        lifetime_secs = 1800
        [[identity.issuer]]
        name = "k8s"
        issuer = "https://kubernetes.default.svc.cluster.local"
        audience = "ferritor"
        jwks_file = "/etc/ferritor/k8s-jwks.json"
        max_token_age_secs = 3600
        [[identity.issuer.map]]
        identity = "k8s/{kubernetes.io.namespace}/{kubernetes.io.serviceaccount.name}"
        require = [{ claim = "kubernetes.io.namespace", one_of = ["billing"] }]
    "#;

    /// `[identity]` resolves: the defaults, the claim names kept as written
    /// (dots and case: they're claims, not config keys); and every mistake
    /// that would let an issuer reach past its own names is refused.
    #[test]
    fn identity_resolves_and_keeps_issuers_to_their_names() {
        let settings = parse(&format!("{TLS}\n{POLICY}\n{IDENTITY}")).unwrap();
        let identity = settings.identity().unwrap().unwrap();
        assert_eq!(identity.lifetime, Duration::from_secs(1800));
        let issuer = &identity.issuers[0];
        assert_eq!(issuer.max_token_age, Duration::from_secs(3600));
        assert_eq!(issuer.exchange_burst.get(), 10);
        let large = parse(&format!(
            "{TLS}\n{POLICY}\n{}",
            IDENTITY.replace(
                "max_token_age_secs = 3600",
                "max_token_age_secs = 3600\nexchange_burst = 200"
            )
        ))
        .unwrap();
        assert_eq!(
            large.identity().unwrap().unwrap().issuers[0]
                .exchange_burst
                .get(),
            200
        );
        assert_eq!(
            issuer.jwks,
            crate::identity::JwksSource::File("/etc/ferritor/k8s-jwks.json".into())
        );
        assert_eq!(
            issuer.mappings[0].require,
            [(
                "kubernetes.io.namespace".to_owned(),
                vec!["billing".to_owned()]
            )]
        );
        // A claim name with capitals survives the config layer as written.
        let cased = parse(&format!(
            "{TLS}\n{POLICY}\n{}",
            IDENTITY.replace(
                "claim = \"kubernetes.io.namespace\"",
                "claim = \"Repository_Owner\""
            )
        ))
        .unwrap();
        assert_eq!(
            cased.identity().unwrap().unwrap().issuers[0].mappings[0].require[0].0,
            "Repository_Owner"
        );
        assert!(parse("").unwrap().identity().unwrap().is_none());

        // Cutoffs: per issuer and per identity, in RFC 3339.
        let cut = parse(&format!(
            "{TLS}\n{POLICY}\n{}\n[[identity.revoke]]\nidentity = \"k8s/billing/api\"\nnot_before = \"2026-10-24T12:00:00Z\"\n",
            IDENTITY.replace(
                "max_token_age_secs = 3600",
                "max_token_age_secs = 3600\nnot_before = \"2026-10-24T00:00:00Z\"",
            )
        ))
        .unwrap()
        .identity()
        .unwrap()
        .unwrap();
        assert_eq!(cut.issuers[0].not_before, Some(1_792_800_000));
        assert_eq!(cut.revoked[0].0.as_str(), "k8s/billing/api");
        assert_eq!(cut.revoked[0].1, 1_792_843_200);

        let base = format!("{TLS}\n{POLICY}\n{IDENTITY}");
        for (text, says) in [
            (IDENTITY.to_owned(), "needs secured mode"),
            (
                base.replace("name = \"k8s\"", "name = \"ops\"")
                    .replace("identity = \"k8s/", "identity = \"ops/"),
                "reserved",
            ),
            (
                base.replace("identity = \"k8s/{", "identity = \"ops/{"),
                "the issuer's name",
            ),
            (
                base.replace("lifetime_secs = 1800", "lifetime_secs = 10"),
                "between 60 and 86400",
            ),
            (
                base.replace("lifetime_secs = 1800", "lifetime_secs = 100000"),
                "between 60 and 86400",
            ),
            (
                base.replace(
                    "jwks_file = \"/etc/ferritor/k8s-jwks.json\"",
                    "jwks_url = \"http://k8s/jwks\"",
                ),
                "https://",
            ),
            (
                base.replace("jwks_file = \"/etc/ferritor/k8s-jwks.json\"", ""),
                "exactly one of",
            ),
            (
                base.replace("max_token_age_secs = 3600", "max_token_age_secs = 0"),
                "max_token_age_secs",
            ),
            (
                base.replace(
                    "max_token_age_secs = 3600",
                    "max_token_age_secs = 3600\nexchange_burst = 0",
                ),
                "exchange_burst must be between 1 and 10000",
            ),
            (
                base.replace(
                    "max_token_age_secs = 3600",
                    "max_token_age_secs = 3600\nexchange_burst = 10001",
                ),
                "exchange_burst must be between 1 and 10000",
            ),
            (
                base.replace(
                    "listen_addr = \"127.0.0.1:7071\"",
                    "listen_addr = \"127.0.0.1:7070\"",
                ),
                "must differ",
            ),
            (
                base.replace("name = \"k8s\"", "name = \"k8s/x\""),
                "one path segment",
            ),
            (
                base.replace(
                    "{kubernetes.io.namespace}/{kubernetes.io.serviceaccount.name}",
                    "{kubernetes.io.namespace}-{kubernetes.io.serviceaccount.name}",
                ),
                "must fill a whole segment",
            ),
            (
                base.replace("one_of = [\"billing\"]", "one_of = []"),
                "at least one value",
            ),
            (
                base.replace("audience = \"ferritor\"", "audience = \"\""),
                "must be set",
            ),
            (
                format!(
                    "{base}\n[[identity.issuer]]\nname = \"k8s\"\nissuer = \"https://other\"\naudience = \"ferritor\"\njwks_file = \"/x\"\n[[identity.issuer.map]]\nidentity = \"k8s/{{sub}}\"\n"
                ),
                "the same name or iss",
            ),
            (format!("{base}\nunknown = 1"), "unknown"),
            (
                base.replace(
                    "max_token_age_secs = 3600",
                    "max_token_age_secs = 3600\nnot_before = \"yesterday\"",
                ),
                "RFC 3339",
            ),
            (
                base.replace(
                    "max_token_age_secs = 3600",
                    "max_token_age_secs = 3600\njwks_ca = \"/ca.pem\"",
                ),
                "jwks_ca is for jwks_url",
            ),
            (
                format!(
                    "{base}\n[[identity.revoke]]\nidentity = \"ops/alice\"\nnot_before = \"2026-10-24T12:00:00Z\"\n"
                ),
                "not under any issuer",
            ),
        ] {
            let error = parse(&text).map(drop).unwrap_err();
            assert!(error.contains(says), "{says}: {error}");
        }
    }

    fn parse(toml: &str) -> Result<Settings, String> {
        let toml = format!("{DATABASES}\n{toml}");
        ensure_known_keys(&config::File::from_str(&toml, config::FileFormat::Toml))
            .map_err(|e| e.to_string())?;
        Settings::from_builder(
            config::Config::builder()
                .add_source(config::File::from_str(&toml, config::FileFormat::Toml)),
        )
        .map_err(|e| e.to_string())
    }

    /// Through the same environment source `load` uses, with a fake
    /// environment.
    fn from_env(vars: &[(&str, &str)]) -> Result<Settings, String> {
        let vars = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Settings::from_builder(
            config::Config::builder().add_source(environment().source(Some(vars))),
        )
        .map_err(|e| e.to_string())
    }

    #[test]
    fn plain_and_nested_variables_are_both_read() {
        let base = [
            ("FERRITOR_KEYS_DATABASE_URL", "postgres://k"),
            ("FERRITOR_DATA_DATABASE_URL", "postgres://d"),
            ("FERRITOR_DATABASE_TIMEOUT_MS", "7000"),
        ];
        let settings = from_env(&base).unwrap();
        assert_eq!(settings.database_timeout_ms, 7000);
        assert!(settings.tls.is_none());

        // [tls] from variables; a policy can only come from the file.
        let mut with_tls = base.to_vec();
        with_tls.extend([
            ("FERRITOR_TLS__CERT", "s.pem"),
            ("FERRITOR_TLS__KEY", "s-key.pem"),
            ("FERRITOR_TLS__CLIENT_CA", "ca.pem"),
        ]);
        let error = from_env(&with_tls).unwrap_err();
        assert!(error.contains("no [[policy]]"), "{error}");
    }

    #[test]
    fn a_misspelled_setting_refuses_to_start() {
        let typo = parse("listen_adress = \"0.0.0.0:7070\"").unwrap_err();
        assert!(typo.contains("unknown setting `listen_adress`"), "{typo}");
    }

    /// The documented example config, `ferritor.example.toml`. Outside the
    /// crate, which `cargo package` would refuse; nothing is published.
    const EXAMPLE: &str = include_str!("../../../ferritor.example.toml");

    fn from_toml(toml: &str) -> Result<Settings, String> {
        ensure_known_keys(&config::File::from_str(toml, config::FileFormat::Toml))
            .map_err(|e| e.to_string())?;
        Settings::from_builder(
            config::Config::builder()
                .add_source(config::File::from_str(toml, config::FileFormat::Toml)),
        )
        .map_err(|e| e.to_string())
    }

    /// The example as shipped is a working dev-mode config, and with every
    /// setting uncommented (a line starting `#` and then no space: prose
    /// comments start `# `) a working secured one with the defaults, so it
    /// can't drift from what the server accepts. It mentions every key.
    #[test]
    fn the_example_config_loads_in_both_modes() {
        let dev = from_toml(EXAMPLE).unwrap();
        assert!(dev.tls.is_none() && dev.policy.is_empty());
        assert_eq!(dev.listen_addr, "127.0.0.1:7070".parse().unwrap());

        let all: String = EXAMPLE
            .lines()
            .map(|line| match line.strip_prefix('#') {
                Some(rest) if !rest.is_empty() && !rest.starts_with(' ') => rest,
                _ => line,
            })
            .map(|line| format!("{line}\n"))
            .collect();
        // One provider's section at a time: the example's AWS one, and its
        // Google one with the provider switched to it.
        let (before_gcp, gcp_section) = all.split_at(all.find("[seal.gcpkms]").unwrap());
        let before_aws = &all[..all.find("[seal.awskms]").unwrap()];
        let gcp = format!(
            "{}{gcp_section}",
            before_aws.replace("provider = \"awskms\"", "provider = \"gcpkms\"")
        );
        assert!(matches!(
            from_toml(&gcp).unwrap().auto_unseal().unwrap(),
            Some(crate::auto_unseal::ProviderConfig::GcpKms(_))
        ));
        let all = before_gcp.to_owned();
        let secured = from_toml(&all).unwrap();
        let limits = secured.limits().unwrap();
        assert_eq!(limits.server_max_in_flight.get(), 36);
        let batch = ferritor_core::path::SecretPath::parse("apps/batch/nightly").unwrap();
        assert_eq!(
            limits.quota(&batch).max_in_flight.map(|m| m.get()),
            Some(18)
        );
        let tls = secured.tls.as_ref().unwrap();
        assert_eq!(tls.crl, Some(PathBuf::from("/etc/ferritor/client-ca.crl")));
        let identity = secured.identity().unwrap().unwrap();
        assert_eq!(identity.lifetime, crate::identity::DEFAULT_LIFETIME);
        assert_eq!(
            identity.issuers[0].max_token_age,
            crate::identity::DEFAULT_MAX_TOKEN_AGE
        );
        assert_eq!(secured.policy.len(), 3);
        // The example operator can do every admin action: a fresh secured
        // deployment from it needs someone allowed to init.
        use crate::authz::Action;
        let operator = &secured.policy[0].actions;
        for action in [
            Action::Status,
            Action::Init,
            Action::Unseal,
            Action::Seal,
            Action::Rekey,
            Action::Rotate,
            Action::Rewrap,
            Action::Purge,
            Action::DestroyKek,
            Action::Namespace,
            Action::Policy,
            Action::Identity,
        ] {
            assert!(action.is_admin());
            assert!(
                operator.contains(&action),
                "the example operator lacks {action:?}"
            );
        }
        // The commented values are the defaults.
        let defaults =
            from_toml("keys_database_url = \"postgres://k\"\ndata_database_url = \"postgres://d\"")
                .unwrap();
        assert_eq!(
            (
                secured.database_timeout_ms,
                secured.lock_timeout_ms,
                secured.purge_deleted_after_days,
                secured.max_versions,
                secured.keyring_refresh_secs,
                secured.policy_refresh_secs,
                secured.shutdown_delay_secs,
            ),
            (
                defaults.database_timeout_ms,
                defaults.lock_timeout_ms,
                defaults.purge_deleted_after_days,
                defaults.max_versions,
                defaults.keyring_refresh_secs,
                defaults.policy_refresh_secs,
                defaults.shutdown_delay_secs,
            )
        );
        assert_eq!(
            (tls.max_connection_age_secs, tls.connection_age_grace_secs),
            (
                default_max_connection_age_secs(),
                default_connection_age_grace_secs()
            )
        );
        for key in KNOWN_KEYS.iter().filter(|key| {
            !["tls", "policy", "rate_limit", "identity", "seal", "metrics"].contains(key)
        }) {
            assert!(
                EXAMPLE.contains(&format!("{key} = ")),
                "{key} isn't in the example"
            );
        }
        assert!(EXAMPLE.contains("#[seal.awskms]") && EXAMPLE.contains("#[seal.gcpkms]"));
        assert_eq!(dev.metrics().unwrap(), Metrics::OtlpIfConfigured);
        assert_eq!(
            secured.metrics().unwrap(),
            Metrics::Prometheus(PrometheusListener {
                addr: "0.0.0.0:9464".parse().unwrap(),
                tls: true,
                client_ca: Some(PathBuf::from("/etc/ferritor/metrics-ca.pem")),
            })
        );
        assert!(matches!(
            secured.auto_unseal().unwrap(),
            Some(crate::auto_unseal::ProviderConfig::AwsKms(_))
        ));
    }

    /// Every known key, so `KNOWN_KEYS` can't lag behind `Settings`
    /// unnoticed in the other direction (a known key it doesn't parse).
    #[test]
    fn every_known_key_is_accepted() {
        let all = format!(
            "listen_addr = \"127.0.0.1:7070\"\ndatabase_timeout_ms = 5000\nlock_timeout_ms = 2000\n\
             keys_database_max_connections = 4\ndata_database_max_connections = 32\n\
             purge_deleted_after_days = 7\nmax_versions = 3\nkeyring_refresh_secs = 30\npolicy_refresh_secs = 2\nshutdown_delay_secs = 5\n\
             {TLS}\n{POLICY}\n\
             [rate_limit]\nserver_max_in_flight = 40\nmax_in_flight = 8\nrequests_per_second = 50\nburst = 60\n\
             [[rate_limit.identity]]\nidentity = \"apps/a\"\nmax_in_flight = 4\nrequests_per_second = 5\nburst = 6\n\
             {IDENTITY}\n\
             [seal]\nprovider = \"shamir\"\n\
             [metrics]\nexporter = \"prometheus\"\nlisten_addr = \"0.0.0.0:9464\"\ntls = true\nclient_ca = \"ca.pem\"\n"
        );
        let all = parse(&all).unwrap();
        assert_eq!(all.rate_limit.identity.len(), 1);
        assert_eq!((all.purge_deleted_after_days, all.max_versions), (7, 3));
        assert_eq!(all.keyring_refresh_secs, 30);
        assert_eq!(all.policy_refresh_secs, 2);
        assert_eq!(parse("").unwrap().policy_refresh_secs, 5);
        assert_eq!(all.shutdown_delay_secs, 5);
        assert_eq!(parse("").unwrap().shutdown_delay_secs, 0);
        assert_eq!(KNOWN_KEYS.len(), 19);
        assert!(matches!(all.metrics().unwrap(), Metrics::Prometheus(_)));
        assert_eq!(all.identity().unwrap().unwrap().issuers.len(), 1);
        assert_eq!(
            (
                all.keys_database_max_connections,
                all.data_database_max_connections
            ),
            (4, 32)
        );
        let defaults = parse("").unwrap();
        assert_eq!(
            (
                defaults.keys_database_max_connections,
                defaults.data_database_max_connections
            ),
            (10, 10)
        );
        assert_eq!(all.audit_signing_key, Some(PathBuf::from("audit-key.pem")));
        assert_eq!(parse("").unwrap().max_versions, 10);
        // Unset: deletions are kept 30 days.
        assert_eq!(
            parse("").unwrap().purge_retention(),
            Duration::from_secs(30 * 24 * 3600)
        );
    }

    /// `[metrics]`: the exporter as chosen; the Prometheus listener on
    /// loopback by default, plaintext there, TLS elsewhere (secured mode
    /// only) unless plaintext is asked for, and never on another listener's
    /// address.
    #[test]
    fn the_metrics_exporter_and_its_listener() {
        let metrics = |toml: &str| parse(toml).map(|s| s.metrics().unwrap());
        assert_eq!(metrics("").unwrap(), Metrics::OtlpIfConfigured);
        assert_eq!(
            metrics("[metrics]\nexporter = \"otlp\"").unwrap(),
            Metrics::Otlp
        );
        assert_eq!(
            metrics("[metrics]\nexporter = \"none\"").unwrap(),
            Metrics::Off
        );
        let prometheus = |addr: &str, tls| {
            Metrics::Prometheus(PrometheusListener {
                addr: addr.parse().unwrap(),
                tls,
                client_ca: None,
            })
        };
        assert_eq!(
            metrics("[metrics]\nexporter = \"prometheus\"").unwrap(),
            prometheus(DEFAULT_METRICS_ADDR, false)
        );
        // Off loopback: TLS, which dev mode doesn't have, unless plaintext
        // is asked for.
        let anywhere = "[metrics]\nexporter = \"prometheus\"\nlisten_addr = \"0.0.0.0:9464\"";
        assert!(
            parse(anywhere)
                .unwrap_err()
                .contains("needs secured mode ([tls])")
        );
        assert_eq!(
            metrics(&format!("{anywhere}\ntls = false")).unwrap(),
            prometheus("0.0.0.0:9464", false)
        );
        assert_eq!(
            metrics(&format!("{TLS}\n{POLICY}\n{anywhere}")).unwrap(),
            prometheus("0.0.0.0:9464", true)
        );
        // TLS on loopback too, when asked, in secured mode only.
        let loopback_tls = "[metrics]\nexporter = \"prometheus\"\ntls = true";
        assert!(parse(loopback_tls).is_err());
        assert_eq!(
            metrics(&format!("{TLS}\n{POLICY}\n{loopback_tls}")).unwrap(),
            prometheus(DEFAULT_METRICS_ADDR, true)
        );
        assert!(
            parse("[metrics]\nexporter = \"prometheus\"\nclient_ca = \"ca.pem\"")
                .unwrap_err()
                .contains("metrics.client_ca needs TLS")
        );
        for refused in [
            "[metrics]\nlisten_addr = \"127.0.0.1:9464\"",
            "[metrics]\nexporter = \"otlp\"\ntls = false",
            "[metrics]\nexporter = \"none\"\nclient_ca = \"ca.pem\"",
        ] {
            assert!(
                parse(refused).unwrap_err().contains("are for exporter"),
                "{refused}"
            );
        }
        assert!(
            parse("[metrics]\nexporter = \"prometheus\"\nlisten_addr = \"127.0.0.1:7070\"")
                .unwrap_err()
                .contains("must differ from listen_addr")
        );
        assert!(
            parse(&format!(
                "{TLS}\n{POLICY}\n{IDENTITY}\n[metrics]\nexporter = \"prometheus\"\n\
                 listen_addr = \"127.0.0.1:7071\""
            ))
            .unwrap_err()
            .contains("must differ from identity.listen_addr")
        );
        assert!(parse("[metrics]\nexporter = \"statsd\"").is_err());
        assert!(parse("[metrics]\nexporter = \"prometheus\"\nport = 9464").is_err());
    }

    /// The audit key loads from PKCS#8 PEM (what `openssl genpkey
    /// -algorithm ed25519` writes); anything else refuses to start, naming
    /// the file but never its contents.
    #[test]
    fn the_audit_signing_key_is_pkcs8_pem() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;

        let dir = std::env::temp_dir().join(format!("ferritor-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = SigningKey::from_bytes(&[9; 32]);
        let good = dir.join("audit-key.pem");
        std::fs::write(&good, key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap();
        assert_eq!(
            audit_key(&good).unwrap().verifying_key(),
            key.verifying_key()
        );

        let bad = dir.join("not-a-key.pem");
        std::fs::write(
            &bad,
            "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let error = crate::error_chain(&audit_key(&bad).unwrap_err());
        assert!(
            error.contains("not-a-key.pem is not an Ed25519 private key"),
            "{error}"
        );
        assert!(!error.contains("c2VjcmV0"), "{error}");
        assert!(matches!(
            audit_key(&dir.join("missing.pem")),
            Err(SecurityError::Read { .. })
        ));

        // Readable beyond its owner: loaded, with a warning.
        use std::os::unix::fs::PermissionsExt;
        let mode = |m| std::fs::set_permissions(&good, std::fs::Permissions::from_mode(m));
        mode(0o600).unwrap();
        assert_eq!(shared_mode(&good), None);
        mode(0o640).unwrap();
        assert_eq!(shared_mode(&good), Some(0o640));
        mode(0o604).unwrap();
        assert_eq!(shared_mode(&good), Some(0o604));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dev_mode_is_loopback_only() {
        assert!(parse("").is_ok());
        let wide = parse("listen_addr = \"0.0.0.0:7070\"").unwrap_err();
        assert!(wide.contains("is not loopback"), "{wide}");
    }

    #[test]
    fn secured_mode_may_listen_anywhere() {
        let settings = parse(&format!("listen_addr = \"0.0.0.0:7443\"\n{TLS}\n{POLICY}")).unwrap();
        let tls = settings.tls.unwrap();
        assert_eq!(
            (tls.max_connection_age_secs, tls.connection_age_grace_secs),
            (3600, 30)
        );
    }

    #[test]
    fn half_secured_refuses_to_start() {
        let tls_only = parse(&format!("listen_addr = \"0.0.0.0:7443\"\n{TLS}")).unwrap_err();
        assert!(tls_only.contains("no [[policy]]"), "{tls_only}");
        // Even on loopback: TLS without a policy would let nobody in.
        assert!(parse(TLS).unwrap_err().contains("no [[policy]]"));
        let policy_only = parse(POLICY).unwrap_err();
        assert!(policy_only.contains("needs [tls]"), "{policy_only}");
        // TLS and a policy, but nothing to sign the audit log with.
        let unsigned = TLS.replace("audit_signing_key = \"audit-key.pem\"", "");
        let unsigned = parse(&format!("{unsigned}\n{POLICY}")).unwrap_err();
        assert!(unsigned.contains("needs audit_signing_key"), "{unsigned}");
    }

    #[test]
    fn a_bad_policy_refuses_to_start() {
        let unknown = parse(&format!(
            "{TLS}\n[[policy]]\nidentity = \"ops/a\"\nactions = [\"sael\"]"
        ))
        .unwrap_err();
        assert!(unknown.contains("sael"), "{unknown}");
        let no_actions = parse(&format!(
            "{TLS}\n[[policy]]\nidentity = \"ops/a\"\nactions = []"
        ))
        .unwrap_err();
        assert!(no_actions.contains("no actions"), "{no_actions}");
    }

    /// SIGHUP reloads the policy, in the mode the server runs in; switching
    /// modes needs a restart.
    #[test]
    fn a_reload_keeps_the_mode() {
        let secured = parse(&format!("{TLS}\n{POLICY}\n{POLICY}")).unwrap();
        let ReloadedPolicy { authz, info } = secured.authz_for_reload(true).unwrap().unwrap();
        assert_eq!(info, PolicyInfo::of(&secured.policy).unwrap());
        assert_eq!(info.rules, 2);
        let alice = Caller::Identity(ferritor_core::path::SecretPath::parse("ops/alice").unwrap());
        assert!(
            authz
                .authorize(&alice, Action::Seal, Target::System)
                .is_ok()
        );
        assert!(
            authz
                .authorize(&alice, Action::Rotate, Target::System)
                .is_err()
        );

        let dev = parse("").unwrap();
        // Dev mode: nothing to reload.
        assert!(dev.authz_for_reload(false).unwrap().is_none());

        for (settings, running) in [(&secured, false), (&dev, true)] {
            let refused = settings.authz_for_reload(running).err().unwrap();
            assert!(
                matches!(refused, ReloadError::ModeChanged { .. }),
                "{refused}"
            );
        }
        assert_eq!(
            dev.authz_for_reload(true).err().unwrap().to_string(),
            "the settings now describe dev mode, but the server runs in secured mode: \
             changing modes needs a restart"
        );
    }

    /// A huge delay (a typo, `u64::MAX` for "infinity") is a config error,
    /// not an overflow panic when startup adds it to the drain limits.
    #[test]
    fn the_shutdown_delay_is_capped() {
        assert_eq!(
            parse("shutdown_delay_secs = 300")
                .unwrap()
                .shutdown_delay_secs,
            300
        );
        // TOML integers are i64, so its largest; the environment can say
        // u64::MAX, which was the overflow.
        for huge in ["301", "9223372036854775807"] {
            let error = parse(&format!("shutdown_delay_secs = {huge}")).unwrap_err();
            assert!(error.contains("must be at most 300"), "{error}");
        }
        let error = from_env(&[
            ("FERRITOR_KEYS_DATABASE_URL", "postgres://k"),
            ("FERRITOR_DATA_DATABASE_URL", "postgres://d"),
            ("FERRITOR_SHUTDOWN_DELAY_SECS", "18446744073709551615"),
        ])
        .unwrap_err();
        assert!(error.contains("must be at most 300"), "{error}");
    }

    /// `[seal]`: the shares by default; AWS KMS with the region from the key's
    /// ARN; an endpoint over plain http only on loopback (the root key is in
    /// the request), decided without DNS.
    #[test]
    fn seal_settings_resolve_and_refuse_what_they_must() {
        let get = |toml: &str| parse(toml).unwrap().auto_unseal();
        assert_eq!(get("").unwrap(), None);
        assert_eq!(get("[seal]\nprovider = \"shamir\"").unwrap(), None);
        let arn = "arn:aws:kms:ap-southeast-1:111122223333:key/k";
        let kms = get(&format!(
            "[seal]\nprovider = \"awskms\"\n[seal.awskms]\nkey_id = \"{arn}\""
        ))
        .unwrap();
        let Some(crate::auto_unseal::ProviderConfig::AwsKms(kms)) = kms else {
            panic!("{kms:?}");
        };
        assert_eq!(
            (kms.key_id.as_str(), kms.region.as_str()),
            (arn, "ap-southeast-1")
        );
        for endpoint in [
            "https://kms.example",
            "http://127.0.0.1:4566",
            "http://[::1]:4566",
            "http://localhost:4566",
        ] {
            let toml = format!(
                "[seal]\nprovider = \"awskms\"\n[seal.awskms]\nkey_id = \"{arn}\"\n\
                 endpoint = \"{endpoint}\""
            );
            assert!(get(&toml).is_ok(), "{endpoint}");
        }
        for (toml, says) in [
            (
                format!(
                    "[seal]\nprovider = \"awskms\"\n[seal.awskms]\nkey_id = \"{arn}\"\n\
                     endpoint = \"http://kms.internal\""
                ),
                "https",
            ),
            (
                "[seal]\nprovider = \"awskms\"\n[seal.awskms]\nkey_id = \"alias/x\"".to_owned(),
                "region",
            ),
            ("[seal]\nprovider = \"awskms\"".to_owned(), "key_id"),
            ("[seal]\nprovider = \"vault\"".to_owned(), "isn't known"),
            (format!("[seal.awskms]\nkey_id = \"{arn}\""), "provider"),
        ] {
            let error = get(&toml).unwrap_err();
            assert!(error.contains(says), "{toml}: {error}");
        }
    }

    /// Every seal mode's provider is one `[seal] provider` knows, with a
    /// section of its own.
    #[test]
    fn every_seal_mode_is_a_known_provider() {
        for provider in crate::seal::SealMode::ALL
            .iter()
            .filter_map(|mode| mode.provider())
        {
            let error = parse(&format!("[seal]\nprovider = \"{provider}\""))
                .unwrap()
                .auto_unseal()
                .unwrap_err();
            assert!(
                error.contains(&format!("needs [seal.{provider}]")),
                "{error}"
            );
        }
    }

    /// `[seal.gcpkms]`: the key's full resource name, never a version or
    /// anything that would change the request's URL; the endpoint as for
    /// AWS; one provider's section at a time.
    #[test]
    fn gcp_kms_settings_resolve_and_refuse_what_they_must() {
        let get = |toml: &str| parse(toml).unwrap().auto_unseal();
        let gcp = |key: &str, extra: &str| {
            get(&format!(
                "[seal]\nprovider = \"gcpkms\"\n[seal.gcpkms]\nkey_name = \"{key}\"\n{extra}"
            ))
        };
        let name = "projects/p-1/locations/asia-southeast1/keyRings/ferritor/cryptoKeys/root-key";
        assert_eq!(
            gcp(name, "").unwrap(),
            Some(crate::auto_unseal::ProviderConfig::GcpKms(
                crate::auto_unseal::GcpKmsConfig {
                    key_name: name.to_owned(),
                    endpoint: None,
                }
            ))
        );
        let scoped = "projects/example.com:p/locations/global/keyRings/r_1/cryptoKeys/k";
        assert!(gcp(scoped, "").is_ok());
        for endpoint in [
            "https://cloudkms-x.p.googleapis.com",
            "http://127.0.0.1:8080",
        ] {
            assert!(
                gcp(name, &format!("endpoint = \"{endpoint}\"")).is_ok(),
                "{endpoint}"
            );
        }
        for (key, says) in [
            (format!("{name}/cryptoKeyVersions/1"), "not a version"),
            ("root-key".to_owned(), "resource name"),
            (format!("{name}/"), "resource name"),
            (
                "projects//locations/l/keyRings/r/cryptoKeys/k".to_owned(),
                "resource name",
            ),
            (
                "projects/p/locations/l/keyRings/r/cryptoKeys/k?x=1".to_owned(),
                "resource name",
            ),
            (
                "projects/p/locations/l/keyRings/r/cryptoKeys/k:encrypt".to_owned(),
                "resource name",
            ),
            (
                "projects/p/locations/l/keyRings/../cryptoKeys/k".to_owned(),
                "resource name",
            ),
            (
                "projects/../locations/l/keyRings/r/cryptoKeys/k".to_owned(),
                "resource name",
            ),
        ] {
            let error = gcp(&key, "").unwrap_err();
            assert!(error.contains(says), "{key}: {error}");
        }
        for (toml, says) in [
            (
                format!(
                    "[seal]\nprovider = \"gcpkms\"\n[seal.gcpkms]\nkey_name = \"{name}\"\n\
                     endpoint = \"http://kms.internal\""
                ),
                "https",
            ),
            ("[seal]\nprovider = \"gcpkms\"".to_owned(), "key_name"),
            (format!("[seal.gcpkms]\nkey_name = \"{name}\""), "provider"),
            (
                format!(
                    "[seal]\nprovider = \"awskms\"\n[seal.awskms]\n\
                     key_id = \"arn:aws:kms:ap-southeast-1:111122223333:key/k\"\n\
                     [seal.gcpkms]\nkey_name = \"{name}\""
                ),
                "one provider at a time",
            ),
        ] {
            let error = get(&toml).unwrap_err();
            assert!(error.contains(says), "{toml}: {error}");
        }
    }

    /// The defaults, each identity entry's fallbacks, and what's refused.
    #[test]
    fn rate_limits_resolve_with_their_defaults_and_fallbacks() {
        use ferritor_core::path::SecretPath;
        let path = |p: &str| SecretPath::parse(p).unwrap();
        let get = |toml: &str| parse(toml).unwrap().limits().unwrap();
        let max = |q: crate::ratelimit::Quota| q.max_in_flight.map(|m| m.get());

        // Nothing configured: the cap from the pool (2 × 10 + 16), a quarter
        // of it per identity, no rate.
        let defaults = get("");
        assert_eq!(defaults.server_max_in_flight.get(), 36);
        assert_eq!(max(defaults.default), Some(9));
        assert_eq!(defaults.default.rate, None);
        // A small cap still leaves each identity 1, never "none".
        assert_eq!(
            max(get("[rate_limit]\nserver_max_in_flight = 3").default),
            Some(1)
        );
        // 0: no per-identity limit.
        assert_eq!(max(get("[rate_limit]\nmax_in_flight = 0").default), None);

        // An entry replaces the default field by field; a rate brings a
        // burst of its own (twice the rate unless given).
        let limits = get(
            "[rate_limit]\nmax_in_flight = 8\nrequests_per_second = 10\n\
             [[rate_limit.identity]]\nidentity = \"apps/batch\"\nmax_in_flight = 32\n\
             [[rate_limit.identity]]\nidentity = \"apps/fast\"\nrequests_per_second = 100\n\
             [[rate_limit.identity]]\nidentity = \"apps/free\"\nrequests_per_second = 0\n",
        );
        let batch = limits.quota(&path("apps/batch/nightly"));
        assert_eq!(max(batch), Some(32));
        assert_eq!(batch.rate, limits.default.rate);
        let fast = limits.quota(&path("apps/fast"));
        assert_eq!(max(fast), Some(8));
        assert_eq!(
            fast.rate,
            Some(crate::ratelimit::Rate::new(
                NonZeroU32::new(100).unwrap(),
                NonZeroU32::new(200).unwrap()
            ))
        );
        assert_eq!(limits.quota(&path("apps/free")).rate, None);

        // Watch streams: 256 per identity by default, an entry's own, or none.
        let streams = |q: crate::ratelimit::Quota| q.max_watch_streams.map(|m| m.get());
        assert_eq!(streams(defaults.default), Some(256));
        let limits = get("[rate_limit]\nmax_watch_streams = 0\n\
             [[rate_limit.identity]]\nidentity = \"k8s/billing\"\nmax_watch_streams = 1000\n");
        assert_eq!(streams(limits.default), None);
        assert_eq!(streams(limits.quota(&path("k8s/billing/api"))), Some(1000));

        for (toml, says) in [
            ("[rate_limit]\nserver_max_in_flight = 0", "at least 1"),
            ("[rate_limit]\nmax_in_flight = 50", "above"),
            ("[rate_limit]\nmax_watch_streams = 5000", "above"),
            ("[rate_limit]\nrequests_per_second = 5\nburst = 0", "burst"),
            (
                "[rate_limit]\nrequests_per_second = 1000001",
                "at most 1000000",
            ),
            (
                "[[rate_limit.identity]]\nidentity = \"a\"\nrequests_per_second = 4000000000",
                "at most 1000000",
            ),
            ("[rate_limit]\nspeed = 5", "unknown field"),
            (
                "[[rate_limit.identity]]\nidentity = \"/bad\"\nmax_in_flight = 1",
                "not a valid identity",
            ),
            (
                "[[rate_limit.identity]]\nidentity = \"a\"\n[[rate_limit.identity]]\nidentity = \"a\"",
                "twice",
            ),
        ] {
            let error = parse(toml).unwrap_err();
            assert!(error.contains(says), "{toml}: {error}");
        }
    }

    #[test]
    fn a_pool_has_at_least_one_connection() {
        let error = parse("data_database_max_connections = 0")
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be at least 1"), "{error}");
        assert!(parse("keys_database_max_connections = 0").is_err());
    }

    #[test]
    fn the_lock_timeout_must_be_below_the_database_timeout() {
        assert!(ensure_timeouts(5000, 2000).is_ok());
        for (database, lock) in [(5000, 5000), (5000, 6000), (5000, 0)] {
            assert!(
                ensure_timeouts(database, lock).is_err(),
                "{database}/{lock}"
            );
        }
    }

    #[test]
    fn only_loopback_addresses_are_allowed_in_dev_mode() {
        for ok in [
            "127.0.0.1:7070",
            "127.0.0.2:1",
            "[::1]:7070",
            "[::ffff:127.0.0.1]:7070",
        ] {
            assert!(ensure_loopback(ok.parse().unwrap()).is_ok(), "{ok}");
        }
        for bad in [
            "0.0.0.0:7070",
            "[::]:7070",
            "10.0.0.5:7070",
            "[2001:db8::1]:7070",
            "[::ffff:10.0.0.5]:7070",
        ] {
            assert!(ensure_loopback(bad.parse().unwrap()).is_err(), "{bad}");
        }
    }
}
