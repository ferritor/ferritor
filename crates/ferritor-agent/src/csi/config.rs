//! The provider's configuration (TOML), checked whole when it loads, unknown
//! keys refused, like the agent's. What each volume holds is the
//! `SecretProviderClass`'s (see `request`); this is the node's: where the
//! server and its exchange are, the socket, and the caches' lifetimes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::config::ConfigError;
use crate::metrics::{MetricsConfig, RawMetrics};

/// Where the driver looks for providers' sockets: its chart's main
/// directory (it also looks in `/etc/kubernetes/secrets-store-csi-providers`).
pub const DEFAULT_SOCKET: &str = "/var/run/secrets-store-csi-providers/ferritor.sock";
/// The token audience the driver's `CSIDriver` asks the kubelet for.
pub const DEFAULT_AUDIENCE: &str = "ferritor";
/// How long a read is shared between the pods of one identity on the node.
pub const DEFAULT_SHARE_READS: Duration = Duration::from_secs(30);
pub const MAX_SHARE_READS: Duration = Duration::from_secs(600);
/// An authoritative refusal's first backoff (the driver's rotation interval
/// by default), doubling to ten times it.
pub const DEFAULT_REFUSAL_BACKOFF: Duration = Duration::from_secs(120);
/// A volume not mounted again for this long is forgotten (the driver never
/// says a volume is gone), with the values kept for it.
pub const DEFAULT_FORGET_VOLUMES: Duration = Duration::from_secs(3600);
/// The largest volume (every file together): under the driver's default
/// gRPC receive limit (4 MiB), with room for the message around it.
pub const DEFAULT_MAX_VOLUME_BYTES: usize = 4 * 1024 * 1024 - 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderConfig {
    /// The ferritor server, `https://`.
    pub server: String,
    /// The CA to verify it (and its exchange) with.
    pub ca: PathBuf,
    /// Its token exchange (`[identity] listen_addr`), `https://`.
    pub exchange: String,
    pub socket: PathBuf,
    pub audience: String,
    /// Zero: every pod reads for itself.
    pub share_reads: Duration,
    pub refusal_backoff: Duration,
    pub forget_volumes_after: Duration,
    pub max_volume_bytes: usize,
    /// Keep a watch stream open per identity, so a read stays valid until
    /// it changes rather than for `share_reads` only.
    pub watch: bool,
    /// `[metrics]`: the exporter, and where the scrape is served.
    pub metrics: MetricsConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    server: String,
    ca: PathBuf,
    exchange: String,
    socket: Option<PathBuf>,
    audience: Option<String>,
    share_reads_secs: Option<u64>,
    refusal_backoff_secs: Option<u64>,
    forget_volumes_after_secs: Option<u64>,
    max_volume_bytes: Option<usize>,
    watch: Option<bool>,
    metrics: Option<RawMetrics>,
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

/// The driver finds a provider by its socket's name, `<name>.sock` with
/// `<name>` of at most 30 letters, digits, `_` and `-`.
fn socket_name_ok(socket: &Path) -> bool {
    socket
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".sock"))
        .is_some_and(|name| {
            name.len() <= 30
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

impl ProviderConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let raw: Raw = toml::from_str(text).map_err(ConfigError::Parse)?;
        for (key, addr) in [("server", &raw.server), ("exchange", &raw.exchange)] {
            if !addr.starts_with("https://") {
                return Err(invalid(format!("{key} {addr:?}: an https:// address")));
            }
        }
        let socket = raw.socket.unwrap_or_else(|| DEFAULT_SOCKET.into());
        if !socket.is_absolute() || !socket_name_ok(&socket) {
            return Err(invalid(format!(
                "socket {}: an absolute path to <name>.sock, <name> at most 30 letters, digits, \
                 '_' and '-' (the driver looks for it by that name)",
                socket.display()
            )));
        }
        let audience = raw.audience.unwrap_or_else(|| DEFAULT_AUDIENCE.to_owned());
        if audience.is_empty() {
            return Err(invalid("audience must be set"));
        }
        let share_reads = raw
            .share_reads_secs
            .map_or(DEFAULT_SHARE_READS, Duration::from_secs);
        if share_reads > MAX_SHARE_READS {
            return Err(invalid(format!(
                "share_reads_secs must be at most {}",
                MAX_SHARE_READS.as_secs()
            )));
        }
        let refusal_backoff = raw
            .refusal_backoff_secs
            .map_or(DEFAULT_REFUSAL_BACKOFF, Duration::from_secs);
        if !(5..=86_400).contains(&refusal_backoff.as_secs()) {
            return Err(invalid("refusal_backoff_secs must be between 5 and 86400"));
        }
        let forget_volumes_after = raw
            .forget_volumes_after_secs
            .map_or(DEFAULT_FORGET_VOLUMES, Duration::from_secs);
        if forget_volumes_after < Duration::from_secs(600) {
            return Err(invalid(
                "forget_volumes_after_secs must be at least 600: longer than the driver's \
                 rotation interval, or a volume's kept values go between two refreshes",
            ));
        }
        let max_volume_bytes = raw.max_volume_bytes.unwrap_or(DEFAULT_MAX_VOLUME_BYTES);
        if !(1024..=64 * 1024 * 1024).contains(&max_volume_bytes) {
            return Err(invalid(
                "max_volume_bytes must be between 1024 and 67108864",
            ));
        }
        Ok(Self {
            server: raw.server,
            ca: raw.ca,
            exchange: raw.exchange,
            socket,
            audience,
            share_reads,
            refusal_backoff,
            forget_volumes_after,
            max_volume_bytes,
            watch: raw.watch.unwrap_or(true),
            metrics: crate::metrics::resolve(
                raw.metrics,
                ferritor_metrics::DEFAULT_CSI_PROVIDER_ADDR,
            )
            .map_err(invalid)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        server = "https://ferritor.internal:7070"
        ca = "/etc/ferritor/ca.pem"
        exchange = "https://ferritor.internal:7071"
    "#;

    #[test]
    fn the_minimal_config_loads_with_its_defaults() {
        let config = ProviderConfig::parse(MINIMAL).unwrap();
        assert_eq!(config.socket, Path::new(DEFAULT_SOCKET));
        assert_eq!(config.audience, "ferritor");
        assert_eq!(config.share_reads, DEFAULT_SHARE_READS);
        assert_eq!(config.refusal_backoff, DEFAULT_REFUSAL_BACKOFF);
        assert_eq!(config.max_volume_bytes, DEFAULT_MAX_VOLUME_BYTES);
    }

    #[test]
    fn mistakes_refuse_to_start() {
        for (extra, says) in [
            ("socket = \"/run/x/ferritor provider.sock\"", "<name>.sock"),
            ("socket = \"relative.sock\"", "absolute"),
            ("socket = \"/run/ferritor.socket\"", "<name>.sock"),
            ("share_reads_secs = 601", "at most 600"),
            ("refusal_backoff_secs = 1", "between 5 and 86400"),
            ("forget_volumes_after_secs = 60", "at least 600"),
            ("max_volume_bytes = 10", "between 1024"),
            ("audience = \"\"", "must be set"),
            ("unknown = 1", "unknown field"),
        ] {
            let error = ProviderConfig::parse(&format!("{MINIMAL}\n{extra}")).unwrap_err();
            let message = format!("{error}: {:?}", std::error::Error::source(&error));
            assert!(message.contains(says), "{extra}\n=> {message}");
        }
        let plain = MINIMAL.replace(
            "https://ferritor.internal:7070",
            "http://ferritor.internal:7070",
        );
        assert!(ProviderConfig::parse(&plain).is_err());
    }
}
