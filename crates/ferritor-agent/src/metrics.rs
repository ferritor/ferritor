//! Metrics, for both binaries: the `[metrics]` section (the server's
//! choice of exporter, `ferritor_metrics`), the scrape's listener, and the
//! instruments ([`agent`] for `ferritor-agent`, `provider`, on Unix only,
//! for `ferritor-csi-provider`). Their tables, with the Prometheus names, are in
//! `agent.md` and `csi.md`, held to a scrape by `tests/metrics.rs`.
//!
//! Attributes are small fixed sets (result, call, state, event, kind):
//! never a path, an identity, a pod, a file or a value. The Prometheus
//! endpoint is plaintext only, neither binary having a certificate to
//! serve with: on loopback by default, anywhere else only with
//! `tls = false` said.

use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};

use ferritor_core::net::is_loopback;
pub use ferritor_metrics::Chosen;
use ferritor_metrics::Exporting;
use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter};
use opentelemetry::{KeyValue, global};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// `[metrics]` as written.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawMetrics {
    exporter: Option<Exporter>,
    listen_addr: Option<SocketAddr>,
    tls: Option<bool>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Exporter {
    Otlp,
    Prometheus,
    None,
}

/// `[metrics]`, checked: the exporter (as the server chooses one), and for
/// Prometheus where the scrape is served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricsConfig {
    pub exporter: Chosen,
    /// Prometheus only.
    pub listen_addr: Option<SocketAddr>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            exporter: Chosen::OtlpIfConfigured,
            listen_addr: None,
        }
    }
}

/// Checks `raw`: `listen_addr` and `tls` only for Prometheus; the address
/// `default_addr` unless given; plaintext off loopback only with
/// `tls = false` said, and never `tls = true` (no certificate to serve).
pub(crate) fn resolve(
    raw: Option<RawMetrics>,
    default_addr: &str,
) -> Result<MetricsConfig, String> {
    let raw = raw.unwrap_or_default();
    let exporter = match raw.exporter {
        None => Chosen::OtlpIfConfigured,
        Some(Exporter::Otlp) => Chosen::Otlp,
        Some(Exporter::Prometheus) => Chosen::Prometheus,
        Some(Exporter::None) => Chosen::Off,
    };
    if exporter != Chosen::Prometheus {
        if raw.listen_addr.is_some() || raw.tls.is_some() {
            return Err(
                "metrics.listen_addr and metrics.tls are for exporter = \"prometheus\"".to_owned(),
            );
        }
        return Ok(MetricsConfig {
            exporter,
            listen_addr: None,
        });
    }
    if raw.tls == Some(true) {
        return Err(
            "metrics.tls = true: metrics are served in plaintext only (there's no certificate \
             to serve them with); scrape on loopback, or set metrics.tls = false off it"
                .to_owned(),
        );
    }
    let addr = match raw.listen_addr {
        Some(addr) => addr,
        None => default_addr
            .parse()
            .map_err(|e| format!("the default metrics address: {e}"))?,
    };
    if !is_loopback(addr.ip()) && raw.tls != Some(false) {
        return Err(format!(
            "metrics.listen_addr {addr} is off loopback, where metrics are served in plaintext: \
             set metrics.tls = false to do so on purpose"
        ));
    }
    Ok(MetricsConfig {
        exporter,
        listen_addr: Some(addr),
    })
}

/// The exporter in use, and the scrape's listener if there is one.
pub struct Running {
    exporting: Exporting,
    serving: Option<(oneshot::Sender<()>, JoinHandle<()>)>,
    /// Where the scrape is served, as bound (a port 0 resolved).
    local_addr: Option<SocketAddr>,
}

/// Installs the exporter `config` chose, as `service`, and serves the
/// scrape if it's Prometheus (unless `serve` is false: `once` exits before
/// anyone would scrape it). Before anything records.
pub async fn start(
    config: &MetricsConfig,
    service: &'static str,
    serve: bool,
) -> Result<Running, String> {
    let chosen = match config.exporter {
        Chosen::Prometheus if !serve => {
            tracing::info!("metrics not served: once exits before a scrape");
            Chosen::Off
        }
        chosen => chosen,
    };
    let exporting =
        ferritor_metrics::start(chosen, service).map_err(|e| crate::agent::error_chain(&e))?;
    let mut local_addr = None;
    let serving = match (exporting.scrape(), config.listen_addr) {
        (Some(scrape), Some(addr)) => {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| format!("listening on {addr} ([metrics] listen_addr): {e}"))?;
            let addr = listener.local_addr().unwrap_or(addr);
            local_addr = Some(addr);
            if !is_loopback(addr.ip()) {
                tracing::warn!(
                    %addr,
                    "serving metrics in plaintext off loopback (metrics.tls = false): anyone who \
                     reaches the port reads them"
                );
            }
            tracing::info!(%addr, "serving metrics for Prometheus (GET /metrics)");
            let (stop, stopped) = oneshot::channel::<()>();
            let routes = scrape.clone().router();
            let task = tokio::spawn(async move {
                let served = ferritor_metrics::serve_plaintext(routes, listener, async {
                    stopped.await.ok();
                })
                .await;
                if let Err(e) = served {
                    tracing::error!(error = %crate::agent::error_chain(&e), "the metrics listener stopped");
                }
            });
            Some((stop, task))
        }
        _ => None,
    };
    Ok(Running {
        exporting,
        serving,
        local_addr,
    })
}

impl Running {
    /// Where the scrape is served, if it is.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// At exit: stops the scrape's listener (a scrape still open is waited
    /// for a moment), then flushes the last OTLP export.
    pub async fn finish(self) {
        if let Some((stop, task)) = self.serving {
            stop.send(()).ok();
            if tokio::time::timeout(ferritor_metrics::FLUSH_LIMIT, task)
                .await
                .is_err()
            {
                tracing::warn!("a scrape still open at exit: not waiting for it");
            }
        }
        self.exporting.finish().await;
    }
}

/// Request durations: a round is a few calls, each a few milliseconds, up
/// to the client's timeouts against a server that doesn't answer.
const DURATION_BUCKETS: [f64; 13] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// A call's result as the agent sorts it (`agent::classify`): `ok`,
/// `permission_denied`, `not_found`, `invalid` (authoritative), or
/// `transient`.
pub(crate) fn call_result(result: Result<(), &ferritor_client::ServerError>) -> &'static str {
    use crate::agent::{Refusal, Revoked, classify};
    match result {
        Ok(()) => "ok",
        Err(e) => match classify(e) {
            Refusal::Authoritative(Revoked::PermissionDenied) => "permission_denied",
            Refusal::Authoritative(Revoked::NotFound) => "not_found",
            Refusal::Authoritative(Revoked::Invalid) => "invalid",
            Refusal::Transient { .. } => "transient",
        },
    }
}

/// Whole seconds since the epoch, for a time gauge.
fn unix_secs(at: SystemTime) -> u64 {
    at.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// `ferritor-agent`'s instruments.
pub struct AgentMetrics {
    rounds: Counter<u64>,
    round_duration: Histogram<f64>,
    calls: Counter<u64>,
    writes: Counter<u64>,
    notifications: Counter<u64>,
    exchanges: Counter<u64>,
    watch_events: Counter<u64>,
    secrets: Gauge<u64>,
    last_success: Gauge<u64>,
    watch_ready: Gauge<u64>,
    certificate_expiry: Gauge<u64>,
}

static AGENT: LazyLock<AgentMetrics> =
    LazyLock::new(|| AgentMetrics::new(&global::meter("ferritor-agent")));

/// The agent's instruments: created on first use from the global meter, and
/// bound to whatever provider it has then, for the life of the process. So
/// `main` starts the exporter ([`start`]) before anything records.
pub fn agent() -> &'static AgentMetrics {
    &AGENT
}

impl AgentMetrics {
    fn new(meter: &Meter) -> Self {
        Self {
            rounds: meter
                .u64_counter("ferritor.agent.rounds")
                .with_description("Rounds, by result (ok, transient: stopped by a transient refusal)")
                .build(),
            round_duration: meter
                .f64_histogram("ferritor.agent.round.duration")
                .with_unit("s")
                .with_description("Time a round took (its writes included), by result")
                .with_boundaries(DURATION_BUCKETS.to_vec())
                .build(),
            calls: meter
                .u64_counter("ferritor.agent.calls")
                .with_description("Calls to the server, by call (get, list, watch) and result")
                .build(),
            writes: meter
                .u64_counter("ferritor.agent.writes")
                .with_description("Sets of files written (a new generation swapped in), by result")
                .build(),
            notifications: meter
                .u64_counter("ferritor.agent.notifications")
                .with_description(
                    "Applications told of a change (on_change), by kind (signal, command) and result",
                )
                .build(),
            exchanges: meter
                .u64_counter("ferritor.agent.exchanges")
                .with_description("Token exchanges for a client certificate, by result")
                .build(),
            watch_events: meter
                .u64_counter("ferritor.agent.watch.events")
                .with_description(
                    "What the watch stream did: ready, changed, resync, ended, failed (to open or \
                     while open)",
                )
                .build(),
            secrets: meter
                .u64_gauge("ferritor.agent.secrets")
                .with_description(
                    "Configured secrets, by state (current: readable, its value in its file; \
                     refused: refused for good, its file per on_revoked; pending: neither yet)",
                )
                .build(),
            last_success: meter
                .u64_gauge("ferritor.agent.last_success")
                .with_unit("s")
                .with_description("When the last round succeeded (unix seconds)")
                .build(),
            watch_ready: meter
                .u64_gauge("ferritor.agent.watch.ready")
                .with_description("1 while a ready watch stream covers every watched secret, else 0")
                .build(),
            certificate_expiry: meter
                .u64_gauge("ferritor.agent.certificate.expiry")
                .with_unit("s")
                .with_description(
                    "When the client certificate in use expires (unix seconds; from its file, or \
                     as exchanged)",
                )
                .build(),
        }
    }

    pub fn round(&self, transient: bool, took: Duration) {
        let result = [KeyValue::new(
            "result",
            if transient { "transient" } else { "ok" },
        )];
        self.rounds.add(1, &result);
        self.round_duration.record(took.as_secs_f64(), &result);
        if !transient {
            self.last_success.record(unix_secs(SystemTime::now()), &[]);
        }
    }

    pub fn call(&self, call: &'static str, result: &'static str) {
        self.calls.add(
            1,
            &[KeyValue::new("call", call), KeyValue::new("result", result)],
        );
    }

    pub fn write(&self, ok: bool) {
        self.writes.add(
            1,
            &[KeyValue::new("result", if ok { "ok" } else { "failed" })],
        );
    }

    /// `result`: ok, failed, timed_out (a command still running, left to
    /// itself).
    pub fn notification(&self, kind: &'static str, result: &'static str) {
        self.notifications.add(
            1,
            &[KeyValue::new("kind", kind), KeyValue::new("result", result)],
        );
    }

    pub fn exchange(&self, ok: bool) {
        self.exchanges.add(
            1,
            &[KeyValue::new("result", if ok { "ok" } else { "failed" })],
        );
    }

    pub fn watch_event(&self, event: &'static str) {
        self.watch_events.add(1, &[KeyValue::new("event", event)]);
    }

    pub fn secrets(&self, current: u64, refused: u64, pending: u64) {
        for (state, count) in [
            ("current", current),
            ("refused", refused),
            ("pending", pending),
        ] {
            self.secrets.record(count, &[KeyValue::new("state", state)]);
        }
    }

    pub fn watch_ready(&self, ready: bool) {
        self.watch_ready.record(u64::from(ready), &[]);
    }

    pub fn certificate_expiry(&self, not_after: SystemTime) {
        self.certificate_expiry.record(unix_secs(not_after), &[]);
    }
}

#[cfg(unix)]
/// `ferritor-csi-provider`'s instruments (its gauges are observed from its
/// state: `csi::provider`). Unix only, as the provider is.
pub struct ProviderMetrics {
    mounts: Counter<u64>,
    mount_duration: Histogram<f64>,
    calls: Counter<u64>,
    from_memory: Counter<u64>,
    exchanges: Counter<u64>,
    watch_events: Counter<u64>,
}

#[cfg(unix)]
/// The provider's meter, for its observed gauges too.
pub(crate) fn provider_meter() -> Meter {
    global::meter("ferritor-csi-provider")
}

#[cfg(unix)]
static PROVIDER: LazyLock<ProviderMetrics> =
    LazyLock::new(|| ProviderMetrics::new(&provider_meter()));

#[cfg(unix)]
/// The provider's instruments, as [`agent`]'s: bound to the provider the
/// global meter has at first use.
pub fn provider() -> &'static ProviderMetrics {
    &PROVIDER
}

#[cfg(unix)]
impl ProviderMetrics {
    fn new(meter: &Meter) -> Self {
        Self {
            mounts: meter
                .u64_counter("ferritor.csi.mounts")
                .with_description(
                    "Mount calls from the driver, by result (ok, refused, failed: transient, \
                     invalid: the SecretProviderClass)",
                )
                .build(),
            mount_duration: meter
                .f64_histogram("ferritor.csi.mount.duration")
                .with_unit("s")
                .with_description("Time to answer a mount, by result")
                .with_boundaries(DURATION_BUCKETS.to_vec())
                .build(),
            calls: meter
                .u64_counter("ferritor.csi.calls")
                .with_description("Calls to the server, by call (get, list, watch) and result")
                .build(),
            from_memory: meter
                .u64_counter("ferritor.csi.from_memory")
                .with_description(
                    "Answers from memory instead of the server, by kind (read: shared, vouched \
                     for by a watch, or the volume's own at the listed version; listing: shared \
                     or vouched for by a watch; refusal: remembered, backing off)",
                )
                .build(),
            exchanges: meter
                .u64_counter("ferritor.csi.exchanges")
                .with_description(
                    "Pods' tokens exchanged for a certificate (renewals too), by result (issued, \
                     refused, failed)",
                )
                .build(),
            watch_events: meter
                .u64_counter("ferritor.csi.watch.events")
                .with_description(
                    "What the identities' watch streams did: ready, changed, resync, ended, failed",
                )
                .build(),
        }
    }

    /// `result`: ok, refused, failed, invalid.
    pub fn mount(&self, result: &'static str, took: Duration) {
        let result = [KeyValue::new("result", result)];
        self.mounts.add(1, &result);
        self.mount_duration.record(took.as_secs_f64(), &result);
    }

    pub fn call(&self, call: &'static str, result: &'static str) {
        self.calls.add(
            1,
            &[KeyValue::new("call", call), KeyValue::new("result", result)],
        );
    }

    /// `kind`: read, listing, refusal.
    pub fn answered_from_memory(&self, kind: &'static str) {
        self.from_memory.add(1, &[KeyValue::new("kind", kind)]);
    }

    /// `result`: issued, refused, failed.
    pub fn exchange(&self, result: &'static str) {
        self.exchanges.add(1, &[KeyValue::new("result", result)]);
    }

    pub fn watch_event(&self, event: &'static str) {
        self.watch_events.add(1, &[KeyValue::new("event", event)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<MetricsConfig, String> {
        let raw: RawMetrics = toml::from_str(text).map_err(|e| e.to_string())?;
        resolve(Some(raw), "127.0.0.1:9465")
    }

    /// As the server chooses an exporter; the listener plaintext, off
    /// loopback only with `tls = false` said, never TLS.
    #[test]
    fn the_exporter_and_its_listener() {
        assert_eq!(
            resolve(None, "127.0.0.1:9465"),
            Ok(MetricsConfig::default())
        );
        assert_eq!(
            parse("exporter = \"otlp\"").map(|m| m.exporter),
            Ok(Chosen::Otlp)
        );
        assert_eq!(
            parse("exporter = \"none\"").map(|m| m.exporter),
            Ok(Chosen::Off)
        );
        assert_eq!(
            parse("exporter = \"prometheus\""),
            Ok(MetricsConfig {
                exporter: Chosen::Prometheus,
                listen_addr: "127.0.0.1:9465".parse().ok(),
            })
        );
        let anywhere = "exporter = \"prometheus\"\nlisten_addr = \"0.0.0.0:9465\"";
        assert!(parse(anywhere).is_err_and(|e| e.contains("tls = false")));
        assert_eq!(
            parse(&format!("{anywhere}\ntls = false")).map(|m| m.listen_addr),
            Ok("0.0.0.0:9465".parse().ok())
        );
        assert!(parse("exporter = \"prometheus\"\ntls = true").is_err());
        assert!(parse("exporter = \"prometheus\"\nlisten_addr = \"[::1]:1\"\ntls = false").is_ok());
        for misplaced in [
            "listen_addr = \"127.0.0.1:1\"",
            "exporter = \"otlp\"\ntls = false",
        ] {
            assert!(parse(misplaced).is_err(), "{misplaced}");
        }
        assert!(parse("exporter = \"statsd\"").is_err());
        assert!(parse("port = 1").is_err());
    }
}
