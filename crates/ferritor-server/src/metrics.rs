//! Metrics, the OpenTelemetry way: instruments on the global meter, read by
//! the exporter `[metrics]` chose. Pushed over OTLP/gRPC ([`init`]) to a
//! collector, with the standard variables (`OTEL_EXPORTER_OTLP_ENDPOINT` or
//! `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`; also `OTEL_METRIC_EXPORT_INTERVAL`,
//! default 60 s, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_SERVICE_NAME`, default
//! `ferritor-server`), or scraped by Prometheus ([`init_prometheus`], see
//! [`crate::prometheus`] for the names there). With neither no provider is
//! installed, and every instrument is a no-op.
//!
//! `https://` (or an endpoint without a scheme, per the OTLP spec, unless
//! `OTEL_EXPORTER_OTLP_INSECURE=true`) uses TLS with the web PKI roots,
//! plus `OTEL_EXPORTER_OTLP_CERTIFICATE` for a private CA and
//! `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`/`_CLIENT_KEY` for mTLS (see
//! [`Export`]); `http://` is plaintext, fine for a local agent.
//!
//! Attributes are small fixed sets (operation, result, action, decision,
//! reason, limit): never secret paths, caller identities, certificate
//! fingerprints or values, which would
//! leak names and make the number of series unbounded.
//!
//! | Instrument | Kind | Attributes |
//! |---|---|---|
//! | `ferritor.secret.requests` | counter | `operation` (get, put, delete, list), `result` |
//! | `ferritor.secret.request.duration` | histogram (s) | `operation`, `result` |
//! | `ferritor.admin.outcomes` | counter | `operation`, `result` (succeeded, failed, unknown) |
//! | `ferritor.authorization.decisions` | counter | `action`, `decision` |
//! | `ferritor.audit.failures` | counter | `kind` (refused: a request refused unaudited; lost: an entry not written) |
//! | `ferritor.versions.trimmed` | counter | |
//! | `ferritor.versions.purged` | counter | |
//! | `ferritor.deks.rewrapped` | counter | |
//! | `ferritor.tls.handshake.failures` | counter | `listener` (api, exchange, metrics), `reason` (failed, timed_out) |
//! | `ferritor.rate_limit.refused` | counter | `limit` (rate, in_flight, denied, unauthenticated; server: no slot under the server-wide cap in time) |
//! | `ferritor.identity.exchanges` | counter | `issuer` (a configured issuer's name, or unknown), `result` (issued, refused, unavailable, rate_limited) |
//! | `ferritor.rate_limit.waited` | histogram (s) | (the wait for a slot under the server-wide cap) |
//! | `ferritor.reloads` | counter | `kind` (policy, certificate, crl, keyring), `result` (succeeded, failed, skipped; keyring: changed, unchanged, failed) |
//! | `ferritor.audit.queue.depth` | gauge | (entries waiting for the writer) |
//! | `ferritor.in_flight` | gauge | (calls in flight, every one: exempt admin calls too) |
//! | `ferritor.sealed` | gauge | (1 sealed, 0 unsealed) |
//! | `ferritor.namespaces` | gauge | (namespaces this server holds KEKs of; absent while sealed) |
//! | `ferritor.policy.revision` | gauge | (the stored policies' verified revision in force; absent unless one is: compare it across servers to catch a rollback) |
//! | `ferritor.policies` | gauge | (stored policies in force; absent unless verified) |
//! | `ferritor.seal.auto_unseal` | counter | `result` (ok, kms_unavailable, denied, mismatch, root_commitment, below_floor, no_wrap, held, failed) |
//! | `ferritor.seal.hold_pending` | gauge | (auto-unseal hold writes being retried; 0 normally) |
//! | `ferritor.seal.floor_pending` | gauge | (root-generation floor raises being retried; 0 normally) |
//! | `ferritor.kek.vanished` | gauge | (KEKs held for reading only that the keys database lost; 0 normally, absent while sealed) |
//! | `ferritor.server_certificate.expiry` | gauge (unix s) | (secured mode only) |
//! | `ferritor.tls.crl.next_update` | gauge (unix s) | (the earliest `nextUpdate` of the CRLs in force; absent without) |
//! | `ferritor.watch.streams` | gauge | (watch streams open) |
//! | `ferritor.watch.feed.live` | gauge | (1 while the change feed polls the data database, 0 while it can't) |
//! | `ferritor.watch.feed.held_back` | gauge (s) | (how long one transaction, open on the data database's Postgres server, has held the change feed back; 0 normally) |
//! | `ferritor.watch.resyncs` | counter | `reason` (too_many, restarted: every stream told; lagged: one stream behind) |
//!
//! A secret request's `result` is `ok` or the error's category (`denied`,
//! `sealed`, `not_found`, `version_mismatch`, …: see `secrets`).

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use opentelemetry::metrics::{Counter, Histogram, Meter, ObservableGauge};
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{ExporterBuildError, MetricExporter, WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use tonic::transport::{Certificate, ClientTlsConfig, Identity};
use zeroize::Zeroizing;

use crate::audit::Gate;
use crate::policy_store::PolicyView;
use crate::prometheus::Scrape;
use crate::ratelimit;
use crate::seal::Seal;
use crate::tls::ServerTls;
use crate::watch::Watch;

/// Where and how to export: built from the standard variables
/// ([`Export::from_env`]) or directly (tests).
#[derive(Default)]
pub struct Export {
    /// As given; `None`: the exporter's default (`http://localhost:4317`).
    pub endpoint: Option<String>,
    /// `OTEL_EXPORTER_OTLP_INSECURE`: a scheme-less endpoint is plaintext.
    pub insecure: bool,
    /// Trusted for the collector's certificate, besides the public roots
    /// (`OTEL_EXPORTER_OTLP_CERTIFICATE`: a private CA, PEM).
    pub ca_pem: Option<Vec<u8>>,
    /// Presented to the collector (mTLS: `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`
    /// and `OTEL_EXPORTER_OTLP_CLIENT_KEY`, PEM, both or neither).
    pub client: Option<(Vec<u8>, Zeroizing<Vec<u8>>)>,
}

#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    #[error("reading {var} ({path})")]
    Read {
        var: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE and OTEL_EXPORTER_OTLP_CLIENT_KEY go together")]
    HalfAClientIdentity,
    #[error("building the OTLP exporter")]
    Exporter(#[source] ExporterBuildError),
}

/// The metrics-specific variable, else the general one (the OTLP spec's
/// precedence).
fn var(name: &str) -> Option<String> {
    let specific = name.replacen("OTEL_EXPORTER_OTLP_", "OTEL_EXPORTER_OTLP_METRICS_", 1);
    [specific.as_str(), name]
        .into_iter()
        .find_map(|var| std::env::var(var).ok())
        .filter(|value| !value.trim().is_empty())
}

/// Whether an OTLP endpoint is configured (`OTEL_EXPORTER_OTLP_ENDPOINT`
/// or its metrics variant), for a warning when another exporter is chosen.
pub fn otlp_endpoint_set() -> bool {
    var("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
}

impl Export {
    /// From the standard variables; `None` if no endpoint is set (metrics
    /// off). The exporter reads the endpoint itself too; the TLS settings
    /// it doesn't implement, so they're applied here.
    pub fn from_env() -> Result<Option<Self>, MetricsError> {
        let Some(endpoint) = var("OTEL_EXPORTER_OTLP_ENDPOINT") else {
            return Ok(None);
        };
        let read = |var_name: &'static str| -> Result<Option<Vec<u8>>, MetricsError> {
            var(var_name)
                .map(|path| {
                    std::fs::read(&path).map_err(|source| MetricsError::Read {
                        var: var_name,
                        path,
                        source,
                    })
                })
                .transpose()
        };
        let client = match (
            read("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE")?,
            read("OTEL_EXPORTER_OTLP_CLIENT_KEY")?,
        ) {
            (Some(cert), Some(key)) => Some((cert, Zeroizing::new(key))),
            (None, None) => None,
            _ => return Err(MetricsError::HalfAClientIdentity),
        };
        Ok(Some(Self {
            endpoint: Some(endpoint),
            insecure: var("OTEL_EXPORTER_OTLP_INSECURE")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("true")),
            ca_pem: read("OTEL_EXPORTER_OTLP_CERTIFICATE")?,
            client,
        }))
    }

    /// Whether the collector is reached over TLS, as the OTLP spec says:
    /// by the scheme, and without one unless insecure.
    fn uses_tls(&self) -> bool {
        match self.endpoint.as_deref() {
            None => false,
            Some(endpoint) if endpoint.starts_with("https://") => true,
            Some(endpoint) if endpoint.contains("://") => false,
            Some(_) => !self.insecure,
        }
    }

    /// The TLS to reach the collector with: the public (webpki) roots, a
    /// private CA if given, and a client certificate for mTLS. Applied by
    /// us because the exporter's own default for https enables no roots at
    /// all in tonic 0.14, so it couldn't verify any collector.
    fn tls(&self) -> ClientTlsConfig {
        let mut tls = ClientTlsConfig::new().with_webpki_roots();
        if let Some(ca) = &self.ca_pem {
            tls = tls.ca_certificate(Certificate::from_pem(ca));
        }
        if let Some((cert, key)) = &self.client {
            tls = tls.identity(Identity::from_pem(cert, key.as_slice()));
        }
        tls
    }
}

/// Starts exporting as `export` says; `None` when there's nothing to
/// export to (metrics off). Must run before anything records (see
/// [`metrics`]), inside the tokio runtime (the exporter uses tonic), and the
/// returned provider must be shut down at exit to flush.
pub fn init(export: Option<Export>) -> Result<Option<SdkMeterProvider>, MetricsError> {
    let Some(export) = export else {
        return Ok(None);
    };
    let mut exporter = MetricExporter::builder().with_tonic();
    if let Some(endpoint) = &export.endpoint {
        // Scheme-less endpoints get theirs from the exporter (insecure:
        // http, else https), which `uses_tls` mirrors.
        exporter = exporter.with_endpoint(endpoint);
    }
    if export.uses_tls() {
        exporter = exporter.with_tls_config(export.tls());
    }
    let provider = SdkMeterProvider::builder()
        .with_periodic_exporter(exporter.build().map_err(MetricsError::Exporter)?)
        .with_resource(
            Resource::builder()
                .with_service_name("ferritor-server")
                .build(),
        )
        .build();
    global::set_meter_provider(provider.clone());
    Ok(Some(provider))
}

/// Serves the instruments for Prometheus to scrape instead
/// (`[metrics] exporter = "prometheus"`): the returned [`Scrape`] renders
/// them on demand. As with [`init`], before anything records; the provider
/// needs no flush at exit (nothing is pushed), but stays alive as long as
/// the scrape is served.
pub fn init_prometheus() -> (SdkMeterProvider, Scrape) {
    let scrape = Scrape::new();
    let provider = SdkMeterProvider::builder()
        .with_reader(scrape.reader())
        .with_resource(
            Resource::builder()
                .with_service_name("ferritor-server")
                .build(),
        )
        .build();
    global::set_meter_provider(provider.clone());
    (provider, scrape)
}

/// The instruments that record events, created on first use from the
/// global meter (so after [`init`]).
pub struct Metrics {
    secret_requests: Counter<u64>,
    secret_duration: Histogram<f64>,
    admin_outcomes: Counter<u64>,
    decisions: Counter<u64>,
    audit_failures: Counter<u64>,
    trimmed: Counter<u64>,
    purged: Counter<u64>,
    rewrapped: Counter<u64>,
    handshake_failures: Counter<u64>,
    reloads: Counter<u64>,
    rate_limited: Counter<u64>,
    rate_limit_waited: Histogram<f64>,
    exchanges: Counter<u64>,
    watch_resyncs: Counter<u64>,
    auto_unseals: Counter<u64>,
}

static METRICS: LazyLock<Metrics> = LazyLock::new(|| Metrics::new(&meter()));

/// The process's instruments. Created on first use from the global meter,
/// and bound to whatever provider it has then, for the life of the process:
/// anything that records before [`init`] runs leaves every instrument a
/// no-op for good. So `main` calls `init` before anything else, and nothing
/// may record during startup ahead of it.
pub fn metrics() -> &'static Metrics {
    &METRICS
}

fn meter() -> Meter {
    global::meter("ferritor-server")
}

impl Metrics {
    fn new(meter: &Meter) -> Self {
        Self {
            secret_requests: meter
                .u64_counter("ferritor.secret.requests")
                .with_description("Secret operations, by operation and result")
                .build(),
            secret_duration: meter
                .f64_histogram("ferritor.secret.request.duration")
                .with_unit("s")
                .with_description("Time to answer a secret operation")
                .with_boundaries(vec![
                    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ])
                .build(),
            admin_outcomes: meter
                .u64_counter("ferritor.admin.outcomes")
                .with_description("Admin calls that change state, by operation and result")
                .build(),
            decisions: meter
                .u64_counter("ferritor.authorization.decisions")
                .with_description("Authorization decisions, by action and decision")
                .build(),
            audit_failures: meter
                .u64_counter("ferritor.audit.failures")
                .with_description("Audit log failures: requests refused unaudited, entries lost")
                .build(),
            trimmed: meter
                .u64_counter("ferritor.versions.trimmed")
                .with_description("Versions a put marked deleted to stay within max_versions")
                .build(),
            purged: meter
                .u64_counter("ferritor.versions.purged")
                .with_description("Deleted versions removed for good")
                .build(),
            rewrapped: meter
                .u64_counter("ferritor.deks.rewrapped")
                .with_description("DEKs moved to the active KEK")
                .build(),
            handshake_failures: meter
                .u64_counter("ferritor.tls.handshake.failures")
                .with_description("TLS handshakes that failed or timed out")
                .build(),
            reloads: meter
                .u64_counter("ferritor.reloads")
                .with_description("SIGHUP reloads of the policy and the server certificate")
                .build(),
            rate_limited: meter
                .u64_counter("ferritor.rate_limit.refused")
                .with_description("Requests refused by a rate limit, by limit (never the caller)")
                .build(),
            exchanges: meter
                .u64_counter("ferritor.identity.exchanges")
                .with_description(
                    "Workload token exchanges, by issuer (as configured; never an identity) and result",
                )
                .build(),
            rate_limit_waited: meter
                .f64_histogram("ferritor.rate_limit.waited")
                .with_unit("s")
                .with_description("Time a call waited for a slot under the server-wide cap")
                .with_boundaries(vec![
                    0.0, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0,
                ])
                .build(),
            auto_unseals: meter
                .u64_counter("ferritor.seal.auto_unseal")
                .with_description(
                    "Auto-unseal attempts, by result (ok, kms_unavailable, denied, mismatch, \
                     root_commitment, below_floor, no_wrap, held, failed)",
                )
                .build(),
            watch_resyncs: meter
                .u64_counter("ferritor.watch.resyncs")
                .with_description(
                    "Watch streams told to read everything again, by reason: too_many and \
                     restarted count once for every stream, lagged once per stream",
                )
                .build(),
        }
    }

    /// `limit`: rate, in_flight, denied, unauthenticated, or server (no slot
    /// under the server-wide cap in time).
    pub fn rate_limited(&self, limit: &'static str) {
        self.rate_limited.add(1, &[KeyValue::new("limit", limit)]);
    }

    /// `issuer`: a configured issuer's name, or `unknown`; `result`:
    /// issued, refused, unavailable.
    pub fn exchange(&self, issuer: &str, result: &'static str) {
        self.exchanges.add(
            1,
            &[
                KeyValue::new("issuer", issuer.to_owned()),
                KeyValue::new("result", result),
            ],
        );
    }

    pub fn rate_limit_waited(&self, took: Duration) {
        self.rate_limit_waited.record(took.as_secs_f64(), &[]);
    }

    pub fn secret_request(&self, operation: &'static str, result: &'static str, took: Duration) {
        let attributes = [
            KeyValue::new("operation", operation),
            KeyValue::new("result", result),
        ];
        self.secret_requests.add(1, &attributes);
        self.secret_duration.record(took.as_secs_f64(), &attributes);
    }

    pub fn admin_outcome(&self, operation: &'static str, result: &'static str) {
        self.admin_outcomes.add(
            1,
            &[
                KeyValue::new("operation", operation),
                KeyValue::new("result", result),
            ],
        );
    }

    pub fn decision(&self, action: &'static str, decision: &'static str) {
        self.decisions.add(
            1,
            &[
                KeyValue::new("action", action),
                KeyValue::new("decision", decision),
            ],
        );
    }

    pub fn audit_failure(&self, kind: &'static str) {
        self.audit_failures.add(1, &[KeyValue::new("kind", kind)]);
    }

    pub fn trimmed(&self, count: u64) {
        self.trimmed.add(count, &[]);
    }

    pub fn purged(&self, count: u64) {
        self.purged.add(count, &[]);
    }

    pub fn rewrapped(&self, count: u64) {
        self.rewrapped.add(count, &[]);
    }

    /// `kind`: policy or certificate; `result`: succeeded, failed, skipped.
    pub fn reload(&self, kind: &'static str, result: &'static str) {
        self.reloads.add(
            1,
            &[KeyValue::new("kind", kind), KeyValue::new("result", result)],
        );
    }

    /// `listener`: api, exchange or metrics (a scraper without the right
    /// certificate isn't a failing API client); `reason`: failed, timed_out.
    pub fn handshake_failure(&self, listener: &'static str, reason: &'static str) {
        self.handshake_failures.add(
            1,
            &[
                KeyValue::new("listener", listener),
                KeyValue::new("reason", reason),
            ],
        );
    }

    /// `reason`: too_many, restarted (the feed's, for every stream) or
    /// lagged (one stream's).
    pub fn watch_resync(&self, reason: &'static str) {
        self.watch_resyncs
            .add(1, &[KeyValue::new("reason", reason)]);
    }

    /// `result`: the auto-unseal attempt's (see [`crate::seal::AutoReport`]).
    pub fn auto_unseal(&self, result: &'static str) {
        self.auto_unseals.add(1, &[KeyValue::new("result", result)]);
    }
}

/// The watch hub's gauges: streams open, and whether its change feed is
/// live. Keep the returned handles for as long as they should report.
pub fn observe_watch(watch: Arc<Watch>) -> Vec<ObservableGauge<u64>> {
    let meter = meter();
    let streams = {
        let watch = Arc::clone(&watch);
        meter
            .u64_observable_gauge("ferritor.watch.streams")
            .with_description("Watch streams open on this server")
            .with_callback(move |gauge| {
                gauge.observe(u64::try_from(watch.streams()).unwrap_or(u64::MAX), &[]);
            })
            .build()
    };
    let live = meter
        .u64_observable_gauge("ferritor.watch.feed.live")
        .with_description(
            "1 while the change feed polls the data database; 0 while it can't (no new \
             watch streams, open ones hear of changes once it's back)",
        )
        .with_callback({
            let watch = Arc::clone(&watch);
            move |gauge| gauge.observe(u64::from(watch.is_live()), &[])
        })
        .build();
    let held_back = meter
        .u64_observable_gauge("ferritor.watch.feed.held_back")
        .with_unit("s")
        .with_description(
            "How long the oldest transaction running on the data database's Postgres server has \
             held the change feed back (each poll reads every change since it began); 0 normally",
        )
        .with_callback(move |gauge| gauge.observe(watch.held_back().as_secs(), &[]))
        .build();
    vec![streams, live, held_back]
}

/// Gauges read at collection time from the server's state: whether it's
/// sealed, the active KEK version, and (secured mode) when the server
/// certificate expires. Keep the returned handles for as long as they
/// should report.
pub fn observe(
    seal: Arc<Seal>,
    tls: Option<ServerTls>,
    gate: Arc<Gate>,
) -> Vec<ObservableGauge<u64>> {
    let meter = meter();
    let audit_queue = meter
        .u64_observable_gauge("ferritor.audit.queue.depth")
        .with_description(
            "Audit entries waiting for the writer: rising means stdout is stalling, \
             before requests start being refused",
        )
        .with_callback(move |gauge| gauge.observe(gate.audit_queue_depth(), &[]))
        .build();
    let in_flight = meter
        .u64_observable_gauge("ferritor.in_flight")
        .with_description(
            "Calls in flight, every one (exempt admin calls included); the server-wide cap \
             counts only the limited ones",
        )
        .with_callback(|gauge| gauge.observe(ratelimit::calls_in_flight(), &[]))
        .build();
    let sealed = {
        let seal = Arc::clone(&seal);
        meter
            .u64_observable_gauge("ferritor.sealed")
            .with_description("1 while sealed, 0 while unsealed")
            .with_callback(move |gauge| gauge.observe(u64::from(seal.is_sealed()), &[]))
            .build()
    };
    let vanished = {
        let seal = Arc::clone(&seal);
        meter
            .u64_observable_gauge("ferritor.kek.vanished")
            .with_description(
                "KEKs this server holds for reading only because the keys database lost them \
                 (absent while sealed): above 0, rewrap against this server before it seals",
            )
            .with_callback(move |gauge| {
                if let Some(count) = seal.vanished_kek_count() {
                    gauge.observe(count, &[]);
                }
            })
            .build()
    };
    let hold_pending = {
        let seal = Arc::clone(&seal);
        meter
            .u64_observable_gauge("ferritor.seal.hold_pending")
            .with_description(
                "Auto-unseal hold (or release) writes being retried after a seal (0 normally): \
                 until one lands, a restart could auto-unseal a server meant to stay sealed",
            )
            .with_callback(move |gauge| gauge.observe(seal.hold_pending(), &[]))
            .build()
    };
    let floor_pending = {
        let seal = Arc::clone(&seal);
        meter
            .u64_observable_gauge("ferritor.seal.floor_pending")
            .with_description(
                "Root-generation floor raises being retried after an init or a rekey (0 \
                 normally): until one lands, an older keys database could be put back",
            )
            .with_callback(move |gauge| gauge.observe(seal.root_floor_pending(), &[]))
            .build()
    };
    // A count, not one series per namespace: names never go into
    // attributes.
    let namespaces = {
        let seal = Arc::clone(&seal);
        meter
            .u64_observable_gauge("ferritor.namespaces")
            .with_description("Namespaces this server holds KEKs of (absent while sealed)")
            .with_callback(move |gauge| {
                if let Some(count) = seal.namespace_count() {
                    gauge.observe(count, &[]);
                }
            })
            .build()
    };
    let revision = {
        let seal = Arc::clone(&seal);
        meter
            .u64_observable_gauge("ferritor.policy.revision")
            .with_description(
                "The stored policies' verified revision in force (absent unless one is): a \
                 server lower than another for longer than the refresh interval saw a rollback",
            )
            .with_callback(move |gauge| {
                if let PolicyView::Loaded(set) = seal.policy_view() {
                    gauge.observe(set.revision, &[]);
                }
            })
            .build()
    };
    let stored_policies = {
        let seal = Arc::clone(&seal);
        meter
            .u64_observable_gauge("ferritor.policies")
            .with_description("Stored policies in force (absent unless verified)")
            .with_callback(move |gauge| {
                if let PolicyView::Loaded(set) = seal.policy_view() {
                    gauge.observe(u64::try_from(set.policies.len()).unwrap_or(u64::MAX), &[]);
                }
            })
            .build()
    };
    let mut gauges = vec![
        audit_queue,
        in_flight,
        sealed,
        vanished,
        floor_pending,
        hold_pending,
        namespaces,
        revision,
        stored_policies,
    ];
    if let Some(tls) = tls {
        let crl_tls = tls.clone();
        gauges.push(
            meter
                .u64_observable_gauge("ferritor.tls.crl.next_update")
                .with_unit("s")
                .with_description(
                    "When the first CRL in force is due for renewal (unix time): past it, it \
                     may be missing revocations",
                )
                .with_callback(move |gauge| {
                    if let Some(next_update) = crl_tls.crl_next_update() {
                        gauge.observe(next_update, &[]);
                    }
                })
                .build(),
        );
        gauges.push(
            meter
                .u64_observable_gauge("ferritor.server_certificate.expiry")
                .with_unit("s")
                .with_description("When the server certificate expires (unix time)")
                .with_callback(move |gauge| {
                    if let Some(expiry) = tls.certificate_expiry() {
                        gauge.observe(expiry, &[]);
                    }
                })
                .build(),
        );
    }
    gauges
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TLS or not, as the OTLP spec says: by the scheme, and for an
    /// endpoint without one, unless `OTEL_EXPORTER_OTLP_INSECURE`.
    #[test]
    fn the_scheme_decides_tls_and_none_means_tls_unless_insecure() {
        let export = |endpoint: &str, insecure| Export {
            endpoint: Some(endpoint.to_owned()),
            insecure,
            ..Export::default()
        };
        assert!(export("https://collector:4317", false).uses_tls());
        assert!(!export("http://localhost:4317", false).uses_tls());
        assert!(export("collector:4317", false).uses_tls());
        assert!(!export("collector:4317", true).uses_tls());
        // The scheme wins over the flag.
        assert!(export("https://collector:4317", true).uses_tls());
        assert!(!Export::default().uses_tls());
    }
}
