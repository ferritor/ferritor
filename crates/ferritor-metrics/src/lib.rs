//! Metrics for ferritor's binaries (the server, the agent, the CSI
//! provider), the OpenTelemetry way: each binary records on the global
//! meter, read by the exporter its `[metrics]` section chose. Pushed over
//! OTLP/gRPC ([`init`]) to a collector, with the standard variables
//! (`OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`;
//! also `OTEL_METRIC_EXPORT_INTERVAL`, default 60 s,
//! `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_SERVICE_NAME`, default the binary's
//! name), or scraped by Prometheus ([`init_prometheus`], see [`prometheus`]
//! for the names there, and [`serve_plaintext`] for its listener). With
//! neither no provider is installed, and every instrument is a no-op.
//!
//! `https://` (or an endpoint without a scheme, per the OTLP spec, unless
//! `OTEL_EXPORTER_OTLP_INSECURE=true`) uses TLS with the web PKI roots,
//! plus `OTEL_EXPORTER_OTLP_CERTIFICATE` for a private CA and
//! `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`/`_CLIENT_KEY` for mTLS (see
//! [`Export`]); `http://` is plaintext, fine for a local agent.
//!
//! Attributes are each binary's small fixed sets: never secret paths,
//! identities, certificate fingerprints, pods or values, which would leak
//! names and make the number of series unbounded. A scrape serves them as
//! they are.

pub mod prometheus;

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ferritor_core::net::{is_loopback, is_loopback_host};
use opentelemetry::global;
use opentelemetry_otlp::{ExporterBuildError, MetricExporter, WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::service::Routes;
use tonic::transport::{Certificate, ClientTlsConfig, Identity, Server};
use zeroize::Zeroizing;

pub use prometheus::Scrape;

/// Where the Prometheus endpoint listens by default (OpenTelemetry's usual
/// Prometheus port), per binary, so they can share a host: loopback.
pub const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:9464";
pub const DEFAULT_AGENT_ADDR: &str = "127.0.0.1:9465";
pub const DEFAULT_CSI_PROVIDER_ADDR: &str = "127.0.0.1:9466";

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

/// Starts exporting as `export` says, as `service` (the resource's service
/// name unless `OTEL_SERVICE_NAME` says otherwise); `None` when there's
/// nothing to export to (metrics off). Must run before anything records,
/// inside the tokio runtime (the exporter uses tonic), and the returned
/// provider must be shut down at exit to flush.
pub fn init(
    export: Option<Export>,
    service: &'static str,
) -> Result<Option<SdkMeterProvider>, MetricsError> {
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
        .with_resource(Resource::builder().with_service_name(service).build())
        .build();
    global::set_meter_provider(provider.clone());
    Ok(Some(provider))
}

/// Serves the instruments for Prometheus to scrape instead
/// (`[metrics] exporter = "prometheus"`): the returned [`Scrape`] renders
/// them on demand. As with [`init`], before anything records; the provider
/// needs no flush at exit (nothing is pushed), but stays alive as long as
/// the scrape is served.
pub fn init_prometheus(service: &'static str) -> (SdkMeterProvider, Scrape) {
    let scrape = Scrape::new();
    let provider = SdkMeterProvider::builder()
        .with_reader(scrape.reader())
        .with_resource(Resource::builder().with_service_name(service).build())
        .build();
    global::set_meter_provider(provider.clone());
    (provider, scrape)
}

/// How long [`Exporting::finish`] waits for the last OTLP export.
pub const FLUSH_LIMIT: Duration = Duration::from_secs(3);

/// The exporter a binary's `[metrics]` chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chosen {
    /// No `exporter`: OTLP if its endpoint variable is set, off otherwise.
    OtlpIfConfigured,
    /// `exporter = "otlp"`: the endpoint variable is required.
    Otlp,
    /// `exporter = "prometheus"`: scraped (the binary serves the scrape).
    Prometheus,
    /// `exporter = "none"`.
    Off,
}

/// The metrics exporter in use.
pub enum Exporting {
    /// Pushing: flushed by [`Exporting::finish`].
    Otlp(SdkMeterProvider),
    /// Scraped: the provider lives as long as the scrape is served.
    Prometheus {
        provider: SdkMeterProvider,
        scrape: Scrape,
    },
    Off,
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Metrics(#[from] MetricsError),
    #[error(
        "[metrics] exporter = \"otlp\" needs OTEL_EXPORTER_OTLP_ENDPOINT (or \
         OTEL_EXPORTER_OTLP_METRICS_ENDPOINT)"
    )]
    NoEndpoint,
}

/// Installs the exporter `chosen` names, as `service`, and says which in
/// the log. Before anything records.
pub fn start(chosen: Chosen, service: &'static str) -> Result<Exporting, StartError> {
    let otlp = |export: Export| -> Result<Exporting, StartError> {
        match init(Some(export), service)? {
            Some(provider) => {
                tracing::info!("exporting metrics over OTLP (OTEL_EXPORTER_OTLP_* settings)");
                Ok(Exporting::Otlp(provider))
            }
            None => Err(StartError::NoEndpoint),
        }
    };
    match chosen {
        Chosen::OtlpIfConfigured => match Export::from_env()? {
            Some(export) => otlp(export),
            None => {
                tracing::info!(
                    "metrics off: no OTEL_EXPORTER_OTLP_ENDPOINT, no [metrics] exporter"
                );
                Ok(Exporting::Off)
            }
        },
        Chosen::Otlp => otlp(Export::from_env()?.ok_or(StartError::NoEndpoint)?),
        Chosen::Prometheus => {
            if otlp_endpoint_set() {
                tracing::warn!(
                    "OTEL_EXPORTER_OTLP_ENDPOINT is set, but [metrics] exporter = \"prometheus\": \
                     nothing is pushed over OTLP"
                );
            }
            let (provider, scrape) = init_prometheus(service);
            Ok(Exporting::Prometheus { provider, scrape })
        }
        Chosen::Off => {
            tracing::info!("metrics off ([metrics] exporter = \"none\")");
            Ok(Exporting::Off)
        }
    }
}

impl Exporting {
    /// The scrape to serve, if Prometheus was chosen.
    pub fn scrape(&self) -> Option<&Scrape> {
        match self {
            Self::Prometheus { scrape, .. } => Some(scrape),
            _ => None,
        }
    }

    /// At exit: flushes the last OTLP export, within [`FLUSH_LIMIT`]. The
    /// flush blocks, so it runs off the runtime's workers, and is bounded: a
    /// collector that doesn't answer mustn't hold the exit for the
    /// exporter's own timeout (10 s by default).
    pub async fn finish(self) {
        let Self::Otlp(provider) = self else {
            return;
        };
        let flushed = tokio::time::timeout(
            FLUSH_LIMIT,
            tokio::task::spawn_blocking(move || provider.shutdown()),
        )
        .await;
        match flushed {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => tracing::warn!(error = %e, "flushing metrics at shutdown failed"),
            Ok(Err(e)) => tracing::warn!(error = %e, "flushing metrics at shutdown failed"),
            Err(_) => tracing::warn!(
                "the metrics collector didn't answer within {FLUSH_LIMIT:?}; the last export is \
                 lost"
            ),
        }
    }
}

/// Serves `routes` (a [`Scrape::router`]) in plaintext on `listener` until
/// `shutdown`. On a loopback address only requests addressed to loopback
/// are answered (421 otherwise): listening there isn't enough, since with
/// DNS rebinding a web page gets its own name resolved to 127.0.0.1, and
/// the browser on the same machine then lets it read the answers. Off
/// loopback the caller has made sure plaintext was asked for.
pub async fn serve_plaintext(
    routes: axum::Router,
    listener: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> Result<(), tonic::transport::Error> {
    let on_loopback = listener
        .local_addr()
        .is_ok_and(|addr: SocketAddr| is_loopback(addr.ip()));
    let routes = if on_loopback {
        routes.layer(axum::middleware::from_fn(require_loopback_host))
    } else {
        routes
    };
    Server::builder()
        .accept_http1(true)
        .add_routes(Routes::from(routes))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
}

async fn require_loopback_host(request: Request, next: Next) -> Response {
    if addressed_to_loopback(&request) {
        return next.run(request).await;
    }
    tracing::warn!(
        host = ?request.headers().get(header::HOST),
        authority = ?request.uri().authority(),
        "refused a scrape not addressed to loopback (DNS rebinding?)"
    );
    (
        StatusCode::MISDIRECTED_REQUEST,
        "metrics on a loopback address are only served to requests addressed to localhost or a \
         loopback address\n",
    )
        .into_response()
}

/// The defence against DNS rebinding for anything served in plaintext on
/// loopback (the server's dev mode and its metrics, the agent's and the
/// provider's metrics), one check for all: every host the request names
/// (the URI's authority, HTTP/2's `:authority` or an absolute-form HTTP/1.1
/// target, and each `Host` header) is loopback
/// ([`ferritor_core::net::is_loopback_host`]), and it names at least one.
pub fn addressed_to_loopback<B>(request: &axum::http::Request<B>) -> bool {
    let mut hosts = Vec::new();
    if let Some(authority) = request.uri().authority() {
        hosts.push(authority.host().to_owned());
    }
    for value in request.headers().get_all(header::HOST) {
        let Some(authority) = value
            .to_str()
            .ok()
            .and_then(|host| host.parse::<axum::http::uri::Authority>().ok())
        else {
            return false;
        };
        hosts.push(authority.host().to_owned());
    }
    !hosts.is_empty() && hosts.iter().all(|host| is_loopback_host(host))
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
