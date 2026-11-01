//! Metrics end to end: real operations through `Secrets`, exported over
//! OTLP/gRPC with mutual TLS (a private CA, a client certificate) to a fake
//! collector, which checks what arrives and who sent it. One test in its own binary, since the meter provider is
//! process-wide.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::Labels;
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate, PolicyReload};
use ferritor_server::authz::{Action, Authorizer, Caller, Denied, Target};
use ferritor_server::metrics;
use ferritor_server::namespaces::Namespaces;
use ferritor_server::seal::Seal;
use ferritor_server::secrets::{Secrets, SecretsError};
use ferritor_testkit::pki::Ca;
use ferritor_testkit::{TestDatabase, TestResult};
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_server::{
    MetricsService, MetricsServiceServer,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
use opentelemetry_proto::tonic::metrics::v1::metric::Data;
use opentelemetry_proto::tonic::metrics::v1::number_data_point::Value as Number;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use zeroize::Zeroizing;

const ANON: Caller = Caller::Unauthenticated;

/// Keeps every export it receives.
#[derive(Clone, Default)]
struct Collector(Arc<Mutex<Vec<Received>>>);

/// An export, and the fingerprint of the client certificate it came with
/// (`None`: without one).
#[derive(Clone)]
struct Received {
    export: ExportMetricsServiceRequest,
    client: Option<String>,
}

#[tonic::async_trait]
impl MetricsService for Collector {
    async fn export(
        &self,
        request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        let client = request
            .peer_certs()
            .and_then(|chain| chain.first().map(|leaf| ferritor_server::fingerprint(leaf)));
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Received {
                export: request.into_inner(),
                client,
            });
        Ok(tonic::Response::new(ExportMetricsServiceResponse {
            partial_success: None,
        }))
    }
}

/// Allows everything but deleting.
struct NoDeletes;

impl Authorizer for NoDeletes {
    fn authorize(&self, caller: &Caller, action: Action, target: Target<'_>) -> Result<(), Denied> {
        if action == Action::Delete {
            return Err(Denied::new(caller, action, target));
        }
        Ok(())
    }
}

/// Every integer data point (counters, gauges) and histogram count received:
/// (metric name, attributes) → latest value.
fn points(
    exports: &[ExportMetricsServiceRequest],
) -> BTreeMap<(String, Vec<(String, String)>), i64> {
    let mut points = BTreeMap::new();
    let attributes = |kvs: &[opentelemetry_proto::tonic::common::v1::KeyValue]| {
        kvs.iter()
            .map(|kv| {
                let value = match kv.value.as_ref().and_then(|v| v.value.as_ref()) {
                    Some(AnyValue::StringValue(s)) => s.clone(),
                    other => format!("{other:?}"),
                };
                (kv.key.clone(), value)
            })
            .collect::<Vec<_>>()
    };
    for metric in exports
        .iter()
        .flat_map(|e| &e.resource_metrics)
        .flat_map(|r| &r.scope_metrics)
        .flat_map(|s| &s.metrics)
    {
        let name = metric.name.clone();
        let numbers = match &metric.data {
            Some(Data::Sum(sum)) => sum.data_points.clone(),
            Some(Data::Gauge(gauge)) => gauge.data_points.clone(),
            Some(Data::Histogram(histogram)) => {
                for point in &histogram.data_points {
                    let count = i64::try_from(point.count).unwrap_or(i64::MAX);
                    points.insert((name.clone(), attributes(&point.attributes)), count);
                }
                continue;
            }
            _ => continue,
        };
        for point in numbers {
            let value = match point.value {
                Some(Number::AsInt(i)) => i,
                Some(Number::AsDouble(d)) => d as i64,
                None => continue,
            };
            points.insert((name.clone(), attributes(&point.attributes)), value);
        }
    }
    points
}

fn key(name: &str, attributes: &[(&str, &str)]) -> (String, Vec<(String, String)>) {
    (
        name.to_owned(),
        attributes
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn operations_are_exported_over_otlp_without_paths() {
    // The fake collector, over TLS with a certificate from a private CA.
    let ca = Ca::new().unwrap();
    let cert = ca.server().unwrap();
    let exporter_cert = ca.client("ferritor/metrics").unwrap();
    let client_ca = ca.cert.clone();
    let collector = Collector::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let serving = tokio::spawn({
        let collector = collector.clone();
        async move {
            tonic::transport::Server::builder()
                .tls_config(
                    ServerTlsConfig::new()
                        .identity(Identity::from_pem(&cert.cert, &cert.key))
                        // Mutual TLS: no client certificate, no connection.
                        .client_ca_root(Certificate::from_pem(&client_ca))
                        .client_auth_optional(false),
                )
                .unwrap()
                .add_service(MetricsServiceServer::new(collector))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .ok();
        }
    });
    let provider = metrics::init(Some(metrics::Export {
        endpoint: Some(endpoint),
        ca_pem: Some(ca.cert.as_bytes().to_vec()),
        client: Some((
            exporter_cert.cert.as_bytes().to_vec(),
            Zeroizing::new(exporter_cert.key.as_bytes().to_vec()),
        )),
        ..metrics::Export::default()
    }))
    .unwrap()
    .unwrap();

    let env = Env::new().await.unwrap();
    let _gauges = metrics::observe(Arc::clone(&env.seal), None, Arc::clone(&env.gate));
    // A hub whose feed never ran: no stream, not live.
    let _watch_gauges = metrics::observe_watch(ferritor_server::watch::Watch::new());
    env.gate
        .reload_policy(PolicyReload::Skipped("dev mode: no policy"));
    env.secrets.put(&ANON, "app/db", b"x").await.unwrap();
    env.secrets.get(&ANON, "app/db", None).await.unwrap();
    assert!(env.secrets.get(&ANON, "app/missing", None).await.is_err());
    assert!(matches!(
        env.secrets.delete(&ANON, "app/db").await,
        Err(SecretsError::Denied(_))
    ));
    env.seal.seal().await;
    assert!(matches!(
        env.secrets.get(&ANON, "app/db", None).await,
        Err(SecretsError::Sealed)
    ));

    tokio::task::spawn_blocking(move || provider.force_flush())
        .await
        .unwrap()
        .unwrap();
    let received = collector
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    // Every export came over mutual TLS, with the exporter's certificate.
    let expected_client = Some(ferritor_server::fingerprint(
        &CertificateDer::from_pem_slice(exporter_cert.cert.as_bytes()).unwrap(),
    ));
    assert!(!received.is_empty());
    assert!(
        received
            .iter()
            .all(|received| received.client == expected_client)
    );
    let exports: Vec<_> = received.into_iter().map(|r| r.export).collect();
    let points = points(&exports);
    let requests = |operation, result| {
        points
            .get(&key(
                "ferritor.secret.requests",
                &[("operation", operation), ("result", result)],
            ))
            .copied()
    };
    assert_eq!(requests("put", "ok"), Some(1));
    assert_eq!(requests("get", "ok"), Some(1));
    assert_eq!(requests("get", "not_found"), Some(1));
    assert_eq!(requests("delete", "denied"), Some(1));
    assert_eq!(requests("get", "sealed"), Some(1));
    assert_eq!(
        points.get(&key(
            "ferritor.secret.request.duration",
            &[("operation", "get"), ("result", "ok")]
        )),
        Some(&1)
    );
    assert_eq!(
        points.get(&key(
            "ferritor.authorization.decisions",
            &[("action", "delete"), ("decision", "denied")]
        )),
        Some(&1)
    );
    assert_eq!(points.get(&key("ferritor.sealed", &[])), Some(&1));
    assert_eq!(
        points.get(&key("ferritor.audit.queue.depth", &[])),
        Some(&0)
    );
    assert_eq!(points.get(&key("ferritor.watch.streams", &[])), Some(&0));
    assert_eq!(points.get(&key("ferritor.watch.feed.live", &[])), Some(&0));
    assert_eq!(
        points.get(&key("ferritor.watch.feed.held_back", &[])),
        Some(&0)
    );
    assert_eq!(
        points.get(&key(
            "ferritor.reloads",
            &[("kind", "policy"), ("result", "skipped")]
        )),
        Some(&1)
    );
    // Recorded from the first put, at 0 while nothing was trimmed.
    assert_eq!(points.get(&key("ferritor.versions.trimmed", &[])), Some(&0));
    // Never a path (nor a value) in what's exported.
    let everything = format!("{exports:?}");
    assert!(!everything.contains("app/db") && !everything.contains("app/missing"));

    serving.abort();
    env.destroy().await.unwrap();
}

/// An initialized, unsealed server with secrets wired up.
struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    seal: Arc<Seal>,
    gate: Arc<Gate>,
    secrets: Secrets,
}

impl Env {
    async fn new() -> TestResult<Self> {
        let keys = TestDatabase::new(
            "KEYS_DATABASE_URL",
            "ferritor_server_test",
            &ferritor_keystore::MIGRATOR,
        )
        .await?;
        let data = TestDatabase::new(
            "DATA_DATABASE_URL",
            "ferritor_server_test",
            &ferritor_datastore::MIGRATOR,
        )
        .await?;
        let seal = Arc::new(Seal::new(Keystore::new(keys.pool().clone())));
        let shares = seal.init(ShareParams::new(3, 2)?).await?;
        for share in &shares[..2] {
            seal.unseal(&share.to_bytes(), false).await?;
        }
        let namespaces = Namespaces::new(Arc::clone(&seal), Datastore::new(data.pool().clone()));
        for name in ["app"] {
            namespaces.create(name, &Labels::new()).await?;
        }
        let gate = Arc::new(Gate::new(
            Arc::new(NoDeletes),
            AuditLog::new(std::io::sink(), Duration::from_secs(5))?,
        ));
        let secrets = Secrets::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
            Arc::clone(&gate),
        );
        Ok(Self {
            keys,
            data,
            seal,
            gate,
            secrets,
        })
    }

    async fn destroy(self) -> TestResult<()> {
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}
