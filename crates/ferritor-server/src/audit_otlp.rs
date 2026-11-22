//! The audit log over OTLP (`[audit_otlp]`): every line, as written to the
//! file, becomes one log record whose body is the line itself, byte for
//! byte but its newline, so the chain verifies from what the collector
//! stored (`ferritor audit verify` over the bodies, one per line, in
//! order). The writer thread collects what's queued, sends it as one
//! export and answers the batch's entries only once the collector has
//! acknowledged it: a collector down, refusing or slower than
//! the audit timeout refuses them (fail closed), and the next line
//! starts a new chain, so a lost batch is a gap the verifier reports.
//!
//! Acknowledged means in the collector's pipeline: stored only if the
//! collector keeps a persistent queue (its `file_storage` extension), and a
//! collector on the server's own node goes when the node does. Each record
//! carries its chain and `seq` as attributes ([`CHAIN`], [`SEQ`]), so a
//! backend that returns records by time can put them back in chain order:
//! the body alone has its `seq`, but only the chain's start names the
//! chain, and the wall clock a record is stamped with can step back.
//!
//! Its own gRPC client (`opentelemetry-proto`'s generated one), not the
//! OpenTelemetry logs SDK: that one batches in the background and can't
//! tell a caller its record arrived, nor keep a body exactly as given.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use opentelemetry_proto::tonic::common::v1::any_value::Value;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs, SeverityNumber};
use opentelemetry_proto::tonic::resource::v1::Resource;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use zeroize::Zeroizing;

/// The records' `service.name`.
const SERVICE: &str = "ferritor-server";
/// Their instrumentation scope: what a collector routes audit records by.
pub const SCOPE: &str = "ferritor.audit";
/// A record's attribute: its chain's id (hex, as `chain_start` has it).
pub const CHAIN: &str = "ferritor.audit.chain";
/// A record's attribute: its line's `seq` in that chain.
pub const SEQ: &str = "ferritor.audit.seq";

/// What `[audit_otlp]` resolved to (the files read).
#[derive(Clone)]
pub struct OtlpSettings {
    /// `https://…` (or `http://` on loopback), gRPC.
    pub endpoint: String,
    /// Trusted for the collector's certificate, besides the public roots.
    pub ca_pem: Option<Vec<u8>>,
    /// Presented to the collector (mTLS): certificate and key, PEM.
    pub client: Option<(Vec<u8>, Zeroizing<Vec<u8>>)>,
}

/// The collector, and the lines waiting for the next export.
pub(crate) struct Otlp {
    /// Drives the client: the writer is a thread of its own, outside the
    /// server's runtime, and only waits for an export.
    runtime: tokio::runtime::Runtime,
    client: LogsServiceClient<Channel>,
    resource: Resource,
    pending: Vec<LogRecord>,
    timeout: Duration,
}

impl Otlp {
    /// The client for `settings`, connecting when first used (a collector
    /// down at startup refuses requests until it's up, rather than the
    /// server not starting). An export that takes longer than `timeout`
    /// fails.
    pub(crate) fn new(settings: &OtlpSettings, timeout: Duration) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut endpoint = Endpoint::from_shared(settings.endpoint.clone())
            .map_err(std::io::Error::other)?
            .connect_timeout(timeout)
            .timeout(timeout);
        if settings.endpoint.starts_with("https://") {
            let mut tls = ClientTlsConfig::new().with_webpki_roots();
            if let Some(ca) = &settings.ca_pem {
                tls = tls.ca_certificate(Certificate::from_pem(ca));
            }
            if let Some((cert, key)) = &settings.client {
                tls = tls.identity(Identity::from_pem(cert, key.as_slice()));
            }
            endpoint = endpoint.tls_config(tls).map_err(std::io::Error::other)?;
        }
        // The channel's worker lives on this runtime, which runs while an
        // export is waited for.
        let channel = {
            let _entered = runtime.enter();
            endpoint.connect_lazy()
        };
        let mut instance = [0u8; 16];
        getrandom::fill(&mut instance).map_err(std::io::Error::other)?;
        let instance: String = instance.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            runtime,
            client: LogsServiceClient::new(channel),
            resource: Resource {
                attributes: vec![
                    string("service.name", SERVICE),
                    // Each server process's records apart: chains verify
                    // one server at a time.
                    string("service.instance.id", &instance),
                ],
                ..Default::default()
            },
            pending: Vec::new(),
            timeout,
        })
    }

    /// `line` (newline included), the `seq`th of chain `chain`, as a record
    /// for the next export.
    pub(crate) fn push(&mut self, line: &[u8], chain: String, seq: u64) {
        let body = line.strip_suffix(b"\n").unwrap_or(line);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        self.pending.push(LogRecord {
            time_unix_nano: now,
            observed_time_unix_nano: now,
            severity_number: SeverityNumber::Info.into(),
            severity_text: "INFO".to_owned(),
            // Lines are JSON: UTF-8. Anything else would be the writer's
            // bug; lossy keeps the record, and the chain then won't verify.
            body: Some(AnyValue {
                value: Some(Value::StringValue(
                    String::from_utf8_lossy(body).into_owned(),
                )),
            }),
            attributes: vec![
                string(CHAIN, &chain),
                KeyValue {
                    key: SEQ.to_owned(),
                    value: Some(AnyValue {
                        value: Some(Value::IntValue(i64::try_from(seq).unwrap_or(i64::MAX))),
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
    }

    /// Sends everything pushed since the last export, and returns once the
    /// collector has acknowledged all of it. Nothing pending: nothing sent.
    pub(crate) fn export(&mut self) -> std::io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let records = std::mem::take(&mut self.pending);
        let count = records.len();
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(self.resource.clone()),
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope {
                        name: SCOPE.to_owned(),
                        version: env!("CARGO_PKG_VERSION").to_owned(),
                        ..Default::default()
                    }),
                    log_records: records,
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let mut client = self.client.clone();
        let timeout = self.timeout;
        let response = self
            .runtime
            .block_on(async move { tokio::time::timeout(timeout, client.export(request)).await });
        let response = match response {
            Err(_) => return Err(std::io::ErrorKind::TimedOut.into()),
            Ok(Err(status)) => {
                return Err(std::io::Error::other(format!(
                    "the collector refused the audit entries: {}",
                    status.message()
                )));
            }
            Ok(Ok(response)) => response.into_inner(),
        };
        match response.partial_success {
            Some(partial) if partial.rejected_log_records > 0 => {
                Err(std::io::Error::other(format!(
                    "the collector rejected {} of {count} audit entries: {}",
                    partial.rejected_log_records, partial.error_message
                )))
            }
            _ => Ok(()),
        }
    }
}

fn string(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(AnyValue {
            value: Some(Value::StringValue(value.to_owned())),
        }),
        ..Default::default()
    }
}
