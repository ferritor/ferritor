//! The Prometheus side of [`crate::metrics`]: the same instruments, read
//! when scraped instead of pushed. A [`Scrape`] is the meter provider's
//! reader (the SDK's `ManualReader`); each `GET /metrics` collects from it
//! and writes the Prometheus text format (version 0.0.4), served on a
//! listener of its own (`[metrics] listen_addr`, see `main` and
//! [`crate::tls::serve_metrics`]), never the main one.
//!
//! Names follow OpenTelemetry's Prometheus conventions: every character but
//! letters, digits, `_` and `:` becomes `_` (`ferritor.secret.requests` →
//! `ferritor_secret_requests`), a unit adds its suffix (`s` → `_seconds`),
//! and a counter ends in `_total`. A histogram is its `_bucket` series (one
//! per boundary, cumulative, `le="+Inf"` last), `_sum` and `_count`.
//! Attributes become labels as they are: the fixed sets `metrics`
//! describes, never paths, identities or values.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Weak};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use opentelemetry::KeyValue;
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::metrics::data::{
    AggregatedMetrics, Histogram, Metric, MetricData, ResourceMetrics,
};
use opentelemetry_sdk::metrics::reader::MetricReader;
use opentelemetry_sdk::metrics::{InstrumentKind, ManualReader, Pipeline, Temporality};

/// The text format's content type.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The reader a scrape collects from: one per meter provider. Give the
/// provider [`Scrape::reader`], and keep the `Scrape` to serve it.
#[derive(Clone, Debug, Default)]
pub struct Scrape(Arc<ManualReader>);

/// A [`Scrape`]'s reader as the meter provider holds it (the provider takes
/// its readers by value; the scrape keeps the other handle).
#[derive(Debug)]
pub struct Reader(Arc<ManualReader>);

impl Scrape {
    pub fn new() -> Self {
        Self::default()
    }

    /// For `SdkMeterProvider::builder().with_reader(…)`: once only.
    pub fn reader(&self) -> Reader {
        Reader(Arc::clone(&self.0))
    }

    /// Every instrument as it is now, in the text format: the observable
    /// gauges' callbacks run here.
    pub fn render(&self) -> Result<String, OTelSdkError> {
        let mut collected = ResourceMetrics::default();
        self.0.collect(&mut collected)?;
        Ok(encode(&collected))
    }

    /// `GET /metrics`, and nothing else.
    pub fn router(self) -> Router {
        Router::new()
            .route("/metrics", get(scrape))
            .with_state(self)
    }
}

impl MetricReader for Reader {
    fn register_pipeline(&self, pipeline: Weak<Pipeline>) {
        self.0.register_pipeline(pipeline);
    }

    fn collect(&self, rm: &mut ResourceMetrics) -> OTelSdkResult {
        self.0.collect(rm)
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.0.force_flush()
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.0.shutdown_with_timeout(timeout)
    }

    /// Prometheus wants running totals.
    fn temporality(&self, _kind: InstrumentKind) -> Temporality {
        Temporality::Cumulative
    }
}

async fn scrape(State(scrape): State<Scrape>) -> Response {
    match scrape.render() {
        Ok(body) => ([(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "collecting metrics for a scrape failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// A metric's name in Prometheus: `name` with every character outside
/// `[a-zA-Z0-9_:]` made `_`, the unit's suffix (`s` → `_seconds`), and
/// `_total` for a counter.
pub fn family_name(name: &str, unit: &str, counter: bool) -> String {
    let mut family = sanitize(name, |c| c.is_ascii_alphanumeric() || c == '_' || c == ':');
    let suffix = match unit {
        "" | "1" => None,
        "s" => Some("seconds".to_owned()),
        "ms" => Some("milliseconds".to_owned()),
        "By" => Some("bytes".to_owned()),
        // Annotations (`{request}`) carry no unit.
        other if other.starts_with('{') => None,
        other => Some(sanitize(other, |c| c.is_ascii_alphanumeric() || c == '_')),
    };
    if let Some(suffix) = suffix
        && !family.ends_with(&format!("_{suffix}"))
    {
        family.push('_');
        family.push_str(&suffix);
    }
    if counter && !family.ends_with("_total") {
        family.push_str("_total");
    }
    family
}

fn sanitize(name: &str, keep: impl Fn(char) -> bool) -> String {
    let mut out: String = name
        .chars()
        .map(|c| if keep(c) { c } else { '_' })
        .collect();
    if out.chars().next().is_none_or(|c| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// A family: its `# HELP` and `# TYPE`, and its sample lines.
struct Family {
    help: String,
    kind: &'static str,
    samples: Vec<String>,
}

/// Every metric in `collected`, in the text format, families sorted by
/// name and each one's samples by labels, so two scrapes of the same state
/// read alike.
pub fn encode(collected: &ResourceMetrics) -> String {
    let mut families = BTreeMap::new();
    for metric in collected.scope_metrics().flat_map(|scope| scope.metrics()) {
        let family = match metric.data() {
            AggregatedMetrics::F64(data) => family(metric, data),
            AggregatedMetrics::U64(data) => family(metric, data),
            AggregatedMetrics::I64(data) => family(metric, data),
        };
        if let Some((name, family)) = family
            && families.insert(name.clone(), family).is_some()
        {
            // Two instruments under one Prometheus name: the scrape would
            // show only the last. Renaming one is the fix.
            tracing::warn!(
                metric = name,
                "two instruments map to one Prometheus name; only one is scraped"
            );
            debug_assert!(false, "two instruments map to the Prometheus name {name}");
        }
    }
    let mut out = String::new();
    for (name, family) in families {
        let _ = writeln!(out, "# HELP {name} {}", escape_help(&family.help));
        let _ = writeln!(out, "# TYPE {name} {}", family.kind);
        for sample in family.samples {
            out.push_str(&sample);
            out.push('\n');
        }
    }
    out
}

fn family<T: Number>(metric: &Metric, data: &MetricData<T>) -> Option<(String, Family)> {
    let (name, unit, help) = (
        metric.name(),
        metric.unit(),
        metric.description().to_owned(),
    );
    match data {
        MetricData::Gauge(gauge) => {
            let name = family_name(name, unit, false);
            let samples = sorted(
                gauge
                    .data_points()
                    .map(|p| sample(&name, &labels(p.attributes(), None), p.value().render())),
            );
            Some((
                name,
                Family {
                    help,
                    kind: "gauge",
                    samples,
                },
            ))
        }
        MetricData::Sum(sum) => {
            let counter = sum.is_monotonic();
            let name = family_name(name, unit, counter);
            let samples = sorted(
                sum.data_points()
                    .map(|p| sample(&name, &labels(p.attributes(), None), p.value().render())),
            );
            let kind = if counter { "counter" } else { "gauge" };
            Some((
                name,
                Family {
                    help,
                    kind,
                    samples,
                },
            ))
        }
        MetricData::Histogram(histogram) => {
            let name = family_name(name, unit, false);
            let samples = histogram_samples(&name, histogram);
            Some((
                name,
                Family {
                    help,
                    kind: "histogram",
                    samples,
                },
            ))
        }
        MetricData::ExponentialHistogram(_) => {
            // Never configured here; the text format has no such type.
            tracing::debug!(metric = name, "an exponential histogram can't be scraped");
            None
        }
    }
}

fn histogram_samples<T: Number>(name: &str, histogram: &Histogram<T>) -> Vec<String> {
    let mut points: Vec<_> = histogram
        .data_points()
        .map(|point| (labels(point.attributes(), None), point))
        .collect();
    points.sort_by(|a, b| a.0.cmp(&b.0));
    let mut samples = Vec::new();
    for (plain, point) in points {
        let mut cumulative = 0u64;
        let counts: Vec<u64> = point.bucket_counts().collect();
        for (bound, count) in point.bounds().zip(&counts) {
            cumulative = cumulative.saturating_add(*count);
            let le = labels(point.attributes(), Some(&bound.render()));
            samples.push(sample(
                &format!("{name}_bucket"),
                &le,
                cumulative.to_string(),
            ));
        }
        let le = labels(point.attributes(), Some("+Inf"));
        samples.push(sample(
            &format!("{name}_bucket"),
            &le,
            point.count().to_string(),
        ));
        samples.push(sample(&format!("{name}_sum"), &plain, point.sum().render()));
        samples.push(sample(
            &format!("{name}_count"),
            &plain,
            point.count().to_string(),
        ));
    }
    samples
}

fn sorted(samples: impl Iterator<Item = String>) -> Vec<String> {
    let mut samples: Vec<String> = samples.collect();
    samples.sort();
    samples
}

fn sample(name: &str, labels: &str, value: String) -> String {
    format!("{name}{labels} {value}")
}

/// `{key="value",…}` (empty for none), keys sorted, with `le` last.
fn labels<'a>(attributes: impl Iterator<Item = &'a KeyValue>, le: Option<&str>) -> String {
    let mut pairs: Vec<(String, String)> = attributes
        .map(|kv| {
            (
                sanitize(kv.key.as_str(), |c| c.is_ascii_alphanumeric() || c == '_'),
                escape_label(&kv.value.as_str()),
            )
        })
        .collect();
    pairs.sort();
    if let Some(le) = le {
        pairs.push(("le".to_owned(), le.to_owned()));
    }
    if pairs.is_empty() {
        return String::new();
    }
    let inner: Vec<String> = pairs
        .into_iter()
        .map(|(key, value)| format!("{key}=\"{value}\""))
        .collect();
    format!("{{{}}}", inner.join(","))
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn escape_help(help: &str) -> String {
    help.replace('\\', "\\\\").replace('\n', "\\n")
}

/// A value as the text format writes it.
trait Number: Copy {
    fn render(self) -> String;
}

impl Number for u64 {
    fn render(self) -> String {
        self.to_string()
    }
}

impl Number for i64 {
    fn render(self) -> String {
        self.to_string()
    }
}

impl Number for f64 {
    fn render(self) -> String {
        if self.is_nan() {
            "NaN".to_owned()
        } else if self.is_infinite() {
            if self > 0.0 { "+Inf" } else { "-Inf" }.to_owned()
        } else {
            self.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::SdkMeterProvider;

    use super::*;

    #[test]
    fn names_follow_the_prometheus_conventions() {
        assert_eq!(
            family_name("ferritor.secret.requests", "", true),
            "ferritor_secret_requests_total"
        );
        assert_eq!(
            family_name("ferritor.secret.request.duration", "s", false),
            "ferritor_secret_request_duration_seconds"
        );
        assert_eq!(
            family_name("ferritor.watch.feed.held_back", "s", false),
            "ferritor_watch_feed_held_back_seconds"
        );
        assert_eq!(family_name("ferritor.sealed", "", false), "ferritor_sealed");
        assert_eq!(family_name("a-b", "{request}", true), "a_b_total");
        assert_eq!(family_name("x_total", "", true), "x_total");
        assert_eq!(family_name("9lives", "By", false), "_9lives_bytes");
    }

    /// A provider of its own (never the global one): counters, a gauge and
    /// a histogram as the text format writes them, labels escaped.
    #[test]
    fn a_scrape_writes_the_text_format() {
        let scrape = Scrape::new();
        let provider = SdkMeterProvider::builder()
            .with_reader(scrape.reader())
            .build();
        let meter = provider.meter("test");
        let counter = meter
            .u64_counter("t.requests")
            .with_description("Requests\nsplit")
            .build();
        counter.add(2, &[KeyValue::new("result", "ok")]);
        counter.add(1, &[KeyValue::new("result", "say \"no\"\\")]);
        let histogram = meter
            .f64_histogram("t.duration")
            .with_unit("s")
            .with_description("Time")
            .with_boundaries(vec![0.1, 1.0])
            .build();
        histogram.record(0.05, &[]);
        histogram.record(0.5, &[]);
        histogram.record(5.0, &[]);
        let _gauge = meter
            .u64_observable_gauge("t.sealed")
            .with_description("Sealed")
            .with_callback(|gauge| gauge.observe(1, &[]))
            .build();

        assert_eq!(
            scrape.render().unwrap(),
            "# HELP t_duration_seconds Time\n\
             # TYPE t_duration_seconds histogram\n\
             t_duration_seconds_bucket{le=\"0.1\"} 1\n\
             t_duration_seconds_bucket{le=\"1\"} 2\n\
             t_duration_seconds_bucket{le=\"+Inf\"} 3\n\
             t_duration_seconds_sum 5.55\n\
             t_duration_seconds_count 3\n\
             # HELP t_requests_total Requests\\nsplit\n\
             # TYPE t_requests_total counter\n\
             t_requests_total{result=\"ok\"} 2\n\
             t_requests_total{result=\"say \\\"no\\\"\\\\\"} 1\n\
             # HELP t_sealed Sealed\n\
             # TYPE t_sealed gauge\n\
             t_sealed 1\n"
        );
    }
}
