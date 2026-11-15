//! The Grafana dashboards in `deploy/grafana/` query only metrics the
//! monitoring page documents (whose tables are in turn held to a scrape:
//! the server's `tests/prometheus.rs`, the agent's `tests/metrics.rs`), so
//! renaming an instrument can't leave a dashboard's panel empty unnoticed.
//! Each panel asks for the dashboard's data source variable, and each
//! dashboard has its own uid.

use std::collections::BTreeSet;

const MONITORING: &str = include_str!("../../../docs/src/content/docs/operations/monitoring.md");

const DASHBOARDS: [(&str, &str); 3] = [
    (
        "ferritor-server.json",
        include_str!("../../../deploy/grafana/ferritor-server.json"),
    ),
    (
        "ferritor-agent.json",
        include_str!("../../../deploy/grafana/ferritor-agent.json"),
    ),
    (
        "ferritor-csi.json",
        include_str!("../../../deploy/grafana/ferritor-csi.json"),
    ),
];

/// Every Prometheus family the monitoring page's tables name.
fn documented() -> BTreeSet<String> {
    MONITORING
        .lines()
        .filter(|line| line.starts_with("| `ferritor."))
        .filter_map(|line| line.split('|').nth(2))
        .map(|cell| cell.trim().trim_matches('`').to_owned())
        .collect()
}

/// The `ferritor_…` metric names in a query, as written.
fn metrics_in(expr: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut rest = expr;
    while let Some(at) = rest.find("ferritor_") {
        let tail = &rest[at..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(tail.len());
        found.insert(tail[..end].to_owned());
        rest = &tail[end..];
    }
    found
}

/// The documented family `name` belongs to: itself, or for a histogram's
/// series (`_bucket`, `_sum`, `_count`) the histogram.
fn family<'a>(name: &str, documented: &'a BTreeSet<String>) -> Option<&'a String> {
    documented.get(name).or_else(|| {
        ["_bucket", "_sum", "_count"]
            .iter()
            .find_map(|suffix| name.strip_suffix(suffix))
            .and_then(|family| documented.get(family))
    })
}

/// Every panel, rows' nested ones included.
fn panels(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    let mut all = Vec::new();
    for panel in value["panels"].as_array().into_iter().flatten() {
        all.push(panel);
        all.extend(panels(panel));
    }
    all
}

#[test]
fn the_dashboards_query_documented_metrics_only() -> Result<(), serde_json::Error> {
    let documented = documented();
    assert!(documented.len() > 40, "the page's tables weren't found");
    let mut uids = BTreeSet::new();
    for (file, text) in DASHBOARDS {
        let dashboard: serde_json::Value = serde_json::from_str(text)?;
        let uid = dashboard["uid"].as_str().unwrap_or_default().to_owned();
        assert!(uids.insert(uid), "{file}: a uid another dashboard has");
        let mut queried = 0;
        for panel in panels(&dashboard) {
            if panel["type"] == "row" {
                continue;
            }
            let title = panel["title"].as_str().unwrap_or_default();
            assert_eq!(
                panel["datasource"]["uid"], "${datasource}",
                "{file}, {title}: not the dashboard's data source"
            );
            for target in panel["targets"].as_array().into_iter().flatten() {
                let expr = target["expr"].as_str().unwrap_or_default();
                for metric in metrics_in(expr) {
                    assert!(
                        family(&metric, &documented).is_some(),
                        "{file}, {title}: {metric} isn't in monitoring.md's tables"
                    );
                    queried += 1;
                }
            }
        }
        assert!(queried > 0, "{file}: no ferritor metric queried");
    }
    Ok(())
}

#[test]
fn a_query_names_its_families() {
    let found = metrics_in(
        "histogram_quantile(0.95, sum by (le) (rate(ferritor_csi_mount_duration_seconds_bucket[5m]))) \
         / sum(ferritor_csi_volumes{pod=~\"$pod\"})",
    );
    assert_eq!(
        found.iter().map(String::as_str).collect::<Vec<_>>(),
        [
            "ferritor_csi_mount_duration_seconds_bucket",
            "ferritor_csi_volumes"
        ]
    );
    let documented: BTreeSet<String> = [
        "ferritor_csi_mount_duration_seconds",
        "ferritor_csi_volumes",
    ]
    .map(str::to_owned)
    .into();
    assert!(found.iter().all(|m| family(m, &documented).is_some()));
    // A name ending in _count is its own unless only the histogram is known.
    assert!(family("ferritor_csi_volume_count", &documented).is_none());
}
