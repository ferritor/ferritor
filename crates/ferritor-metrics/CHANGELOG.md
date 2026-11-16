# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.3](https://github.com/ferritor/ferritor/compare/ferritor-metrics-v0.9.2...ferritor-metrics-v0.9.3) - 2026-11-16

### Added

- Grafana dashboards for the server, the agent and the CSI provider
- *(agent)* metrics for the agent and the CSI provider, OTLP or Prometheus

### Fixed

- dashboard panels per pod, mount ratio at zero, histogram suffixes only for histograms
- *(agent)* metrics count what's in the files, and honour OTEL_SERVICE_NAME
