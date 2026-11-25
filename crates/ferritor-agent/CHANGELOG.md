# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0](https://github.com/ferritor/ferritor/compare/ferritor-agent-v1.0.1...ferritor-agent-v1.1.0) - 2026-11-25

### Added

- ferritor list --overdue and --older-than

## [1.0.1](https://github.com/ferritor/ferritor/compare/ferritor-agent-v1.0.0...ferritor-agent-v1.0.1) - 2026-11-22

### Other

- update Cargo.toml dependencies

## [1.0.0](https://github.com/ferritor/ferritor/compare/ferritor-agent-v0.9.2...ferritor-agent-v1.0.0) - 2026-11-16

### Added

- *(agent)* metrics for the agent and the CSI provider, OTLP or Prometheus
- *(agent)* the agent on Windows

### Fixed

- *(agent)* metrics count what's in the files, and honour OTEL_SERVICE_NAME
- *(agent)* stop the test's run once its round has connected
- *(agent)* stop at once, also in the middle of a round

### Other

- one Monitoring page for the server's, the agent's and the provider's metrics

## [0.9.2](https://github.com/ferritor/ferritor/compare/ferritor-agent-v0.9.1...ferritor-agent-v0.9.2) - 2026-11-08

### Other

- update Cargo.toml dependencies

## [0.9.0](https://github.com/ferritor/ferritor/releases/tag/ferritor-agent-v0.9.0) - 2026-11-03

### Added

- ferritor 0.9.0

### Other

- *(agent)* a longer certificate lifetime in the renewal test
- *(agent)* count queued exchange entries only once they're written
