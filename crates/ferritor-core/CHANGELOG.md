# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0](https://github.com/ferritor/ferritor/compare/ferritor-core-v1.0.1...ferritor-core-v1.1.0) - 2026-11-25

### Added

- the server runs purge and rewrap on its own schedule
- owner may name a ferritor identity
- metadata labels owner, contact and description
- the rotation flag, ferritor.rotation=true, and reserved label keys

### Fixed

- the labels fuzz target formatted, and = allowed in a description's value

## [1.0.1](https://github.com/ferritor/ferritor/compare/ferritor-core-v1.0.0...ferritor-core-v1.0.1) - 2026-11-22

### Changed

- the audit log to a file (audit_file) or a collector (audit_otlp)

## [1.0.0](https://github.com/ferritor/ferritor/compare/ferritor-core-v0.9.2...ferritor-core-v1.0.0) - 2026-11-16

### Added

- *(agent)* metrics for the agent and the CSI provider, OTLP or Prometheus

## [0.9.2](https://github.com/ferritor/ferritor/compare/ferritor-core-v0.9.1...ferritor-core-v0.9.2) - 2026-11-08

### Other

- update Cargo.toml dependencies

## [0.9.0](https://github.com/ferritor/ferritor/releases/tag/ferritor-core-v0.9.0) - 2026-11-03

### Added

- ferritor 0.9.0
