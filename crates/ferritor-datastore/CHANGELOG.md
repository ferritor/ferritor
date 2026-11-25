# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0](https://github.com/ferritor/ferritor/compare/ferritor-datastore-v1.0.1...ferritor-datastore-v1.1.0) - 2026-11-25

### Added

- *(datastore)* a shared schedule for the server's tasks
- ferritor list --overdue and --older-than
- rotation gauges for flagged secrets, KEKs and the root key
- rotation ages, and a flagged secret's due date in its metadata

### Fixed

- a purge pause holds inside each batch: once it returns, nothing deletes

## [1.0.1](https://github.com/ferritor/ferritor/compare/ferritor-datastore-v1.0.0...ferritor-datastore-v1.0.1) - 2026-11-22

### Other

- update Cargo.toml dependencies

## [0.9.0](https://github.com/ferritor/ferritor/releases/tag/ferritor-datastore-v0.9.0) - 2026-11-03

### Added

- ferritor 0.9.0

### Other

- the exhausted-pool tests open their one connection before the timeout matters
