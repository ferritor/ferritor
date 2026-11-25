# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0](https://github.com/ferritor/ferritor/compare/ferritor-cli-v1.0.1...ferritor-cli-v1.1.0) - 2026-11-25

### Added

- the server runs purge and rewrap on its own schedule
- the root key's and the KEKs' rotation due dates in status
- metadata labels owner, contact and description
- ferritor list --overdue and --older-than
- rotation ages, and a flagged secret's due date in its metadata

### Fixed

- a purge pause holds inside each batch: once it returns, nothing deletes
- older_than_days bounded in OpenAPI, --older-than described as an age cutoff

## [1.0.1](https://github.com/ferritor/ferritor/compare/ferritor-cli-v1.0.0...ferritor-cli-v1.0.1) - 2026-11-22

### Other

- update Cargo.toml dependencies

## [1.0.0](https://github.com/ferritor/ferritor/compare/ferritor-cli-v0.9.2...ferritor-cli-v1.0.0) - 2026-11-16

### Added

- *(cli)* an owner-only access list for login --key-out on Windows

### Fixed

- *(cli)* no cargo doc output collision with the root crate

### Other

- a CLI reference, and the docs start from a pinned release
- Merge pull request #18 from ferritor/feat/cli-key-out-acl

## [0.9.2](https://github.com/ferritor/ferritor/compare/ferritor-cli-v0.9.1...ferritor-cli-v0.9.2) - 2026-11-08

### Added

- the CLI for macOS and Windows
- auto-unseal with Google Cloud KMS

## [0.9.0](https://github.com/ferritor/ferritor/releases/tag/ferritor-cli-v0.9.0) - 2026-11-03

### Added

- ferritor 0.9.0
