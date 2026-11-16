# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.3](https://github.com/ferritor/ferritor/compare/v0.9.2...v0.9.3) - 2026-11-16

### Added

- *(agent)* metrics for the agent and the CSI provider, OTLP or Prometheus
- *(server)* Prometheus scrape endpoint, chosen in [metrics]
- Grafana dashboards for the server, the agent and the CSI provider
- *(cli)* an owner-only access list for login --key-out on Windows
- *(agent)* the agent on Windows

### Fixed

- *(server)* room for the whole first auto-unseal in the loop's test
- *(server)* room for the short-bound tests' setup on a busy runner
- *(server)* room for the stalled-keys-database test's setup on a busy runner
- dashboard panels per pod, mount ratio at zero, histogram suffixes only for histograms
- *(release)* ferritor-winsec released with the other crates
- *(agent)* metrics count what's in the files, and honour OTEL_SERVICE_NAME
- *(cli)* login --key-out's check refuses entries it can't read
- *(cli)* login --key-out's file checked, and long paths, on Windows
- *(agent)* stop the test's run once its round has connected
- *(cli)* no cargo doc output collision with the root crate
- *(agent)* stop at once, also in the middle of a round

### Other

- one Monitoring page for the server's, the agent's and the provider's metrics
- the docs download and verify 1.0.0
- Windows access lists by SID, the folder's list cleared and checked
- probe the databases over TCP, set owners on Windows, install the CLI from a fresh folder
- install steps stop at a failed check, wait for the databases
- a CLI reference, and the docs start from a pinned release
- the agent on Linux and on Windows Server, under platform groups
- Merge pull request #18 from ferritor/feat/cli-key-out-acl
- Merge pull request #17 from ferritor/fix/agent-stop-mid-round
- Merge pull request #12 from ferritor/dependabot/github_actions/actions-d6da0f860a
- bump the actions group across 1 directory with 4 updates
- Rust 1.100.0, Zig 0.17.1, cargo-zigbuild 0.24.1

## [0.9.2](https://github.com/ferritor/ferritor/compare/v0.9.1...v0.9.2) - 2026-11-08

### Added

- auto-unseal with Google Cloud KMS
- the CLI for macOS and Windows

### Other

- the examples name 0.9.2, the next release
- update dependencies
- fuzz/Cargo.lock for the Google Cloud KMS dependencies
- release-pr only when started by hand
- update Cargo.toml dependencies

## [0.9.1](https://github.com/ferritor/ferritor/compare/v0.9.0...v0.9.1) - 2026-11-03

### Added

- the release's binaries, checksums and signatures, published from a draft
- ferritor 0.9.0

### Fixed

- every commit in the product's changelog (the workspace root as a package)
- name libmimalloc-sys's two licenses, so the notices are the same everywhere

### Other

- the fuzz lockfile's update as a request file, not an argument
- the release pull request brings fuzz/Cargo.lock in line
- the examples name 0.9.1, the next release
- release v0.9.0
- tag the release as the ferritor-release App
- *(agent)* a longer certificate lifetime in the renewal test
- the exhausted-pool tests open their one connection before the timeout matters
- *(deps)* pulldown-cmark 0.13.6 (RUSTSEC-2026-0433)
- open the release pull request as the ferritor-release GitHub App
- Dependabot for the workflows' actions
- no `toolchain` input for dtolnay/rust-toolchain's version branch
- *(agent)* count queued exchange entries only once they're written
- rate-limit tests on a stopped clock
- *(fuzz)* rustfmt's import order after the rename

### Security

- ctutils 0.4.8 (RUSTSEC-2026-0385)

## [0.9.0](https://github.com/ferritor/ferritor/releases/tag/v0.9.0) - 2026-11-03

### Added

- ferritor 0.9.0

### Other

- rate-limit tests on a stopped clock
