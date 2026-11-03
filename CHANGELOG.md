# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
