# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-16

### Added

- *(cli)* an owner-only access list for login --key-out on Windows
- *(agent)* the agent on Windows

### Fixed

- *(cli)* login --key-out's check refuses entries it can't read
- *(cli)* login --key-out's file checked, and long paths, on Windows

### Other

- the agent on Linux and on Windows Server, under platform groups
