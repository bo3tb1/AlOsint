# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-12

### Added

- DNS A-record lookups.
- RDAP domain registration summaries.
- RDAP IP network summaries with `--ip`.
- Subdomain discovery through crt.sh.
- Email search through crt.sh with `--email`.
- Unified JSON output with `--json`.
- Tor/SOCKS5 proxy support with `--tor`.
- File output with `--output`.
- Quiet mode with `--quiet`.
- Verbose stderr diagnostics with `--verbose`.
- Version reporting with `--version`.
- Legal and usage documentation.

### Fixed

- Lookup failures now exit with status 1.
- Oversized crt.sh responses are reported as "response too large".
- CLI usage errors exit with status 2.
