# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1-alpha.22] - 2026-06-01

Parity-sync release: brings the Rust client to feature/behavior parity with
the Go and Zig reference clients.

### Added

- Graph-native `Node`, `Edge`, and `Path` types with `as_node`, `as_edge`,
  and `as_path` conversions from object-shaped result values.
- GQL quoting helpers: `sanitize_graph_name`, `quote_ident` (digit-prefixed
  identifiers allowed; leading hyphen rejected), and `quote_string`.
- Named error predicates `Error::is_auth_error` (status class `28000` or the
  Geode `08P01` extension) and `Error::is_syntax_error` (status class
  `42000`), plus SQLSTATE class constants.
- Public `redact_dsn` for safely logging DSN strings.
- `Dsn::to_dsn` (and `Display`) for round-trip DSN formatting, mirroring Go's
  `FormatDSN`; password-only credentials fall back to a `pass=` query
  parameter. Backed by a proptest round-trip property.
- `RetryPolicy` and async `retry` helper with exponential backoff that retries
  only transient (retryable) errors.

### Fixed

- QUIC paging finalized: buffered frame reader, trailer draining, and real
  PULL paging (page size + session id).
- Skip server-emitted null-sentinel rows for `NODE`/`EDGE`/`PATH` columns so a
  no-match `MATCH` returns zero rows instead of one row of nulls (parity with
  Go fix `aa67cb0`).
