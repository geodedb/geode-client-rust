# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Multi-tenancy and FLE support in the HELLO handshake (GAP-0841): new
  `Client::tenant` and `Client::role` builder methods, and `tenant` /
  `tenant_id` / `role` DSN query parameters. When set, these are sent as
  `HelloRequest.tenant_id` (field 3) and `HelloRequest.role` (field 8) on both
  the QUIC and gRPC connect paths, so multi-tenant isolation and field-level
  encryption work from the Rust client. Both fields stay unset (no wire bytes)
  when not configured, preserving single-tenant / non-FLE behavior. Synced
  `proto/geode.proto` to add `role = 8` to match the server canonical schema.

## [0.2.0] - 2026-06-01

Parity-sync release: brings the Rust client to feature/behavior parity with
the Go and Zig reference clients. Promoted from the `0.1.1-alpha` line to a
`0.2.0` minor release to reflect the new public API surface (graph-native
types, quoting helpers, error predicates, DSN round-trip, retry policy).

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
- `PATH` result values now decode into the `{nodes, edges}` object shape (a
  `PathVal` conversion arm was missing), so `as_path` works against real
  server data.

### Notes

- The Go null-sentinel no-match skip (`aa67cb0`) was evaluated and intentionally
  not ported: the current Geode server (v0.6.x) already returns zero rows for a
  no-match `MATCH`, so the heuristic was unnecessary and produced false
  positives that dropped legitimate `CREATE ... RETURN` rows. Regression tests
  (`test_no_match_returns_empty`, `test_no_match_path_returns_empty`) assert the
  empty-result behavior.
