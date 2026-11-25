# Rust Client Parity-Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Use TDD: failing test first, then minimal implementation.

**Goal:** Bring the Rust Geode client to feature/behavior parity with the Go (`v0.1.22` + unreleased `main`) and Zig (`v0.2.10`) reference clients, then ship on `main` with a version bump and green CI.

**Architecture:** The Rust client already uses the same transport stack as the references (QUIC default via `quinn`, optional gRPC via `tonic`, ALPN `geode/1`, TLS 1.3, length-prefixed protobuf). This plan finalizes in-flight QUIC paging/heartbeat work and adds the recently-landed reference features the Rust client lacks: graph-native `Node`/`Edge`/`Path` types, GQL quoting helpers, named error predicates, DSN round-trip + public redaction, and a retry policy.

**Tech Stack:** Rust 2024 edition, MSRV 1.85, `quinn`/`rustls`/`tonic`, `cargo test`, GitLab CI (`rust-lint`, `rust-build`, `rust-test`, `security:cargo-audit`).

**Reference sources to mirror (read these):**

- Go types: `../geode-client-go/types.go` (`Node`, `Edge`, `Path`, `AsNode/AsEdge/AsPath`)
- Go quoting: `../geode-client-go/quote.go` (`SanitizeGraphName`, `QuoteIdent`, `QuoteString`, digit-prefix rule)
- Go errors: `../geode-client-go/errors.go` (`IsAuthError` → class 28000 + `08P01`; `IsSyntaxError` → 42000; `IsRetryableError`)
- Go config: `../geode-client-go/config.go` (`FormatDSN`), `pool.go` (`RedactDSN`)
- Go rows no-match fix: `../geode-client-go/rows.go` (skip null-sentinel rows for NODE/EDGE/PATH on no-match)
- Existing Node client equivalents: `../geode-client-nodejs/src/types.ts` (`GQLNode/GQLEdge/GQLPath`), `src/errors.ts`, `src/validate.ts`

---

## Baseline (verified 2026-06-01)

- Branch `codex/client-parity-sync`, builds clean (`cargo build --all-features`), `cargo test --lib` = 385 passed.
- Restored WIP in `src/client.rs`: buffered QUIC frame decoder (`decode_buffered_quic_message`, `read_proto_quic_buffered`, `try_read_proto_quic_buffered`), trailer draining (`drain_execute_trailers_quic`), real PULL paging (page_size + session_id), status-only statement handling. **Uncommitted.**
- Branch commits ahead of `main`: `bb6652b` (tolerate interleaved frames + gRPC TLS connector), `efe4eaa` (gRPC per-RPC reconnect + pool username/password).
- Dead-code warning: old `try_read_proto_quic` now unused (superseded by buffered variant).

---

### Task 1: Clean up & commit the in-flight QUIC paging WIP

**Files:**

- Modify: `src/client.rs` (remove now-dead `try_read_proto_quic`/`read_proto_quic` if fully superseded, or `#[allow(dead_code)]` only if still referenced by gRPC path — verify with grep first)
- Test: `tests/integration.rs` (existing), `src/client.rs` unit tests

- [ ] **Step 1:** Run `cargo build --all-features 2>&1 | grep -A3 dead_code` to enumerate dead-code warnings. Grep for each reported symbol to confirm zero call sites before removing.
- [ ] **Step 2:** Remove genuinely-dead readers; keep buffered variants. Re-run `cargo build --all-features` → expect zero warnings.
- [ ] **Step 3:** Run `cargo test --lib` → expect 385+ passed (no regressions).
- [ ] **Step 4:** Run `cargo clippy --all-features --all-targets -- -D warnings` → expect clean (fix any lint).
- [ ] **Step 5:** Commit: `git add -A && git commit -m "fix(quic): finalize buffered frame reader, trailer draining, and real PULL paging"`

---

### Task 2: Graph-native `Node` / `Edge` / `Path` types

**Files:**

- Create: `src/graph.rs` (new module for graph entity types)
- Modify: `src/lib.rs` (add `pub mod graph;` and re-export `Node`, `Edge`, `Path`)
- Modify: `src/types.rs` (add `Value::as_node`/`as_edge`/`as_path` conversions OR free fns in graph.rs that take `&Value`)
- Test: `src/graph.rs` `#[cfg(test)]`

Mirror Go `types.go`:

```
Node  { id: i64, labels: Vec<String>, properties: HashMap<String, Value> }
Edge  { id: i64, start_node: i64, end_node: i64, edge_type: String, properties: HashMap<String, Value> }
Path  { nodes: Vec<Node>, edges: Vec<Edge> }
```

Plus `fn as_node(v: &Value) -> Option<Node>`, `as_edge`, `as_path` that decode the server's object-shaped graph values (match how `client.rs` currently surfaces NODE/EDGE/PATH columns — inspect the decode path first).

- [ ] **Step 1:** Read `src/types.rs` decode path + how the server encodes NODE/EDGE/PATH (check `proto/geode.proto` and a live row via integration). Confirm the object key names (`id`, `labels`, `properties`, `start_node`/`startNode`, `end_node`, `type`).
- [ ] **Step 2:** Write failing tests in `src/graph.rs`: `test_as_node_from_object`, `test_as_edge_from_object`, `test_as_path_from_object`, `test_as_node_rejects_scalar`.
- [ ] **Step 3:** Run `cargo test --lib graph` → expect FAIL (module/types absent).
- [ ] **Step 4:** Implement `Node`/`Edge`/`Path` structs + `as_node`/`as_edge`/`as_path`. Derive `Debug, Clone, PartialEq`.
- [ ] **Step 5:** Re-export from `src/lib.rs`. Run `cargo test --lib graph` → PASS.
- [ ] **Step 6:** Run full `cargo test --lib` → no regressions. Commit: `feat(types): add graph-native Node/Edge/Path with as_node/as_edge/as_path`

---

### Task 3: GQL quoting / sanitization helpers

**Files:**

- Create: `src/quote.rs`
- Modify: `src/lib.rs` (re-export `sanitize_graph_name`, `quote_ident`, `quote_string`)
- Test: `src/quote.rs` `#[cfg(test)]`

Mirror Go `quote.go` semantics exactly:

- `sanitize_graph_name(&str) -> String` — strip to `[A-Za-z0-9_-]`.
- `quote_ident(&str) -> Result<String>` — validate bare GQL identifier: letters/digits/`_`/`-`, **digit-prefix allowed** (per fix `631132f`), no leading `-`, reject empty/control chars; return `Error::Validation` on invalid.
- `quote_string(&str) -> Result<String>` — single-quote wrap, escape `\\` then `'`, reject control chars.

- [ ] **Step 1:** Write failing tests covering: valid idents, digit-prefixed ident (`123abc` OK), leading-dash rejected, empty rejected, control-char rejected; string escaping of `\` and `'`; graph-name stripping.
- [ ] **Step 2:** `cargo test --lib quote` → FAIL.
- [ ] **Step 3:** Implement the three functions matching Go behavior.
- [ ] **Step 4:** `cargo test --lib quote` → PASS; full `cargo test --lib` → no regressions.
- [ ] **Step 5:** Commit: `feat(quote): add sanitize_graph_name, quote_ident, quote_string`

---

### Task 4: Named error predicates + public DSN redaction

**Files:**

- Modify: `src/error.rs` (add `is_auth_error`, `is_syntax_error` as methods on `Error` and/or free fns; confirm `is_retryable` parity)
- Modify: `src/dsn.rs` or `src/client.rs` (make `redact_dsn` public; add `Dsn::redacted()` / free `redact_dsn(&str) -> String`)
- Modify: `src/lib.rs` (re-export `redact_dsn`)
- Test: `src/error.rs`, `src/dsn.rs` `#[cfg(test)]`

Mirror Go `errors.go`: `is_auth_error` true for status class `28000` or Geode `08P01`; `is_syntax_error` true for `42000`.

- [ ] **Step 1:** Write failing tests: `Error::Query{code:"28000"}.is_auth_error()` true; `08P01` true; `42000` is_syntax_error true; non-matching false; `redact_dsn("quic://u:secret@h:3141")` masks password.
- [ ] **Step 2:** `cargo test --lib error dsn` → FAIL.
- [ ] **Step 3:** Implement predicates + make redaction public (it already exists privately in `client.rs:32`).
- [ ] **Step 4:** `cargo test --lib` → PASS, no regressions.
- [ ] **Step 5:** Commit: `feat(errors): add is_auth_error/is_syntax_error predicates and public redact_dsn`

---

### Task 5: DSN round-trip (`FormatDSN` equivalent)

**Files:**

- Modify: `src/dsn.rs` (impl `Display for Dsn` or `Dsn::to_dsn(&self) -> String`)
- Test: `src/dsn.rs` `#[cfg(test)]`

Mirror Go `Config.FormatDSN()`: emit `scheme://userinfo@host:port/graph?onlyNonDefaultParams`; password-only credentials fall back to `?pass=` (matches Go fix `6aee266`). Round-trip property: `Dsn::parse(d.to_dsn()) == d` for representative DSNs.

- [ ] **Step 1:** Write failing tests: round-trip for `quic://`, `grpc://`, graph path, page_size param, password-only.
- [ ] **Step 2:** `cargo test --lib dsn` → FAIL.
- [ ] **Step 3:** Implement `to_dsn`/`Display`.
- [ ] **Step 4:** Add a proptest round-trip case in `tests/proptest.rs` (parse∘format identity over generated DSNs).
- [ ] **Step 5:** `cargo test --lib && cargo test --test proptest` → PASS.
- [ ] **Step 6:** Commit: `feat(dsn): add DSN round-trip formatting (to_dsn)`

---

### Task 6: Retry policy with exponential backoff

**Files:**

- Create: `src/retry.rs`
- Modify: `src/lib.rs` (re-export `RetryPolicy`, `retry`)
- Test: `src/retry.rs` `#[cfg(test)]`

Mirror Go `RetryPolicy`/`Retry`: `RetryPolicy { max_attempts, initial_backoff, max_backoff, multiplier }`, `default()`; `async fn retry<F,Fut,T>(policy, f) -> Result<T>` retrying only when `Error::is_retryable()`.

- [ ] **Step 1:** Write failing tests: succeeds first try; retries retryable error then succeeds; gives up after max_attempts; does NOT retry non-retryable (e.g. Auth/Validation).
- [ ] **Step 2:** `cargo test --lib retry` → FAIL.
- [ ] **Step 3:** Implement using `tokio::time::sleep`; cap backoff at `max_backoff`.
- [ ] **Step 4:** `cargo test --lib` → PASS, no regressions.
- [ ] **Step 5:** Commit: `feat(retry): add RetryPolicy with exponential backoff for transient errors`

---

### Task 7: No-match null-sentinel row fix (bug parity with Go `aa67cb0`)

**Files:**

- Modify: `src/client.rs` (page decode: skip all-null sentinel rows when columns are NODE/EDGE/PATH and the query matched nothing)
- Test: `tests/integration.rs` (reproduction) + `src/client.rs` unit test if the decode is unit-testable

- [ ] **Step 1:** Reproduce: a `MATCH (n:NoSuch) RETURN n` style query should yield zero rows, not one row of nulls. Write a failing integration test `test_no_match_returns_empty` (mark with the integration feature; validate locally against the running server).
- [ ] **Step 2:** Inspect Go `rows.go` fix; port the equivalent guard into the Rust page decode.
- [ ] **Step 3:** Verify locally: `GEODE_HOST=127.0.0.1 GEODE_PORT=3141 GEODE_USERNAME=geode GEODE_PASSWORD=... cargo test --features integration test_no_match` → PASS.
- [ ] **Step 4:** Run `cargo test --lib` → no regressions. Commit: `fix(rows): skip null-sentinel rows for NODE/EDGE/PATH on no-match`

---

### Task 8: Validate, version bump, merge to main

**Files:**

- Modify: `Cargo.toml` (`version = "0.1.1-alpha.22"`), `CHANGELOG.md` (add entry)

- [ ] **Step 1:** Full local gate: `cargo fmt --check && cargo clippy --all-features --all-targets -- -D warnings && cargo test --lib && cargo test --test proptest && cargo test --doc`.
- [ ] **Step 2:** Integration gate vs local server (QUIC): `cargo test --features integration` with `GEODE_*` env → record pass/fail; fix regressions via TDD.
- [ ] **Step 3:** Bump `Cargo.toml` to `0.1.1-alpha.22`; update `CHANGELOG.md`. Commit: `chore(release): v0.1.1-alpha.22`.
- [ ] **Step 4:** Merge `codex/client-parity-sync` → `main` (no-ff), push `main`. **(Orchestrator handles git push + tag + CI.)**

---

## Self-Review Notes

- Spec coverage: Node/Edge/Path (T2), quoting (T3), error predicates+redaction (T4), DSN round-trip (T5), retry (T6), no-match fix (T7), WIP finalize (T1) — all reference features covered.
- AuthClient functional RBAC is intentionally **out of scope** (the Go reference does auth via HELLO only and exposes no RBAC client; Rust's type-only `AuthClient` matches Go's posture). Document as future parity-with-Node/Python item.
- crypto FLE and Go `graph` batch/pipeline/schema package are out of scope (Go-only; not part of the cross-client baseline).
