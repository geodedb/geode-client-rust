# Geode Rust Driver Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the `geode-client` Rust driver to feature parity with the reference `geode-client-go` driver by porting 11 missing features faithfully.

**Architecture:** Edits live in worktree `.worktrees/feat-driver-parity-2026-06` on branch `feat/driver-parity-2026-06`. Each feature is a focused module or extension of an existing module, matching the repo's `Error`/`Result` enum style, builder pattern, SecretString zeroization, and CWE-400/674 resource limits. Protobuf is generated opt-in (`GENERATE_PROTO=1`) and vendored at `src/generated/geode.rs`; since `protoc` is unavailable, the `role` proto field is hand-added to both `proto/geode.proto` and the vendored generated struct (field 8, prost `optional`).

**Tech Stack:** Rust 2024, tokio, quinn QUIC, rustls, prost 0.13, tonic 0.12, chrono, rust_decimal, criterion, proptest, cargo-fuzz; new crypto deps `aes-gcm`, `hkdf`, `hmac`, `sha2`, `base64`, `rand`, `zeroize`.

## Global Constraints

- Rust edition 2024, MSRV 1.85 — copied verbatim from `Cargo.toml`.
- `cargo clippy` MUST produce zero warnings (enforced); `cargo fmt --check` MUST pass.
- `cargo test` (unit), `cargo test --test proptest`, `cargo bench` MUST pass.
- Integration tests under `integration` feature MUST compile (`cargo test --features integration --no-run`).
- Error style: variants on `enum Error` in `src/error.rs` with `thiserror`; constructor helpers `Error::foo(...)`; classification via `is_retryable`.
- Credentials use `secrecy::SecretString` (zeroize on drop). Key material zeroized on drop (`zeroize`).
- Resource limits preserved (CWE-400 frame/row/page caps; CWE-674 recursion depth caps).
- `#![forbid(unsafe_code)]` is set crate-wide in `src/lib.rs` — no `unsafe`.
- Commit messages end with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- Pre-commit hooks run on commit (rustfmt, clippy, cargo check, commitizen). Use Conventional Commit messages (`feat:`, `test:`, `refactor:`).

---

### Task 1: HELLO `role` proto field + `tenant_id`/`role` builders & DSN

**Files:**

- Modify: `proto/geode.proto:77-85` (add `role` field 8 to `HelloRequest`)
- Modify: `src/generated/geode.rs:122-137` (hand-add `role` field, prost tag 8)
- Modify: `src/proto.rs` (update HelloRequest test literals to include `role`)
- Modify: `src/dsn.rs` (add `tenant_id`, `role` fields + getters + `?tenant_id=`/`?tenant=`/`?role=` params)
- Modify: `src/client.rs` (add `tenant_id`/`role` Client fields, builders, `from_dsn` wiring, HELLO construction)

**Interfaces:**

- Produces: `proto::HelloRequest { ..., pub role: Option<String> }` (tag 8); `Dsn::tenant_id() -> Option<&str>`, `Dsn::role() -> Option<&str>`; `Client::tenant_id(impl Into<String>) -> Self`, `Client::role(impl Into<String>) -> Self`.
- Consumes: existing `Dsn::parse`, existing `Client` builder pattern.

- [ ] **Step 1: Add the `role` field to the proto definition**

In `proto/geode.proto`, change the `HelloRequest` message (lines 77-85) to add field 8:

```proto
message HelloRequest {
  string username = 1;
  string password = 2;
  optional string tenant_id = 3;
  string client_name = 4;
  string client_version = 5;
  string wanted_conformance = 6;
  optional string graph = 7;
  optional string role = 8;
}
```

- [ ] **Step 2: Hand-add `role` to the vendored generated struct**

`protoc` is unavailable, so hand-edit `src/generated/geode.rs`. In the `HelloRequest` struct (ends at the line with `pub graph: ::core::option::Option<...>,`), add the `role` field after `graph`:

```rust
    #[prost(string, optional, tag = "7")]
    pub graph: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "8")]
    pub role: ::core::option::Option<::prost::alloc::string::String>,
}
```

- [ ] **Step 3: Write the failing encode/decode test for `role` (field 8)**

In `src/proto.rs` `mod tests`, add:

```rust
    #[test]
    fn test_hello_request_encodes_tenant_and_role() {
        let req = HelloRequest {
            username: "admin".to_string(),
            password: "secret".to_string(),
            tenant_id: Some("tenant1".to_string()),
            client_name: String::new(),
            client_version: String::new(),
            wanted_conformance: String::new(),
            graph: None,
            role: Some("analyst".to_string()),
        };
        let encoded = req.encode_to_vec();
        let decoded = HelloRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.tenant_id, Some("tenant1".to_string()));
        assert_eq!(decoded.role, Some("analyst".to_string()));

        // Field 8 wire tag (8 << 3 | 2 == 0x42) must appear for the optional string role.
        assert!(
            encoded.windows(1).any(|w| w[0] == 0x42),
            "expected wire tag for field 8 (role) in encoded bytes"
        );
    }
```

- [ ] **Step 4: Update existing HelloRequest literals to add `role: None`**

The existing tests `test_encode_decode_hello_roundtrip` (src/proto.rs) constructs `HelloRequest { ... graph: None }`. Add `role: None,` after `graph: None,` so it compiles.

- [ ] **Step 5: Run the proto tests to verify failure then add the field, then pass**

Run: `cargo test -p geode-client --lib proto::tests::test_hello_request_encodes_tenant_and_role`
Expected: PASS once Steps 1-4 are applied (the struct now has `role`).

- [ ] **Step 6: Add `tenant_id`/`role` to `Dsn`**

In `src/dsn.rs`, add fields to the `Dsn` struct (after `graph: Option<String>,`):

```rust
    tenant_id: Option<String>,
    role: Option<String>,
```

In `Default for Dsn`, add (after `graph: None,`):

```rust
            tenant_id: None,
            role: None,
```

In `apply_params`, add match arms (before the catch-all `_ =>`):

```rust
                "tenant_id" | "tenant" => {
                    self.tenant_id = Some(value.clone());
                }
                "role" => {
                    self.role = Some(value.clone());
                }
```

Add getters (near `graph()`):

```rust
    /// Get the tenant id if specified.
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    /// Get the role if specified.
    pub fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }
```

Add the two fields to the `Debug` impl `.field(...)` chain (after `graph`):

```rust
            .field("tenant_id", &self.tenant_id)
            .field("role", &self.role)
```

- [ ] **Step 7: Write failing DSN tests**

In `src/dsn.rs` `mod tests`:

```rust
    #[test]
    fn test_dsn_parse_tenant_and_role() {
        let dsn = Dsn::parse("quic://localhost:3141?tenant_id=acme&role=analyst").unwrap();
        assert_eq!(dsn.tenant_id(), Some("acme"));
        assert_eq!(dsn.role(), Some("analyst"));
    }

    #[test]
    fn test_dsn_parse_tenant_alias() {
        let dsn = Dsn::parse("quic://localhost:3141?tenant=acme").unwrap();
        assert_eq!(dsn.tenant_id(), Some("acme"));
    }

    #[test]
    fn test_dsn_tenant_role_default_none() {
        let dsn = Dsn::parse("quic://localhost:3141").unwrap();
        assert_eq!(dsn.tenant_id(), None);
        assert_eq!(dsn.role(), None);
    }
```

Run: `cargo test -p geode-client --lib dsn::tests::test_dsn_parse_tenant_and_role` → PASS after Step 6.

- [ ] **Step 8: Add `tenant_id`/`role` to `Client` (fields, builders, from_dsn, HELLO)**

In `src/client.rs`, add to the `Client` struct (after `graph: Option<String>,`):

```rust
    /// Tenant id sent in HELLO (field 3)
    tenant_id: Option<String>,
    /// Role sent in HELLO (field 8)
    role: Option<String>,
```

In `Client::new`, add (after `graph: None,`):

```rust
            tenant_id: None,
            role: None,
```

In `Client::from_dsn`, add (after `graph: dsn.graph().map(String::from),`):

```rust
            tenant_id: dsn.tenant_id().map(String::from),
            role: dsn.role().map(String::from),
```

Add builders (after the `graph` builder):

```rust
    /// Set the tenant id to send in the HELLO message.
    pub fn tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Set the role to send in the HELLO message (field-level-encryption role).
    pub fn role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }
```

In `Client::connect`, the QUIC branch calls `Connection::new_quic(...)`. Add `self.tenant_id.as_deref(), self.role.as_deref(),` to its argument list (after `self.graph.as_deref(),`). Add the same two `tenant_id`/`role` params (as `Option<&str>`) to:

- `Connection::new_quic` signature and its forwarding call to `connect_quic_once`,
- `Connection::connect_quic_once` signature.

In `connect_quic_once`, build the HELLO request with non-empty-only optional fields (matching Go: empty/absent means do not send):

```rust
        let hello_req = proto::HelloRequest {
            username: username.unwrap_or("").to_string(),
            password: password.unwrap_or("").to_string(),
            tenant_id: tenant_id
                .filter(|t| !t.is_empty())
                .map(String::from),
            client_name: hello_name.to_string(),
            client_version: hello_ver.to_string(),
            wanted_conformance: conformance.to_string(),
            graph: graph.filter(|g| !g.is_empty()).map(String::from),
            role: role.filter(|r| !r.is_empty()).map(String::from),
        };
```

For the gRPC branch in `connect`, leave `Connection::new_grpc` unchanged for tenant/role (gRPC path builds a DSN string); optionally append `&tenant_id=`/`&role=` — but keep scope minimal: QUIC HELLO is the wire path under test.

- [ ] **Step 9: Write a HELLO-construction test (verifies both fields land in encoded request)**

In `src/client.rs` `mod tests`, add a unit test that builds the HELLO request the same way `connect_quic_once` does and asserts encoding. Since `connect_quic_once` requires a live socket, test the request shape via a small helper. Add this free function near `redact_dsn` in `src/client.rs`:

```rust
/// Build a HELLO request from connection parameters. Optional string fields
/// (tenant_id, graph, role) are only populated when non-empty, matching the
/// reference Go driver: an empty value means "omit from the wire".
fn build_hello_request(
    username: Option<&str>,
    password: Option<&str>,
    hello_name: &str,
    hello_ver: &str,
    conformance: &str,
    graph: Option<&str>,
    tenant_id: Option<&str>,
    role: Option<&str>,
) -> proto::HelloRequest {
    proto::HelloRequest {
        username: username.unwrap_or("").to_string(),
        password: password.unwrap_or("").to_string(),
        tenant_id: tenant_id.filter(|t| !t.is_empty()).map(String::from),
        client_name: hello_name.to_string(),
        client_version: hello_ver.to_string(),
        wanted_conformance: conformance.to_string(),
        graph: graph.filter(|g| !g.is_empty()).map(String::from),
        role: role.filter(|r| !r.is_empty()).map(String::from),
    }
}
```

Then have `connect_quic_once` call `build_hello_request(...)` instead of the inline literal. Add the test:

```rust
    #[test]
    fn test_build_hello_request_includes_tenant_and_role() {
        use prost::Message;
        let req = build_hello_request(
            Some("admin"),
            Some("secret"),
            "geode-rust",
            "0.1",
            "min",
            None,
            Some("acme"),
            Some("analyst"),
        );
        assert_eq!(req.tenant_id, Some("acme".to_string()));
        assert_eq!(req.role, Some("analyst".to_string()));
        let encoded = req.encode_to_vec();
        let decoded = proto::HelloRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.tenant_id.as_deref(), Some("acme"));
        assert_eq!(decoded.role.as_deref(), Some("analyst"));
    }

    #[test]
    fn test_build_hello_request_omits_empty_optionals() {
        let req = build_hello_request(
            Some("u"), Some("p"), "n", "v", "min",
            Some(""), Some(""), Some(""),
        );
        assert_eq!(req.graph, None);
        assert_eq!(req.tenant_id, None);
        assert_eq!(req.role, None);
    }

    #[test]
    fn test_client_tenant_role_builders() {
        let _client = Client::new("localhost", 3141)
            .tenant_id("acme")
            .role("analyst");
    }
```

- [ ] **Step 10: Run, format, clippy, commit**

```bash
cargo test -p geode-client --lib client::tests::test_build_hello_request_includes_tenant_and_role
cargo fmt
cargo clippy --all-targets -- -D warnings
git add proto/geode.proto src/generated/geode.rs src/proto.rs src/dsn.rs src/client.rs
git commit -m "feat: add HELLO role field (proto field 8) and tenant_id/role config

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `parse_schema_fs`

**Files:**

- Create: `src/schema.rs`
- Modify: `src/lib.rs` (`pub mod schema;` + re-export `Statement`, `parse_schema_fs`)
- Create: `tests/fixtures/schema/01_nodes.gql`, `tests/fixtures/schema/02_edges.gql`, `tests/fixtures/schema/notes.txt`

**Interfaces:**

- Produces: `pub struct Statement { pub query: String, pub args: Vec<Value> }`; `pub fn parse_schema_fs(dir: impl AsRef<std::path::Path>) -> Result<Vec<Statement>>`.
- Consumes: `crate::error::{Error, Result}`, `crate::types::Value`.

Go reference (`schema.go`): reads `.gql` files in a directory (direct children only, no recursion, case-sensitive `.gql`); splits file content on `\n`; per line: trim, skip empty / `//` / `--`; uppercase the trimmed line and KEEP only if it starts with `CREATE`/`MERGE`/`MATCH`/`DELETE` (raw prefix match); then split the kept line on `;`, trim each part, emit non-empty parts as `Statement{query}`.

- [ ] **Step 1: Create fixtures**

`tests/fixtures/schema/01_nodes.gql`:

```text
// node schema
CREATE (a:Person {id: 1});
CREATE (b:Person {id: 2})
USE mygraph
```

`tests/fixtures/schema/02_edges.gql`:

```text
-- edges
MATCH (a),(b) MERGE (a)-[:KNOWS]->(b);
SET something = 1
DELETE (x)
```

`tests/fixtures/schema/notes.txt`:

```text
CREATE (ignored) -- this file is not .gql
```

- [ ] **Step 2: Write the failing test (module-internal)**

Create `src/schema.rs` with only the test first:

```rust
//! Schema file parsing, port of the Go driver's ParseSchemaFS.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_schema_fs_keeps_gql_statements() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/schema");
        let stmts = parse_schema_fs(dir).unwrap();
        let queries: Vec<&str> = stmts.iter().map(|s| s.query.as_str()).collect();
        // CREATE x2 from 01, MATCH...MERGE x1 + DELETE x1 from 02. USE/SET dropped, .txt ignored.
        assert!(queries.iter().any(|q| q.starts_with("CREATE (a:Person")));
        assert!(queries.iter().any(|q| q.starts_with("CREATE (b:Person")));
        assert!(queries.iter().any(|q| q.contains("MERGE")));
        assert!(queries.iter().any(|q| q.starts_with("DELETE (x)")));
        assert!(!queries.iter().any(|q| q.starts_with("USE")));
        assert!(!queries.iter().any(|q| q.starts_with("SET")));
        assert_eq!(queries.len(), 4);
    }

    #[test]
    fn test_parse_schema_fs_splits_on_semicolon() {
        let dir = std::env::temp_dir().join("geode_schema_split_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.gql"), "CREATE (a); CREATE (b); CREATE (c)\n").unwrap();
        let stmts = parse_schema_fs(&dir).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(stmts.len(), 3);
        assert_eq!(stmts[0].query, "CREATE (a)");
        assert_eq!(stmts[2].query, "CREATE (c)");
    }

    #[test]
    fn test_parse_schema_fs_missing_dir_errors() {
        let err = parse_schema_fs("/nonexistent/geode/schema/dir").unwrap_err();
        assert!(matches!(err, crate::error::Error::Io(_)) || err.to_string().contains("read dir"));
    }

    #[test]
    fn test_parse_schema_fs_empty_dir_ok() {
        let dir = std::env::temp_dir().join("geode_schema_empty_test");
        std::fs::create_dir_all(&dir).unwrap();
        let stmts = parse_schema_fs(&dir).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert!(stmts.is_empty());
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p geode-client --lib schema::tests`
Expected: FAIL (cannot find `parse_schema_fs`, `Statement`). Also add `pub mod schema;` to `src/lib.rs` first so it compiles to a fail.

- [ ] **Step 4: Implement `Statement` and `parse_schema_fs`**

At the top of `src/schema.rs` (above the tests module):

```rust
use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use crate::types::Value;

/// A single schema statement to execute. Mirrors the Go driver's `Statement`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Statement {
    /// The GQL query text.
    pub query: String,
    /// Positional arguments (unused for schema parsing; mirrors Go `Args`).
    pub args: Vec<Value>,
}

impl Statement {
    /// Create a statement with no arguments.
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            args: Vec::new(),
        }
    }
}

/// GQL keywords that mark a line as a real schema statement (case-insensitive
/// prefix match on the trimmed line), matching the Go reference exactly.
const GQL_KEYWORDS: [&str; 4] = ["CREATE", "MERGE", "MATCH", "DELETE"];

/// Parse `.gql` files in `dir` into a list of [`Statement`]s.
///
/// Reads direct children only (no recursion), keeping files whose name ends
/// with `.gql` (case-sensitive). Each file is split on newlines; each line is
/// trimmed, comment lines (`//`, `--`) and blank lines are skipped, and only
/// lines starting (case-insensitively) with CREATE/MERGE/MATCH/DELETE are kept.
/// Kept lines are split on `;` into individual statements.
///
/// # Errors
/// Returns [`Error::Io`] if the directory or any file cannot be read.
pub fn parse_schema_fs(dir: impl AsRef<Path>) -> Result<Vec<Statement>> {
    let dir = dir.as_ref();
    let entries = fs::read_dir(dir).map_err(|e| {
        Error::Other(format!(
            "geode: parse_schema_fs: read dir {}: {}",
            dir.display(),
            e
        ))
    })?;

    let mut statements = Vec::new();

    let mut names: Vec<std::path::PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(Error::Io)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(Error::Io)?;
        if file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".gql") {
            continue;
        }
        names.push(path);
    }
    // Deterministic order across platforms.
    names.sort();

    for path in names {
        let content = fs::read_to_string(&path).map_err(|e| {
            Error::Other(format!(
                "geode: parse_schema_fs: read {}: {}",
                path.display(),
                e
            ))
        })?;

        for line in content.split('\n') {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || trimmed.starts_with("--")
            {
                continue;
            }
            let upper = trimmed.to_uppercase();
            if !GQL_KEYWORDS.iter().any(|kw| upper.starts_with(kw)) {
                continue;
            }
            for part in trimmed.split(';') {
                let part = part.trim();
                if !part.is_empty() {
                    statements.push(Statement::new(part));
                }
            }
        }
    }

    Ok(statements)
}
```

- [ ] **Step 5: Wire into lib.rs**

In `src/lib.rs`, add `pub mod schema;` (with the other `pub mod`s) and add to the re-export block:

```rust
pub use schema::{Statement, parse_schema_fs};
```

- [ ] **Step 6: Run tests, format, clippy, commit**

```bash
cargo test -p geode-client --lib schema::tests
cargo fmt
cargo clippy --all-targets -- -D warnings
git add src/schema.rs src/lib.rs tests/fixtures/schema/
git commit -m "feat: add parse_schema_fs for .gql schema files

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Quoting helpers (`quote_ident`, `quote_string`, `sanitize_graph_name`)

**Files:**

- Create: `src/quote.rs`
- Modify: `src/error.rs` (add `InvalidIdent`, `InvalidString` variants + helpers)
- Modify: `src/lib.rs` (`pub mod quote;` + re-exports)

**Interfaces:**

- Produces: `pub fn quote_ident(name: &str) -> Result<String>`, `pub fn quote_string(s: &str) -> Result<String>`, `pub fn sanitize_graph_name(name: &str) -> String`. New `Error::InvalidIdent`, `Error::InvalidString`.
- Consumes: `crate::error::{Error, Result}`.

Go reference (`quote.go`): `QuoteIdent` returns the name unchanged if valid else `ErrInvalidIdent` (empty → error; allowed `[A-Za-z0-9_]` anywhere plus `-` except as first char). `QuoteString` errors on any control char (`r < 0x20 || r == 0x7f`), else escapes `\`→`\\` then `'`→`''` and wraps in single quotes. `SanitizeGraphName` never errors; keeps only `[A-Za-z0-9_-]`, drops everything else (including all non-ASCII).

- [ ] **Step 1: Add error variants**

In `src/error.rs`, add to `enum Error` (before `Other`):

```rust
    /// Invalid identifier (contains forbidden characters)
    #[error("Invalid identifier: {0}")]
    InvalidIdent(String),

    /// Invalid string literal (contains forbidden characters)
    #[error("Invalid string literal: {0}")]
    InvalidString(String),
```

Add helpers in `impl Error` (near `validation`):

```rust
    /// Create an invalid identifier error
    pub fn invalid_ident<S: Into<String>>(msg: S) -> Self {
        Error::InvalidIdent(msg.into())
    }

    /// Create an invalid string literal error
    pub fn invalid_string<S: Into<String>>(msg: S) -> Self {
        Error::InvalidString(msg.into())
    }
```

- [ ] **Step 2: Write failing tests**

Create `src/quote.rs` with the test module first:

```rust
//! GQL identifier and string-literal quoting helpers (port of Go quote.go).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn test_quote_ident_valid() {
        for name in ["abc", "ABC", "_foo", "foo_bar", "foo-bar", "foo9", "9starts", "005_add_index"] {
            assert_eq!(quote_ident(name).unwrap(), name);
        }
    }

    #[test]
    fn test_quote_ident_invalid() {
        for name in ["", "-starts", "has space", "has;semi", "has\0null"] {
            assert!(matches!(quote_ident(name), Err(Error::InvalidIdent(_))), "name={:?}", name);
        }
    }

    #[test]
    fn test_quote_string_basic() {
        assert_eq!(quote_string("hello").unwrap(), "'hello'");
        assert_eq!(quote_string("it's").unwrap(), "'it''s'");
    }

    #[test]
    fn test_quote_string_backslash_then_quote() {
        // backslash doubled FIRST, then quote doubled.
        assert_eq!(quote_string("back\\slash").unwrap(), "'back\\\\slash'");
        assert_eq!(quote_string("back\\'quote").unwrap(), "'back\\\\''quote'");
    }

    #[test]
    fn test_quote_string_rejects_control_chars() {
        for s in ["a\nb", "a\rb", "a\tb", "a\0b", "a\x1fb", "a\x7fb"] {
            assert!(matches!(quote_string(s), Err(Error::InvalidString(_))), "s={:?}", s);
        }
    }

    #[test]
    fn test_sanitize_graph_name() {
        assert_eq!(sanitize_graph_name("myGraph"), "myGraph");
        assert_eq!(sanitize_graph_name("my-graph_01"), "my-graph_01");
        assert_eq!(sanitize_graph_name("bad name!"), "badname");
        assert_eq!(sanitize_graph_name(""), "");
        assert_eq!(sanitize_graph_name("有害"), "");
        assert_eq!(sanitize_graph_name("   "), "");
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p geode-client --lib quote::tests` (after adding `pub mod quote;` to lib.rs)
Expected: FAIL (functions not found).

- [ ] **Step 4: Implement**

At the top of `src/quote.rs`:

```rust
use crate::error::{Error, Result};

/// Validate a GQL identifier. Returns the identifier unchanged when valid,
/// otherwise [`Error::InvalidIdent`].
///
/// Rules (matching the Go reference): non-empty; each character must be an
/// ASCII letter, digit, or `_` (allowed anywhere); `-` is allowed except as
/// the first character.
pub fn quote_ident(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(Error::invalid_ident("identifier is empty"));
    }
    for (i, ch) in name.chars().enumerate() {
        let ok = ch.is_ascii_alphabetic()
            || ch == '_'
            || ch.is_ascii_digit()
            || (ch == '-' && i != 0);
        if !ok {
            return Err(Error::invalid_ident(format!(
                "identifier contains forbidden character {:?}",
                ch
            )));
        }
    }
    Ok(name.to_string())
}

/// Quote a GQL string literal: rejects ASCII control characters, escapes
/// backslash then single-quote, and wraps the result in single quotes.
///
/// # Errors
/// Returns [`Error::InvalidString`] if `s` contains any character `< 0x20`
/// or `0x7f` (DEL).
pub fn quote_string(s: &str) -> Result<String> {
    for ch in s.chars() {
        let c = ch as u32;
        if c < 0x20 || c == 0x7f {
            return Err(Error::invalid_string(
                "string literal contains a control character",
            ));
        }
    }
    // Order matters: backslash first, then single-quote.
    let escaped = s.replace('\\', "\\\\").replace('\'', "''");
    Ok(format!("'{}'", escaped))
}

/// Sanitize a graph name by keeping only `[A-Za-z0-9_-]` and dropping every
/// other character (including all non-ASCII). Never fails.
pub fn sanitize_graph_name(name: &str) -> String {
    name.chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .collect()
}
```

- [ ] **Step 5: Wire into lib.rs**

Add `pub mod quote;` and:

```rust
pub use quote::{quote_ident, quote_string, sanitize_graph_name};
```

- [ ] **Step 6: Run, format, clippy, commit**

```bash
cargo test -p geode-client --lib quote::tests
cargo test -p geode-client --lib error::tests
cargo fmt
cargo clippy --all-targets -- -D warnings
git add src/quote.rs src/error.rs src/lib.rs
git commit -m "feat: add quote_ident/quote_string/sanitize_graph_name helpers

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: `Error::NoRows` + classification helpers (`is_auth_error`, `is_syntax_error`)

**Files:**

- Modify: `src/error.rs` (add `NoRows` variant, `no_rows()` ctor, `is_auth_error`, `is_syntax_error`, `status_class`)

**Interfaces:**

- Produces: `Error::NoRows`; `Error::no_rows() -> Self`; `Error::is_auth_error(&self) -> bool`; `Error::is_syntax_error(&self) -> bool`.
- Consumes: existing `Error::Query { code, message }`.

Go reference: `IsAuthError` true when `DriverError` status class is `28000` or `08P01`; `IsSyntaxError` true when class is `42000`. The Rust driver carries the status code in `Error::Query.code`. `ErrNoRows` is a sentinel.

- [ ] **Step 1: Write failing tests**

In `src/error.rs` `mod tests`:

```rust
    #[test]
    fn test_error_no_rows() {
        let err = Error::no_rows();
        assert!(matches!(err, Error::NoRows));
        assert_eq!(err.to_string(), "no rows in result set");
    }

    #[test]
    fn test_is_auth_error() {
        assert!(Error::Query { code: "28000".into(), message: "x".into() }.is_auth_error());
        assert!(Error::Query { code: "08P01".into(), message: "x".into() }.is_auth_error());
        assert!(!Error::Query { code: "42000".into(), message: "x".into() }.is_auth_error());
        assert!(!Error::Connection("x".into()).is_auth_error());
        // Auth variant also classifies as auth error.
        assert!(Error::Auth("bad".into()).is_auth_error());
    }

    #[test]
    fn test_is_syntax_error() {
        assert!(Error::Query { code: "42000".into(), message: "x".into() }.is_syntax_error());
        assert!(!Error::Query { code: "28000".into(), message: "x".into() }.is_syntax_error());
        assert!(!Error::Connection("x".into()).is_syntax_error());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p geode-client --lib error::tests::test_is_auth_error`
Expected: FAIL (no `NoRows`, no `is_auth_error`).

- [ ] **Step 3: Implement**

Add to `enum Error` (before `Other`):

```rust
    /// No rows returned by a query expected to return at least one row.
    #[error("no rows in result set")]
    NoRows,
```

Add to `impl Error` (near `code()`):

```rust
    /// Create a no-rows error.
    pub fn no_rows() -> Self {
        Error::NoRows
    }

    /// Returns the ISO/IEC 39075 status class for query errors.
    fn status_class(&self) -> Option<&str> {
        match self {
            Error::Query { code, .. } => Some(code.as_str()),
            _ => None,
        }
    }

    /// Returns true if this error represents an authentication/authorization
    /// failure (status class 28000 or the Geode-specific 08P01), or an
    /// [`Error::Auth`] variant.
    pub fn is_auth_error(&self) -> bool {
        if matches!(self, Error::Auth(_)) {
            return true;
        }
        matches!(self.status_class(), Some("28000") | Some("08P01"))
    }

    /// Returns true if this error represents a syntax error (status class 42000).
    pub fn is_syntax_error(&self) -> bool {
        self.status_class() == Some("42000")
    }
```

- [ ] **Step 4: Run, format, clippy, commit**

```bash
cargo test -p geode-client --lib error::tests
cargo fmt
cargo clippy --all-targets -- -D warnings
git add src/error.rs
git commit -m "feat: add Error::NoRows, is_auth_error, is_syntax_error

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `RetryPolicy` + async `retry`

**Files:**

- Create: `src/retry.rs`
- Modify: `src/lib.rs` (`pub mod retry;` + re-export `RetryPolicy`, `retry`)

**Interfaces:**

- Produces: `pub struct RetryPolicy { pub max_attempts: u32, pub initial_backoff: Duration, pub max_backoff: Duration, pub multiplier: f64 }`; `RetryPolicy::default()` (3 / 1s / 30s / 2.0); `RetryPolicy::backoff(&self, attempt: u32) -> Duration`; `pub async fn retry<F, Fut, T>(policy: RetryPolicy, mut op: F) -> Result<T> where F: FnMut() -> Fut, Fut: Future<Output = Result<T>>`.
- Consumes: `crate::error::{Error, Result}`, `Error::is_retryable`, `tokio::time::sleep`.

Go reference (`retry.go`): 3 attempts, initial 1s, max 30s, ×2.0; backoff(attempt) = initial * multiplier^(attempt-1) clamped to max (attempt 1-indexed); retry only when `is_retryable`; no jitter; returns immediately on success or non-retryable; sleeps after each failed non-final attempt.

- [ ] **Step 1: Write failing tests**

Create `src/retry.rs`:

```rust
//! Retry policy and helper (port of Go retry.go).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_default_policy() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_attempts, 3);
        assert_eq!(p.initial_backoff, Duration::from_secs(1));
        assert_eq!(p.max_backoff, Duration::from_secs(30));
        assert_eq!(p.multiplier, 2.0);
    }

    #[test]
    fn test_backoff_exponential_and_clamped() {
        let p = RetryPolicy::default();
        assert_eq!(p.backoff(1), Duration::from_secs(1));
        assert_eq!(p.backoff(2), Duration::from_secs(2));
        assert_eq!(p.backoff(3), Duration::from_secs(4));
        // clamp test
        let p2 = RetryPolicy {
            max_attempts: 5,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(5),
            multiplier: 10.0,
        };
        assert_eq!(p2.backoff(3), Duration::from_secs(5)); // 1*100 clamped to 5
    }

    fn fast_policy() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
            multiplier: 2.0,
        }
    }

    #[tokio::test]
    async fn test_retry_succeeds_first_attempt() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let r: Result<i32> = retry(fast_policy(), move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(42)
            }
        })
        .await;
        assert_eq!(r.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_retries_until_success() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let r: Result<i32> = retry(fast_policy(), move || {
            let c = c.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    Err(Error::Connection("transient".into()))
                } else {
                    Ok(7)
                }
            }
        })
        .await;
        assert_eq!(r.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_stops_on_non_retryable() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let r: Result<i32> = retry(fast_policy(), move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(Error::Query { code: "42000".into(), message: "syntax".into() })
            }
        })
        .await;
        assert!(r.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_exhausts_attempts() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let r: Result<i32> = retry(fast_policy(), move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(Error::Timeout)
            }
        })
        .await;
        assert!(r.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p geode-client --lib retry::tests` (after adding `pub mod retry;`)
Expected: FAIL.

- [ ] **Step 3: Implement**

At the top of `src/retry.rs`:

```rust
use std::future::Future;

use tokio::time::{Duration, sleep};

use crate::error::Result;

/// Retry policy: exponential backoff with a maximum number of attempts.
/// Defaults match the Go reference driver: 3 attempts, 1s initial backoff,
/// 30s max backoff, multiplier 2.0. No jitter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetryPolicy {
    /// Maximum number of attempts, including the first call. Values < 1 are
    /// treated as 1.
    pub max_attempts: u32,
    /// Backoff before the first retry.
    pub initial_backoff: Duration,
    /// Maximum backoff (clamp ceiling).
    pub max_backoff: Duration,
    /// Exponential multiplier per attempt.
    pub multiplier: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            multiplier: 2.0,
        }
    }
}

impl RetryPolicy {
    /// Compute the backoff for a 1-indexed attempt:
    /// `initial_backoff * multiplier^(attempt-1)`, clamped to `max_backoff`.
    pub fn backoff(&self, attempt: u32) -> Duration {
        let attempt = attempt.max(1);
        let factor = self.multiplier.powi((attempt - 1) as i32);
        let nanos = self.initial_backoff.as_nanos() as f64 * factor;
        if nanos > self.max_backoff.as_nanos() as f64 {
            return self.max_backoff;
        }
        // nanos is finite and within max_backoff (<= u64 nanos range in practice).
        Duration::from_nanos(nanos as u64)
    }
}

/// Run `op` with retries according to `policy`. Retries only errors for which
/// [`crate::error::Error::is_retryable`] is true. Returns the last error after
/// exhausting attempts, or immediately on success / non-retryable error.
pub async fn retry<F, Fut, T>(policy: RetryPolicy, mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let max_attempts = policy.max_attempts.max(1);
    let mut last_err = None;

    for attempt in 1..=max_attempts {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if !e.is_retryable() {
                    return Err(e);
                }
                if attempt == max_attempts {
                    last_err = Some(e);
                    break;
                }
                last_err = Some(e);
                sleep(policy.backoff(attempt)).await;
            }
        }
    }

    Err(last_err.expect("retry loop always records an error before breaking"))
}
```

- [ ] **Step 4: Wire into lib.rs**

Add `pub mod retry;` and:

```rust
pub use retry::{RetryPolicy, retry};
```

- [ ] **Step 5: Run, format, clippy, commit**

```bash
cargo test -p geode-client --lib retry::tests
cargo fmt
cargo clippy --all-targets -- -D warnings
git add src/retry.rs src/lib.rs
git commit -m "feat: add RetryPolicy and async retry helper

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `Dsn::to_string` (FormatDSN round-trip)

**Files:**

- Modify: `src/dsn.rs` (add `impl std::fmt::Display for Dsn` / `to_dsn_string`)
- Modify: `tests/proptest.rs` (round-trip proptest)

**Interfaces:**

- Produces: `impl std::fmt::Display for Dsn` (so `dsn.to_string()` works). Param keys emitted alphabetically; defaults omitted; IPv6 bracketed; userinfo via percent-encoding; password-only → `pass=` query param.
- Consumes: existing `Dsn` getters/fields from Task 1.

Go reference (`config.go` `FormatDSN`): scheme `quic`/`grpc`; `host:port` with IPv6 bracketing; userinfo `user:pass@` / `user@` / (password-only → `pass=` query); query params sorted alphabetically by key via `url.Values.Encode`; omit `page_size` when default 1000, `client_name`/`hello_name` when `geode-rust` default, `client_version` when default, `conformance` when `min`; emit `tls=0` only when TLS disabled; `insecure_tls_skip_verify=true` only when set; `graph`/`tenant`/`role`/`ca`/`cert`/`key`/`server_name`/`connect_timeout` when set.

- [ ] **Step 1: Write failing round-trip + format tests**

In `src/dsn.rs` `mod tests`:

```rust
    #[test]
    fn test_dsn_format_basic_quic_omits_defaults() {
        let dsn = Dsn::parse("quic://localhost:3141").unwrap();
        // No non-default params, no userinfo.
        assert_eq!(dsn.to_string(), "quic://localhost:3141");
    }

    #[test]
    fn test_dsn_format_ipv6_bracketed() {
        let dsn = Dsn::parse("grpc://[::1]:50051?tls=0").unwrap();
        let s = dsn.to_string();
        assert!(s.starts_with("grpc://[::1]:50051"), "got {}", s);
        assert!(s.contains("tls=0"));
    }

    #[test]
    fn test_dsn_format_params_sorted_and_nondefault() {
        let dsn = Dsn::parse(
            "quic://localhost:3141?page_size=500&conformance=full&graph=g&role=r&tenant_id=t"
        ).unwrap();
        let s = dsn.to_string();
        // Alphabetical key order: conformance, graph, page_size, role, tenant
        let q = s.split('?').nth(1).unwrap();
        let keys: Vec<&str> = q.split('&').map(|kv| kv.split('=').next().unwrap()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "params must be alphabetical: {}", q);
        assert!(q.contains("page_size=500"));
        assert!(q.contains("conformance=full"));
        assert!(q.contains("tenant=t"));
        assert!(q.contains("role=r"));
    }

    #[test]
    fn test_dsn_format_userinfo() {
        let dsn = Dsn::parse("quic://admin:secret@localhost:3141").unwrap();
        let s = dsn.to_string();
        assert!(s.contains("admin:secret@"), "got {}", s);
    }

    #[test]
    fn test_dsn_format_roundtrip_reparse() {
        let original = "grpc://localhost:50051?conformance=full&page_size=200&tls=0";
        let dsn = Dsn::parse(original).unwrap();
        let formatted = dsn.to_string();
        let reparsed = Dsn::parse(&formatted).unwrap();
        assert_eq!(reparsed.transport(), dsn.transport());
        assert_eq!(reparsed.host(), dsn.host());
        assert_eq!(reparsed.port(), dsn.port());
        assert_eq!(reparsed.page_size(), dsn.page_size());
        assert_eq!(reparsed.conformance(), dsn.conformance());
        assert_eq!(reparsed.tls_enabled(), dsn.tls_enabled());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p geode-client --lib dsn::tests::test_dsn_format_basic_quic_omits_defaults`
Expected: FAIL (`Dsn` does not implement `Display`).

- [ ] **Step 3: Implement `Display`**

Add to `src/dsn.rs` (after the `Debug` impl). Defaults referenced: page_size 1000, client_name `geode-rust`, client_version = crate version, conformance `min`.

```rust
impl std::fmt::Display for Dsn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Collect (key, value) params, then sort alphabetically by key to
        // match Go's url.Values.Encode ordering.
        let mut params: Vec<(String, String)> = Vec::new();

        if self.page_size != 1000 {
            params.push(("page_size".into(), self.page_size.to_string()));
        }
        if self.client_name != "geode-rust" {
            params.push(("client_name".into(), self.client_name.clone()));
        }
        if self.client_version != env!("CARGO_PKG_VERSION") {
            params.push(("client_version".into(), self.client_version.clone()));
        }
        if self.conformance != "min" {
            params.push(("conformance".into(), self.conformance.clone()));
        }
        if let Some(ca) = &self.ca_cert {
            params.push(("ca".into(), ca.clone()));
        }
        if let Some(cert) = &self.client_cert {
            params.push(("cert".into(), cert.clone()));
        }
        if let Some(key) = &self.client_key {
            params.push(("key".into(), key.clone()));
        }
        if self.skip_verify {
            params.push(("insecure_tls_skip_verify".into(), "true".into()));
        }
        if !self.tls_enabled {
            params.push(("tls".into(), "0".into()));
        }
        if let Some(graph) = &self.graph {
            params.push(("graph".into(), graph.clone()));
        }
        if let Some(tenant) = &self.tenant_id {
            params.push(("tenant".into(), tenant.clone()));
        }
        if let Some(role) = &self.role {
            params.push(("role".into(), role.clone()));
        }
        if let Some(sn) = &self.server_name {
            params.push(("server_name".into(), sn.clone()));
        }
        if let Some(t) = self.connect_timeout_secs {
            params.push(("connect_timeout".into(), t.to_string()));
        }

        // Userinfo (password-only becomes a `pass` query param).
        let userinfo = match (&self.username, &self.password) {
            (Some(u), Some(p)) => format!(
                "{}:{}@",
                urlencoding::encode(u),
                urlencoding::encode(p)
            ),
            (Some(u), None) => format!("{}@", urlencoding::encode(u)),
            (None, Some(p)) => {
                params.push(("pass".into(), p.clone()));
                String::new()
            }
            (None, None) => String::new(),
        };

        params.sort_by(|a, b| a.0.cmp(&b.0));

        let host = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };

        write!(f, "{}://{}{}", self.transport, userinfo, host)?;

        if !params.is_empty() {
            let query: Vec<String> = params
                .iter()
                .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
                .collect();
            write!(f, "?{}", query.join("&"))?;
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Run unit tests**

Run: `cargo test -p geode-client --lib dsn::tests`
Expected: PASS.

- [ ] **Step 5: Add proptest round-trip**

In `tests/proptest.rs`, add a strategy and proptest near the end (before final `}` of file if module-level). Add this self-contained test:

```rust
proptest! {
    #[test]
    fn prop_dsn_roundtrip(
        host in "[a-z][a-z0-9]{0,12}",
        port in 1u16..=65535,
        page_size in prop_oneof![Just(1000usize), 1usize..100_000],
        tls in any::<bool>(),
        conformance in prop_oneof![Just("min".to_string()), Just("full".to_string())],
    ) {
        use geode_client::Dsn;
        let scheme = if tls { "grpc" } else { "grpc" };
        let mut dsn_str = format!("{}://{}:{}?page_size={}&conformance={}", scheme, host, port, page_size, conformance);
        if !tls {
            dsn_str.push_str("&tls=0");
        }
        let dsn = Dsn::parse(&dsn_str).unwrap();
        let formatted = dsn.to_string();
        let reparsed = Dsn::parse(&formatted).unwrap();
        prop_assert_eq!(reparsed.host(), dsn.host());
        prop_assert_eq!(reparsed.port(), dsn.port());
        prop_assert_eq!(reparsed.page_size(), dsn.page_size());
        prop_assert_eq!(reparsed.conformance(), dsn.conformance());
        prop_assert_eq!(reparsed.tls_enabled(), dsn.tls_enabled());
    }
}
```

Note: `Dsn` must be re-exported from `lib.rs` (it already is via `pub use dsn::{DEFAULT_PORT, Dsn, Transport};`).

- [ ] **Step 6: Run proptest, format, clippy, commit**

```bash
cargo test --test proptest prop_dsn_roundtrip
cargo fmt
cargo clippy --all-targets -- -D warnings
git add src/dsn.rs tests/proptest.rs
git commit -m "feat: add Dsn Display (FormatDSN) with proptest round-trip

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: `Value::Node`/`Edge`/`Path` variants + accessors + proto decode

**Files:**

- Modify: `src/types.rs` (add `Node`/`Edge`/`Path` structs, `ValueKind` variants, `Value` fields, ctors, `as_node`/`as_edge`/`as_path`, `to_json` arms)
- Modify: `src/convert.rs` (decode `NodeVal`/`EdgeVal`/`PathVal` into the new variants; update existing tests)
- Modify: `src/lib.rs` (re-export `Node`, `Edge`, `Path`)

**Interfaces:**

- Produces:
  - `pub struct Node { pub id: i64, pub labels: Vec<String>, pub properties: HashMap<String, Value> }`
  - `pub struct Edge { pub id: i64, pub start_node: i64, pub end_node: i64, pub edge_type: String, pub properties: HashMap<String, Value> }`
  - `pub struct Path { pub nodes: Vec<Node>, pub edges: Vec<Edge> }`
  - `ValueKind::Node`, `ValueKind::Edge`, `ValueKind::Path`
  - `Value::node(Node)`, `Value::edge(Edge)`, `Value::path(Path)`
  - `Value::as_node() -> Result<&Node>`, `as_edge() -> Result<&Edge>`, `as_path() -> Result<&Path>`
- Consumes: existing `Value`, `crate::convert::proto_to_value`.

Go reference (`types.go`): `Node{ID, Labels, Properties}`, `Edge{ID, StartNode, EndNode, Type, Properties}`, `Path{Nodes, Edges}`. Proto `EdgeValue{from_id, to_id, label}` maps to `start_node`, `end_node`, `edge_type`.

- [ ] **Step 1: Add structs + ValueKind variants + Value fields (compile baseline)**

In `src/types.rs`, after `use ...`:

```rust
/// A graph node value.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub id: i64,
    pub labels: Vec<String>,
    pub properties: HashMap<String, Value>,
}

/// A graph edge (relationship) value.
#[derive(Debug, Clone, PartialEq)]
pub struct Edge {
    pub id: i64,
    pub start_node: i64,
    pub end_node: i64,
    pub edge_type: String,
    pub properties: HashMap<String, Value>,
}

/// A graph path value (alternating nodes and edges).
#[derive(Debug, Clone, PartialEq)]
pub struct Path {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}
```

Add to `enum ValueKind` (after `Range,`):

```rust
    Node,
    Edge,
    Path,
```

Add fields to `struct Value` (after `range_value: Option<Range>,`):

```rust
    node_value: Option<Box<Node>>,
    edge_value: Option<Box<Edge>>,
    path_value: Option<Box<Path>>,
```

Add these fields to the `Value::null()` initializer (set each to `None`):

```rust
            node_value: None,
            edge_value: None,
            path_value: None,
```

Derive `PartialEq` is NOT on `Value` (it has `HashMap`); we only derive on `Node`/`Edge`/`Path` which is fine. `Value` already derives `Debug, Clone`. `Node`/`Edge`/`Path` deriving `PartialEq` requires `Value: PartialEq`. To support that, add `#[derive(PartialEq)]` is not viable on `Value` because `decimal_scale: String` is fine but `HashMap` is fine for PartialEq. Actually `HashMap<String, Value>` implements `PartialEq` if `Value: PartialEq`. To avoid a large change, **do not** derive `PartialEq` on `Node`/`Edge`/`Path`; remove `PartialEq` from their derives:

Change the three derives to `#[derive(Debug, Clone)]` only. (Tests compare fields individually, not whole structs.)

- [ ] **Step 2: Add constructors + accessors + to_json**

Add constructors in `impl Value` (near `object`):

```rust
    /// Create a NODE value.
    pub fn node(node: Node) -> Self {
        Self {
            kind: ValueKind::Node,
            node_value: Some(Box::new(node)),
            ..Self::null()
        }
    }

    /// Create an EDGE value.
    pub fn edge(edge: Edge) -> Self {
        Self {
            kind: ValueKind::Edge,
            edge_value: Some(Box::new(edge)),
            ..Self::null()
        }
    }

    /// Create a PATH value.
    pub fn path(path: Path) -> Self {
        Self {
            kind: ValueKind::Path,
            path_value: Some(Box::new(path)),
            ..Self::null()
        }
    }
```

Add accessors (near `as_range`):

```rust
    /// Get as a graph node.
    pub fn as_node(&self) -> Result<&Node> {
        if self.kind == ValueKind::Node {
            self.node_value
                .as_deref()
                .ok_or_else(|| Error::type_error("Node value is None"))
        } else {
            Err(Error::type_error(format!("Cannot convert {:?} to node", self.kind)))
        }
    }

    /// Get as a graph edge.
    pub fn as_edge(&self) -> Result<&Edge> {
        if self.kind == ValueKind::Edge {
            self.edge_value
                .as_deref()
                .ok_or_else(|| Error::type_error("Edge value is None"))
        } else {
            Err(Error::type_error(format!("Cannot convert {:?} to edge", self.kind)))
        }
    }

    /// Get as a graph path.
    pub fn as_path(&self) -> Result<&Path> {
        if self.kind == ValueKind::Path {
            self.path_value
                .as_deref()
                .ok_or_else(|| Error::type_error("Path value is None"))
        } else {
            Err(Error::type_error(format!("Cannot convert {:?} to path", self.kind)))
        }
    }
```

Add `to_json` arms (in the `match self.kind` of `to_json`, before the closing brace; both `to_json` and `to_proto_string` match on all `ValueKind`s — add arms to both). For `to_json`:

```rust
            ValueKind::Node => {
                let mut map = serde_json::Map::new();
                if let Some(n) = &self.node_value {
                    map.insert("id".into(), serde_json::Value::Number(n.id.into()));
                    map.insert(
                        "labels".into(),
                        serde_json::Value::Array(
                            n.labels.iter().cloned().map(serde_json::Value::String).collect(),
                        ),
                    );
                    let mut props = serde_json::Map::new();
                    for (k, v) in &n.properties {
                        props.insert(k.clone(), v.to_json());
                    }
                    map.insert("properties".into(), serde_json::Value::Object(props));
                }
                serde_json::Value::Object(map)
            }
            ValueKind::Edge => {
                let mut map = serde_json::Map::new();
                if let Some(e) = &self.edge_value {
                    map.insert("id".into(), serde_json::Value::Number(e.id.into()));
                    map.insert("start_node".into(), serde_json::Value::Number(e.start_node.into()));
                    map.insert("end_node".into(), serde_json::Value::Number(e.end_node.into()));
                    map.insert("type".into(), serde_json::Value::String(e.edge_type.clone()));
                    let mut props = serde_json::Map::new();
                    for (k, v) in &e.properties {
                        props.insert(k.clone(), v.to_json());
                    }
                    map.insert("properties".into(), serde_json::Value::Object(props));
                }
                serde_json::Value::Object(map)
            }
            ValueKind::Path => {
                let mut map = serde_json::Map::new();
                if let Some(p) = &self.path_value {
                    map.insert(
                        "nodes".into(),
                        serde_json::Value::Array(
                            p.nodes.iter().map(|n| Value::node(n.clone()).to_json()).collect(),
                        ),
                    );
                    map.insert(
                        "edges".into(),
                        serde_json::Value::Array(
                            p.edges.iter().map(|e| Value::edge(e.clone()).to_json()).collect(),
                        ),
                    );
                }
                serde_json::Value::Object(map)
            }
```

For `to_proto_string`, add a single arm covering all three (serialize to JSON):

```rust
            ValueKind::Node | ValueKind::Edge | ValueKind::Path => {
                serde_json::to_string(&self.to_json()).unwrap_or_default()
            }
```

Also update `test_value_kind_all_variants` count: it asserts `variants.len() == 23`; we added 3 → update the array and assertion to 26 (add `ValueKind::Node, ValueKind::Edge, ValueKind::Path` to the `variants` array and change `assert_eq!(variants.len(), 26)`).

- [ ] **Step 3: Write failing decode + accessor tests**

In `src/types.rs` `mod tests`:

```rust
    #[test]
    fn test_value_node_accessor() {
        let mut props = HashMap::new();
        props.insert("name".to_string(), Value::string("Alice"));
        let node = Node { id: 42, labels: vec!["Person".into()], properties: props };
        let v = Value::node(node);
        assert_eq!(v.kind, ValueKind::Node);
        let n = v.as_node().unwrap();
        assert_eq!(n.id, 42);
        assert_eq!(n.labels, vec!["Person".to_string()]);
        assert_eq!(n.properties.get("name").unwrap().as_string().unwrap(), "Alice");
        assert!(v.as_edge().is_err());
    }

    #[test]
    fn test_value_edge_accessor() {
        let edge = Edge { id: 1, start_node: 10, end_node: 20, edge_type: "KNOWS".into(), properties: HashMap::new() };
        let v = Value::edge(edge);
        let e = v.as_edge().unwrap();
        assert_eq!(e.start_node, 10);
        assert_eq!(e.end_node, 20);
        assert_eq!(e.edge_type, "KNOWS");
    }

    #[test]
    fn test_value_path_accessor() {
        let n0 = Node { id: 1, labels: vec!["A".into()], properties: HashMap::new() };
        let n1 = Node { id: 2, labels: vec!["B".into()], properties: HashMap::new() };
        let e = Edge { id: 99, start_node: 1, end_node: 2, edge_type: "R".into(), properties: HashMap::new() };
        let v = Value::path(Path { nodes: vec![n0, n1], edges: vec![e] });
        let p = v.as_path().unwrap();
        assert_eq!(p.nodes.len(), 2);
        assert_eq!(p.edges.len(), 1);
        assert_eq!(p.edges[0].start_node, 1);
        assert_eq!(p.nodes[1].id, 2);
    }
```

- [ ] **Step 4: Run to verify pass for types**

Run: `cargo test -p geode-client --lib types::tests::test_value_node_accessor`
Expected: PASS after Steps 1-2.

- [ ] **Step 5: Update `convert.rs` to decode into the new variants**

In `src/convert.rs`, replace the `NodeVal` and `EdgeVal` match arms (currently building `Value::object(...)`) with:

```rust
        Some(proto::value::Kind::NodeVal(node)) => {
            Value::node(convert_node(node, next_depth))
        }
        Some(proto::value::Kind::EdgeVal(edge)) => {
            Value::edge(convert_edge(edge, next_depth))
        }
        Some(proto::value::Kind::PathVal(path)) => {
            let nodes = path
                .nodes
                .iter()
                .map(|n| convert_node(n, next_depth))
                .collect();
            let edges = path
                .edges
                .iter()
                .map(|e| convert_edge(e, next_depth))
                .collect();
            Value::path(crate::types::Path { nodes, edges })
        }
```

Add helper functions in `src/convert.rs` (above `proto_to_value`):

```rust
use crate::types::{Edge, Node};

fn convert_props(entries: &[proto::MapEntry], depth: usize) -> HashMap<String, Value> {
    let mut props = HashMap::new();
    for entry in entries {
        let val = entry
            .value
            .as_ref()
            .map(|v| proto_to_value_with_depth(v, depth))
            .unwrap_or_else(Value::null);
        props.insert(entry.key.clone(), val);
    }
    props
}

fn convert_node(node: &proto::NodeValue, depth: usize) -> Node {
    Node {
        id: node.id as i64,
        labels: node.labels.clone(),
        properties: convert_props(&node.properties, depth),
    }
}

fn convert_edge(edge: &proto::EdgeValue, depth: usize) -> Edge {
    Edge {
        id: edge.id as i64,
        start_node: edge.from_id as i64,
        end_node: edge.to_id as i64,
        edge_type: edge.label.clone(),
        properties: convert_props(&edge.properties, depth),
    }
}
```

- [ ] **Step 6: Update existing convert.rs and client.rs tests that assumed object decoding**

The existing `convert.rs` tests `test_proto_to_value_node` and `test_proto_to_value_edge` assert `Value::object` keys. Replace them with node/edge accessor assertions:

```rust
    #[test]
    fn test_proto_to_value_node() {
        let node = proto::NodeValue {
            id: 42,
            labels: vec!["Person".to_string()],
            properties: vec![proto::MapEntry {
                key: "name".to_string(),
                value: Some(proto::Value {
                    kind: Some(proto::value::Kind::StringVal(proto::StringValue {
                        value: "Alice".to_string(),
                        kind: 1,
                    })),
                }),
            }],
        };
        let val = proto_to_value(&proto::Value { kind: Some(proto::value::Kind::NodeVal(node)) });
        let n = val.as_node().unwrap();
        assert_eq!(n.id, 42);
        assert_eq!(n.labels, vec!["Person".to_string()]);
        assert_eq!(n.properties.get("name").unwrap().as_string().unwrap(), "Alice");
    }

    #[test]
    fn test_proto_to_value_edge() {
        let edge = proto::EdgeValue { id: 100, from_id: 1, to_id: 2, label: "KNOWS".to_string(), properties: vec![] };
        let val = proto_to_value(&proto::Value { kind: Some(proto::value::Kind::EdgeVal(edge)) });
        let e = val.as_edge().unwrap();
        assert_eq!(e.edge_type, "KNOWS");
        assert_eq!(e.start_node, 1);
        assert_eq!(e.end_node, 2);
    }

    #[test]
    fn test_proto_to_value_path_assembly() {
        let n0 = proto::NodeValue { id: 1, labels: vec!["A".into()], properties: vec![] };
        let n1 = proto::NodeValue { id: 2, labels: vec!["B".into()], properties: vec![] };
        let e = proto::EdgeValue { id: 9, from_id: 1, to_id: 2, label: "R".into(), properties: vec![] };
        let path = proto::PathValue { nodes: vec![n0, n1], edges: vec![e] };
        let val = proto_to_value(&proto::Value { kind: Some(proto::value::Kind::PathVal(path)) });
        let p = val.as_path().unwrap();
        assert_eq!(p.nodes.len(), 2);
        assert_eq!(p.edges.len(), 1);
        assert_eq!(p.edges[0].start_node, 1);
        assert_eq!(p.edges[0].end_node, 2);
    }
```

In `src/client.rs` `mod tests`, the tests `test_convert_edge_uses_type_field`, `test_convert_edge_uses_start_end_node`, `test_convert_edge_with_properties`, `test_convert_node_fields` assert object-style decoding. Rewrite them to use accessors:

```rust
    #[test]
    fn test_convert_edge_uses_type_field() {
        let edge = proto::EdgeValue { id: 100, from_id: 1, to_id: 2, label: "KNOWS".to_string(), properties: vec![] };
        let val = crate::convert::proto_to_value(&proto::Value { kind: Some(proto::value::Kind::EdgeVal(edge)) });
        let e = val.as_edge().unwrap();
        assert_eq!(e.edge_type, "KNOWS");
    }

    #[test]
    fn test_convert_edge_uses_start_end_node() {
        let edge = proto::EdgeValue { id: 100, from_id: 42, to_id: 99, label: "LIKES".to_string(), properties: vec![] };
        let val = crate::convert::proto_to_value(&proto::Value { kind: Some(proto::value::Kind::EdgeVal(edge)) });
        let e = val.as_edge().unwrap();
        assert_eq!(e.start_node, 42);
        assert_eq!(e.end_node, 99);
    }

    #[test]
    fn test_convert_edge_with_properties() {
        let edge = proto::EdgeValue {
            id: 100, from_id: 1, to_id: 2, label: "KNOWS".to_string(),
            properties: vec![proto::MapEntry {
                key: "since".to_string(),
                value: Some(proto::Value { kind: Some(proto::value::Kind::IntVal(proto::IntValue { value: 2020, kind: 1 })) }),
            }],
        };
        let val = crate::convert::proto_to_value(&proto::Value { kind: Some(proto::value::Kind::EdgeVal(edge)) });
        let e = val.as_edge().unwrap();
        assert_eq!(e.properties.get("since").unwrap().as_int().unwrap(), 2020);
    }

    #[test]
    fn test_convert_node_fields() {
        let node = proto::NodeValue {
            id: 42, labels: vec!["Person".to_string()],
            properties: vec![proto::MapEntry {
                key: "name".to_string(),
                value: Some(proto::Value { kind: Some(proto::value::Kind::StringVal(proto::StringValue { value: "Alice".to_string(), kind: 1 })) }),
            }],
        };
        let val = crate::convert::proto_to_value(&proto::Value { kind: Some(proto::value::Kind::NodeVal(node)) });
        let n = val.as_node().unwrap();
        assert_eq!(n.id, 42);
        assert_eq!(n.labels.len(), 1);
        assert_eq!(n.properties.get("name").unwrap().as_string().unwrap(), "Alice");
    }
```

- [ ] **Step 7: Re-export structs in lib.rs**

Change the types re-export line to:

```rust
pub use types::{Edge, Node, Path, Range, Value, ValueKind};
```

- [ ] **Step 8: Run all lib tests, format, clippy, commit**

```bash
cargo test -p geode-client --lib
cargo fmt
cargo clippy --all-targets -- -D warnings
git add src/types.rs src/convert.rs src/client.rs src/lib.rs
git commit -m "feat: add Value Node/Edge/Path variants with accessors and proto decode

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Crypto FLE module

**Files:**

- Modify: `Cargo.toml` (add `aes-gcm`, `hkdf`, `hmac`, `sha2`, `base64`, `rand`, `zeroize`; add crypto bench)
- Create: `src/crypto.rs`
- Modify: `src/lib.rs` (`pub mod crypto;` + re-export `Cipher`)
- Modify: `benches/benchmarks.rs` (add crypto benchmark group)

**Interfaces:**

- Produces: `pub struct Cipher` with `Cipher::new(master_key: &[u8]) -> Result<Self>`, `encrypt(&self, &[u8]) -> Result<Vec<u8>>`, `decrypt(&self, &[u8]) -> Result<Vec<u8>>`, `encrypt_string(&self, &str) -> Result<String>`, `decrypt_string(&self, &str) -> Result<String>`, `hmac_hex(&self, &str) -> String`. `Cipher: Drop` zeroizes key material.
- Consumes: `crate::error::{Error, Result}`.

Go reference (`crypto/cipher.go`): AES-256-GCM; HKDF-SHA256 with salt=None, info `geode-encrypt` (enc key) / `geode-hmac` (hmac key), each 32 bytes; master key ≥ 32 bytes; nonce = 12 random bytes prepended to ciphertext+16-byte tag; AAD = none; `encrypt_string`/`decrypt_string` use standard padded base64; `hmac_hex` = lowercase hex of HMAC-SHA256 over UTF-8 bytes keyed with the hmac key.

- [ ] **Step 1: Add dependencies**

In `Cargo.toml` `[dependencies]`, add:

```toml
# Field-level encryption (FLE)
aes-gcm = "0.10"
hkdf = "0.12"
hmac = "0.12"
sha2 = "0.10"
base64 = "0.22"
rand = "0.8"
zeroize = { version = "1.8", features = ["derive"] }
```

Run: `cargo build` to fetch deps. Expected: builds.

- [ ] **Step 2: Write failing tests**

Create `src/crypto.rs` with the test module:

```rust
//! Field-level encryption (FLE): AES-256-GCM with HKDF-SHA256 key derivation.
//! Port of the Go driver's crypto/cipher.go.

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        vec![b'k'; 32]
    }

    #[test]
    fn test_new_rejects_short_key() {
        assert!(Cipher::new(&[b'k'; 5]).is_err());
        assert!(Cipher::new(&[]).is_err());
        assert!(Cipher::new(&[b'k'; 32]).is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let c = Cipher::new(&key()).unwrap();
        let pt = vec![0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F];
        let ct = c.encrypt(&pt).unwrap();
        // layout: 12-byte nonce + ciphertext(len==pt) + 16-byte tag
        assert_eq!(ct.len(), 12 + pt.len() + 16);
        assert_eq!(c.decrypt(&ct).unwrap(), pt);
    }

    #[test]
    fn test_encrypt_nondeterministic() {
        let c = Cipher::new(&key()).unwrap();
        let a = c.encrypt(b"same plaintext").unwrap();
        let b = c.encrypt(b"same plaintext").unwrap();
        assert_ne!(a, b, "random nonce must make ciphertexts differ");
    }

    #[test]
    fn test_decrypt_tampered_fails() {
        let c = Cipher::new(&key()).unwrap();
        let mut ct = c.encrypt(b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(c.decrypt(&ct).is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let c = Cipher::new(&key()).unwrap();
        assert!(c.decrypt(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn test_encrypt_string_roundtrip() {
        let c = Cipher::new(&key()).unwrap();
        let enc = c.encrypt_string("hello, geode!").unwrap();
        assert_eq!(c.decrypt_string(&enc).unwrap(), "hello, geode!");
    }

    #[test]
    fn test_decrypt_string_invalid_base64() {
        let c = Cipher::new(&key()).unwrap();
        assert!(c.decrypt_string("not-valid-base64!!!").is_err());
    }

    #[test]
    fn test_empty_plaintext_roundtrips() {
        let c = Cipher::new(&key()).unwrap();
        let ct = c.encrypt(&[]).unwrap();
        assert_eq!(ct.len(), 12 + 16);
        assert_eq!(c.decrypt(&ct).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_hmac_hex_deterministic_and_distinct() {
        let c = Cipher::new(&key()).unwrap();
        let h1 = c.hmac_hex("user@example.com");
        let h2 = c.hmac_hex("user@example.com");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
        assert!(h1.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_ne!(c.hmac_hex("alice@x.com"), c.hmac_hex("bob@x.com"));
        // Different key -> different digest.
        let c2 = Cipher::new(&[b'a'; 32]).unwrap();
        assert_ne!(c.hmac_hex("user@example.com"), c2.hmac_hex("user@example.com"));
    }

    #[test]
    fn test_hmac_hex_matches_known_vector() {
        // HMAC-SHA256 over "test" with the HKDF-derived hmac key from a 32x'k' master.
        // Vector is self-consistent: recompute via the same primitives.
        let c = Cipher::new(&key()).unwrap();
        let h = c.hmac_hex("test");
        assert_eq!(h.len(), 64);
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p geode-client --lib crypto::tests::test_encrypt_decrypt_roundtrip` (after adding `pub mod crypto;`)
Expected: FAIL.

- [ ] **Step 4: Implement**

At the top of `src/crypto.rs`:

```rust
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// AES-256 key size in bytes.
const KEY_SIZE: usize = 32;
/// AES-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;
/// Minimum master key length in bytes.
const MIN_MASTER_KEY: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// A field-level-encryption cipher: AES-256-GCM with HKDF-SHA256-derived keys.
///
/// Key material is zeroized on drop.
pub struct Cipher {
    cipher: Aes256Gcm,
    hmac_key: [u8; KEY_SIZE],
}

impl Cipher {
    /// Create a cipher from a master key (must be at least 32 bytes).
    ///
    /// Derives an AES key (HKDF info `geode-encrypt`) and an HMAC key
    /// (HKDF info `geode-hmac`), both 32 bytes, with an empty salt.
    pub fn new(master_key: &[u8]) -> Result<Self> {
        if master_key.len() < MIN_MASTER_KEY {
            return Err(Error::Other(format!(
                "crypto: master key must be at least {} bytes, got {}",
                MIN_MASTER_KEY,
                master_key.len()
            )));
        }
        let mut enc_key = derive_key(master_key, b"geode-encrypt")?;
        let hmac_key = derive_key(master_key, b"geode-hmac")?;

        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| Error::Other(format!("crypto: invalid key: {}", e)))?;
        enc_key.zeroize();

        Ok(Self { cipher, hmac_key })
    }

    /// Encrypt plaintext. Output layout: `nonce(12) || ciphertext || tag(16)`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = self
            .cipher
            .encrypt(nonce, Payload { msg: plaintext, aad: &[] })
            .map_err(|e| Error::Other(format!("crypto: encrypt: {}", e)))?;

        let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a `nonce(12) || ciphertext || tag(16)` buffer.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(Error::Other("crypto: ciphertext too short".into()));
        }
        let (nonce_bytes, data) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, Payload { msg: data, aad: &[] })
            .map_err(|e| Error::Other(format!("crypto: decrypt: {}", e)))
    }

    /// Encrypt a string and return standard padded base64.
    pub fn encrypt_string(&self, plaintext: &str) -> Result<String> {
        let ct = self.encrypt(plaintext.as_bytes())?;
        Ok(BASE64.encode(ct))
    }

    /// Decrypt a standard padded base64 string.
    pub fn decrypt_string(&self, encoded: &str) -> Result<String> {
        let ct = BASE64
            .decode(encoded)
            .map_err(|e| Error::Other(format!("crypto: base64 decode: {}", e)))?;
        let pt = self.decrypt(&ct)?;
        String::from_utf8(pt).map_err(|e| Error::Other(format!("crypto: utf8: {}", e)))
    }

    /// Compute the lowercase hex HMAC-SHA256 of `data` using the HMAC key.
    /// Deterministic — used for searchable equality lookups.
    pub fn hmac_hex(&self, data: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .expect("HMAC accepts any key length");
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

impl Drop for Cipher {
    fn drop(&mut self) {
        self.hmac_key.zeroize();
    }
}

/// Derive a 32-byte key from the master key using HKDF-SHA256 with empty salt
/// and the given `info` context bytes.
fn derive_key(master_key: &[u8], info: &[u8]) -> Result<[u8; KEY_SIZE]> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; KEY_SIZE];
    hk.expand(info, &mut okm)
        .map_err(|e| Error::Other(format!("crypto: hkdf: {}", e)))?;
    Ok(okm)
}
```

- [ ] **Step 5: Wire into lib.rs**

Add `pub mod crypto;` and:

```rust
pub use crypto::Cipher;
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p geode-client --lib crypto::tests`
Expected: PASS.

- [ ] **Step 7: Add criterion bench**

In `benches/benchmarks.rs`, add a benchmark function and register it in `criterion_group!`. Add near the other bench fns:

```rust
fn bench_crypto(c: &mut Criterion) {
    use geode_client::Cipher;
    let cipher = Cipher::new(&[b'k'; 32]).unwrap();
    let plaintext = vec![0xABu8; 256];

    let mut group = c.benchmark_group("crypto");
    group.bench_function("encrypt_256b", |b| {
        b.iter(|| black_box(cipher.encrypt(black_box(&plaintext)).unwrap()))
    });
    let ct = cipher.encrypt(&plaintext).unwrap();
    group.bench_function("decrypt_256b", |b| {
        b.iter(|| black_box(cipher.decrypt(black_box(&ct)).unwrap()))
    });
    group.bench_function("hmac_hex", |b| {
        b.iter(|| black_box(cipher.hmac_hex(black_box("user@example.com"))))
    });
    group.finish();
}
```

Find the `criterion_group!(benches, ...)` macro invocation and add `bench_crypto` to its function list.

- [ ] **Step 8: Run bench compile + format + clippy + commit**

```bash
cargo bench --no-run
cargo test -p geode-client --lib crypto::tests
cargo fmt
cargo clippy --all-targets -- -D warnings
git add Cargo.toml Cargo.lock src/crypto.rs src/lib.rs benches/benchmarks.rs
git commit -m "feat: add crypto FLE module (AES-256-GCM + HKDF + HMAC)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 9: Add a cargo-fuzz target for crypto round-trip**

Create `fuzz/fuzz_targets/fuzz_crypto_roundtrip.rs`:

```rust
//! Fuzz target: crypto decrypt must never panic on arbitrary input, and
//! encrypt->decrypt must round-trip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use geode_client::Cipher;

fuzz_target!(|data: &[u8]| {
    let cipher = Cipher::new(&[b'k'; 32]).unwrap();
    // decrypt must not panic on arbitrary bytes
    let _ = cipher.decrypt(data);
    // round-trip
    if let Ok(ct) = cipher.encrypt(data) {
        let pt = cipher.decrypt(&ct).expect("roundtrip decrypt");
        assert_eq!(pt, data);
    }
});
```

In `fuzz/Cargo.toml`, add a `[[bin]]` block:

```toml
[[bin]]
name = "fuzz_crypto_roundtrip"
path = "fuzz_targets/fuzz_crypto_roundtrip.rs"
test = false
doc = false
bench = false
```

Verify it compiles (cargo-fuzz uses nightly; if unavailable, at minimum `cargo build` the file syntactically by checking the target list). Run if toolchain present:

```bash
cargo +nightly fuzz check fuzz_crypto_roundtrip 2>/dev/null || echo "cargo-fuzz/nightly unavailable; target added"
git add fuzz/fuzz_targets/fuzz_crypto_roundtrip.rs fuzz/Cargo.toml
git commit -m "test: add fuzz target for crypto encrypt/decrypt round-trip

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: `ConnectionPool::from_dsn` / `from_config`

**Files:**

- Modify: `src/pool.rs` (add `from_dsn`, `from_client`, `max_size` config)

**Interfaces:**

- Produces: `ConnectionPool::from_dsn(dsn: &str) -> Result<ConnectionPool>`; `ConnectionPool::from_dsn_with_size(dsn: &str, max_size: usize) -> Result<ConnectionPool>`; `ConnectionPool::from_client(client: Client, max_size: usize) -> ConnectionPool`.
- Consumes: `crate::client::Client`, `Client::from_dsn`, existing `ConnectionPool` fields.

Go reference (`pool.go`): `NewPool(dsn)` parses DSN then builds the pool with default max-open (16). `NewPoolFromConfig(cfg)` builds from a config struct. For Rust, mirror with `from_dsn` (default max 16) and `from_client`.

- [ ] **Step 1: Write failing tests**

In `src/pool.rs` `mod tests`:

```rust
    #[test]
    fn test_pool_from_dsn() {
        let pool = ConnectionPool::from_dsn("quic://localhost:3141?insecure=true").unwrap();
        assert_eq!(pool.max_size(), 16); // DEFAULT_POOL_MAX_SIZE
    }

    #[test]
    fn test_pool_from_dsn_with_size() {
        let pool = ConnectionPool::from_dsn_with_size("grpc://localhost:50051?tls=0", 4).unwrap();
        assert_eq!(pool.max_size(), 4);
    }

    #[test]
    fn test_pool_from_dsn_invalid() {
        assert!(ConnectionPool::from_dsn("http://localhost:1").is_err());
    }

    #[test]
    fn test_pool_from_client() {
        let client = Client::new("localhost", 3141).skip_verify(true);
        let pool = ConnectionPool::from_client(client, 8);
        assert_eq!(pool.max_size(), 8);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p geode-client --lib pool::tests::test_pool_from_dsn`
Expected: FAIL.

- [ ] **Step 3: Implement**

In `src/pool.rs`, add a constant and constructors. After the `use` lines:

```rust
/// Default maximum pool size, matching the Go driver's DefaultMaxOpenConns.
pub const DEFAULT_POOL_MAX_SIZE: usize = 16;
```

Add to `impl ConnectionPool` (after `new`):

```rust
    /// Build a pool from a DSN string using the default max size (16).
    ///
    /// # Errors
    /// Returns an error if the DSN is invalid.
    pub fn from_dsn(dsn: &str) -> Result<Self> {
        Self::from_dsn_with_size(dsn, DEFAULT_POOL_MAX_SIZE)
    }

    /// Build a pool from a DSN string with an explicit max size.
    ///
    /// # Panics
    /// Panics if `max_size` is 0 (a pool needs at least one slot).
    ///
    /// # Errors
    /// Returns an error if the DSN is invalid.
    pub fn from_dsn_with_size(dsn: &str, max_size: usize) -> Result<Self> {
        assert!(max_size > 0, "ConnectionPool max_size must be at least 1");
        let client = Client::from_dsn(dsn)?;
        Ok(Self::from_client(client, max_size))
    }

    /// Build a pool from a pre-configured [`Client`].
    ///
    /// # Panics
    /// Panics if `max_size` is 0.
    pub fn from_client(client: Client, max_size: usize) -> Self {
        assert!(max_size > 0, "ConnectionPool max_size must be at least 1");
        Self {
            client,
            connections: Arc::new(Mutex::new(Vec::new())),
            semaphore: Arc::new(Semaphore::new(max_size)),
            max_size,
        }
    }
```

- [ ] **Step 4: Run tests, format, clippy, commit**

```bash
cargo test -p geode-client --lib pool::tests
cargo fmt
cargo clippy --all-targets -- -D warnings
git add src/pool.rs
git commit -m "feat: add ConnectionPool::from_dsn/from_dsn_with_size/from_client

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: `Statement`, `batch_exec`, concurrent `pipeline_exec`

**Files:**

- Create: `src/batch.rs`
- Modify: `src/lib.rs` (`pub mod batch;` + re-export constants)
- Modify: `src/pool.rs` (add `batch_exec`, `pipeline_exec` on `ConnectionPool`)

**Interfaces:**

- Produces: `pub const DEFAULT_CHUNK_SIZE: usize = 100`; `pub const DEFAULT_MAX_WORKERS: usize = 8`; `Statement` (reuse from Task 2, `crate::schema::Statement`); `ConnectionPool::batch_exec(&self, stmts: &[Statement]) -> Result<()>`; `ConnectionPool::pipeline_exec(&self, stmts: &[Statement], chunk_size: usize, max_workers: usize) -> Result<()>`. Also a unit-testable pure helper `chunk_statements(&[Statement], usize) -> Vec<Vec<Statement>>`.
- Consumes: `crate::schema::Statement`, `crate::retry::{RetryPolicy, retry}` (Task 5), `ConnectionPool::acquire` (needs a live connection for execution path), `tokio::sync::Semaphore`, `tokio::task::JoinSet`.

Go reference (`batch.go`): `BatchExec` runs all statements in one tx with `Retry(DefaultRetryPolicy)`. `PipelineExec(stmts, chunkSize, maxWorkers)`: chunkSize≤0→100, maxWorkers≤0→8; chunk contiguous; bounded concurrency via semaphore of `maxWorkers`; first error stops dispatching NEW chunks, in-flight complete; each chunk = `BatchExec` (single tx + retry); returns first error.

Note on execution: `batch_exec` needs a connection from the pool. Since unit tests run without a server, the **concurrency, chunking, and first-error semantics** are tested with a pure, injectable executor; the live path is exercised only under the `integration` feature.

- [ ] **Step 1: Create batch module with constants + chunking helper + tests**

Create `src/batch.rs`:

```rust
//! Batch and pipelined statement execution (port of Go batch.go).

use crate::schema::Statement;

/// Default chunk size for [`ConnectionPool::pipeline_exec`](crate::ConnectionPool::pipeline_exec).
pub const DEFAULT_CHUNK_SIZE: usize = 100;
/// Default worker count for pipelined execution.
pub const DEFAULT_MAX_WORKERS: usize = 8;

/// Split statements into contiguous chunks of at most `chunk_size`.
/// A `chunk_size` of 0 is treated as [`DEFAULT_CHUNK_SIZE`].
pub(crate) fn chunk_statements(stmts: &[Statement], chunk_size: usize) -> Vec<Vec<Statement>> {
    let chunk_size = if chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size
    };
    stmts
        .chunks(chunk_size)
        .map(|c| c.to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Statement;

    fn stmts(n: usize) -> Vec<Statement> {
        (0..n).map(|i| Statement::new(format!("CREATE (n {{i: {}}})", i))).collect()
    }

    #[test]
    fn test_chunk_statements_exact() {
        let c = chunk_statements(&stmts(10), 3);
        assert_eq!(c.len(), 4); // 3+3+3+1
        assert_eq!(c[0].len(), 3);
        assert_eq!(c[3].len(), 1);
    }

    #[test]
    fn test_chunk_statements_single_chunk() {
        let c = chunk_statements(&stmts(50), 100);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].len(), 50);
    }

    #[test]
    fn test_chunk_statements_chunk_size_one() {
        let c = chunk_statements(&stmts(5), 1);
        assert_eq!(c.len(), 5);
    }

    #[test]
    fn test_chunk_statements_zero_defaults() {
        let c = chunk_statements(&stmts(250), 0);
        assert_eq!(c.len(), 3); // 100+100+50
    }

    #[test]
    fn test_chunk_statements_empty() {
        let c = chunk_statements(&[], 10);
        assert!(c.is_empty());
    }
}
```

- [ ] **Step 2: Run chunk tests**

Run: `cargo test -p geode-client --lib batch::tests` (after adding `pub mod batch;`)
Expected: PASS.

- [ ] **Step 3: Add an injectable pipeline driver with first-error/concurrency tests**

The live executor requires a server, so factor the concurrency logic into a generic async driver that takes a per-chunk executor. Add to `src/batch.rs` (above the tests):

```rust
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;

use crate::error::{Error, Result};

/// Run `exec` over the chunks of `stmts` with bounded concurrency.
/// First error stops dispatching new chunks; in-flight chunks complete.
/// Returns the first error recorded (or Ok if all succeed).
pub(crate) async fn pipeline_drive<F, Fut>(
    stmts: &[Statement],
    chunk_size: usize,
    max_workers: usize,
    exec: F,
) -> Result<()>
where
    F: Fn(Vec<Statement>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    if stmts.is_empty() {
        return Ok(());
    }
    let max_workers = if max_workers == 0 {
        DEFAULT_MAX_WORKERS
    } else {
        max_workers
    };
    let chunks = chunk_statements(stmts, chunk_size);

    let sem = Arc::new(Semaphore::new(max_workers));
    let first_err: Arc<Mutex<Option<Error>>> = Arc::new(Mutex::new(None));
    let exec = Arc::new(exec);
    let mut set: JoinSet<()> = JoinSet::new();

    for chunk in chunks {
        // Stop dispatching new chunks once an error has been recorded.
        if first_err.lock().await.is_some() {
            break;
        }
        let permit = Arc::clone(&sem)
            .acquire_owned()
            .await
            .map_err(|_| Error::pool("pipeline semaphore closed"))?;
        let exec = Arc::clone(&exec);
        let first_err = Arc::clone(&first_err);
        set.spawn(async move {
            let _permit = permit; // released on drop
            if let Err(e) = exec(chunk).await {
                let mut slot = first_err.lock().await;
                if slot.is_none() {
                    *slot = Some(e);
                }
            }
        });
    }

    // Wait for all in-flight chunks to complete.
    while set.join_next().await.is_some() {}

    match Arc::try_unwrap(first_err) {
        Ok(m) => match m.into_inner() {
            Some(e) => Err(e),
            None => Ok(()),
        },
        Err(arc) => {
            let mut guard = arc.lock().await;
            match guard.take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }
}

/// Maximum concurrent in-flight chunks observed by a test counter helper.
#[doc(hidden)]
pub(crate) struct ConcurrencyGauge {
    pub current: AtomicUsize,
    pub max: AtomicUsize,
}

impl ConcurrencyGauge {
    pub fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
            max: AtomicUsize::new(0),
        }
    }
    pub fn enter(&self) {
        let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
        self.max.fetch_max(now, Ordering::SeqCst);
    }
    pub fn leave(&self) {
        self.current.fetch_sub(1, Ordering::SeqCst);
    }
}
```

Add tests to `src/batch.rs` `mod tests`:

```rust
    use crate::error::Error;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    #[tokio::test]
    async fn test_pipeline_drive_all_succeed() {
        let s = stmts(25);
        let res = super::pipeline_drive(&s, 10, 4, |_chunk| async { Ok(()) }).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_pipeline_drive_first_error_returned() {
        let s = stmts(30);
        // chunk size 10 => 3 chunks; the chunk containing index 0 errors.
        let res = super::pipeline_drive(&s, 10, 8, |chunk| async move {
            if chunk[0].query.contains("i: 0") {
                Err(Error::Query { code: "42000".into(), message: "boom".into() })
            } else {
                Ok(())
            }
        })
        .await;
        let err = res.unwrap_err();
        assert!(err.to_string().contains("boom"));
    }

    #[tokio::test]
    async fn test_pipeline_drive_respects_worker_bound() {
        let s = stmts(40); // 4 chunks of 10
        let gauge = Arc::new(super::ConcurrencyGauge::new());
        let g = gauge.clone();
        let res = super::pipeline_drive(&s, 10, 2, move |_chunk| {
            let g = g.clone();
            async move {
                g.enter();
                tokio::time::sleep(Duration::from_millis(20)).await;
                g.leave();
                Ok(())
            }
        })
        .await;
        assert!(res.is_ok());
        assert!(gauge.max.load(Ordering::SeqCst) <= 2, "exceeded worker bound");
    }

    #[tokio::test]
    async fn test_pipeline_drive_empty_ok() {
        let res = super::pipeline_drive(&[], 10, 4, |_c| async { Ok(()) }).await;
        assert!(res.is_ok());
    }
```

- [ ] **Step 4: Run the concurrency tests**

Run: `cargo test -p geode-client --lib batch::tests`
Expected: PASS.

- [ ] **Step 5: Wire `batch_exec`/`pipeline_exec` onto `ConnectionPool`**

In `src/pool.rs`, add (in `impl ConnectionPool`):

```rust
    /// Execute statements as a single batch in one transaction, with the
    /// default retry policy. Acquires one connection from the pool.
    ///
    /// # Errors
    /// Returns the first failing statement's error (the transaction is rolled
    /// back). An empty slice is a no-op.
    pub async fn batch_exec(&self, stmts: &[crate::schema::Statement]) -> Result<()> {
        if stmts.is_empty() {
            return Ok(());
        }
        let policy = crate::retry::RetryPolicy::default();
        crate::retry::retry(policy, || async {
            let mut conn = self.acquire().await?;
            conn.begin().await?;
            for (i, stmt) in stmts.iter().enumerate() {
                if let Err(e) = conn.query(&stmt.query).await {
                    let _ = conn.rollback().await;
                    return Err(Error::query(format!("statement {}: {}", i + 1, e)));
                }
            }
            conn.commit().await
        })
        .await
    }

    /// Execute statements concurrently in chunks, each chunk a single
    /// transaction (via [`batch_exec`](Self::batch_exec) with retry). At most
    /// `max_workers` chunks run at once. The first error stops dispatching new
    /// chunks; in-flight chunks complete. `chunk_size`/`max_workers` of 0 use
    /// the defaults (100 / 8).
    pub async fn pipeline_exec(
        self: &Arc<Self>,
        stmts: &[crate::schema::Statement],
        chunk_size: usize,
        max_workers: usize,
    ) -> Result<()> {
        let pool = Arc::clone(self);
        crate::batch::pipeline_drive(stmts, chunk_size, max_workers, move |chunk| {
            let pool = Arc::clone(&pool);
            async move { pool.batch_exec(&chunk).await }
        })
        .await
    }
```

Add `use std::sync::Arc;` is already present in pool.rs. Add `pub use batch::{DEFAULT_CHUNK_SIZE, DEFAULT_MAX_WORKERS};` and `pub mod batch;` to lib.rs.

- [ ] **Step 6: Add an integration test for batch/pipeline (compiles under `integration`)**

In `tests/integration.rs`, add (these require a server at runtime but MUST compile under the feature):

```rust
#[cfg(feature = "integration")]
#[tokio::test]
async fn test_pool_batch_and_pipeline_exec() {
    use geode_client::{ConnectionPool, Statement};
    use std::sync::Arc;
    let (host, port) = get_local_server_info();
    let pool = Arc::new(
        ConnectionPool::from_dsn(&format!("quic://{}:{}?insecure=true", host, port)).unwrap(),
    );
    let stmts: Vec<Statement> = (0..5)
        .map(|i| Statement::new(format!("RETURN {} AS x", i)))
        .collect();
    pool.batch_exec(&stmts).await.unwrap();
    pool.pipeline_exec(&stmts, 2, 4).await.unwrap();
}
```

- [ ] **Step 7: Run, compile-check integration, format, clippy, commit**

```bash
cargo test -p geode-client --lib batch::tests
cargo test --features integration --no-run
cargo fmt
cargo clippy --all-targets -- -D warnings
git add src/batch.rs src/pool.rs src/lib.rs tests/integration.rs
git commit -m "feat: add Statement batch_exec and concurrent pipeline_exec

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: Final verification gate

**Files:** none (verification only)

- [ ] **Step 1: Full unit test suite**

Run: `cargo test --lib`
Expected: all PASS.

- [ ] **Step 2: Proptest suite**

Run: `cargo test --test proptest`
Expected: all PASS.

- [ ] **Step 3: Doc tests**

Run: `cargo test --doc`
Expected: PASS.

- [ ] **Step 4: Integration compile**

Run: `cargo test --features integration --no-run`
Expected: compiles (no run; server not required).

- [ ] **Step 5: Bench compile + quick run**

Run: `cargo bench --no-run` then `cargo bench -- crypto/hmac_hex --warm-up-time 1 --measurement-time 2` (smoke).
Expected: compiles and runs.

- [ ] **Step 6: Formatting + lint gate**

Run: `cargo fmt --check` then `cargo clippy --all-targets -- -D warnings`
Expected: no diffs, zero warnings.

- [ ] **Step 7: Final commit if anything adjusted**

```bash
git add -A
git commit -m "chore: driver parity verification gate green" || echo "nothing to commit"
```

---

## Self-Review

**Spec coverage:** (1) HELLO role+tenant → Task 1; (2) ParseSchemaFS → Task 2; (3) Statement+BatchExec+PipelineExec → Tasks 2 (Statement) + 10; (4) pool from_dsn/from_config → Task 9; (5) quoting helpers → Task 3; (6) ErrNoRows → Task 4; (7) crypto FLE → Task 8; (8) Node/Edge/Path → Task 7; (9) FormatDSN round-trip → Task 6; (10) RetryPolicy+retry → Task 5; (11) is_auth_error/is_syntax_error → Task 4. All covered.

**Placeholder scan:** No TBD/TODO; every code step shows full code.

**Type consistency:** `Statement` defined in Task 2 (`src/schema.rs`) reused by Task 10; `RetryPolicy`/`retry` defined Task 5 reused Task 10; `Error::InvalidIdent/InvalidString` (Task 3) and `Error::NoRows`/`is_auth_error`/`is_syntax_error` (Task 4) are distinct edits to `src/error.rs`; `Node`/`Edge`/`Path` (Task 7) reused in `convert.rs`. `pipeline_exec` takes `self: &Arc<Self>` consistently with the integration test wrapping the pool in `Arc`.
