# CLAUDE.md

This file provides guidance to Claude Code when working with the Geode Rust client library.

## Build Commands

```bash
# Build
cargo build              # Debug build
cargo build --release    # Release build

# Test
cargo test               # Run all unit tests (252 tests)
cargo test --lib         # Run library tests only
cargo test -- --nocapture  # Show println! output

# Lint
cargo clippy             # Run clippy lints
cargo fmt                # Format code
cargo fmt -- --check     # Check formatting

# Benchmarks
cargo bench              # Run all benchmarks (59 benchmarks)
cargo bench -- "value"   # Run value-related benchmarks
cargo bench -- --test    # Test mode (verify benchmarks work)

# Property-based tests (stable Rust)
cargo test --test proptest  # Run 28 proptest tests

# Fuzzing (requires nightly Rust)
cargo +nightly fuzz list    # List fuzz targets
cargo +nightly fuzz run fuzz_value_from_json  # Run a target

# Integration Tests (requires running Geode server)
cargo test --features integration

# Documentation
cargo doc --open         # Build and open docs
```

## Running Examples

```bash
# Requires a running Geode server on localhost:3141
cargo run --example basic
cargo run --example advanced
cargo run --example test_quinn
```

## Project Structure

```
src/
├── lib.rs           # Library entry point, re-exports
├── client.rs        # QUIC client, Connection, query execution
├── types.rs         # Value types, ValueKind, type conversions
├── query_builder.rs # QueryBuilder, PatternBuilder, PredicateBuilder
├── pool.rs          # ConnectionPool for concurrent access
├── error.rs         # Error types with is_retryable() support
├── auth.rs          # Auth types (User, Role, Permission, RLSPolicy)
└── validate.rs      # Input validation (query, params, hostname, port)
```

## Architecture

### Client Module (`client.rs`)

The client module handles QUIC connections using Quinn:

- **Client**: Builder for configuring connections (host, port, TLS settings)
- **Connection**: Active QUIC connection with query methods
- **Page/Column**: Query result structures

**Connection Flow:**
```
Client::new() -> configure -> connect() -> Connection
Connection: query() / query_with_params() / begin() / commit() / rollback()
```

**Protocol:**
- ALPN: `b"geode/1"`
- Wire format: JSON line protocol (one JSON object per line)
- Handshake: HELLO message exchange
- Retry: 3 attempts with 150ms backoff

### Type System (`types.rs`)

25 value kinds supporting all GQL types:

| Category | Types |
|----------|-------|
| Scalars | Null, Int, Bool, String, Decimal |
| Collections | Array, Object |
| Binary | Bytea |
| Temporal | Date, Time, TimeTz, Timestamp, TimestampTz, Interval |
| Special | Json, Jsonb, Xml, Url, Domain, Uuid, Enum, BitString, Range |

**Key Functions:**
- `Value::from_json()` / `Value::to_json()` - JSON conversion
- `decode_value(raw, type_name)` - Type-aware decoding from server
- `as_int()`, `as_string()`, etc. - Type-safe accessors

### Query Builders (`query_builder.rs`)

Fluent API for constructing GQL queries:

```rust
let (query, params) = QueryBuilder::new()
    .match_pattern("(p:Person)")
    .where_clause("p.age > $min_age")
    .return_(&["p.name", "p.age"])
    .order_by(&["p.age DESC"])
    .limit(100)
    .with_param("min_age", 25)
    .build();
```

**PatternBuilder** for graph patterns:
```rust
let pattern = PatternBuilder::new()
    .node("a", "Person")
    .edge("r", "KNOWS", EdgeDirection::Outgoing)
    .node("b", "Person")
    .build();
// "(a:Person)-[r:KNOWS]->(b:Person)"
```

### Error Handling (`error.rs`)

Rich error types with ISO/IEC 39075 support:

| Error Type | Retryable | Description |
|------------|-----------|-------------|
| Connection | Yes | Network/QUIC issues |
| Query | Conditional | Query execution (40001/40P01/40502 = retryable) |
| Timeout | Yes | Operation timeout |
| Pool | Yes | Connection pool exhausted |
| Auth | No | Authentication failure |
| Tls | No | TLS/certificate errors |
| InvalidDsn | No | Invalid connection string |
| Type | No | Type conversion errors |

Use `err.is_retryable()` to check if retry is appropriate.

### Connection Pool (`pool.rs`)

Semaphore-based connection pooling:

```rust
let pool = ConnectionPool::new("localhost", 3141, 10)
    .skip_verify(true);

let conn = pool.acquire().await?;
let (page, _) = conn.query("RETURN 1").await?;
drop(conn); // Returns to pool
```

## Testing

### Test Organization

Tests are inline in each module using `#[cfg(test)]`:

| Module | Test Count | Coverage |
|--------|------------|----------|
| error.rs | 48 | Display, From, helpers, is_retryable |
| types.rs | 104 | All value kinds, JSON conversion, decode_value |
| query_builder.rs | 51 | All builders, pattern generation |
| pool.rs | 12 | Configuration, semaphore permits |
| auth.rs | 24 | Serialization, deserialization |
| validate.rs | 25 | Query, param names, hostname, port, page_size |

### Running Specific Tests

```bash
# Run tests for a specific module
cargo test error::tests
cargo test types::tests
cargo test query_builder::tests
cargo test pool::tests
cargo test auth::tests

# Run a specific test
cargo test test_value_int
cargo test test_error_is_retryable
```

## Wire Protocol

### Client Messages

| Message | Purpose |
|---------|---------|
| HELLO | Connection handshake |
| RUN_GQL | Execute GQL query |
| PULL | Fetch result pages |
| BEGIN | Start transaction |
| COMMIT | Commit transaction |
| ROLLBACK | Rollback transaction |
| SAVEPOINT | Create savepoint |
| ROLLBACK_TO | Rollback to savepoint |
| PING | Keep-alive |

### Server Responses

| Response | Purpose |
|----------|---------|
| HELLO | Handshake acknowledgment |
| SCHEMA | Column definitions |
| BINDINGS | Result rows |
| ERROR | Error with ISO code |
| RESULT | Operation success |
| PROFILE | Performance metrics |

## Dependencies

### Core
- `tokio` (1.35) - Async runtime
- `quinn` (0.11) - Pure Rust QUIC
- `rustls` (0.23) - TLS 1.3 with AWS-LC-RS crypto

### Serialization
- `serde` + `serde_json` - JSON handling

### Types
- `rust_decimal` (1.33) - Decimal precision
- `chrono` (0.4) - Temporal types

### Error Handling
- `thiserror` (1.0) - Derive Error trait

## Code Style

- Use `cargo fmt` before committing
- Run `cargo clippy` and address warnings
- Add tests for new functionality
- Document public APIs with rustdoc

## Common Patterns

### Error Handling

```rust
// Use ? operator with Result<T>
let conn = client.connect().await?;

// Check if retry is appropriate
match result {
    Err(e) if e.is_retryable() => retry(),
    Err(e) => return Err(e),
    Ok(v) => v,
}
```

### Parameterized Queries

```rust
use std::collections::HashMap;

let mut params = HashMap::new();
params.insert("name".to_string(), Value::string("Alice").to_json());
params.insert("age".to_string(), Value::int(30).to_json());

let (page, _) = conn.query_with_params(
    "CREATE (p:Person {name: $name, age: $age}) RETURN p",
    params
).await?;
```

### Transactions

```rust
conn.begin().await?;
conn.query("CREATE (n:Node)").await?;
conn.query("CREATE (m:Node)").await?;
conn.commit().await?;
// Or: conn.rollback().await? on error
```

## Fuzzing & Property Testing

### Property-Based Tests (Stable Rust)

Located in `tests/proptest.rs`, these tests verify invariants with random inputs:

| Category | Tests | Description |
|----------|-------|-------------|
| Value roundtrips | 7 | int, bool, string, decimal, array, object |
| JSON handling | 3 | to_json, from_json, roundtrip |
| Query builders | 6 | QueryBuilder, PatternBuilder, PredicateBuilder |
| Error handling | 2 | Type accessor errors |
| Stress tests | 2 | Large nested structures |
| Fuzz-like | 3 | Random bytes/strings |

Run with: `cargo test --test proptest`

### Fuzz Targets (Nightly Rust)

Located in `fuzz/fuzz_targets/`, these use libFuzzer for deep fuzzing:

| Target | Description |
|--------|-------------|
| `fuzz_value_from_json` | Value::from_json with arbitrary JSON |
| `fuzz_query_builder` | QueryBuilder with arbitrary strings |
| `fuzz_pattern_builder` | PatternBuilder with arbitrary patterns |
| `fuzz_json_parsing` | JSON parsing and Value conversion |

Run with:
```bash
cargo +nightly fuzz run fuzz_value_from_json
cargo +nightly fuzz run fuzz_value_from_json -- -max_total_time=60
```

## Benchmarks

Benchmarks use Criterion and are located in `benches/benchmarks.rs`:

| Category | Benchmarks | Description |
|----------|------------|-------------|
| value_creation | 12 | Creating Value types |
| value_accessors | 7 | Reading values with type accessors |
| value_clone | 4 | Cloning values of various sizes |
| query_builder | 5 | Building queries with QueryBuilder |
| pattern_builder | 4 | Building graph patterns |
| predicate_builder | 2 | Building WHERE predicates |
| connection | 1 | Connect/disconnect (requires server) |
| query_execution | 4 | Query execution (requires server) |
| query_throughput | 3 | Sequential query throughput |
| decimal_parsing | 6 | Parsing decimal strings |
| json_serialization | 6 | JSON serialize/deserialize |

```bash
# Run all benchmarks
cargo bench

# Run specific group
cargo bench -- "query_builder"
cargo bench -- "connection"

# Save baseline for comparison
cargo bench -- --save-baseline main

# Compare against baseline
cargo bench -- --baseline main
```

## Integration Testing

Integration tests require a running Geode server and are in `tests/integration.rs`:

| Test Category | Tests | Description |
|---------------|-------|-------------|
| Basic operations | 3 | Ping, simple queries, parameterized |
| Node CRUD | 5 | Create, read, update, delete, labels |
| Relationships | 4 | Creation, properties, traversal, direction |
| Transactions | 4 | Begin/commit, rollback, multi-op, savepoints |
| Query operations | 4 | WHERE, ORDER BY, LIMIT/SKIP, predicates |
| Aggregations | 5 | COUNT, SUM, AVG, MIN, MAX |
| Data types | 6 | Null, bool, int, decimal, string, collections |
| Concurrent access | 5 | Connection pool under load |

Run with: `cargo test --features integration`

### Test Harness

Use the test harness for comprehensive cross-client testing:

```bash
cd ../geode-test-harness
make test-rust
```

Or manually:

```bash
# Terminal 1: Start Geode
cd ../geode && ./zig-out/bin/geode serve

# Terminal 2: Run integration examples
cargo run --example basic
```
