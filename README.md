# Geode Rust Client

A high-performance async Rust client library for [Geode](https://gitlab.com/devnw/codepros/geode/geode) graph database with full GQL (ISO/IEC 39075:2024) support via QUIC+TLS.

## Features

- 🚀 **Fully async** using tokio with type safety
- 🔒 **QUIC + TLS 1.3** for secure, high-performance networking
- 📝 **Full GQL support** (98.6% ISO compliance)
- 🏗️ **Query builders** for programmatic query construction
- 🔐 **Complete authentication** with RBAC and RLS support
- 🏊 **Connection pooling** for concurrent workloads
- 📊 **Rich type system** with Decimal, temporal types
- 🎯 **Type-safe** with Rust's strong type system and zero-cost abstractions

## Installation

Install from [crates.io](https://crates.io/crates/geode-client):

```bash
cargo add geode-client tokio --features tokio/full
```

Or add to your `Cargo.toml`:

```toml
[dependencies]
geode-client = "0.1.1-alpha.1"
tokio = { version = "1", features = ["full"] }
```

## Requirements

- Rust 1.70+
- quinn >= 0.10 (QUIC support)
- tokio runtime
- Running Geode server with QUIC enabled

## Quick Start

### Basic QUIC Connection

```rust
use geode_client::{Client, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Create QUIC client (skip TLS verification for development)
    let client = Client::new("127.0.0.1", 3141)
        .skip_verify(true)
        .page_size(1000);

    // Connect via QUIC
    let conn = client.connect().await?;
    println!("Connected to Geode via QUIC!");

    // Execute query
    let page = conn.query("RETURN 1 AS x, 'Hello QUIC' AS greeting", None).await?;

    for row in &page.rows {
        let x = row.get("x").unwrap().as_int()?;
        let greeting = row.get("greeting").unwrap().as_string()?;
        println!("x={}, greeting={}", x, greeting);
    }

    // Close connection
    conn.close().await?;

    Ok(())
}
```

### Query with Parameters

```rust
use std::collections::HashMap;

let mut params = HashMap::new();
params.insert("name".to_string(), serde_json::json!("Alice"));
params.insert("age".to_string(), serde_json::json!(30));

let page = conn.query(
    "MATCH (p:Person {name: $name}) RETURN p.age AS age",
    Some(params)
).await?;
```

### Using Query Builder

```rust
use geode_client::QueryBuilder;

let (query, params) = QueryBuilder::new()
    .match_pattern("(p:Person {name: $name})-[:KNOWS]->(friend:Person)")
    .where_clause("friend.age > 25")
    .return_(&["friend.name AS name", "friend.age AS age"])
    .order_by(&["friend.age DESC"])
    .limit(10)
    .with_param("name", "Alice")
    .build();

let page = conn.query(&query, Some(params)).await?;
```

### Transactions

```rust
conn.begin().await?;

match conn.query("CREATE (p:Person {name: $name})", params).await {
    Ok(_) => conn.commit().await?,
    Err(e) => {
        conn.rollback().await?;
        return Err(e);
    }
}
```

### Savepoints (Partial Rollback)

```rust
conn.begin().await?;

// Create initial data
conn.query("CREATE (p:Person {name: 'Alice', age: 30})").await?;

// Create a savepoint
let sp = conn.savepoint("before_update")?;

// Make changes
conn.query("MATCH (p:Person {name: 'Alice'}) SET p.age = 40").await?;

// Rollback to savepoint (undoes the age change)
conn.rollback_to(&sp).await?;

// Alice's age is still 30
conn.commit().await?;
```

### Connection Pooling

```rust
use geode_client::ConnectionPool;

// Create connection pool
let pool = ConnectionPool::new("127.0.0.1", 3141, 10)
    .skip_verify(true)
    .page_size(1000);

// Acquire connection from pool
let conn = pool.acquire().await?;
let page = conn.query("RETURN 1", None).await?;

// Connection automatically returns to pool when dropped
println!("Pool size: {}", pool.size().await);
```

### Prepared Statements

```rust
use geode_client::PreparedStatement;

// Create a prepared statement
let stmt = conn.prepare("MATCH (p:Person {id: $id}) RETURN p.name, p.age")?;

// Execute multiple times with different parameters
for id in 1..=100 {
    let mut params = HashMap::new();
    params.insert("id".to_string(), Value::int(id));
    let (page, _) = stmt.execute(&mut conn, &params).await?;
    // Process results...
}
```

### Query Explain and Profile

```rust
// Get the execution plan without running the query
let plan = conn.explain("MATCH (p:Person)-[:KNOWS]->(f) RETURN f").await?;
println!("Estimated rows: {}", plan.estimated_rows);
for op in &plan.operations {
    println!("  {} - {}", op.op_type, op.description);
}

// Execute with profiling to get actual timing
let profile = conn.profile("MATCH (p:Person) RETURN p LIMIT 100").await?;
println!("Execution time: {:.2}ms", profile.execution_time_ms);
println!("Actual rows: {}", profile.actual_rows);
```

### Batch Queries

```rust
// Execute multiple queries efficiently
let results = conn.batch(&[
    ("MATCH (n:Person) RETURN count(n)", None),
    ("MATCH (n:Company) RETURN count(n)", None),
    ("MATCH ()-[r:WORKS_AT]->() RETURN count(r)", None),
]).await?;

for (i, page) in results.iter().enumerate() {
    println!("Query {}: {} rows", i + 1, page.rows.len());
}
```

## Connection Configuration

The client uses a builder pattern for configuration:

```rust
let client = Client::new("127.0.0.1", 3141)  // host and port
    .skip_verify(true)                        // Skip TLS verification (development only)
    .page_size(1000)                          // Results page size
    .client_name("my-app")                    // Client name for server logs
    .client_version("1.0.0")                  // Client version
    .conformance("min")                       // GQL conformance level
    .username("admin")                        // Authentication username
    .password("secret");                      // Authentication password
```

### DSN Connection String

You can also create a client from a DSN (Data Source Name) string:

```rust
use geode_client::Client;

// Simple DSN
let client = Client::from_dsn("localhost:3141").unwrap();

// With options
let client = Client::from_dsn("localhost:3141?insecure=true&page_size=500").unwrap();

// URL format with authentication
let client = Client::from_dsn("geode://admin:secret@localhost:3141?insecure=true").unwrap();
```

Supported DSN options:
- `page_size` - Results page size (default: 1000)
- `hello_name` - Client name (default: "geode-rust-quinn")
- `hello_ver` - Client version (default: "0.1.0")
- `conformance` - GQL conformance level (default: "min")
- `insecure` - Skip TLS verification (true/false, default: false)
- `username` or `user` - Authentication username
- `password` or `pass` - Authentication password

### Configuration Options

- `skip_verify(bool)` - Skip TLS certificate verification (default: false, **insecure**)
- `page_size(usize)` - Results page size (default: 1000)
- `client_name(String)` - Client name sent to server (default: "geode-rust")
- `client_version(String)` - Client version (default: "0.1.0")
- `conformance(String)` - GQL conformance level (default: "min")
- `username(String)` - Authentication username (optional)
- `password(String)` - Authentication password (optional)

## Query Builders

### QueryBuilder

Build queries programmatically:

```rust
let (query, params) = QueryBuilder::new()
    .match_pattern("(p:Person)")
    .where_clause("p.age > 25")
    .return_(&["p.name", "p.age"])
    .order_by(&["p.name"])
    .limit(100)
    .build();
```

### PatternBuilder

Build graph patterns:

```rust
use geode_client::{PatternBuilder, EdgeDirection};

let pattern = PatternBuilder::new()
    .node("a", "Person")
    .edge("knows", "KNOWS", EdgeDirection::Undirected)
    .node("b", "Person")
    .build();
```

## Type System

The client provides a rich type system supporting all GQL data types:

```rust
use geode_client::{Value, ValueKind};

let value = row.get("count").unwrap();

// Type-safe access with Result
let int_val = value.as_int()?;
let str_val = value.as_string()?;
let bool_val = value.as_bool()?;
let decimal_val = value.as_decimal()?;
let array_val = value.as_array()?;
let object_val = value.as_object()?;
let date_val = value.as_date()?;
let timestamp_val = value.as_timestamp()?;

// Check value kind
match value.kind {
    ValueKind::Null => println!("null value"),
    ValueKind::Int => println!("integer: {}", value.as_int()?),
    ValueKind::String => println!("string: {}", value.as_string()?),
    _ => println!("other type"),
}

// Create values programmatically
let int_value = Value::int(42);
let str_value = Value::string("hello");
let bool_value = Value::bool(true);
let array_value = Value::array(vec![Value::int(1), Value::int(2)]);
```

### Supported Types

| Type | Rust Type | Description |
|------|-----------|-------------|
| `Null` | `()` | SQL NULL |
| `Int` | `i64` | 64-bit integer |
| `Bool` | `bool` | Boolean |
| `String` | `String` | UTF-8 string |
| `Decimal` | `rust_decimal::Decimal` | Arbitrary precision decimal |
| `Array` | `Vec<Value>` | Ordered collection |
| `Object` | `HashMap<String, Value>` | Key-value map |
| `Date` | `chrono::NaiveDate` | Calendar date |
| `Timestamp` | `chrono::DateTime<Utc>` | Date and time |
| `Bytea` | `Vec<u8>` | Binary data |

## Error Handling

The client provides comprehensive error types with retry support:

```rust
use geode_client::{Error, Result};

async fn query_with_retry(conn: &mut Connection, query: &str) -> Result<Page> {
    let mut attempts = 0;
    loop {
        match conn.query(query).await {
            Ok((page, _)) => return Ok(page),
            Err(e) if e.is_retryable() && attempts < 3 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(100 * attempts)).await;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}
```

### Error Types

| Error | Retryable | Description |
|-------|-----------|-------------|
| `Connection` | Yes | Network/QUIC connection issues |
| `Query` | Conditional | Query execution errors (40001, 40P01, 40502 are retryable) |
| `Timeout` | Yes | Operation timed out |
| `Pool` | Yes | Connection pool exhausted |
| `Auth` | No | Authentication failure |
| `Tls` | No | TLS/certificate errors |
| `Validation` | No | Input validation failure |
| `Type` | No | Type conversion errors |

### Validation

The client provides input validation utilities:

```rust
use geode_client::validate;

// Validate queries before sending
validate::query("MATCH (n) RETURN n")?;

// Validate parameter names
validate::param_name("user_id")?;

// Validate connection parameters
validate::hostname("geode.example.com")?;
validate::port(3141)?;
validate::page_size(1000)?;
```

## Examples

The client includes comprehensive examples demonstrating all features:

- `examples/basic.rs` - Simple connection and queries
- `examples/advanced.rs` - Advanced features and patterns
- `examples/transactions.rs` - Transaction management with savepoints

Run examples:

```bash
cargo run --example basic
cargo run --example advanced
cargo run --example transactions
```

## Development

```bash
# Build
cargo build
cargo build --release

# Run tests
cargo test                           # Unit tests (274 tests)
cargo test --test proptest           # Property-based tests (28 tests)
cargo test --features integration    # Integration tests (requires Geode server)

# Run benchmarks
cargo bench                          # All benchmarks (59 benchmarks)
cargo bench -- "query"               # Filter by name

# Run fuzzing (requires nightly)
cargo +nightly fuzz run fuzz_value_from_json

# Code quality
cargo fmt                            # Format code
cargo clippy                         # Lint (0 warnings)
cargo doc --open                     # Generate documentation

# Run examples
cargo run --example basic
cargo run --example advanced
```

## Testing

The library includes comprehensive testing:

| Test Type | Count | Command |
|-----------|-------|---------|
| Unit tests | 274 | `cargo test` |
| Property tests | 28 | `cargo test --test proptest` |
| Integration tests | 36 | `cargo test --features integration` |
| Benchmarks | 59 | `cargo bench` |
| Fuzz targets | 4 | `cargo +nightly fuzz run <target>` |

### Running Integration Tests

Integration tests require a running Geode server:

```bash
# Terminal 1: Start Geode
cd ../geode && ./zig-out/bin/geode serve

# Terminal 2: Run integration tests
cargo test --features integration
```

### Benchmarks

Benchmarks measure performance of key operations:

```bash
# Run all benchmarks
cargo bench

# Sample output:
# value_creation/int      time: [5.2 ns]
# query_builder/complex   time: [198 ns]
# decimal_parsing/4_places time: [8.3 ns]
```

## Performance

The QUIC client provides:

- **Low latency**: ~1-2ms per query (localhost)
- **High throughput**: 10,000+ queries/second with connection pooling
- **Zero-cost abstractions**: Minimal overhead from Rust's type system
- **Concurrent**: Full async support for parallel queries

### System-Level QUIC Optimizations

For optimal QUIC throughput on high-bandwidth connections, configure UDP buffer sizes at the OS level.

**Linux:**
```bash
# Increase UDP buffer sizes to 7MB
sudo sysctl -w net.core.rmem_max=7340032
sudo sysctl -w net.core.wmem_max=7340032

# Persist across reboots
echo "net.core.rmem_max=7340032" | sudo tee -a /etc/sysctl.d/99-geode-quic.conf
echo "net.core.wmem_max=7340032" | sudo tee -a /etc/sysctl.d/99-geode-quic.conf
```

**BSD/macOS:**
```bash
sudo sysctl -w kern.ipc.maxsockbuf=8441037
```

**GSO (Generic Segmentation Offload)**: Automatically enabled on Linux 4.18+ by quinn. Batches UDP packets to reduce syscall overhead.

**Path MTU Discovery (DPLPMTUD)**: Enabled by default in quinn, probes for optimal packet sizes to reduce per-packet overhead.

## Troubleshooting

### Connection Refused

Ensure Geode server is running with QUIC enabled:

```bash
./zig-out/bin/geode serve --listen 0.0.0.0:3141
```

### TLS Verification Errors

For development, you can skip verification:

```rust
let client = Client::new("localhost", 3141).skip_verify(true);
```

For production, ensure proper TLS certificates are configured on the server.

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork and clone** the repository
2. **Create a feature branch** from `main`
3. **Write tests** for new functionality
4. **Run the test suite**: `cargo test`
5. **Run clippy**: `cargo clippy` (must produce 0 warnings)
6. **Format code**: `cargo fmt`
7. **Submit a pull request**

### Code Quality Standards

- All public APIs must have rustdoc comments
- New features require unit tests
- Integration tests for server-facing changes
- Property-based tests for parsers/converters
- Benchmarks for performance-critical code

### Development Setup

```bash
# Clone the repository
git clone https://gitlab.com/devnw/codepros/geode/geode-client-rust.git
cd geode-client-rust

# Install development tools
rustup component add clippy rustfmt

# Run full test suite
cargo test
cargo test --test proptest
cargo clippy
cargo fmt -- --check
```

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## Related

- [Geode Database](https://gitlab.com/devnw/codepros/geode/geode) - Main Geode project
- [Python Client](https://gitlab.com/devnw/codepros/geode/geode-client-python) - Official Python client
- [Go Client](https://gitlab.com/devnw/codepros/geode/geode-client-go) - Official Go client
- [crates.io](https://crates.io/crates/geode-client) - Package on crates.io
- [docs.rs](https://docs.rs/geode-client) - API documentation
