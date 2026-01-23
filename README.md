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

Add to your `Cargo.toml`:

```toml
[dependencies]
geode-client = "0.1"

# For async runtime
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
conn.begin()?;

match conn.query("CREATE (p:Person {name: $name})", params) {
    Ok(_) => conn.commit()?,
    Err(e) => {
        conn.rollback()?;
        return Err(e);
    }
}
```

### Savepoints (Partial Rollback)

```rust
conn.begin()?;

// Create initial data
conn.query("CREATE (p:Person {name: 'Alice', age: 30})", None)?;

// Create a savepoint
let sp = conn.savepoint("before_update")?;

// Make changes
conn.query("MATCH (p:Person {name: 'Alice'}) SET p.age = 40", None)?;

// Rollback to savepoint (undoes the age change)
conn.rollback_to(&sp)?;

// Alice's age is still 30
conn.commit()?;
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

## Connection Configuration

The client uses a builder pattern for configuration:

```rust
let client = Client::new("127.0.0.1", 3141)  // host and port
    .skip_verify(true)                        // Skip TLS verification (development only)
    .page_size(1000)                          // Results page size
    .client_name("my-app")                    // Client name for server logs
    .client_version("1.0.0")                  // Client version
    .conformance("min");                      // GQL conformance level
```

### Configuration Options

- `skip_verify(bool)` - Skip TLS certificate verification (default: false, **insecure**)
- `page_size(usize)` - Results page size (default: 1000)
- `client_name(String)` - Client name sent to server (default: "geode-rust")
- `client_version(String)` - Client version (default: "0.1.0")
- `conformance(String)` - GQL conformance level (default: "min")

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

```rust
use geode_client::Value;

let value = row.get("count").unwrap();

// Type-safe access
let int_val = value.as_int()?;
let str_val = value.as_string()?;
let bool_val = value.as_bool()?;
let decimal_val = value.as_decimal()?;
let array_val = value.as_array()?;
let object_val = value.as_object()?;
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

# Run tests
cargo test

# Run examples
cargo run --example basic
cargo run --example advanced

# Format code
cargo fmt

# Lint
cargo clippy

# Check types
cargo check
```

## Performance

The QUIC client provides:

- **Low latency**: ~1-2ms per query (localhost)
- **High throughput**: 10,000+ queries/second with connection pooling
- **Zero-cost abstractions**: Minimal overhead from Rust's type system
- **Concurrent**: Full async support for parallel queries

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

## License

MIT License - see LICENSE file for details.

## Related

- [Geode Database](https://gitlab.com/devnw/codepros/geode/geode) - Main Geode project
- [Python Client](../python/) - Official Python client
- [Go Client](../go/) - Official Go client
