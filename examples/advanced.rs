//! Advanced example demonstrating connection pooling and query builders with QUIC.

use geode_client::{ConnectionPool, EdgeDirection, PatternBuilder, QueryBuilder, Result, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Geode Rust QUIC Client - Advanced Examples ===\n");

    // Query builder examples
    query_builder_examples();

    // Connection pooling example
    connection_pool_example().await?;

    Ok(())
}

fn query_builder_examples() {
    println!("\n=== Query Builder Examples ===\n");

    // Complex query
    let (query, params) = QueryBuilder::new()
        .match_pattern("(p:Person)")
        .where_clause("p.age > 25")
        .optional_match("(p)-[:WORKS_AT]->(c:Company)")
        .return_(&["p.name AS person", "c.name AS company"])
        .order_by(&["person"])
        .limit(10)
        .with_param("min_age", 25)
        .build();

    println!("Complex Query:\n{}\n", query);
    println!("Params: {:?}\n", params);

    // Pattern builder
    let pattern = PatternBuilder::new()
        .node("a", "Person")
        .edge("knows", "KNOWS", EdgeDirection::Undirected)
        .node("b", "Person")
        .build();

    println!("Pattern: {}\n", pattern);

    // Simple query with parameters
    let (query, _) = QueryBuilder::new()
        .match_pattern("(n:Person)")
        .return_(&["n.name", "n.age"])
        .limit(100)
        .build();

    println!("Simple Query:\n{}\n", query);
}

async fn connection_pool_example() -> Result<()> {
    println!("\n=== Connection Pool Example ===\n");

    // Create connection pool
    let pool = Arc::new(
        ConnectionPool::new("127.0.0.1", 3141, 10)
            .skip_verify(true)
            .page_size(1000),
    );

    println!("Created connection pool with max_size=10");

    // Execute concurrent queries using the pool
    let mut handles = vec![];

    for i in 1..=5 {
        let pool_clone = Arc::clone(&pool);
        let handle = tokio::spawn(async move {
            match pool_clone.acquire().await {
                Ok(mut conn) => {
                    let mut params = HashMap::new();
                    params.insert("id".to_string(), Value::int(i));
                    params.insert("msg".to_string(), Value::string(format!("Query {}", i)));

                    match conn
                        .query_with_params("RETURN $id AS id, $msg AS message", &params)
                        .await
                    {
                        Ok((page, _)) => {
                            if let Some(row) = page.rows.first() {
                                if let (Ok(id), Ok(msg)) = (
                                    row.get("id").unwrap().as_int(),
                                    row.get("message").unwrap().as_string(),
                                ) {
                                    println!("  Query {}: id={}, message={}", i, id, msg);
                                }
                            }
                            Ok(())
                        }
                        Err(e) => {
                            println!("  Query {} failed: {}", i, e);
                            Err(e)
                        }
                    }
                }
                Err(e) => {
                    println!("  Failed to acquire connection for query {}: {}", i, e);
                    Err(e)
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all queries to complete
    for handle in handles {
        let _ = handle.await;
    }

    println!("\nAll concurrent queries completed!");
    println!("Pool size: {}", pool.size().await);

    Ok(())
}
