//! Criterion benchmarks for geode-client
//!
//! Run with: `cargo bench`
//!
//! For benchmarks that require a Geode server, set GEODE_HOST and GEODE_PORT
//! environment variables, or the benchmarks will be skipped.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use geode_client::{Client, EdgeDirection, PatternBuilder, PredicateBuilder, QueryBuilder, Value};
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

// ============================================================================
// Type Conversion Benchmarks
// ============================================================================

fn bench_value_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_creation");

    group.bench_function("null", |b| b.iter(|| black_box(Value::null())));

    group.bench_function("int", |b| b.iter(|| black_box(Value::int(42))));

    group.bench_function("int_large", |b| b.iter(|| black_box(Value::int(i64::MAX))));

    group.bench_function("bool", |b| b.iter(|| black_box(Value::bool(true))));

    group.bench_function("string_short", |b| {
        b.iter(|| black_box(Value::string("hello")))
    });

    group.bench_function("string_medium", |b| {
        let s = "a".repeat(100);
        b.iter(|| black_box(Value::string(s.clone())))
    });

    group.bench_function("string_long", |b| {
        let s = "a".repeat(10000);
        b.iter(|| black_box(Value::string(s.clone())))
    });

    group.bench_function("decimal", |b| {
        let d = Decimal::from_str("12345.6789").unwrap();
        b.iter(|| black_box(Value::decimal(d)))
    });

    group.bench_function("array_small", |b| {
        b.iter(|| {
            black_box(Value::array(vec![
                Value::int(1),
                Value::int(2),
                Value::int(3),
            ]))
        })
    });

    group.bench_function("array_large", |b| {
        b.iter(|| {
            let arr: Vec<Value> = (0..100).map(Value::int).collect();
            black_box(Value::array(arr))
        })
    });

    group.bench_function("object_small", |b| {
        b.iter(|| {
            let mut map = HashMap::new();
            map.insert("a".to_string(), Value::int(1));
            map.insert("b".to_string(), Value::int(2));
            black_box(Value::object(map))
        })
    });

    group.bench_function("object_large", |b| {
        b.iter(|| {
            let map: HashMap<String, Value> = (0..100)
                .map(|i| (format!("key_{}", i), Value::int(i)))
                .collect();
            black_box(Value::object(map))
        })
    });

    group.finish();
}

fn bench_value_accessors(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_accessors");

    let int_val = Value::int(42);
    let bool_val = Value::bool(true);
    let string_val = Value::string("hello world");
    let decimal_val = Value::decimal(Decimal::from_str("12345.6789").unwrap());
    let array_val = Value::array(vec![Value::int(1), Value::int(2), Value::int(3)]);
    let mut obj_map = HashMap::new();
    obj_map.insert("key".to_string(), Value::string("value"));
    let object_val = Value::object(obj_map);

    group.bench_function("as_int", |b| b.iter(|| black_box(int_val.as_int())));

    group.bench_function("as_bool", |b| b.iter(|| black_box(bool_val.as_bool())));

    group.bench_function("as_string", |b| {
        b.iter(|| black_box(string_val.as_string()))
    });

    group.bench_function("as_decimal", |b| {
        b.iter(|| black_box(decimal_val.as_decimal()))
    });

    group.bench_function("as_array", |b| b.iter(|| black_box(array_val.as_array())));

    group.bench_function("as_object", |b| {
        b.iter(|| black_box(object_val.as_object()))
    });

    group.bench_function("is_null", |b| b.iter(|| black_box(int_val.is_null())));

    group.finish();
}

fn bench_value_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_clone");

    let simple = Value::int(42);
    let string_val = Value::string("a".repeat(1000));
    let nested_array = Value::array(
        (0..100)
            .map(|i| Value::array(vec![Value::int(i), Value::string(format!("item_{}", i))]))
            .collect(),
    );
    let nested_object = {
        let map: HashMap<String, Value> = (0..50)
            .map(|i| {
                let mut inner = HashMap::new();
                inner.insert("id".to_string(), Value::int(i));
                inner.insert("name".to_string(), Value::string(format!("name_{}", i)));
                (format!("obj_{}", i), Value::object(inner))
            })
            .collect();
        Value::object(map)
    };

    group.bench_function("simple", |b| b.iter(|| black_box(simple.clone())));

    group.bench_function("string_1k", |b| b.iter(|| black_box(string_val.clone())));

    group.bench_function("nested_array_100", |b| {
        b.iter(|| black_box(nested_array.clone()))
    });

    group.bench_function("nested_object_50", |b| {
        b.iter(|| black_box(nested_object.clone()))
    });

    group.finish();
}

// ============================================================================
// Query Builder Benchmarks
// ============================================================================

fn bench_query_builder(c: &mut Criterion) {
    let mut group = c.benchmark_group("query_builder");

    group.bench_function("simple_match_return", |b| {
        b.iter(|| {
            let (query, _params) = QueryBuilder::new()
                .match_pattern("(n:Person)")
                .return_(&["n"])
                .build();
            black_box(query)
        })
    });

    group.bench_function("with_where", |b| {
        b.iter(|| {
            let (query, _params) = QueryBuilder::new()
                .match_pattern("(n:Person)")
                .where_clause("n.age > 21")
                .return_(&["n.name", "n.age"])
                .build();
            black_box(query)
        })
    });

    group.bench_function("complex_query", |b| {
        b.iter(|| {
            let (query, _params) = QueryBuilder::new()
                .match_pattern("(p:Person)-[r:KNOWS]->(f:Person)")
                .where_clause("p.age > 21 AND f.city = 'NYC'")
                .with(&["p", "f", "r"])
                .optional_match("(f)-[:WORKS_AT]->(c:Company)")
                .return_(&["p.name", "f.name", "c.name"])
                .order_by(&["p.name ASC"])
                .limit(100)
                .build();
            black_box(query)
        })
    });

    group.bench_function("with_params", |b| {
        b.iter(|| {
            let (query, params) = QueryBuilder::new()
                .match_pattern("(n:Person)")
                .where_clause("n.age > $min_age AND n.city = $city")
                .with_param("min_age", 21)
                .with_param("city", "New York")
                .return_(&["n"])
                .build();
            black_box((query, params))
        })
    });

    group.bench_function("many_params", |b| {
        b.iter(|| {
            let mut builder = QueryBuilder::new()
                .match_pattern("(n:Node)")
                .where_clause("n.id IN $ids");
            for i in 0..100 {
                builder = builder.with_param(&format!("param_{}", i), i);
            }
            let (query, params) = builder.return_(&["n"]).build();
            black_box((query, params))
        })
    });

    group.finish();
}

fn bench_pattern_builder(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_builder");

    group.bench_function("single_node", |b| {
        b.iter(|| {
            let pattern = PatternBuilder::new().node("n", "Person").build();
            black_box(pattern)
        })
    });

    group.bench_function("node_edge_node", |b| {
        b.iter(|| {
            let pattern = PatternBuilder::new()
                .node("a", "Person")
                .edge("r", "KNOWS", EdgeDirection::Outgoing)
                .node("b", "Person")
                .build();
            black_box(pattern)
        })
    });

    group.bench_function("long_path", |b| {
        b.iter(|| {
            let pattern = PatternBuilder::new()
                .node("a", "Person")
                .edge("r1", "KNOWS", EdgeDirection::Outgoing)
                .node("b", "Person")
                .edge("r2", "WORKS_AT", EdgeDirection::Outgoing)
                .node("c", "Company")
                .edge("r3", "LOCATED_IN", EdgeDirection::Outgoing)
                .node("d", "City")
                .edge("r4", "IN_COUNTRY", EdgeDirection::Outgoing)
                .node("e", "Country")
                .build();
            black_box(pattern)
        })
    });

    group.bench_function("all_directions", |b| {
        b.iter(|| {
            let pattern = PatternBuilder::new()
                .node("a", "Node")
                .edge("r1", "OUT", EdgeDirection::Outgoing)
                .node("b", "Node")
                .edge("r2", "IN", EdgeDirection::Incoming)
                .node("c", "Node")
                .edge("r3", "BOTH", EdgeDirection::Undirected)
                .node("d", "Node")
                .build();
            black_box(pattern)
        })
    });

    group.finish();
}

fn bench_predicate_builder(c: &mut Criterion) {
    let mut group = c.benchmark_group("predicate_builder");

    group.bench_function("single_condition", |b| {
        b.iter(|| {
            let pred = PredicateBuilder::new()
                .greater_than("n.age", "21")
                .build_and();
            black_box(pred)
        })
    });

    group.bench_function("multiple_conditions", |b| {
        b.iter(|| {
            let pred = PredicateBuilder::new()
                .greater_than("n.age", "21")
                .is_not_null("n.email")
                .greater_than("n.salary", "50000")
                .build_and();
            black_box(pred)
        })
    });

    group.finish();
}

// ============================================================================
// Connection Benchmarks (require live Geode server)
// ============================================================================

fn get_server_address() -> Option<(String, u16)> {
    let host = std::env::var("GEODE_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("GEODE_PORT")
        .unwrap_or_else(|_| "3141".to_string())
        .parse()
        .unwrap_or(3141);
    Some((host, port))
}

fn bench_connection(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Test if server is available
    let (host, port) = match get_server_address() {
        Some(addr) => addr,
        None => {
            eprintln!("Skipping connection benchmarks: GEODE_HOST/GEODE_PORT not set");
            return;
        }
    };

    // Quick connectivity check
    let client = Client::new(&host, port).skip_verify(true);
    let can_connect = rt.block_on(async {
        match client.connect().await {
            Ok(mut conn) => {
                let _ = conn.close();
                true
            }
            Err(_) => false,
        }
    });

    if !can_connect {
        eprintln!(
            "Skipping connection benchmarks: Cannot connect to Geode at {}:{}",
            host, port
        );
        return;
    }

    let mut group = c.benchmark_group("connection");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    group.bench_function("connect_disconnect", |b| {
        let client = Client::new(&host, port).skip_verify(true);
        b.iter(|| {
            rt.block_on(async {
                let mut conn = client.connect().await.unwrap();
                conn.close().unwrap();
            })
        })
    });

    group.finish();
}

fn bench_query_execution(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let (host, port) = match get_server_address() {
        Some(addr) => addr,
        None => {
            eprintln!("Skipping query benchmarks: GEODE_HOST/GEODE_PORT not set");
            return;
        }
    };

    let client = Client::new(&host, port).skip_verify(true);

    // Quick connectivity check and setup
    let conn = rt.block_on(async {
        match client.connect().await {
            Ok(conn) => Some(conn),
            Err(_) => None,
        }
    });

    let mut conn = match conn {
        Some(c) => c,
        None => {
            eprintln!(
                "Skipping query benchmarks: Cannot connect to Geode at {}:{}",
                host, port
            );
            return;
        }
    };

    let mut group = c.benchmark_group("query_execution");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);

    // Simple return query
    group.bench_function("return_literal", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (page, _) = conn.query("RETURN 1 AS x").await.unwrap();
                black_box(page)
            })
        })
    });

    // Return with multiple values
    group.bench_function("return_multiple", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (page, _) = conn
                    .query("RETURN 1 AS a, 2 AS b, 3 AS c, 'hello' AS d, true AS e")
                    .await
                    .unwrap();
                black_box(page)
            })
        })
    });

    // Parameterized query
    group.bench_function("parameterized", |b| {
        let mut params = HashMap::new();
        params.insert("x".to_string(), Value::int(42));
        params.insert("y".to_string(), Value::string("hello"));
        b.iter(|| {
            rt.block_on(async {
                let (page, _) = conn
                    .query_with_params("RETURN $x AS num, $y AS str", &params)
                    .await
                    .unwrap();
                black_box(page)
            })
        })
    });

    // Computation query
    group.bench_function("computation", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (page, _) = conn
                    .query("RETURN 1 + 2 * 3 - 4 / 2 AS result")
                    .await
                    .unwrap();
                black_box(page)
            })
        })
    });

    group.finish();

    // Cleanup
    let _ = conn.close();
}

fn bench_query_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let (host, port) = match get_server_address() {
        Some(addr) => addr,
        None => {
            eprintln!("Skipping throughput benchmarks: GEODE_HOST/GEODE_PORT not set");
            return;
        }
    };

    let client = Client::new(&host, port).skip_verify(true);

    let conn = rt.block_on(async {
        match client.connect().await {
            Ok(conn) => Some(conn),
            Err(_) => None,
        }
    });

    let mut conn = match conn {
        Some(c) => c,
        None => {
            eprintln!(
                "Skipping throughput benchmarks: Cannot connect to Geode at {}:{}",
                host, port
            );
            return;
        }
    };

    let mut group = c.benchmark_group("query_throughput");
    group.measurement_time(Duration::from_secs(15));

    for count in [10, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::new("sequential", count), count, |b, &count| {
            b.iter(|| {
                rt.block_on(async {
                    for _ in 0..count {
                        let (page, _) = conn.query("RETURN 1 AS x").await.unwrap();
                        black_box(page);
                    }
                })
            })
        });
    }

    group.finish();

    let _ = conn.close();
}

// ============================================================================
// Decimal Parsing Benchmarks
// ============================================================================

fn bench_decimal_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("decimal_parsing");

    group.bench_function("small_integer", |b| {
        b.iter(|| {
            let d = Decimal::from_str(black_box("42")).unwrap();
            black_box(d)
        })
    });

    group.bench_function("large_integer", |b| {
        b.iter(|| {
            let d = Decimal::from_str(black_box("999999999999999999")).unwrap();
            black_box(d)
        })
    });

    group.bench_function("decimal_4_places", |b| {
        b.iter(|| {
            let d = Decimal::from_str(black_box("12345.6789")).unwrap();
            black_box(d)
        })
    });

    group.bench_function("decimal_10_places", |b| {
        b.iter(|| {
            let d = Decimal::from_str(black_box("123.4567890123")).unwrap();
            black_box(d)
        })
    });

    group.bench_function("negative", |b| {
        b.iter(|| {
            let d = Decimal::from_str(black_box("-98765.4321")).unwrap();
            black_box(d)
        })
    });

    group.bench_function("very_small", |b| {
        b.iter(|| {
            let d = Decimal::from_str(black_box("0.000000001234")).unwrap();
            black_box(d)
        })
    });

    group.finish();
}

// ============================================================================
// JSON Serialization Benchmarks
// ============================================================================

fn bench_json_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("json_serialization");

    // Build complex objects for testing
    let simple_object: serde_json::Value = serde_json::json!({
        "id": 1,
        "name": "test",
        "active": true
    });

    let medium_object: serde_json::Value = serde_json::json!({
        "id": 12345,
        "name": "Test User",
        "email": "test@example.com",
        "age": 30,
        "active": true,
        "tags": ["rust", "graph", "database"],
        "metadata": {
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-06-20T14:45:00Z"
        }
    });

    let large_array: serde_json::Value = serde_json::Value::Array(
        (0..1000)
            .map(|i| {
                serde_json::json!({
                    "id": i,
                    "value": format!("item_{}", i)
                })
            })
            .collect(),
    );

    group.bench_function("serialize_simple", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&simple_object)).unwrap();
            black_box(s)
        })
    });

    group.bench_function("serialize_medium", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&medium_object)).unwrap();
            black_box(s)
        })
    });

    group.bench_function("serialize_large_array", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&large_array)).unwrap();
            black_box(s)
        })
    });

    let simple_str = serde_json::to_string(&simple_object).unwrap();
    let medium_str = serde_json::to_string(&medium_object).unwrap();
    let large_str = serde_json::to_string(&large_array).unwrap();

    group.bench_function("deserialize_simple", |b| {
        b.iter(|| {
            let v: serde_json::Value = serde_json::from_str(black_box(&simple_str)).unwrap();
            black_box(v)
        })
    });

    group.bench_function("deserialize_medium", |b| {
        b.iter(|| {
            let v: serde_json::Value = serde_json::from_str(black_box(&medium_str)).unwrap();
            black_box(v)
        })
    });

    group.bench_function("deserialize_large_array", |b| {
        b.iter(|| {
            let v: serde_json::Value = serde_json::from_str(black_box(&large_str)).unwrap();
            black_box(v)
        })
    });

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    type_benches,
    bench_value_creation,
    bench_value_accessors,
    bench_value_clone,
);

criterion_group!(
    builder_benches,
    bench_query_builder,
    bench_pattern_builder,
    bench_predicate_builder,
);

criterion_group!(
    connection_benches,
    bench_connection,
    bench_query_execution,
    bench_query_throughput,
);

criterion_group!(
    parsing_benches,
    bench_decimal_parsing,
    bench_json_serialization,
);

criterion_main!(
    type_benches,
    builder_benches,
    connection_benches,
    parsing_benches
);
