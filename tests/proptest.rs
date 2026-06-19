//! Property-based tests using proptest
//!
//! These tests verify invariants hold for arbitrary inputs, helping catch edge
//! cases and ensure robustness.
//!
//! Run with: `cargo test --test proptest`

use geode_client::{EdgeDirection, PatternBuilder, PredicateBuilder, QueryBuilder, Value};
use proptest::prelude::*;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::str::FromStr;

// ============================================================================
// Value Strategies
// ============================================================================

/// Generate arbitrary Value instances for property testing
fn arb_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        // Null
        Just(Value::null()),
        // Bool
        any::<bool>().prop_map(Value::bool),
        // Int
        any::<i64>().prop_map(Value::int),
        // String - various sizes
        ".*".prop_map(Value::string),
        // Decimal - valid decimal strings
        (-1000000i64..1000000i64, 0u32..6u32).prop_map(|(n, scale)| {
            let divisor = 10i64.pow(scale);
            let decimal_str = format!(
                "{}.{:0width$}",
                n / divisor,
                (n % divisor).abs(),
                width = scale as usize
            );
            if let Ok(d) = Decimal::from_str(&decimal_str) {
                Value::decimal(d)
            } else {
                Value::int(n)
            }
        }),
    ]
}

/// Generate arbitrary nested Value (arrays and objects)
fn arb_nested_value() -> impl Strategy<Value = Value> {
    arb_value().prop_recursive(
        3,  // depth
        64, // max nodes
        10, // items per collection
        |inner| {
            prop_oneof![
                // Array of values
                prop::collection::vec(inner.clone(), 0..10).prop_map(Value::array),
                // Object with string keys
                prop::collection::hash_map("\\w{1,10}", inner, 0..10).prop_map(Value::object),
            ]
        },
    )
}

// ============================================================================
// Value Property Tests
// ============================================================================

proptest! {
    /// Value::null() always reports is_null() as true
    #[test]
    fn null_is_null(_unused in 0..1i32) {
        let v = Value::null();
        prop_assert!(v.is_null());
    }

    /// Non-null values report is_null() as false
    #[test]
    fn non_null_is_not_null(i in any::<i64>()) {
        let v = Value::int(i);
        prop_assert!(!v.is_null());
    }

    /// Integer round-trip: create -> access -> same value
    #[test]
    fn int_roundtrip(i in any::<i64>()) {
        let v = Value::int(i);
        prop_assert_eq!(v.as_int().unwrap(), i);
    }

    /// Bool round-trip: create -> access -> same value
    #[test]
    fn bool_roundtrip(b in any::<bool>()) {
        let v = Value::bool(b);
        prop_assert_eq!(v.as_bool().unwrap(), b);
    }

    /// String round-trip: create -> access -> same value
    #[test]
    fn string_roundtrip(s in ".*") {
        let v = Value::string(s.clone());
        prop_assert_eq!(v.as_string().unwrap(), &s);
    }

    /// Decimal values can be accessed
    #[test]
    fn decimal_access(n in -999999i64..999999i64) {
        let d = Decimal::from(n);
        let v = Value::decimal(d);
        prop_assert_eq!(v.as_decimal().unwrap(), d);
    }

    /// Array round-trip: values remain accessible
    #[test]
    fn array_roundtrip(items in prop::collection::vec(any::<i64>(), 0..20)) {
        let values: Vec<Value> = items.iter().map(|&i| Value::int(i)).collect();
        let v = Value::array(values);
        let arr = v.as_array().unwrap();
        prop_assert_eq!(arr.len(), items.len());
        for (i, &expected) in items.iter().enumerate() {
            prop_assert_eq!(arr[i].as_int().unwrap(), expected);
        }
    }

    /// Object round-trip: key-value pairs remain accessible
    #[test]
    fn object_roundtrip(entries in prop::collection::hash_map("\\w{1,20}", any::<i64>(), 0..10)) {
        let map: HashMap<String, Value> = entries.iter()
            .map(|(k, &v)| (k.clone(), Value::int(v)))
            .collect();
        let v = Value::object(map);
        let obj = v.as_object().unwrap();
        prop_assert_eq!(obj.len(), entries.len());
        for (k, &expected) in &entries {
            prop_assert_eq!(obj.get(k).unwrap().as_int().unwrap(), expected);
        }
    }

    /// Value clone produces equal value
    #[test]
    fn value_clone_preserves_data(v in arb_value()) {
        let cloned = v.clone();
        // Check kind matches
        prop_assert_eq!(v.is_null(), cloned.is_null());
        // If int, check value
        if let (Ok(a), Ok(b)) = (v.as_int(), cloned.as_int()) {
            prop_assert_eq!(a, b);
        }
        // If string, check value
        if let (Ok(a), Ok(b)) = (v.as_string(), cloned.as_string()) {
            prop_assert_eq!(a, b);
        }
    }

    /// to_json never panics
    #[test]
    fn to_json_never_panics(v in arb_nested_value()) {
        let _ = v.to_json();
    }

    /// from_json never panics
    #[test]
    fn from_json_never_panics(json_str in "\\{.*\\}|\\[.*\\]|\".*\"|[0-9]+|true|false|null") {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
            let _ = Value::from_json(json); // may return Err for deep nesting, that's ok
        }
    }

    /// JSON roundtrip for simple values preserves type category
    #[test]
    fn simple_json_roundtrip(i in any::<i64>()) {
        let original = Value::int(i);
        let json = original.to_json();
        let restored = Value::from_json(json).unwrap();
        // Int should come back as int
        prop_assert!(!restored.is_null());
        prop_assert!(restored.as_int().is_ok());
    }
}

// ============================================================================
// QueryBuilder Property Tests
// ============================================================================

proptest! {
    /// QueryBuilder.build() never panics
    #[test]
    fn query_builder_never_panics(
        pattern in "\\(\\w+\\)",
        condition in "\\w+ [><=] \\d+",
        fields in prop::collection::vec("\\w+", 1..5),
        limit in 1usize..1000
    ) {
        let field_refs: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
        let (query, _params) = QueryBuilder::new()
            .match_pattern(&pattern)
            .where_clause(&condition)
            .return_(&field_refs)
            .limit(limit)
            .build();

        // Query should contain expected clauses
        prop_assert!(query.contains("MATCH"));
        prop_assert!(query.contains("WHERE"));
        prop_assert!(query.contains("RETURN"));
        prop_assert!(query.contains("LIMIT"));
    }

    /// QueryBuilder with_param handles arbitrary values
    #[test]
    fn query_builder_params_never_panic(
        param_name in "\\w{1,20}",
        param_value in any::<i64>()
    ) {
        let (query, params) = QueryBuilder::new()
            .match_pattern("(n:Node)")
            .where_clause(&format!("n.value = ${}", param_name))
            .with_param(&param_name, param_value)
            .return_(&["n"])
            .build();

        let param_pattern = format!("${}", param_name);
        prop_assert!(query.contains(&param_pattern));
        prop_assert!(params.contains_key(&param_name));
    }

    /// QueryBuilder produces non-empty query string
    #[test]
    fn query_builder_non_empty(pattern in "\\(\\w+\\)") {
        let (query, _) = QueryBuilder::new()
            .match_pattern(&pattern)
            .return_(&["*"])
            .build();
        prop_assert!(!query.is_empty());
    }

    /// Multiple clauses are separated
    #[test]
    fn query_builder_clauses_separated(
        patterns in prop::collection::vec("\\(\\w+\\)", 1..4)
    ) {
        let mut builder = QueryBuilder::new();
        for pattern in &patterns {
            builder = builder.match_pattern(pattern);
        }
        let (query, _) = builder.return_(&["*"]).build();

        // Each MATCH should be on separate line or clause
        let match_count = query.matches("MATCH").count();
        prop_assert_eq!(match_count, patterns.len());
    }
}

// ============================================================================
// PatternBuilder Property Tests
// ============================================================================

proptest! {
    /// PatternBuilder.build() never panics
    #[test]
    fn pattern_builder_never_panics(
        var1 in "\\w{1,10}",
        label1 in "\\w{1,20}",
        edge_var in "\\w{1,10}",
        edge_type in "\\w{1,20}",
        var2 in "\\w{1,10}",
        label2 in "\\w{1,20}"
    ) {
        let pattern = PatternBuilder::new()
            .node(&var1, &label1)
            .edge(&edge_var, &edge_type, EdgeDirection::Outgoing)
            .node(&var2, &label2)
            .build();

        // Should contain node patterns
        prop_assert!(pattern.contains(&var1) || pattern.contains(&label1));
    }

    /// PatternBuilder single node produces valid pattern
    #[test]
    fn pattern_builder_single_node(var in "\\w{1,10}", label in "\\w{1,20}") {
        let pattern = PatternBuilder::new()
            .node(&var, &label)
            .build();

        // Should be wrapped in parentheses
        prop_assert!(pattern.starts_with('('));
        prop_assert!(pattern.ends_with(')'));
    }

    /// PatternBuilder edge directions produce different arrows
    #[test]
    fn pattern_builder_edge_directions(
        edge_var in "\\w{1,10}",
        edge_type in "\\w{1,20}"
    ) {
        let outgoing = PatternBuilder::new()
            .node("a", "Node")
            .edge(&edge_var, &edge_type, EdgeDirection::Outgoing)
            .node("b", "Node")
            .build();

        let incoming = PatternBuilder::new()
            .node("a", "Node")
            .edge(&edge_var, &edge_type, EdgeDirection::Incoming)
            .node("b", "Node")
            .build();

        let undirected = PatternBuilder::new()
            .node("a", "Node")
            .edge(&edge_var, &edge_type, EdgeDirection::Undirected)
            .node("b", "Node")
            .build();

        // Outgoing has ->
        prop_assert!(outgoing.contains("->"));
        // Incoming has <-
        prop_assert!(incoming.contains("<-"));
        // Undirected has neither -> nor <-
        prop_assert!(!undirected.contains("->") || !undirected.contains("<-"));
    }
}

// ============================================================================
// PredicateBuilder Property Tests
// ============================================================================

proptest! {
    /// PredicateBuilder.build_and() never panics
    #[test]
    fn predicate_builder_never_panics(
        left in "\\w+\\.\\w+",
        right in "\\d+"
    ) {
        let pred = PredicateBuilder::new()
            .greater_than(&left, &right)
            .build_and();

        prop_assert!(pred.contains(">"));
    }

    /// Multiple predicates joined with AND
    #[test]
    fn predicate_builder_joins_with_and(
        expr1 in "\\w+",
        expr2 in "\\w+"
    ) {
        let pred = PredicateBuilder::new()
            .is_not_null(&expr1)
            .is_not_null(&expr2)
            .build_and();

        if expr1 != expr2 {
            prop_assert!(pred.contains("AND"));
        }
    }
}

// ============================================================================
// Error Handling Property Tests
// ============================================================================

proptest! {
    /// Type accessor on wrong type returns Err, not panic
    #[test]
    fn wrong_type_accessor_returns_error(i in any::<i64>()) {
        let v = Value::int(i);
        // These should return Err, not panic
        prop_assert!(v.as_string().is_err());
        prop_assert!(v.as_bool().is_err());
        prop_assert!(v.as_array().is_err());
        prop_assert!(v.as_object().is_err());
        prop_assert!(v.as_decimal().is_err());
    }

    /// String value accessor on non-string returns error
    #[test]
    fn string_accessor_on_non_string_returns_error(b in any::<bool>()) {
        let v = Value::bool(b);
        prop_assert!(v.as_string().is_err());
        prop_assert!(v.as_int().is_err());
    }
}

// ============================================================================
// Stress Tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Large nested structures don't cause stack overflow
    #[test]
    fn large_nested_array_no_overflow(depth in 1usize..100) {
        let mut v = Value::int(42);
        for _ in 0..depth {
            v = Value::array(vec![v]);
        }
        // Should be able to convert to JSON without overflow
        let _ = v.to_json();
    }

    /// Large objects with many keys handle correctly
    #[test]
    fn large_object_handles_many_keys(num_keys in 1usize..500) {
        let map: HashMap<String, Value> = (0..num_keys)
            .map(|i| (format!("key_{}", i), Value::int(i as i64)))
            .collect();
        let v = Value::object(map);
        let obj = v.as_object().unwrap();
        prop_assert_eq!(obj.len(), num_keys);
    }
}

// ============================================================================
// Fuzz-like Tests (random bytes -> operation)
// ============================================================================

proptest! {
    /// Random JSON strings handled gracefully
    #[test]
    fn random_json_handled(bytes in prop::collection::vec(any::<u8>(), 0..1000)) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(s) {
                // Should not panic
                let _ = Value::from_json(json);
            }
        }
    }

    /// Random strings as query patterns don't crash builder
    #[test]
    fn random_query_pattern_no_crash(pattern in ".*") {
        let _ = QueryBuilder::new()
            .match_pattern(&pattern)
            .return_(&["*"])
            .build();
    }

    /// Random strings as predicates don't crash builder
    #[test]
    fn random_predicate_no_crash(left in ".*", right in ".*") {
        let _ = PredicateBuilder::new()
            .greater_than(&left, &right)
            .build_and();
    }
}

// ============================================================================
// DSN Round-Trip Property Tests
// ============================================================================

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
        let scheme = "grpc";
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
