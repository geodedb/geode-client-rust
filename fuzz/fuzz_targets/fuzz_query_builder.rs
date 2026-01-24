//! Fuzz target for QueryBuilder
//!
//! Tests that arbitrary string inputs to QueryBuilder don't cause panics
//! or undefined behavior.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use geode_client::QueryBuilder;

#[derive(Debug, Arbitrary)]
struct QueryInput {
    pattern: String,
    condition: String,
    fields: Vec<String>,
    with_exprs: Vec<String>,
    order_by: Vec<String>,
    limit: Option<usize>,
    params: Vec<(String, i64)>,
}

fuzz_target!(|input: QueryInput| {
    let mut builder = QueryBuilder::new();

    // Apply match pattern
    if !input.pattern.is_empty() {
        builder = builder.match_pattern(&input.pattern);
    }

    // Apply optional match (use same pattern for simplicity)
    if !input.pattern.is_empty() && input.pattern.len() > 10 {
        builder = builder.optional_match(&input.pattern);
    }

    // Apply WHERE clause
    if !input.condition.is_empty() {
        builder = builder.where_clause(&input.condition);
    }

    // Apply WITH clause
    if !input.with_exprs.is_empty() {
        let refs: Vec<&str> = input.with_exprs.iter().map(|s| s.as_str()).collect();
        builder = builder.with(&refs);
    }

    // Apply RETURN clause
    if !input.fields.is_empty() {
        let refs: Vec<&str> = input.fields.iter().map(|s| s.as_str()).collect();
        builder = builder.return_(&refs);
    }

    // Apply ORDER BY
    if !input.order_by.is_empty() {
        let refs: Vec<&str> = input.order_by.iter().map(|s| s.as_str()).collect();
        builder = builder.order_by(&refs);
    }

    // Apply LIMIT
    if let Some(limit) = input.limit {
        if limit > 0 && limit < 1_000_000 {
            builder = builder.limit(limit);
        }
    }

    // Apply parameters
    for (name, value) in &input.params {
        if !name.is_empty() {
            builder = builder.with_param(name, *value);
        }
    }

    // Build should never panic
    let (query, params) = builder.build();

    // Result should be usable
    let _ = query.len();
    let _ = params.len();
});
