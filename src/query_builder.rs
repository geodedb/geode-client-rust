//! Query builder for constructing GQL queries programmatically.

use std::collections::HashMap;

/// Edge direction in patterns
#[derive(Debug, Clone, Copy)]
pub enum EdgeDirection {
    Outgoing,
    Incoming,
    Undirected,
}

/// Query builder for GQL
pub struct QueryBuilder {
    clauses: Vec<(String, String)>,
    params: HashMap<String, serde_json::Value>,
}

impl QueryBuilder {
    pub fn new() -> Self {
        Self {
            clauses: Vec::new(),
            params: HashMap::new(),
        }
    }

    pub fn match_pattern(mut self, pattern: &str) -> Self {
        self.clauses
            .push(("MATCH".to_string(), pattern.to_string()));
        self
    }

    pub fn optional_match(mut self, pattern: &str) -> Self {
        self.clauses
            .push(("OPTIONAL MATCH".to_string(), pattern.to_string()));
        self
    }

    pub fn where_clause(mut self, condition: &str) -> Self {
        self.clauses
            .push(("WHERE".to_string(), condition.to_string()));
        self
    }

    pub fn with(mut self, expressions: &[&str]) -> Self {
        self.clauses
            .push(("WITH".to_string(), expressions.join(", ")));
        self
    }

    pub fn return_(mut self, expressions: &[&str]) -> Self {
        self.clauses
            .push(("RETURN".to_string(), expressions.join(", ")));
        self
    }

    pub fn order_by(mut self, expressions: &[&str]) -> Self {
        self.clauses
            .push(("ORDER BY".to_string(), expressions.join(", ")));
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.clauses.push(("LIMIT".to_string(), n.to_string()));
        self
    }

    pub fn with_param<V: serde::Serialize>(mut self, name: &str, value: V) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.params.insert(name.to_string(), v);
        }
        self
    }

    pub fn build(self) -> (String, HashMap<String, serde_json::Value>) {
        let query = self
            .clauses
            .iter()
            .map(|(clause_type, content)| {
                if content.is_empty() {
                    clause_type.clone()
                } else {
                    format!("{} {}", clause_type, content)
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        (query, self.params)
    }
}

impl Default for QueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Pattern builder for graph patterns
pub struct PatternBuilder {
    elements: Vec<String>,
}

impl PatternBuilder {
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    pub fn node(mut self, variable: &str, label: &str) -> Self {
        let pattern = if label.is_empty() {
            format!("({})", variable)
        } else {
            format!("({}:{})", variable, label)
        };
        self.elements.push(pattern);
        self
    }

    pub fn edge(mut self, variable: &str, edge_type: &str, direction: EdgeDirection) -> Self {
        let pattern = match direction {
            EdgeDirection::Outgoing => {
                if edge_type.is_empty() {
                    "->".to_string()
                } else {
                    format!("-[{}:{}]->", variable, edge_type)
                }
            }
            EdgeDirection::Incoming => {
                if edge_type.is_empty() {
                    "<-".to_string()
                } else {
                    format!("<-[{}:{}]-", variable, edge_type)
                }
            }
            EdgeDirection::Undirected => {
                if edge_type.is_empty() {
                    "-".to_string()
                } else {
                    format!("-[{}:{}]-", variable, edge_type)
                }
            }
        };
        self.elements.push(pattern);
        self
    }

    pub fn build(self) -> String {
        self.elements.join("")
    }
}

impl Default for PatternBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Predicate builder for WHERE conditions
pub struct PredicateBuilder {
    conditions: Vec<String>,
}

impl PredicateBuilder {
    pub fn new() -> Self {
        Self {
            conditions: Vec::new(),
        }
    }

    pub fn greater_than(mut self, left: &str, right: &str) -> Self {
        self.conditions.push(format!("{} > {}", left, right));
        self
    }

    pub fn is_not_null(mut self, expr: &str) -> Self {
        self.conditions.push(format!("{} IS NOT NULL", expr));
        self
    }

    pub fn build_and(self) -> String {
        self.conditions.join(" AND ")
    }
}

impl Default for PredicateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== QueryBuilder Tests ====================

    #[test]
    fn test_query_builder_new() {
        let builder = QueryBuilder::new();
        let (query, params) = builder.build();
        assert!(query.is_empty());
        assert!(params.is_empty());
    }

    #[test]
    fn test_query_builder_default() {
        let builder = QueryBuilder::default();
        let (query, _) = builder.build();
        assert!(query.is_empty());
    }

    #[test]
    fn test_query_builder_match_pattern() {
        let (query, _) = QueryBuilder::new().match_pattern("(n:Person)").build();
        assert_eq!(query, "MATCH (n:Person)");
    }

    #[test]
    fn test_query_builder_optional_match() {
        let (query, _) = QueryBuilder::new()
            .optional_match("(n:Person)-[:KNOWS]->(m)")
            .build();
        assert_eq!(query, "OPTIONAL MATCH (n:Person)-[:KNOWS]->(m)");
    }

    #[test]
    fn test_query_builder_where_clause() {
        let (query, _) = QueryBuilder::new()
            .match_pattern("(n:Person)")
            .where_clause("n.age > 25")
            .build();
        assert_eq!(query, "MATCH (n:Person)\nWHERE n.age > 25");
    }

    #[test]
    fn test_query_builder_with() {
        let (query, _) = QueryBuilder::new()
            .match_pattern("(n:Person)")
            .with(&["n.name AS name", "n.age AS age"])
            .build();
        assert_eq!(query, "MATCH (n:Person)\nWITH n.name AS name, n.age AS age");
    }

    #[test]
    fn test_query_builder_with_single() {
        let (query, _) = QueryBuilder::new()
            .match_pattern("(n)")
            .with(&["n"])
            .build();
        assert_eq!(query, "MATCH (n)\nWITH n");
    }

    #[test]
    fn test_query_builder_return() {
        let (query, _) = QueryBuilder::new()
            .match_pattern("(n:Person)")
            .return_(&["n.name", "n.age"])
            .build();
        assert_eq!(query, "MATCH (n:Person)\nRETURN n.name, n.age");
    }

    #[test]
    fn test_query_builder_return_single() {
        let (query, _) = QueryBuilder::new()
            .match_pattern("(n)")
            .return_(&["n"])
            .build();
        assert_eq!(query, "MATCH (n)\nRETURN n");
    }

    #[test]
    fn test_query_builder_order_by() {
        let (query, _) = QueryBuilder::new()
            .match_pattern("(n:Person)")
            .return_(&["n.name", "n.age"])
            .order_by(&["n.age DESC", "n.name ASC"])
            .build();
        assert!(query.contains("ORDER BY n.age DESC, n.name ASC"));
    }

    #[test]
    fn test_query_builder_limit() {
        let (query, _) = QueryBuilder::new()
            .match_pattern("(n:Person)")
            .return_(&["n"])
            .limit(10)
            .build();
        assert!(query.contains("LIMIT 10"));
    }

    #[test]
    fn test_query_builder_limit_zero() {
        let (query, _) = QueryBuilder::new()
            .match_pattern("(n)")
            .return_(&["n"])
            .limit(0)
            .build();
        assert!(query.contains("LIMIT 0"));
    }

    #[test]
    fn test_query_builder_with_param_int() {
        let (_, params) = QueryBuilder::new()
            .match_pattern("(n:Person)")
            .where_clause("n.age > $min_age")
            .with_param("min_age", 25)
            .build();
        assert_eq!(params.get("min_age").unwrap(), &serde_json::json!(25));
    }

    #[test]
    fn test_query_builder_with_param_string() {
        let (_, params) = QueryBuilder::new()
            .match_pattern("(n:Person)")
            .where_clause("n.name = $name")
            .with_param("name", "Alice")
            .build();
        assert_eq!(params.get("name").unwrap(), &serde_json::json!("Alice"));
    }

    #[test]
    fn test_query_builder_with_param_bool() {
        let (_, params) = QueryBuilder::new().with_param("active", true).build();
        assert_eq!(params.get("active").unwrap(), &serde_json::json!(true));
    }

    #[test]
    fn test_query_builder_multiple_params() {
        let (_, params) = QueryBuilder::new()
            .match_pattern("(n:Person)")
            .where_clause("n.age > $min_age AND n.name = $name")
            .with_param("min_age", 25)
            .with_param("name", "Alice")
            .build();
        assert_eq!(params.len(), 2);
        assert_eq!(params.get("min_age").unwrap(), &serde_json::json!(25));
        assert_eq!(params.get("name").unwrap(), &serde_json::json!("Alice"));
    }

    #[test]
    fn test_query_builder_full_query() {
        let (query, params) = QueryBuilder::new()
            .match_pattern("(p:Person)")
            .where_clause("p.age > $min_age")
            .return_(&["p.name", "p.age"])
            .order_by(&["p.age DESC"])
            .limit(100)
            .with_param("min_age", 25)
            .build();

        assert!(query.contains("MATCH (p:Person)"));
        assert!(query.contains("WHERE p.age > $min_age"));
        assert!(query.contains("RETURN p.name, p.age"));
        assert!(query.contains("ORDER BY p.age DESC"));
        assert!(query.contains("LIMIT 100"));
        assert_eq!(params.get("min_age").unwrap(), &serde_json::json!(25));
    }

    #[test]
    fn test_query_builder_complex_query() {
        let (query, _) = QueryBuilder::new()
            .match_pattern("(a:Person)-[r:KNOWS]->(b:Person)")
            .where_clause("a.name = 'Alice'")
            .optional_match("(b)-[:WORKS_AT]->(c:Company)")
            .return_(&["a.name", "b.name", "c.name"])
            .build();

        let lines: Vec<&str> = query.lines().collect();
        assert_eq!(lines[0], "MATCH (a:Person)-[r:KNOWS]->(b:Person)");
        assert_eq!(lines[1], "WHERE a.name = 'Alice'");
        assert_eq!(lines[2], "OPTIONAL MATCH (b)-[:WORKS_AT]->(c:Company)");
        assert_eq!(lines[3], "RETURN a.name, b.name, c.name");
    }

    #[test]
    fn test_query_builder_empty_content_clause() {
        // Test that empty content produces just the clause type
        let mut builder = QueryBuilder::new();
        builder.clauses.push(("RETURN".to_string(), "".to_string()));
        let (query, _) = builder.build();
        assert_eq!(query, "RETURN");
    }

    #[test]
    fn test_query_builder_chaining() {
        // Test that methods return Self for chaining
        let builder = QueryBuilder::new()
            .match_pattern("(n)")
            .where_clause("n.x > 0")
            .return_(&["n"]);
        let (query, _) = builder.build();
        assert!(query.contains("MATCH"));
        assert!(query.contains("WHERE"));
        assert!(query.contains("RETURN"));
    }

    #[test]
    fn test_query_builder_with_array_param() {
        let (_, params) = QueryBuilder::new().with_param("ids", vec![1, 2, 3]).build();
        assert_eq!(params.get("ids").unwrap(), &serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn test_query_builder_with_null_param() {
        let (_, params) = QueryBuilder::new()
            .with_param("value", serde_json::Value::Null)
            .build();
        assert_eq!(params.get("value").unwrap(), &serde_json::json!(null));
    }

    // ==================== PatternBuilder Tests ====================

    #[test]
    fn test_pattern_builder_new() {
        let builder = PatternBuilder::new();
        let pattern = builder.build();
        assert!(pattern.is_empty());
    }

    #[test]
    fn test_pattern_builder_default() {
        let builder = PatternBuilder::default();
        let pattern = builder.build();
        assert!(pattern.is_empty());
    }

    #[test]
    fn test_pattern_builder_node_with_label() {
        let pattern = PatternBuilder::new().node("n", "Person").build();
        assert_eq!(pattern, "(n:Person)");
    }

    #[test]
    fn test_pattern_builder_node_without_label() {
        let pattern = PatternBuilder::new().node("n", "").build();
        assert_eq!(pattern, "(n)");
    }

    #[test]
    fn test_pattern_builder_edge_outgoing_with_type() {
        let pattern = PatternBuilder::new()
            .node("a", "Person")
            .edge("r", "KNOWS", EdgeDirection::Outgoing)
            .node("b", "Person")
            .build();
        assert_eq!(pattern, "(a:Person)-[r:KNOWS]->(b:Person)");
    }

    #[test]
    fn test_pattern_builder_edge_outgoing_without_type() {
        let pattern = PatternBuilder::new()
            .node("a", "")
            .edge("", "", EdgeDirection::Outgoing)
            .node("b", "")
            .build();
        assert_eq!(pattern, "(a)->(b)");
    }

    #[test]
    fn test_pattern_builder_edge_incoming_with_type() {
        let pattern = PatternBuilder::new()
            .node("a", "Person")
            .edge("r", "KNOWS", EdgeDirection::Incoming)
            .node("b", "Person")
            .build();
        assert_eq!(pattern, "(a:Person)<-[r:KNOWS]-(b:Person)");
    }

    #[test]
    fn test_pattern_builder_edge_incoming_without_type() {
        let pattern = PatternBuilder::new()
            .node("a", "")
            .edge("", "", EdgeDirection::Incoming)
            .node("b", "")
            .build();
        assert_eq!(pattern, "(a)<-(b)");
    }

    #[test]
    fn test_pattern_builder_edge_undirected_with_type() {
        let pattern = PatternBuilder::new()
            .node("a", "Person")
            .edge("r", "KNOWS", EdgeDirection::Undirected)
            .node("b", "Person")
            .build();
        assert_eq!(pattern, "(a:Person)-[r:KNOWS]-(b:Person)");
    }

    #[test]
    fn test_pattern_builder_edge_undirected_without_type() {
        let pattern = PatternBuilder::new()
            .node("a", "")
            .edge("", "", EdgeDirection::Undirected)
            .node("b", "")
            .build();
        assert_eq!(pattern, "(a)-(b)");
    }

    #[test]
    fn test_pattern_builder_chain() {
        let pattern = PatternBuilder::new()
            .node("a", "Person")
            .edge("r1", "KNOWS", EdgeDirection::Outgoing)
            .node("b", "Person")
            .edge("r2", "WORKS_AT", EdgeDirection::Outgoing)
            .node("c", "Company")
            .build();
        assert_eq!(
            pattern,
            "(a:Person)-[r1:KNOWS]->(b:Person)-[r2:WORKS_AT]->(c:Company)"
        );
    }

    #[test]
    fn test_pattern_builder_mixed_directions() {
        let pattern = PatternBuilder::new()
            .node("a", "Person")
            .edge("", "", EdgeDirection::Outgoing)
            .node("b", "Person")
            .edge("", "", EdgeDirection::Incoming)
            .node("c", "Person")
            .build();
        assert_eq!(pattern, "(a:Person)->(b:Person)<-(c:Person)");
    }

    #[test]
    fn test_edge_direction_debug() {
        assert_eq!(format!("{:?}", EdgeDirection::Outgoing), "Outgoing");
        assert_eq!(format!("{:?}", EdgeDirection::Incoming), "Incoming");
        assert_eq!(format!("{:?}", EdgeDirection::Undirected), "Undirected");
    }

    #[test]
    fn test_edge_direction_copy() {
        let dir = EdgeDirection::Outgoing;
        let dir_copy = dir;
        assert!(matches!(dir, EdgeDirection::Outgoing));
        assert!(matches!(dir_copy, EdgeDirection::Outgoing));
    }

    // ==================== PredicateBuilder Tests ====================

    #[test]
    fn test_predicate_builder_new() {
        let builder = PredicateBuilder::new();
        let predicate = builder.build_and();
        assert!(predicate.is_empty());
    }

    #[test]
    fn test_predicate_builder_default() {
        let builder = PredicateBuilder::default();
        let predicate = builder.build_and();
        assert!(predicate.is_empty());
    }

    #[test]
    fn test_predicate_builder_greater_than() {
        let predicate = PredicateBuilder::new()
            .greater_than("n.age", "25")
            .build_and();
        assert_eq!(predicate, "n.age > 25");
    }

    #[test]
    fn test_predicate_builder_is_not_null() {
        let predicate = PredicateBuilder::new().is_not_null("n.email").build_and();
        assert_eq!(predicate, "n.email IS NOT NULL");
    }

    #[test]
    fn test_predicate_builder_multiple_conditions() {
        let predicate = PredicateBuilder::new()
            .greater_than("n.age", "25")
            .is_not_null("n.email")
            .build_and();
        assert_eq!(predicate, "n.age > 25 AND n.email IS NOT NULL");
    }

    #[test]
    fn test_predicate_builder_chain() {
        let predicate = PredicateBuilder::new()
            .greater_than("n.age", "18")
            .greater_than("n.salary", "50000")
            .is_not_null("n.department")
            .build_and();
        assert_eq!(
            predicate,
            "n.age > 18 AND n.salary > 50000 AND n.department IS NOT NULL"
        );
    }

    #[test]
    fn test_predicate_builder_with_param_placeholders() {
        let predicate = PredicateBuilder::new()
            .greater_than("n.age", "$min_age")
            .build_and();
        assert_eq!(predicate, "n.age > $min_age");
    }

    // ==================== Integration Tests ====================

    #[test]
    fn test_query_with_pattern_builder() {
        let pattern = PatternBuilder::new()
            .node("p", "Person")
            .edge("r", "KNOWS", EdgeDirection::Outgoing)
            .node("f", "Person")
            .build();

        let (query, _) = QueryBuilder::new()
            .match_pattern(&pattern)
            .return_(&["p.name", "f.name"])
            .build();

        assert!(query.contains("(p:Person)-[r:KNOWS]->(f:Person)"));
    }

    #[test]
    fn test_query_with_predicate_builder() {
        let predicate = PredicateBuilder::new()
            .greater_than("p.age", "$min_age")
            .is_not_null("p.email")
            .build_and();

        let (query, params) = QueryBuilder::new()
            .match_pattern("(p:Person)")
            .where_clause(&predicate)
            .return_(&["p"])
            .with_param("min_age", 25)
            .build();

        assert!(query.contains("p.age > $min_age AND p.email IS NOT NULL"));
        assert_eq!(params.get("min_age").unwrap(), &serde_json::json!(25));
    }

    #[test]
    fn test_full_integration() {
        let pattern = PatternBuilder::new()
            .node("p", "Person")
            .edge("", "", EdgeDirection::Outgoing)
            .node("c", "City")
            .build();

        let predicate = PredicateBuilder::new()
            .greater_than("p.age", "$min_age")
            .is_not_null("c.name")
            .build_and();

        let (query, params) = QueryBuilder::new()
            .match_pattern(&pattern)
            .where_clause(&predicate)
            .return_(&["p.name", "c.name"])
            .order_by(&["p.age DESC"])
            .limit(50)
            .with_param("min_age", 30)
            .build();

        assert!(query.contains("MATCH (p:Person)->(c:City)"));
        assert!(query.contains("WHERE p.age > $min_age AND c.name IS NOT NULL"));
        assert!(query.contains("RETURN p.name, c.name"));
        assert!(query.contains("ORDER BY p.age DESC"));
        assert!(query.contains("LIMIT 50"));
        assert_eq!(params.get("min_age").unwrap(), &serde_json::json!(30));
    }
}
