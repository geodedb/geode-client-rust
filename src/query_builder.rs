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
