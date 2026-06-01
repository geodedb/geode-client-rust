//! Graph-native entity types: [`Node`], [`Edge`], and [`Path`].
//!
//! When a GQL query projects a node, edge, or path variable
//! (e.g. `MATCH (n) RETURN n`), the driver surfaces the value as an
//! object-shaped [`Value`] with well-known keys. The helpers in this
//! module ([`as_node`], [`as_edge`], [`as_path`]) decode those objects
//! into the typed structs below.
//!
//! These mirror the Go reference client's `Node`/`Edge`/`Path` types and
//! `AsNode`/`AsEdge`/`AsPath` conversions.
//!
//! # Example
//!
//! ```no_run
//! # use geode_client::{Client, graph};
//! # async fn example() -> geode_client::Result<()> {
//! # let client = Client::new("localhost", 3141).skip_verify(true);
//! # let mut conn = client.connect().await?;
//! let (page, _) = conn.query("MATCH (n:Person) RETURN n LIMIT 1").await?;
//! if let Some(v) = page.rows[0].get("n") {
//!     if let Some(node) = graph::as_node(v) {
//!         println!("node {} labels {:?}", node.id, node.labels);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;

use crate::types::Value;

/// The typed representation of a Geode graph node value.
///
/// Produced by [`as_node`] from the object-shaped [`Value`] the driver
/// returns when scanning a `NODE` column.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    /// The node's stable identifier.
    pub id: i64,
    /// The node's labels.
    pub labels: Vec<String>,
    /// The node's properties.
    pub properties: HashMap<String, Value>,
}

/// The typed representation of a Geode graph edge (relationship) value.
///
/// Produced by [`as_edge`] from the object-shaped [`Value`] the driver
/// returns when scanning an `EDGE` column.
#[derive(Debug, Clone, PartialEq)]
pub struct Edge {
    /// The edge's stable identifier.
    pub id: i64,
    /// The identifier of the edge's start (source) node.
    pub start_node: i64,
    /// The identifier of the edge's end (target) node.
    pub end_node: i64,
    /// The edge type (relationship label).
    pub edge_type: String,
    /// The edge's properties.
    pub properties: HashMap<String, Value>,
}

/// The typed representation of a Geode graph path value: the ordered
/// sequence of nodes and edges along a traversal.
///
/// Produced by [`as_path`] from the object-shaped [`Value`] the driver
/// returns when scanning a `PATH` column.
#[derive(Debug, Clone, PartialEq)]
pub struct Path {
    /// The nodes along the path.
    pub nodes: Vec<Node>,
    /// The edges along the path.
    pub edges: Vec<Edge>,
}

/// Convert a driver [`Value`] into a typed [`Node`].
///
/// Returns `None` if `v` is not a node object: it must be an object that
/// has a `labels` key and does *not* have a `start_node` key (which would
/// make it an edge).
pub fn as_node(v: &Value) -> Option<Node> {
    let obj = v.as_object().ok()?;
    if !obj.contains_key("labels") {
        return None;
    }
    if obj.contains_key("start_node") {
        return None; // edges also have "id"
    }
    let id = obj.get("id").and_then(|v| v.as_int().ok()).unwrap_or(0);
    let labels = obj
        .get("labels")
        .and_then(|v| v.as_array().ok())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_string().ok().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let properties = obj
        .get("properties")
        .and_then(|v| v.as_object().ok())
        .cloned()
        .unwrap_or_default();
    Some(Node {
        id,
        labels,
        properties,
    })
}

/// Convert a driver [`Value`] into a typed [`Edge`].
///
/// Returns `None` if `v` is not an edge object: it must be an object that
/// has both `start_node` and `end_node` keys.
pub fn as_edge(v: &Value) -> Option<Edge> {
    let obj = v.as_object().ok()?;
    if !obj.contains_key("start_node") || !obj.contains_key("end_node") {
        return None;
    }
    let id = obj.get("id").and_then(|v| v.as_int().ok()).unwrap_or(0);
    let start_node = obj
        .get("start_node")
        .and_then(|v| v.as_int().ok())
        .unwrap_or(0);
    let end_node = obj
        .get("end_node")
        .and_then(|v| v.as_int().ok())
        .unwrap_or(0);
    let edge_type = obj
        .get("type")
        .and_then(|v| v.as_string().ok())
        .map(String::from)
        .unwrap_or_default();
    let properties = obj
        .get("properties")
        .and_then(|v| v.as_object().ok())
        .cloned()
        .unwrap_or_default();
    Some(Edge {
        id,
        start_node,
        end_node,
        edge_type,
        properties,
    })
}

/// Convert a driver [`Value`] into a typed [`Path`].
///
/// Returns `None` if `v` is not a path object: it must be an object that
/// has both `nodes` and `edges` keys. Individual entries that fail to
/// decode as a [`Node`]/[`Edge`] are skipped.
pub fn as_path(v: &Value) -> Option<Path> {
    let obj = v.as_object().ok()?;
    if !obj.contains_key("nodes") || !obj.contains_key("edges") {
        return None;
    }
    let nodes = obj
        .get("nodes")
        .and_then(|v| v.as_array().ok())
        .map(|arr| arr.iter().filter_map(as_node).collect())
        .unwrap_or_default();
    let edges = obj
        .get("edges")
        .and_then(|v| v.as_array().ok())
        .map(|arr| arr.iter().filter_map(as_edge).collect())
        .unwrap_or_default();
    Some(Path { nodes, edges })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_value(id: i64, labels: &[&str], props: &[(&str, Value)]) -> Value {
        let mut obj = HashMap::new();
        obj.insert("id".to_string(), Value::int(id));
        obj.insert(
            "labels".to_string(),
            Value::array(labels.iter().map(|l| Value::string(*l)).collect()),
        );
        let mut p = HashMap::new();
        for (k, v) in props {
            p.insert(k.to_string(), v.clone());
        }
        obj.insert("properties".to_string(), Value::object(p));
        Value::object(obj)
    }

    fn edge_value(id: i64, start: i64, end: i64, typ: &str) -> Value {
        let mut obj = HashMap::new();
        obj.insert("id".to_string(), Value::int(id));
        obj.insert("start_node".to_string(), Value::int(start));
        obj.insert("end_node".to_string(), Value::int(end));
        obj.insert("type".to_string(), Value::string(typ));
        obj.insert("properties".to_string(), Value::object(HashMap::new()));
        Value::object(obj)
    }

    #[test]
    fn test_as_node_from_object() {
        let v = node_value(42, &["Person", "User"], &[("name", Value::string("Alice"))]);
        let node = as_node(&v).expect("should decode node");
        assert_eq!(node.id, 42);
        assert_eq!(node.labels, vec!["Person".to_string(), "User".to_string()]);
        assert_eq!(
            node.properties.get("name").unwrap().as_string().unwrap(),
            "Alice"
        );
    }

    #[test]
    fn test_as_edge_from_object() {
        let v = edge_value(100, 1, 2, "KNOWS");
        let edge = as_edge(&v).expect("should decode edge");
        assert_eq!(edge.id, 100);
        assert_eq!(edge.start_node, 1);
        assert_eq!(edge.end_node, 2);
        assert_eq!(edge.edge_type, "KNOWS");
        assert!(edge.properties.is_empty());
    }

    #[test]
    fn test_as_path_from_object() {
        let n1 = node_value(1, &["Person"], &[]);
        let n2 = node_value(2, &["Person"], &[]);
        let e1 = edge_value(10, 1, 2, "KNOWS");
        let mut obj = HashMap::new();
        obj.insert("nodes".to_string(), Value::array(vec![n1, n2]));
        obj.insert("edges".to_string(), Value::array(vec![e1]));
        let v = Value::object(obj);

        let path = as_path(&v).expect("should decode path");
        assert_eq!(path.nodes.len(), 2);
        assert_eq!(path.edges.len(), 1);
        assert_eq!(path.nodes[0].id, 1);
        assert_eq!(path.nodes[1].id, 2);
        assert_eq!(path.edges[0].edge_type, "KNOWS");
    }

    #[test]
    fn test_as_node_rejects_scalar() {
        assert!(as_node(&Value::int(5)).is_none());
        assert!(as_node(&Value::string("x")).is_none());
        assert!(as_node(&Value::null()).is_none());
        // An edge object (has start_node) must not decode as a node.
        assert!(as_node(&edge_value(1, 2, 3, "T")).is_none());
    }

    #[test]
    fn test_as_edge_rejects_node() {
        let v = node_value(1, &["Person"], &[]);
        assert!(as_edge(&v).is_none());
        assert!(as_edge(&Value::int(5)).is_none());
    }

    #[test]
    fn test_as_path_rejects_non_path() {
        assert!(as_path(&node_value(1, &["Person"], &[])).is_none());
        assert!(as_path(&Value::int(5)).is_none());
    }
}
