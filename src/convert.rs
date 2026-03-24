//! Shared protobuf-to-Value conversion for QUIC and gRPC transports.

use std::collections::HashMap;

use crate::proto;
use crate::types::Value;

/// Maximum recursion depth for converting nested protobuf values (CWE-674).
const MAX_PROTO_RECURSION_DEPTH: usize = 64;

/// Convert a protobuf Value to our Value type.
#[inline]
pub(crate) fn proto_to_value(proto_val: &proto::Value) -> Value {
    proto_to_value_with_depth(proto_val, 0)
}

/// Depth-limited conversion of protobuf Value to our Value type.
/// Returns `Value::null()` when recursion exceeds `MAX_PROTO_RECURSION_DEPTH`
/// to prevent stack overflow from deeply nested or malicious payloads (CWE-674).
fn proto_to_value_with_depth(proto_val: &proto::Value, depth: usize) -> Value {
    if depth > MAX_PROTO_RECURSION_DEPTH {
        return Value::null();
    }

    let next_depth = depth + 1;

    match &proto_val.kind {
        Some(proto::value::Kind::NullVal(_)) => Value::null(),
        Some(proto::value::Kind::StringVal(s)) => Value::string(s.value.clone()),
        Some(proto::value::Kind::IntVal(i)) => Value::int(i.value),
        Some(proto::value::Kind::DoubleVal(d)) => {
            Value::decimal(rust_decimal::Decimal::from_f64_retain(d.value).unwrap_or_default())
        }
        Some(proto::value::Kind::BoolVal(b)) => Value::bool(*b),
        Some(proto::value::Kind::ListVal(list)) => {
            let values: Vec<Value> = list
                .values
                .iter()
                .map(|v| proto_to_value_with_depth(v, next_depth))
                .collect();
            Value::array(values)
        }
        Some(proto::value::Kind::MapVal(map)) => {
            let mut obj = HashMap::new();
            for entry in &map.entries {
                let val = entry
                    .value
                    .as_ref()
                    .map(|v| proto_to_value_with_depth(v, next_depth))
                    .unwrap_or_else(Value::null);
                obj.insert(entry.key.clone(), val);
            }
            Value::object(obj)
        }
        Some(proto::value::Kind::NodeVal(node)) => {
            let mut obj = HashMap::new();
            obj.insert("id".to_string(), Value::int(node.id as i64));
            let labels: Vec<Value> = node
                .labels
                .iter()
                .map(|l| Value::string(l.clone()))
                .collect();
            obj.insert("labels".to_string(), Value::array(labels));
            let mut props = HashMap::new();
            for entry in &node.properties {
                let val = entry
                    .value
                    .as_ref()
                    .map(|v| proto_to_value_with_depth(v, next_depth))
                    .unwrap_or_else(Value::null);
                props.insert(entry.key.clone(), val);
            }
            obj.insert("properties".to_string(), Value::object(props));
            Value::object(obj)
        }
        Some(proto::value::Kind::EdgeVal(edge)) => {
            let mut obj = HashMap::new();
            obj.insert("id".to_string(), Value::int(edge.id as i64));
            obj.insert("start_node".to_string(), Value::int(edge.from_id as i64));
            obj.insert("end_node".to_string(), Value::int(edge.to_id as i64));
            obj.insert("type".to_string(), Value::string(edge.label.clone()));
            let mut props = HashMap::new();
            for entry in &edge.properties {
                let val = entry
                    .value
                    .as_ref()
                    .map(|v| proto_to_value_with_depth(v, next_depth))
                    .unwrap_or_else(Value::null);
                props.insert(entry.key.clone(), val);
            }
            obj.insert("properties".to_string(), Value::object(props));
            Value::object(obj)
        }
        Some(proto::value::Kind::DecimalVal(d)) => {
            // Try to parse the decimal from coeff + scale
            if let Ok(dec) = d.coeff.parse::<rust_decimal::Decimal>() {
                Value::decimal(dec)
            } else {
                Value::string(d.orig_repr.clone())
            }
        }
        Some(proto::value::Kind::BytesVal(b)) => {
            Value::string(format!("\\x{}", hex::encode(&b.value)))
        }
        _ => Value::null(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proto_to_value_string() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::StringVal(proto::StringValue {
                value: "hello".to_string(),
                kind: 0,
            })),
        };
        let val = proto_to_value(&proto_val);
        assert_eq!(val.as_string().unwrap(), "hello");
    }

    #[test]
    fn test_proto_to_value_int() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::IntVal(proto::IntValue {
                value: 42,
                kind: 0,
            })),
        };
        let val = proto_to_value(&proto_val);
        assert_eq!(val.as_int().unwrap(), 42);
    }

    #[test]
    fn test_proto_to_value_bool() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::BoolVal(true)),
        };
        let val = proto_to_value(&proto_val);
        assert!(val.as_bool().unwrap());
    }

    #[test]
    fn test_proto_to_value_null() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::NullVal(proto::NullValue {})),
        };
        let val = proto_to_value(&proto_val);
        assert!(val.is_null());
    }

    #[test]
    fn test_proto_to_value_none() {
        let proto_val = proto::Value { kind: None };
        let val = proto_to_value(&proto_val);
        assert!(val.is_null());
    }

    #[test]
    fn test_proto_to_value_double() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::DoubleVal(proto::DoubleValue {
                value: 3.15,
                kind: 0,
            })),
        };
        let val = proto_to_value(&proto_val);
        assert!(val.as_decimal().is_ok());
    }

    #[test]
    fn test_proto_to_value_list() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::ListVal(proto::ListValue {
                values: vec![
                    proto::Value {
                        kind: Some(proto::value::Kind::IntVal(proto::IntValue {
                            value: 1,
                            kind: 0,
                        })),
                    },
                    proto::Value {
                        kind: Some(proto::value::Kind::IntVal(proto::IntValue {
                            value: 2,
                            kind: 0,
                        })),
                    },
                ],
            })),
        };
        let val = proto_to_value(&proto_val);
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_int().unwrap(), 1);
        assert_eq!(arr[1].as_int().unwrap(), 2);
    }

    #[test]
    fn test_proto_to_value_map() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::MapVal(proto::MapValue {
                entries: vec![proto::MapEntry {
                    key: "name".to_string(),
                    value: Some(proto::Value {
                        kind: Some(proto::value::Kind::StringVal(proto::StringValue {
                            value: "Alice".to_string(),
                            kind: 0,
                        })),
                    }),
                }],
            })),
        };
        let val = proto_to_value(&proto_val);
        let obj = val.as_object().unwrap();
        assert_eq!(obj.get("name").unwrap().as_string().unwrap(), "Alice");
    }

    #[test]
    fn test_proto_to_value_node() {
        let node = proto::NodeValue {
            id: 42,
            labels: vec!["Person".to_string()],
            properties: vec![proto::MapEntry {
                key: "name".to_string(),
                value: Some(proto::Value {
                    kind: Some(proto::value::Kind::StringVal(proto::StringValue {
                        value: "Alice".to_string(),
                        kind: 1,
                    })),
                }),
            }],
        };
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::NodeVal(node)),
        };
        let val = proto_to_value(&proto_val);
        let obj = val.as_object().unwrap();
        assert_eq!(obj.get("id").unwrap().as_int().unwrap(), 42);
        let labels = obj.get("labels").unwrap().as_array().unwrap();
        assert_eq!(labels.len(), 1);
        let props = obj.get("properties").unwrap().as_object().unwrap();
        assert_eq!(props.get("name").unwrap().as_string().unwrap(), "Alice");
    }

    #[test]
    fn test_proto_to_value_edge() {
        let edge = proto::EdgeValue {
            id: 100,
            from_id: 1,
            to_id: 2,
            label: "KNOWS".to_string(),
            properties: vec![],
        };
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::EdgeVal(edge)),
        };
        let val = proto_to_value(&proto_val);
        let obj = val.as_object().unwrap();
        assert_eq!(obj.get("type").unwrap().as_string().unwrap(), "KNOWS");
        assert_eq!(obj.get("start_node").unwrap().as_int().unwrap(), 1);
        assert_eq!(obj.get("end_node").unwrap().as_int().unwrap(), 2);
    }

    #[test]
    fn test_proto_to_value_decimal() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::DecimalVal(proto::DecimalValue {
                coeff: "123.45".to_string(),
                scale: 2,
                orig_scale: 2,
                orig_repr: "123.45".to_string(),
            })),
        };
        let val = proto_to_value(&proto_val);
        assert!(val.as_decimal().is_ok());
    }

    #[test]
    fn test_proto_to_value_bytes() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::BytesVal(proto::BytesValue {
                value: vec![0xDE, 0xAD],
                kind: 0,
            })),
        };
        let val = proto_to_value(&proto_val);
        assert_eq!(val.as_string().unwrap(), "\\xdead");
    }

    #[test]
    fn test_proto_to_value_depth_limit() {
        // Build a deeply nested list that exceeds MAX_PROTO_RECURSION_DEPTH
        let mut current = proto::Value {
            kind: Some(proto::value::Kind::IntVal(proto::IntValue {
                value: 42,
                kind: 0,
            })),
        };
        for _ in 0..=MAX_PROTO_RECURSION_DEPTH + 1 {
            current = proto::Value {
                kind: Some(proto::value::Kind::ListVal(proto::ListValue {
                    values: vec![current],
                })),
            };
        }
        let val = proto_to_value(&current);
        // The deeply nested value should eventually hit the depth limit and return null
        let mut v = &val;
        let mut found_null = false;
        for _ in 0..MAX_PROTO_RECURSION_DEPTH + 5 {
            if v.is_null() {
                found_null = true;
                break;
            }
            if let Ok(arr) = v.as_array() {
                if arr.is_empty() {
                    break;
                }
                v = &arr[0];
            } else {
                break;
            }
        }
        assert!(
            found_null,
            "depth limit should produce null for overly deep nesting"
        );
    }
}
