//! Type system for Geode values.

use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;

use crate::error::{Error, Result};

/// Default maximum JSON nesting depth when decoding values
pub const DEFAULT_MAX_JSON_DEPTH: usize = 64;

/// Kind of value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    Null,
    Int,
    Bool,
    String,
    Decimal,
    Array,
    Object,
    Bytea,
    Date,
    Time,
    TimeTz,
    Timestamp,
    TimestampTz,
    Interval,
    Json,
    Jsonb,
    Xml,
    Url,
    Domain,
    Uuid,
    Enum,
    BitString,
    Range,
}

/// Range type value
#[derive(Debug, Clone)]
pub struct Range {
    pub lower: Option<Box<Value>>,
    pub upper: Option<Box<Value>>,
    pub bounds: String,
}

/// Native representation of Geode values
#[derive(Debug, Clone)]
pub struct Value {
    pub kind: ValueKind,
    int_value: i64,
    bool_value: bool,
    string_value: String,
    decimal_value: Option<Decimal>,
    #[allow(dead_code)] // Reserved for future decimal scale support
    decimal_scale: String,
    array_value: Vec<Value>,
    object_value: HashMap<String, Value>,
    bytes_value: Vec<u8>,
    date_value: Option<NaiveDate>,
    #[allow(dead_code)] // Reserved for future time type support
    time_value: Option<NaiveTime>,
    timestamp_value: Option<DateTime<Utc>>,
    range_value: Option<Range>,
}

impl Value {
    /// Create a NULL value
    #[inline]
    pub fn null() -> Self {
        Self {
            kind: ValueKind::Null,
            int_value: 0,
            bool_value: false,
            string_value: String::new(),
            decimal_value: None,
            decimal_scale: String::new(),
            array_value: Vec::new(),
            object_value: HashMap::new(),
            bytes_value: Vec::new(),
            date_value: None,
            time_value: None,
            timestamp_value: None,
            range_value: None,
        }
    }

    /// Create an INT value
    #[inline]
    pub fn int(value: i64) -> Self {
        Self {
            kind: ValueKind::Int,
            int_value: value,
            ..Self::null()
        }
    }

    /// Create a BOOL value
    #[inline]
    pub fn bool(value: bool) -> Self {
        Self {
            kind: ValueKind::Bool,
            bool_value: value,
            ..Self::null()
        }
    }

    /// Create a STRING value
    #[inline]
    pub fn string<S: Into<String>>(value: S) -> Self {
        Self {
            kind: ValueKind::String,
            string_value: value.into(),
            ..Self::null()
        }
    }

    /// Create a DECIMAL value
    #[inline]
    pub fn decimal(value: Decimal) -> Self {
        Self {
            kind: ValueKind::Decimal,
            decimal_value: Some(value),
            ..Self::null()
        }
    }

    /// Create an ARRAY value
    #[inline]
    pub fn array(values: Vec<Value>) -> Self {
        Self {
            kind: ValueKind::Array,
            array_value: values,
            ..Self::null()
        }
    }

    /// Create an OBJECT value
    #[inline]
    pub fn object(values: HashMap<String, Value>) -> Self {
        Self {
            kind: ValueKind::Object,
            object_value: values,
            ..Self::null()
        }
    }

    /// Check if value is NULL
    #[inline]
    pub fn is_null(&self) -> bool {
        self.kind == ValueKind::Null
    }

    /// Get as integer
    #[inline]
    pub fn as_int(&self) -> Result<i64> {
        if self.kind == ValueKind::Int {
            Ok(self.int_value)
        } else {
            Err(Error::type_error(format!(
                "Cannot convert {:?} to int",
                self.kind
            )))
        }
    }

    /// Get as boolean
    #[inline]
    pub fn as_bool(&self) -> Result<bool> {
        if self.kind == ValueKind::Bool {
            Ok(self.bool_value)
        } else {
            Err(Error::type_error(format!(
                "Cannot convert {:?} to bool",
                self.kind
            )))
        }
    }

    /// Get as string
    #[inline]
    pub fn as_string(&self) -> Result<&str> {
        match self.kind {
            ValueKind::String
            | ValueKind::Xml
            | ValueKind::Json
            | ValueKind::Jsonb
            | ValueKind::Url
            | ValueKind::Domain
            | ValueKind::Uuid
            | ValueKind::Enum
            | ValueKind::BitString => Ok(&self.string_value),
            _ => Err(Error::type_error(format!(
                "Cannot convert {:?} to string",
                self.kind
            ))),
        }
    }

    /// Get as decimal
    #[inline]
    pub fn as_decimal(&self) -> Result<Decimal> {
        if self.kind == ValueKind::Decimal {
            self.decimal_value
                .ok_or_else(|| Error::type_error("Decimal value is None"))
        } else {
            Err(Error::type_error(format!(
                "Cannot convert {:?} to decimal",
                self.kind
            )))
        }
    }

    /// Get as array
    #[inline]
    pub fn as_array(&self) -> Result<&[Value]> {
        if self.kind == ValueKind::Array {
            Ok(&self.array_value)
        } else {
            Err(Error::type_error(format!(
                "Cannot convert {:?} to array",
                self.kind
            )))
        }
    }

    /// Get as object
    #[inline]
    pub fn as_object(&self) -> Result<&HashMap<String, Value>> {
        if self.kind == ValueKind::Object {
            Ok(&self.object_value)
        } else {
            Err(Error::type_error(format!(
                "Cannot convert {:?} to object",
                self.kind
            )))
        }
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> Result<&[u8]> {
        if self.kind == ValueKind::Bytea {
            Ok(&self.bytes_value)
        } else {
            Err(Error::type_error(format!(
                "Cannot convert {:?} to bytes",
                self.kind
            )))
        }
    }

    /// Get as date
    pub fn as_date(&self) -> Result<NaiveDate> {
        if self.kind == ValueKind::Date {
            self.date_value
                .ok_or_else(|| Error::type_error("Date value is None"))
        } else {
            Err(Error::type_error(format!(
                "Cannot convert {:?} to date",
                self.kind
            )))
        }
    }

    /// Get as timestamp
    pub fn as_timestamp(&self) -> Result<DateTime<Utc>> {
        if self.kind == ValueKind::Timestamp || self.kind == ValueKind::TimestampTz {
            self.timestamp_value
                .ok_or_else(|| Error::type_error("Timestamp value is None"))
        } else {
            Err(Error::type_error(format!(
                "Cannot convert {:?} to timestamp",
                self.kind
            )))
        }
    }

    /// Get as range
    pub fn as_range(&self) -> Result<&Range> {
        if self.kind == ValueKind::Range {
            self.range_value
                .as_ref()
                .ok_or_else(|| Error::type_error("Range value is None"))
        } else {
            Err(Error::type_error(format!(
                "Cannot convert {:?} to range",
                self.kind
            )))
        }
    }

    /// Convert to serde_json::Value for serialization
    pub fn to_json(&self) -> serde_json::Value {
        match self.kind {
            ValueKind::Null => serde_json::Value::Null,
            ValueKind::Int => serde_json::Value::Number(self.int_value.into()),
            ValueKind::Bool => serde_json::Value::Bool(self.bool_value),
            ValueKind::String
            | ValueKind::Xml
            | ValueKind::Json
            | ValueKind::Jsonb
            | ValueKind::Url
            | ValueKind::Domain
            | ValueKind::Uuid
            | ValueKind::Enum
            | ValueKind::BitString => serde_json::Value::String(self.string_value.clone()),
            ValueKind::Decimal => serde_json::Value::String(
                self.decimal_value
                    .map(|d| d.to_string())
                    .unwrap_or_default(),
            ),
            ValueKind::Array => {
                serde_json::Value::Array(self.array_value.iter().map(|v| v.to_json()).collect())
            }
            ValueKind::Object => {
                let mut map = serde_json::Map::new();
                for (k, v) in &self.object_value {
                    map.insert(k.clone(), v.to_json());
                }
                serde_json::Value::Object(map)
            }
            ValueKind::Bytea => {
                if self.bytes_value.is_empty() {
                    serde_json::Value::String(self.string_value.clone())
                } else {
                    serde_json::Value::String(format!("\\x{}", hex::encode(&self.bytes_value)))
                }
            }
            ValueKind::Date
            | ValueKind::Time
            | ValueKind::TimeTz
            | ValueKind::Timestamp
            | ValueKind::TimestampTz
            | ValueKind::Interval => serde_json::Value::String(self.string_value.clone()),
            ValueKind::Range => {
                if let Some(range) = &self.range_value {
                    let mut map = serde_json::Map::new();
                    if let Some(lower) = &range.lower {
                        map.insert("lower".to_string(), lower.to_json());
                    }
                    if let Some(upper) = &range.upper {
                        map.insert("upper".to_string(), upper.to_json());
                    }
                    map.insert(
                        "bounds".to_string(),
                        serde_json::Value::String(range.bounds.clone()),
                    );
                    serde_json::Value::Object(map)
                } else {
                    serde_json::Value::Null
                }
            }
        }
    }

    /// Convert to a proto::Value for protobuf parameter encoding
    pub fn to_proto_value(&self) -> crate::proto::Value {
        use crate::proto::{self, value};
        match self.kind {
            ValueKind::Null => proto::Value {
                kind: Some(value::Kind::NullVal(proto::NullValue {})),
            },
            ValueKind::Int => proto::Value {
                kind: Some(value::Kind::IntVal(proto::IntValue {
                    value: self.int_value,
                    kind: 0,
                })),
            },
            ValueKind::Bool => proto::Value {
                kind: Some(value::Kind::BoolVal(self.bool_value)),
            },
            ValueKind::Decimal => {
                let double_val = self
                    .decimal_value
                    .and_then(|d| {
                        use std::str::FromStr;
                        f64::from_str(&d.to_string()).ok()
                    })
                    .unwrap_or(0.0);
                proto::Value {
                    kind: Some(value::Kind::DoubleVal(proto::DoubleValue {
                        value: double_val,
                        kind: 0,
                    })),
                }
            }
            _ => proto::Value {
                kind: Some(value::Kind::StringVal(proto::StringValue {
                    value: self.to_proto_string(),
                    kind: 0,
                })),
            },
        }
    }

    /// Convert to a string representation for protobuf parameters
    pub fn to_proto_string(&self) -> String {
        match self.kind {
            ValueKind::Null => String::new(),
            ValueKind::Int => self.int_value.to_string(),
            ValueKind::Bool => self.bool_value.to_string(),
            ValueKind::String
            | ValueKind::Xml
            | ValueKind::Json
            | ValueKind::Jsonb
            | ValueKind::Url
            | ValueKind::Domain
            | ValueKind::Uuid
            | ValueKind::Enum
            | ValueKind::BitString => self.string_value.clone(),
            ValueKind::Decimal => self
                .decimal_value
                .map(|d| d.to_string())
                .unwrap_or_default(),
            ValueKind::Array => serde_json::to_string(&self.to_json()).unwrap_or_default(),
            ValueKind::Object => serde_json::to_string(&self.to_json()).unwrap_or_default(),
            ValueKind::Bytea => {
                if self.bytes_value.is_empty() {
                    self.string_value.clone()
                } else {
                    format!("\\x{}", hex::encode(&self.bytes_value))
                }
            }
            ValueKind::Date
            | ValueKind::Time
            | ValueKind::TimeTz
            | ValueKind::Timestamp
            | ValueKind::TimestampTz
            | ValueKind::Interval => self.string_value.clone(),
            ValueKind::Range => serde_json::to_string(&self.to_json()).unwrap_or_default(),
        }
    }

    /// Create a Value from a serde_json::Value using the default depth limit.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON nesting depth exceeds [`DEFAULT_MAX_JSON_DEPTH`].
    pub fn from_json(json: serde_json::Value) -> Result<Self> {
        Self::from_json_with_max_depth(json, DEFAULT_MAX_JSON_DEPTH)
    }

    /// Create a Value from a serde_json::Value with an explicit depth limit.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON nesting depth exceeds `max_depth`.
    pub fn from_json_with_max_depth(json: serde_json::Value, max_depth: usize) -> Result<Self> {
        Self::from_json_with_depth(json, 0, max_depth)
    }

    fn from_json_with_depth(
        json: serde_json::Value,
        depth: usize,
        max_depth: usize,
    ) -> Result<Self> {
        if depth >= max_depth {
            return Err(Error::limit(format!(
                "JSON nesting depth {} exceeds max {}",
                depth, max_depth
            )));
        }

        match json {
            serde_json::Value::Null => Ok(Self::null()),
            serde_json::Value::Bool(b) => Ok(Self::bool(b)),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(Self::int(i))
                } else if let Some(f) = n.as_f64() {
                    // Try to convert to decimal
                    Ok(Self::string(f.to_string()))
                } else {
                    Ok(Self::null())
                }
            }
            serde_json::Value::String(s) => Ok(Self::string(s)),
            serde_json::Value::Array(arr) => {
                let values: Result<Vec<Value>> = arr
                    .into_iter()
                    .map(|v| Self::from_json_with_depth(v, depth + 1, max_depth))
                    .collect();
                Ok(Self::array(values?))
            }
            serde_json::Value::Object(obj) => {
                let mut map = HashMap::new();
                for (k, v) in obj {
                    map.insert(k, Self::from_json_with_depth(v, depth + 1, max_depth)?);
                }
                Ok(Self::object(map))
            }
        }
    }
}

/// Decode a JSON value into a typed Value object using the default depth limit.
///
/// Returns an error if the JSON nesting depth exceeds [`DEFAULT_MAX_JSON_DEPTH`].
pub fn decode_value(raw: &serde_json::Value, type_name: &str) -> Result<Value> {
    decode_value_with_max_depth(raw, type_name, DEFAULT_MAX_JSON_DEPTH)
}

/// Decode a JSON value into a typed Value object with a specific depth limit.
pub fn decode_value_with_max_depth(
    raw: &serde_json::Value,
    type_name: &str,
    max_depth: usize,
) -> Result<Value> {
    decode_value_with_depth(raw, type_name, 0, max_depth)
}

fn decode_value_with_depth(
    raw: &serde_json::Value,
    type_name: &str,
    depth: usize,
    max_depth: usize,
) -> Result<Value> {
    if depth >= max_depth {
        return Err(Error::limit(format!(
            "JSON nesting depth {} exceeds max {}",
            depth, max_depth
        )));
    }

    if raw.is_null() {
        return Ok(Value::null());
    }

    if type_name.eq_ignore_ascii_case("INT") {
        if let Some(n) = raw.as_i64() {
            Ok(Value::int(n))
        } else if let Some(s) = raw.as_str() {
            if let Ok(n) = s.parse::<i64>() {
                Ok(Value::int(n))
            } else {
                Ok(Value::string(s))
            }
        } else {
            Ok(Value::string(raw.to_string()))
        }
    } else if type_name.eq_ignore_ascii_case("DECIMAL") {
        let s = raw
            .as_str()
            .map(|v| v.to_string())
            .unwrap_or_else(|| raw.to_string());
        if let Ok(dec) = s.parse::<Decimal>() {
            Ok(Value::decimal(dec))
        } else {
            Ok(Value::string(s))
        }
    } else if type_name.eq_ignore_ascii_case("BOOL") {
        if let Some(b) = raw.as_bool() {
            Ok(Value::bool(b))
        } else if let Some(s) = raw.as_str() {
            let lower = s.to_ascii_lowercase();
            if lower == "true" {
                Ok(Value::bool(true))
            } else if lower == "false" {
                Ok(Value::bool(false))
            } else {
                Ok(Value::string(s))
            }
        } else {
            Ok(Value::string(raw.to_string()))
        }
    } else if type_name.eq_ignore_ascii_case("STRING") {
        Ok(Value::string(raw.as_str().unwrap_or("")))
    } else if type_name.eq_ignore_ascii_case("BYTEA") {
        let s = raw.as_str().unwrap_or("");
        let bytes = if let Some(hex_str) = s.strip_prefix("\\x") {
            hex::decode(hex_str).unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(Value {
            kind: ValueKind::Bytea,
            bytes_value: bytes,
            string_value: s.to_string(),
            ..Value::null()
        })
    } else if type_name.eq_ignore_ascii_case("JSON") {
        Ok(Value {
            kind: ValueKind::Json,
            string_value: raw.to_string(),
            ..Value::null()
        })
    } else if type_name.eq_ignore_ascii_case("JSONB") {
        Ok(Value {
            kind: ValueKind::Jsonb,
            string_value: raw.to_string(),
            ..Value::null()
        })
    } else if type_name.eq_ignore_ascii_case("DATE") {
        let s = raw.as_str().unwrap_or("");
        let date = NaiveDate::parse_from_str(s, "%Y-%m-%d").ok();
        Ok(Value {
            kind: ValueKind::Date,
            string_value: s.to_string(),
            date_value: date,
            ..Value::null()
        })
    } else if type_name.eq_ignore_ascii_case("TIMESTAMP")
        || type_name.eq_ignore_ascii_case("TIMESTAMPTZ")
    {
        let s = raw.as_str().unwrap_or("");
        let timestamp = DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&Utc));
        let kind = if type_name.eq_ignore_ascii_case("TIMESTAMPTZ") {
            ValueKind::TimestampTz
        } else {
            ValueKind::Timestamp
        };
        Ok(Value {
            kind,
            string_value: s.to_string(),
            timestamp_value: timestamp,
            ..Value::null()
        })
    } else if type_name.to_ascii_uppercase().contains("RANGE") {
        if let Some(obj) = raw.as_object() {
            let range = Range {
                lower: obj.get("lower").and_then(|v| {
                    decode_value_with_depth(v, "", depth + 1, max_depth)
                        .ok()
                        .map(Box::new)
                }),
                upper: obj.get("upper").and_then(|v| {
                    decode_value_with_depth(v, "", depth + 1, max_depth)
                        .ok()
                        .map(Box::new)
                }),
                bounds: obj
                    .get("bounds")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            };
            Ok(Value {
                kind: ValueKind::Range,
                range_value: Some(range),
                ..Value::null()
            })
        } else {
            Ok(Value::string(raw.to_string()))
        }
    } else {
        // Handle arrays and objects generically
        if let Some(arr) = raw.as_array() {
            let values: Result<Vec<_>> = arr
                .iter()
                .map(|v| decode_value_with_depth(v, "", depth + 1, max_depth))
                .collect();
            Ok(Value::array(values?))
        } else if let Some(obj) = raw.as_object() {
            let mut map = HashMap::new();
            for (k, v) in obj {
                map.insert(
                    k.clone(),
                    decode_value_with_depth(v, "", depth + 1, max_depth)?,
                );
            }
            Ok(Value::object(map))
        } else if let Some(b) = raw.as_bool() {
            Ok(Value::bool(b))
        } else if let Some(n) = raw.as_i64() {
            Ok(Value::int(n))
        } else if let Some(f) = raw.as_f64() {
            let s = f.to_string();
            if let Ok(dec) = s.parse::<Decimal>() {
                Ok(Value::decimal(dec))
            } else {
                Ok(Value::string(s))
            }
        } else if let Some(s) = raw.as_str() {
            Ok(Value::string(s))
        } else {
            Ok(Value::string(raw.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};
    use rust_decimal_macros::dec;
    use serde_json::json;

    // ==================== ValueKind Tests ====================

    #[test]
    fn test_value_kind_equality() {
        assert_eq!(ValueKind::Null, ValueKind::Null);
        assert_eq!(ValueKind::Int, ValueKind::Int);
        assert_ne!(ValueKind::Int, ValueKind::String);
    }

    #[test]
    fn test_value_kind_copy() {
        let kind = ValueKind::Int;
        let kind_copy = kind;
        assert_eq!(kind, kind_copy);
    }

    #[test]
    fn test_value_kind_debug() {
        let debug_str = format!("{:?}", ValueKind::Timestamp);
        assert_eq!(debug_str, "Timestamp");
    }

    #[test]
    fn test_value_kind_all_variants() {
        // Ensure all variants exist and are distinct
        let variants = [
            ValueKind::Null,
            ValueKind::Int,
            ValueKind::Bool,
            ValueKind::String,
            ValueKind::Decimal,
            ValueKind::Array,
            ValueKind::Object,
            ValueKind::Bytea,
            ValueKind::Date,
            ValueKind::Time,
            ValueKind::TimeTz,
            ValueKind::Timestamp,
            ValueKind::TimestampTz,
            ValueKind::Interval,
            ValueKind::Json,
            ValueKind::Jsonb,
            ValueKind::Xml,
            ValueKind::Url,
            ValueKind::Domain,
            ValueKind::Uuid,
            ValueKind::Enum,
            ValueKind::BitString,
            ValueKind::Range,
        ];
        assert_eq!(variants.len(), 23);
        // Check uniqueness
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(variants[i], variants[j]);
            }
        }
    }

    // ==================== Value Construction Tests ====================

    #[test]
    fn test_value_null() {
        let v = Value::null();
        assert_eq!(v.kind, ValueKind::Null);
        assert!(v.is_null());
    }

    #[test]
    fn test_value_int() {
        let v = Value::int(42);
        assert_eq!(v.kind, ValueKind::Int);
        assert!(!v.is_null());
        assert_eq!(v.as_int().unwrap(), 42);
    }

    #[test]
    fn test_value_int_negative() {
        let v = Value::int(-100);
        assert_eq!(v.as_int().unwrap(), -100);
    }

    #[test]
    fn test_value_int_zero() {
        let v = Value::int(0);
        assert_eq!(v.as_int().unwrap(), 0);
    }

    #[test]
    fn test_value_int_max() {
        let v = Value::int(i64::MAX);
        assert_eq!(v.as_int().unwrap(), i64::MAX);
    }

    #[test]
    fn test_value_int_min() {
        let v = Value::int(i64::MIN);
        assert_eq!(v.as_int().unwrap(), i64::MIN);
    }

    #[test]
    fn test_value_bool_true() {
        let v = Value::bool(true);
        assert_eq!(v.kind, ValueKind::Bool);
        assert!(v.as_bool().unwrap());
    }

    #[test]
    fn test_value_bool_false() {
        let v = Value::bool(false);
        assert!(!v.as_bool().unwrap());
    }

    #[test]
    fn test_value_string() {
        let v = Value::string("hello");
        assert_eq!(v.kind, ValueKind::String);
        assert_eq!(v.as_string().unwrap(), "hello");
    }

    #[test]
    fn test_value_string_empty() {
        let v = Value::string("");
        assert_eq!(v.as_string().unwrap(), "");
    }

    #[test]
    fn test_value_string_unicode() {
        let v = Value::string("こんにちは世界🌍");
        assert_eq!(v.as_string().unwrap(), "こんにちは世界🌍");
    }

    #[test]
    fn test_value_string_owned() {
        let owned = String::from("owned string");
        let v = Value::string(owned);
        assert_eq!(v.as_string().unwrap(), "owned string");
    }

    #[test]
    fn test_value_decimal() {
        let v = Value::decimal(dec!(123.456));
        assert_eq!(v.kind, ValueKind::Decimal);
        assert_eq!(v.as_decimal().unwrap(), dec!(123.456));
    }

    #[test]
    fn test_value_decimal_precision() {
        let v = Value::decimal(dec!(0.000000001));
        assert_eq!(v.as_decimal().unwrap(), dec!(0.000000001));
    }

    #[test]
    fn test_value_decimal_large() {
        let v = Value::decimal(dec!(99999999999999.99));
        assert_eq!(v.as_decimal().unwrap(), dec!(99999999999999.99));
    }

    #[test]
    fn test_value_array_empty() {
        let v = Value::array(vec![]);
        assert_eq!(v.kind, ValueKind::Array);
        assert!(v.as_array().unwrap().is_empty());
    }

    #[test]
    fn test_value_array() {
        let v = Value::array(vec![Value::int(1), Value::int(2), Value::int(3)]);
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0].as_int().unwrap(), 1);
        assert_eq!(arr[1].as_int().unwrap(), 2);
        assert_eq!(arr[2].as_int().unwrap(), 3);
    }

    #[test]
    fn test_value_array_mixed() {
        let v = Value::array(vec![
            Value::int(42),
            Value::string("hello"),
            Value::bool(true),
            Value::null(),
        ]);
        let arr = v.as_array().unwrap();
        assert_eq!(arr[0].as_int().unwrap(), 42);
        assert_eq!(arr[1].as_string().unwrap(), "hello");
        assert!(arr[2].as_bool().unwrap());
        assert!(arr[3].is_null());
    }

    #[test]
    fn test_value_array_nested() {
        let inner = Value::array(vec![Value::int(1), Value::int(2)]);
        let outer = Value::array(vec![inner]);
        let arr = outer.as_array().unwrap();
        let inner_arr = arr[0].as_array().unwrap();
        assert_eq!(inner_arr.len(), 2);
    }

    #[test]
    fn test_value_object_empty() {
        let v = Value::object(HashMap::new());
        assert_eq!(v.kind, ValueKind::Object);
        assert!(v.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_value_object() {
        let mut map = HashMap::new();
        map.insert("name".to_string(), Value::string("Alice"));
        map.insert("age".to_string(), Value::int(30));
        let v = Value::object(map);

        let obj = v.as_object().unwrap();
        assert_eq!(obj.get("name").unwrap().as_string().unwrap(), "Alice");
        assert_eq!(obj.get("age").unwrap().as_int().unwrap(), 30);
    }

    #[test]
    fn test_value_object_nested() {
        let mut inner = HashMap::new();
        inner.insert("city".to_string(), Value::string("NYC"));

        let mut outer = HashMap::new();
        outer.insert("address".to_string(), Value::object(inner));

        let v = Value::object(outer);
        let obj = v.as_object().unwrap();
        let addr = obj.get("address").unwrap().as_object().unwrap();
        assert_eq!(addr.get("city").unwrap().as_string().unwrap(), "NYC");
    }

    // ==================== Type Accessor Error Tests ====================

    #[test]
    fn test_as_int_wrong_type() {
        let v = Value::string("not an int");
        let result = v.as_int();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("String"));
    }

    #[test]
    fn test_as_bool_wrong_type() {
        let v = Value::int(42);
        let result = v.as_bool();
        assert!(result.is_err());
    }

    #[test]
    fn test_as_string_wrong_type() {
        let v = Value::int(42);
        let result = v.as_string();
        assert!(result.is_err());
    }

    #[test]
    fn test_as_decimal_wrong_type() {
        let v = Value::int(42);
        let result = v.as_decimal();
        assert!(result.is_err());
    }

    #[test]
    fn test_as_array_wrong_type() {
        let v = Value::int(42);
        let result = v.as_array();
        assert!(result.is_err());
    }

    #[test]
    fn test_as_object_wrong_type() {
        let v = Value::int(42);
        let result = v.as_object();
        assert!(result.is_err());
    }

    #[test]
    fn test_as_bytes_wrong_type() {
        let v = Value::int(42);
        let result = v.as_bytes();
        assert!(result.is_err());
    }

    #[test]
    fn test_as_date_wrong_type() {
        let v = Value::int(42);
        let result = v.as_date();
        assert!(result.is_err());
    }

    #[test]
    fn test_as_timestamp_wrong_type() {
        let v = Value::int(42);
        let result = v.as_timestamp();
        assert!(result.is_err());
    }

    #[test]
    fn test_as_range_wrong_type() {
        let v = Value::int(42);
        let result = v.as_range();
        assert!(result.is_err());
    }

    // ==================== String-like Type Accessors ====================

    #[test]
    fn test_as_string_from_xml() {
        let v = Value {
            kind: ValueKind::Xml,
            string_value: "<root/>".to_string(),
            ..Value::null()
        };
        assert_eq!(v.as_string().unwrap(), "<root/>");
    }

    #[test]
    fn test_as_string_from_json() {
        let v = Value {
            kind: ValueKind::Json,
            string_value: r#"{"key":"value"}"#.to_string(),
            ..Value::null()
        };
        assert_eq!(v.as_string().unwrap(), r#"{"key":"value"}"#);
    }

    #[test]
    fn test_as_string_from_url() {
        let v = Value {
            kind: ValueKind::Url,
            string_value: "https://example.com".to_string(),
            ..Value::null()
        };
        assert_eq!(v.as_string().unwrap(), "https://example.com");
    }

    #[test]
    fn test_as_string_from_uuid() {
        let v = Value {
            kind: ValueKind::Uuid,
            string_value: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ..Value::null()
        };
        assert_eq!(
            v.as_string().unwrap(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    // ==================== to_json Tests ====================

    #[test]
    fn test_to_json_null() {
        let v = Value::null();
        assert_eq!(v.to_json(), json!(null));
    }

    #[test]
    fn test_to_json_int() {
        let v = Value::int(42);
        assert_eq!(v.to_json(), json!(42));
    }

    #[test]
    fn test_to_json_bool() {
        let v = Value::bool(true);
        assert_eq!(v.to_json(), json!(true));
    }

    #[test]
    fn test_to_json_string() {
        let v = Value::string("hello");
        assert_eq!(v.to_json(), json!("hello"));
    }

    #[test]
    fn test_to_json_decimal() {
        let v = Value::decimal(dec!(123.45));
        assert_eq!(v.to_json(), json!("123.45"));
    }

    #[test]
    fn test_to_json_array() {
        let v = Value::array(vec![Value::int(1), Value::int(2)]);
        assert_eq!(v.to_json(), json!([1, 2]));
    }

    #[test]
    fn test_to_json_object() {
        let mut map = HashMap::new();
        map.insert("key".to_string(), Value::string("value"));
        let v = Value::object(map);
        assert_eq!(v.to_json(), json!({"key": "value"}));
    }

    #[test]
    fn test_to_json_bytea_empty() {
        let v = Value {
            kind: ValueKind::Bytea,
            bytes_value: vec![],
            string_value: "".to_string(),
            ..Value::null()
        };
        assert_eq!(v.to_json(), json!(""));
    }

    #[test]
    fn test_to_json_bytea_with_data() {
        let v = Value {
            kind: ValueKind::Bytea,
            bytes_value: vec![0xDE, 0xAD, 0xBE, 0xEF],
            ..Value::null()
        };
        assert_eq!(v.to_json(), json!("\\xdeadbeef"));
    }

    #[test]
    fn test_to_json_range() {
        let range = Range {
            lower: Some(Box::new(Value::int(1))),
            upper: Some(Box::new(Value::int(10))),
            bounds: "[)".to_string(),
        };
        let v = Value {
            kind: ValueKind::Range,
            range_value: Some(range),
            ..Value::null()
        };
        let j = v.to_json();
        assert_eq!(j["lower"], json!(1));
        assert_eq!(j["upper"], json!(10));
        assert_eq!(j["bounds"], json!("[)"));
    }

    #[test]
    fn test_to_json_range_none() {
        let v = Value {
            kind: ValueKind::Range,
            range_value: None,
            ..Value::null()
        };
        assert_eq!(v.to_json(), json!(null));
    }

    // ==================== from_json Tests ====================

    #[test]
    fn test_from_json_null() {
        let v = Value::from_json(json!(null)).unwrap();
        assert!(v.is_null());
    }

    #[test]
    fn test_from_json_bool() {
        let v = Value::from_json(json!(true)).unwrap();
        assert!(v.as_bool().unwrap());
    }

    #[test]
    fn test_from_json_int() {
        let v = Value::from_json(json!(42)).unwrap();
        assert_eq!(v.as_int().unwrap(), 42);
    }

    #[test]
    fn test_from_json_float() {
        let v = Value::from_json(json!(1.5)).unwrap();
        // Floats are converted to strings
        assert_eq!(v.kind, ValueKind::String);
    }

    #[test]
    fn test_from_json_string() {
        let v = Value::from_json(json!("hello")).unwrap();
        assert_eq!(v.as_string().unwrap(), "hello");
    }

    #[test]
    fn test_from_json_array() {
        let v = Value::from_json(json!([1, 2, 3])).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn test_from_json_object() {
        let v = Value::from_json(json!({"name": "Alice"})).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.get("name").unwrap().as_string().unwrap(), "Alice");
    }

    #[test]
    fn test_from_json_nested() {
        let v = Value::from_json(json!({
            "users": [
                {"name": "Alice", "age": 30},
                {"name": "Bob", "age": 25}
            ]
        }))
        .unwrap();
        let obj = v.as_object().unwrap();
        let users = obj.get("users").unwrap().as_array().unwrap();
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn test_from_json_depth_limit() {
        // Build deeply nested JSON: {"a":{"a":{"a":...}}}
        let mut json = serde_json::Value::Null;
        for _ in 0..70 {
            let mut obj = serde_json::Map::new();
            obj.insert("a".to_string(), json);
            json = serde_json::Value::Object(obj);
        }
        // Default depth limit is 64, so 70 levels should fail
        let result = Value::from_json(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("depth"));
    }

    #[test]
    fn test_from_json_within_depth_limit() {
        // Build JSON nested to exactly 60 levels (under default 64 limit)
        let mut json = serde_json::Value::Bool(true);
        for _ in 0..60 {
            json = serde_json::Value::Array(vec![json]);
        }
        assert!(Value::from_json(json).is_ok());
    }

    // ==================== decode_value Tests ====================

    #[test]
    fn test_decode_value_null() {
        let v = decode_value(&json!(null), "INT").unwrap();
        assert!(v.is_null());
    }

    #[test]
    fn test_decode_value_int_from_number() {
        let v = decode_value(&json!(42), "INT").unwrap();
        assert_eq!(v.as_int().unwrap(), 42);
    }

    #[test]
    fn test_decode_value_int_from_string() {
        let v = decode_value(&json!("123"), "INT").unwrap();
        assert_eq!(v.as_int().unwrap(), 123);
    }

    #[test]
    fn test_decode_value_int_invalid_string() {
        let v = decode_value(&json!("not_a_number"), "INT").unwrap();
        // Falls back to string
        assert_eq!(v.kind, ValueKind::String);
    }

    #[test]
    fn test_decode_value_decimal() {
        let v = decode_value(&json!("123.456"), "DECIMAL").unwrap();
        assert_eq!(v.as_decimal().unwrap(), dec!(123.456));
    }

    #[test]
    fn test_decode_value_decimal_from_number() {
        let v = decode_value(&json!(123), "DECIMAL").unwrap();
        assert_eq!(v.as_decimal().unwrap(), dec!(123));
    }

    #[test]
    fn test_decode_value_bool_true() {
        let v = decode_value(&json!(true), "BOOL").unwrap();
        assert!(v.as_bool().unwrap());
    }

    #[test]
    fn test_decode_value_bool_false() {
        let v = decode_value(&json!(false), "BOOL").unwrap();
        assert!(!v.as_bool().unwrap());
    }

    #[test]
    fn test_decode_value_bool_from_string_true() {
        let v = decode_value(&json!("true"), "BOOL").unwrap();
        assert!(v.as_bool().unwrap());
    }

    #[test]
    fn test_decode_value_bool_from_string_false() {
        let v = decode_value(&json!("false"), "BOOL").unwrap();
        assert!(!v.as_bool().unwrap());
    }

    #[test]
    fn test_decode_value_bool_from_string_case_insensitive() {
        let v = decode_value(&json!("TRUE"), "BOOL").unwrap();
        assert!(v.as_bool().unwrap());
    }

    #[test]
    fn test_decode_value_string() {
        let v = decode_value(&json!("hello"), "STRING").unwrap();
        assert_eq!(v.as_string().unwrap(), "hello");
    }

    #[test]
    fn test_decode_value_bytea() {
        let v = decode_value(&json!("\\xDEADBEEF"), "BYTEA").unwrap();
        assert_eq!(v.kind, ValueKind::Bytea);
        assert_eq!(v.as_bytes().unwrap(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_decode_value_bytea_no_prefix() {
        let v = decode_value(&json!("plain"), "BYTEA").unwrap();
        assert_eq!(v.kind, ValueKind::Bytea);
        assert!(v.as_bytes().unwrap().is_empty());
    }

    #[test]
    fn test_decode_value_json() {
        let v = decode_value(&json!({"key": "value"}), "JSON").unwrap();
        assert_eq!(v.kind, ValueKind::Json);
    }

    #[test]
    fn test_decode_value_jsonb() {
        let v = decode_value(&json!({"key": "value"}), "JSONB").unwrap();
        assert_eq!(v.kind, ValueKind::Jsonb);
    }

    #[test]
    fn test_decode_value_date() {
        let v = decode_value(&json!("2024-01-15"), "DATE").unwrap();
        assert_eq!(v.kind, ValueKind::Date);
        let date = v.as_date().unwrap();
        assert_eq!(date.to_string(), "2024-01-15");
    }

    #[test]
    fn test_decode_value_date_invalid() {
        let v = decode_value(&json!("not-a-date"), "DATE").unwrap();
        assert_eq!(v.kind, ValueKind::Date);
        // Date parsing fails, but value is stored as string
        assert!(v.date_value.is_none());
    }

    #[test]
    fn test_decode_value_timestamp() {
        let v = decode_value(&json!("2024-01-15T10:30:00Z"), "TIMESTAMP").unwrap();
        assert_eq!(v.kind, ValueKind::Timestamp);
        let ts = v.as_timestamp().unwrap();
        assert_eq!(ts.to_rfc3339(), "2024-01-15T10:30:00+00:00");
    }

    #[test]
    fn test_decode_value_timestamptz() {
        let v = decode_value(&json!("2024-01-15T10:30:00+05:00"), "TIMESTAMPTZ").unwrap();
        assert_eq!(v.kind, ValueKind::TimestampTz);
    }

    #[test]
    fn test_decode_value_range() {
        let v = decode_value(
            &json!({"lower": 1, "upper": 10, "bounds": "[)"}),
            "INT4RANGE",
        )
        .unwrap();
        assert_eq!(v.kind, ValueKind::Range);
        let range = v.as_range().unwrap();
        assert_eq!(range.bounds, "[)");
    }

    #[test]
    fn test_decode_value_array_generic() {
        let v = decode_value(&json!([1, 2, 3]), "").unwrap();
        assert_eq!(v.kind, ValueKind::Array);
        assert_eq!(v.as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_decode_value_object_generic() {
        let v = decode_value(&json!({"key": "value"}), "").unwrap();
        assert_eq!(v.kind, ValueKind::Object);
    }

    #[test]
    fn test_decode_value_generic_bool() {
        let v = decode_value(&json!(true), "UNKNOWN").unwrap();
        assert!(v.as_bool().unwrap());
    }

    #[test]
    fn test_decode_value_generic_int() {
        let v = decode_value(&json!(42), "UNKNOWN").unwrap();
        assert_eq!(v.as_int().unwrap(), 42);
    }

    #[test]
    fn test_decode_value_generic_float() {
        let v = decode_value(&json!(1.23), "UNKNOWN").unwrap();
        // Floats become decimals if parseable
        assert_eq!(v.kind, ValueKind::Decimal);
    }

    #[test]
    fn test_decode_value_generic_string() {
        let v = decode_value(&json!("hello"), "UNKNOWN").unwrap();
        assert_eq!(v.as_string().unwrap(), "hello");
    }

    #[test]
    fn test_decode_value_case_insensitive() {
        let v1 = decode_value(&json!(42), "int").unwrap();
        let v2 = decode_value(&json!(42), "INT").unwrap();
        let v3 = decode_value(&json!(42), "Int").unwrap();
        assert_eq!(v1.as_int().unwrap(), 42);
        assert_eq!(v2.as_int().unwrap(), 42);
        assert_eq!(v3.as_int().unwrap(), 42);
    }

    // ==================== Range Tests ====================

    #[test]
    fn test_range_construction() {
        let range = Range {
            lower: Some(Box::new(Value::int(0))),
            upper: Some(Box::new(Value::int(100))),
            bounds: "[)".to_string(),
        };
        assert_eq!(range.lower.as_ref().unwrap().as_int().unwrap(), 0);
        assert_eq!(range.upper.as_ref().unwrap().as_int().unwrap(), 100);
        assert_eq!(range.bounds, "[)");
    }

    #[test]
    fn test_range_unbounded_lower() {
        let range = Range {
            lower: None,
            upper: Some(Box::new(Value::int(100))),
            bounds: "(]".to_string(),
        };
        assert!(range.lower.is_none());
        assert!(range.upper.is_some());
    }

    #[test]
    fn test_range_unbounded_upper() {
        let range = Range {
            lower: Some(Box::new(Value::int(0))),
            upper: None,
            bounds: "[)".to_string(),
        };
        assert!(range.lower.is_some());
        assert!(range.upper.is_none());
    }

    #[test]
    fn test_range_clone() {
        let range = Range {
            lower: Some(Box::new(Value::int(1))),
            upper: Some(Box::new(Value::int(10))),
            bounds: "[]".to_string(),
        };
        let cloned = range.clone();
        assert_eq!(cloned.bounds, "[]");
    }

    // ==================== Value Clone Tests ====================

    #[test]
    fn test_value_clone() {
        let v = Value::string("test");
        let cloned = v.clone();
        assert_eq!(cloned.as_string().unwrap(), "test");
    }

    #[test]
    fn test_value_clone_array() {
        let v = Value::array(vec![Value::int(1), Value::int(2)]);
        let cloned = v.clone();
        assert_eq!(cloned.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_value_clone_object() {
        let mut map = HashMap::new();
        map.insert("key".to_string(), Value::string("value"));
        let v = Value::object(map);
        let cloned = v.clone();
        assert_eq!(
            cloned
                .as_object()
                .unwrap()
                .get("key")
                .unwrap()
                .as_string()
                .unwrap(),
            "value"
        );
    }

    // ==================== JSON Round-Trip Tests ====================

    #[test]
    fn test_json_roundtrip_int() {
        let original = Value::int(42);
        let json = original.to_json();
        let restored = Value::from_json(json).unwrap();
        assert_eq!(restored.as_int().unwrap(), 42);
    }

    #[test]
    fn test_json_roundtrip_string() {
        let original = Value::string("hello world");
        let json = original.to_json();
        let restored = Value::from_json(json).unwrap();
        assert_eq!(restored.as_string().unwrap(), "hello world");
    }

    #[test]
    fn test_json_roundtrip_bool() {
        let original = Value::bool(true);
        let json = original.to_json();
        let restored = Value::from_json(json).unwrap();
        assert!(restored.as_bool().unwrap());
    }

    #[test]
    fn test_json_roundtrip_array() {
        let original = Value::array(vec![Value::int(1), Value::string("two")]);
        let json = original.to_json();
        let restored = Value::from_json(json).unwrap();
        let arr = restored.as_array().unwrap();
        assert_eq!(arr[0].as_int().unwrap(), 1);
        assert_eq!(arr[1].as_string().unwrap(), "two");
    }

    #[test]
    fn test_json_roundtrip_object() {
        let mut map = HashMap::new();
        map.insert("name".to_string(), Value::string("Alice"));
        map.insert("age".to_string(), Value::int(30));
        let original = Value::object(map);
        let json = original.to_json();
        let restored = Value::from_json(json).unwrap();
        let obj = restored.as_object().unwrap();
        assert_eq!(obj.get("name").unwrap().as_string().unwrap(), "Alice");
        assert_eq!(obj.get("age").unwrap().as_int().unwrap(), 30);
    }

    #[test]
    fn test_json_roundtrip_null() {
        let original = Value::null();
        let json = original.to_json();
        let restored = Value::from_json(json).unwrap();
        assert!(restored.is_null());
    }

    // ==================== Timestamp Accessor Tests ====================

    #[test]
    fn test_as_timestamp_from_timestamp() {
        let v = decode_value(&json!("2024-01-15T10:30:00Z"), "TIMESTAMP").unwrap();
        let ts = v.as_timestamp().unwrap();
        assert_eq!(ts.year(), 2024);
        assert_eq!(ts.month(), 1);
        assert_eq!(ts.day(), 15);
    }

    #[test]
    fn test_as_timestamp_from_timestamptz() {
        let v = decode_value(&json!("2024-01-15T10:30:00Z"), "TIMESTAMPTZ").unwrap();
        let ts = v.as_timestamp().unwrap();
        assert!(ts.hour() == 10);
    }
}
