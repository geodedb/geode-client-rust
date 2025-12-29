//! Type system for Geode values.

use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;

use crate::error::{Error, Result};

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
    decimal_scale: String,
    array_value: Vec<Value>,
    object_value: HashMap<String, Value>,
    bytes_value: Vec<u8>,
    date_value: Option<NaiveDate>,
    time_value: Option<NaiveTime>,
    timestamp_value: Option<DateTime<Utc>>,
    range_value: Option<Range>,
}

impl Value {
    /// Create a NULL value
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
    pub fn int(value: i64) -> Self {
        Self {
            kind: ValueKind::Int,
            int_value: value,
            ..Self::null()
        }
    }

    /// Create a BOOL value
    pub fn bool(value: bool) -> Self {
        Self {
            kind: ValueKind::Bool,
            bool_value: value,
            ..Self::null()
        }
    }

    /// Create a STRING value
    pub fn string<S: Into<String>>(value: S) -> Self {
        Self {
            kind: ValueKind::String,
            string_value: value.into(),
            ..Self::null()
        }
    }

    /// Create a DECIMAL value
    pub fn decimal(value: Decimal) -> Self {
        Self {
            kind: ValueKind::Decimal,
            decimal_value: Some(value),
            ..Self::null()
        }
    }

    /// Create an ARRAY value
    pub fn array(values: Vec<Value>) -> Self {
        Self {
            kind: ValueKind::Array,
            array_value: values,
            ..Self::null()
        }
    }

    /// Create an OBJECT value
    pub fn object(values: HashMap<String, Value>) -> Self {
        Self {
            kind: ValueKind::Object,
            object_value: values,
            ..Self::null()
        }
    }

    /// Check if value is NULL
    pub fn is_null(&self) -> bool {
        self.kind == ValueKind::Null
    }

    /// Get as integer
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

    /// Create a Value from a serde_json::Value
    pub fn from_json(json: serde_json::Value) -> Self {
        match json {
            serde_json::Value::Null => Self::null(),
            serde_json::Value::Bool(b) => Self::bool(b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Self::int(i)
                } else if let Some(f) = n.as_f64() {
                    // Try to convert to decimal
                    Self::string(f.to_string())
                } else {
                    Self::null()
                }
            }
            serde_json::Value::String(s) => Self::string(s),
            serde_json::Value::Array(arr) => {
                let values: Vec<Value> = arr.into_iter().map(Self::from_json).collect();
                Self::array(values)
            }
            serde_json::Value::Object(obj) => {
                let mut map = HashMap::new();
                for (k, v) in obj {
                    map.insert(k, Self::from_json(v));
                }
                Self::object(map)
            }
        }
    }
}

/// Decode a JSON value into a typed Value object
pub fn decode_value(raw: &serde_json::Value, type_name: &str) -> Result<Value> {
    if raw.is_null() {
        return Ok(Value::null());
    }

    let type_upper = type_name.to_uppercase();

    match type_upper.as_str() {
        "INT" => {
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
        }
        "DECIMAL" => {
            let s = raw
                .as_str()
                .map(|v| v.to_string())
                .unwrap_or_else(|| raw.to_string());
            if let Ok(dec) = s.parse::<Decimal>() {
                Ok(Value::decimal(dec))
            } else {
                Ok(Value::string(s))
            }
        }
        "BOOL" => {
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
        }
        "STRING" => Ok(Value::string(raw.as_str().unwrap_or(""))),
        "BYTEA" => {
            let s = raw.as_str().unwrap_or("");
            let bytes = if s.starts_with("\\x") {
                hex::decode(&s[2..]).unwrap_or_default()
            } else {
                Vec::new()
            };
            Ok(Value {
                kind: ValueKind::Bytea,
                bytes_value: bytes,
                string_value: s.to_string(),
                ..Value::null()
            })
        }
        "JSON" => Ok(Value {
            kind: ValueKind::Json,
            string_value: raw.to_string(),
            ..Value::null()
        }),
        "JSONB" => Ok(Value {
            kind: ValueKind::Jsonb,
            string_value: raw.to_string(),
            ..Value::null()
        }),
        "DATE" => {
            let s = raw.as_str().unwrap_or("");
            let date = NaiveDate::parse_from_str(s, "%Y-%m-%d").ok();
            Ok(Value {
                kind: ValueKind::Date,
                string_value: s.to_string(),
                date_value: date,
                ..Value::null()
            })
        }
        "TIMESTAMP" | "TIMESTAMPTZ" => {
            let s = raw.as_str().unwrap_or("");
            let timestamp = DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc));
            let kind = if type_upper == "TIMESTAMPTZ" {
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
        }
        _ if type_upper.contains("RANGE") => {
            if let Some(obj) = raw.as_object() {
                let range = Range {
                    lower: obj
                        .get("lower")
                        .and_then(|v| decode_value(v, "").ok().map(Box::new)),
                    upper: obj
                        .get("upper")
                        .and_then(|v| decode_value(v, "").ok().map(Box::new)),
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
        }
        _ => {
            // Handle arrays and objects generically
            if let Some(arr) = raw.as_array() {
                let values: Result<Vec<_>> = arr.iter().map(|v| decode_value(v, "")).collect();
                Ok(Value::array(values?))
            } else if let Some(obj) = raw.as_object() {
                let mut map = HashMap::new();
                for (k, v) in obj {
                    map.insert(k.clone(), decode_value(v, "")?);
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
}
