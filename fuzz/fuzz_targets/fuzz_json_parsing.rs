//! Fuzz target for JSON parsing and Value conversion
//!
//! Tests that arbitrary byte sequences processed as JSON don't cause
//! panics or undefined behavior when converted to Value types.

#![no_main]

use libfuzzer_sys::fuzz_target;
use geode_client::Value;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    // Try to interpret as UTF-8 string
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to parse as JSON
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(s) {
            // Test from_json (may return Err for deep nesting)
            if let Ok(value) = Value::from_json(json.clone()) {
                // Test to_json roundtrip
                let back = value.to_json();
                let _ = Value::from_json(back);
            }

            // Test various Value constructors with string input
            let _ = Value::string(s);

            // Test with truncated input
            if s.len() > 10 {
                let _ = Value::string(&s[..10]);
            }
        }

        // Test string Value directly
        let str_value = Value::string(s);
        let _ = str_value.as_string();
        let _ = str_value.to_json();
        let _ = str_value.clone();
    }

    // Test with raw bytes as hex
    let hex_str = format!("\\x{}", hex::encode(data));
    let _ = Value::string(&hex_str);

    // Test array of values from bytes
    let arr: Vec<Value> = data.iter()
        .take(100) // Limit to prevent huge allocations
        .map(|&b| Value::int(b as i64))
        .collect();
    let array_val = Value::array(arr);
    let _ = array_val.as_array();
    let _ = array_val.to_json();

    // Test object with byte-derived keys
    if data.len() >= 2 {
        let mut map = HashMap::new();
        for chunk in data.chunks(2).take(50) {
            let key = format!("key_{}", chunk[0]);
            let val = Value::int(chunk.get(1).copied().unwrap_or(0) as i64);
            map.insert(key, val);
        }
        let obj_val = Value::object(map);
        let _ = obj_val.as_object();
        let _ = obj_val.to_json();
    }
});
