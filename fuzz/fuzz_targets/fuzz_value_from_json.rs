//! Fuzz target for Value::from_json
//!
//! Tests that arbitrary JSON values can be safely converted to Value types
//! without panicking or causing undefined behavior.

#![no_main]

use libfuzzer_sys::fuzz_target;
use geode_client::Value;

fuzz_target!(|data: &[u8]| {
    // Try to parse the bytes as JSON
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
        // Convert to Value - should never panic
        let value = Value::from_json(json.clone());

        // Try to convert back to JSON - should never panic
        let _ = value.to_json();

        // Try various accessors - they should return Err, not panic
        let _ = value.as_int();
        let _ = value.as_string();
        let _ = value.as_bool();
        let _ = value.as_decimal();
        let _ = value.as_array();
        let _ = value.as_object();
        let _ = value.is_null();

        // Clone should work
        let _ = value.clone();
    }
});
