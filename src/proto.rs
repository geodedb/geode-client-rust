//! Protobuf types generated from geode.proto via prost-build/tonic-build.
//!
//! This module re-exports the generated types and provides helper functions
//! for QUIC transport framing (4-byte big-endian length prefix).

// Include the prost-generated code.
#[allow(clippy::large_enum_variant)]
#[path = "generated/geode.rs"]
mod generated;

// Re-export all generated types at this module level.
pub use generated::*;

use prost::Message;

// Note: We use fully-qualified `crate::error::Error` to avoid collision with
// the generated `proto::Error` message type (from `message Error` in geode.proto).
use crate::error::Result;

// =============================================================================
// QUIC framing helpers (length-prefixed protobuf)
// =============================================================================

/// Encode a QuicClientMessage to protobuf bytes with a 4-byte big-endian
/// length prefix, as required by the QUIC transport.
pub fn encode_with_length_prefix(msg: &QuicClientMessage) -> Vec<u8> {
    let data = msg.encode_to_vec();
    let length = data.len() as u32;
    let mut result = Vec::with_capacity(4 + data.len());
    result.extend(&length.to_be_bytes());
    result.extend(data);
    result
}

/// Decode a 4-byte big-endian length prefix from the start of a byte slice.
pub fn decode_length_prefix(data: &[u8]) -> Result<u32> {
    if data.len() < 4 {
        return Err(crate::error::Error::protocol(
            "Insufficient data for length prefix",
        ));
    }
    Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

/// Decode a QuicServerMessage from raw protobuf bytes (without length prefix).
pub fn decode_quic_server_message(data: &[u8]) -> Result<QuicServerMessage> {
    QuicServerMessage::decode(data)
        .map_err(|e| crate::error::Error::protocol(format!("Protobuf decode error: {}", e)))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_hello_roundtrip() {
        let req = HelloRequest {
            username: "admin".to_string(),
            password: "secret".to_string(),
            tenant_id: Some("tenant1".to_string()),
            client_name: String::new(),
            client_version: String::new(),
            wanted_conformance: String::new(),
        };
        let msg = QuicClientMessage {
            msg: Some(quic_client_message::Msg::Hello(req)),
        };
        let encoded = msg.encode_to_vec();
        assert!(!encoded.is_empty());

        // Decode the client message as a QuicClientMessage
        let decoded = QuicClientMessage::decode(encoded.as_slice()).unwrap();
        match decoded.msg {
            Some(quic_client_message::Msg::Hello(hello)) => {
                assert_eq!(hello.username, "admin");
                assert_eq!(hello.password, "secret");
                assert_eq!(hello.tenant_id, Some("tenant1".to_string()));
            }
            _ => panic!("Expected Hello variant"),
        }
    }

    #[test]
    fn test_encode_decode_execute_roundtrip() {
        let params = vec![
            Param {
                name: "name".to_string(),
                value: Some(Value {
                    kind: Some(value::Kind::StringVal(StringValue {
                        value: "Alice".to_string(),
                        kind: 0,
                    })),
                }),
            },
            Param {
                name: "age".to_string(),
                value: Some(Value {
                    kind: Some(value::Kind::IntVal(IntValue { value: 30, kind: 0 })),
                }),
            },
        ];

        let req = ExecuteRequest {
            session_id: "session123".to_string(),
            query: "MATCH (n) RETURN n".to_string(),
            params,
        };
        let msg = QuicClientMessage {
            msg: Some(quic_client_message::Msg::Execute(req)),
        };
        let encoded = msg.encode_to_vec();
        assert!(!encoded.is_empty());

        let decoded = QuicClientMessage::decode(encoded.as_slice()).unwrap();
        match decoded.msg {
            Some(quic_client_message::Msg::Execute(exec)) => {
                assert_eq!(exec.session_id, "session123");
                assert_eq!(exec.query, "MATCH (n) RETURN n");
                assert_eq!(exec.params.len(), 2);
            }
            _ => panic!("Expected Execute variant"),
        }
    }

    #[test]
    fn test_encode_with_length_prefix() {
        let msg = QuicClientMessage {
            msg: Some(quic_client_message::Msg::Ping(PingRequest {})),
        };
        let encoded = encode_with_length_prefix(&msg);
        // Should have 4-byte length prefix
        assert!(encoded.len() >= 4);
        let length = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(length as usize, encoded.len() - 4);
    }

    #[test]
    fn test_decode_length_prefix() {
        let data = [0x00, 0x00, 0x00, 0x10];
        let length = decode_length_prefix(&data).unwrap();
        assert_eq!(length, 16);
    }

    #[test]
    fn test_decode_length_prefix_insufficient_data() {
        let data = [0x00, 0x00];
        let result = decode_length_prefix(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_hello_response() {
        // Build a HelloResponse, encode it, then decode
        let resp = HelloResponse {
            success: true,
            session_id: "sess123".to_string(),
            error_message: String::new(),
            capabilities: vec![],
        };
        let encoded = resp.encode_to_vec();
        let decoded = HelloResponse::decode(encoded.as_slice()).unwrap();
        assert!(decoded.success);
        assert_eq!(decoded.session_id, "sess123");
    }

    #[test]
    fn test_decode_ping_response() {
        let resp = PingResponse { ok: true };
        let encoded = resp.encode_to_vec();
        let decoded = PingResponse::decode(encoded.as_slice()).unwrap();
        assert!(decoded.ok);
    }

    #[test]
    fn test_value_null() {
        let val = Value {
            kind: Some(value::Kind::NullVal(NullValue {})),
        };
        assert!(matches!(val.kind, Some(value::Kind::NullVal(_))));
    }

    #[test]
    fn test_value_default() {
        let val = Value::default();
        assert!(val.kind.is_none());
    }

    #[test]
    fn test_message_defaults() {
        let client_msg = QuicClientMessage::default();
        assert!(client_msg.msg.is_none());

        let server_msg = QuicServerMessage::default();
        assert!(server_msg.msg.is_none());
    }
}
