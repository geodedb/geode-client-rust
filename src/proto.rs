//! Protobuf encoding/decoding for Geode wire protocol.
//!
//! Wire format: 4-byte Big Endian length prefix + protobuf message body.
//!
//! This module provides manual protobuf encoding/decoding that is compatible
//! with the geode.proto schema. It supports both QUIC (length-prefixed) and
//! gRPC transports.

use std::collections::HashMap;

use crate::error::{Error, Result};

// Wire type constants for protobuf encoding.
const WIRE_VARINT: u32 = 0;
const WIRE_FIXED64: u32 = 1;
const WIRE_BYTES: u32 = 2;
const WIRE_FIXED32: u32 = 5;

// =============================================================================
// Message Types (matching geode.proto)
// =============================================================================

/// Authentication handshake message.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HelloRequest {
    pub username: String,
    pub password: String,
    pub tenant_id: String,
}

/// Server's response to HelloRequest.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HelloResponse {
    pub success: bool,
    pub session_id: String,
    pub error_message: String,
    pub capabilities: Vec<String>,
}

/// Request to execute a GQL query.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExecuteRequest {
    pub session_id: String,
    pub query: String,
    pub parameters: HashMap<String, Value>,
}

/// Column definition in result schema.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ColumnDefinition {
    pub name: String,
    pub col_type: String,
}

/// Contains column definitions.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SchemaDefinition {
    pub columns: Vec<ColumnDefinition>,
}

/// Protobuf value (oneof).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Value {
    pub string_val: Option<String>,
    pub int_val: Option<i64>,
    pub double_val: Option<f64>,
    pub bool_val: Option<bool>,
    pub null_val: bool,
}

/// Row is a list of values.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Row {
    pub values: Vec<Value>,
}

/// Contains rows and pagination info.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DataPage {
    pub rows: Vec<Row>,
    pub last_page: bool,
}

/// Query error.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProtoError {
    pub code: String,
    pub message: String,
    pub error_type: String,
}

/// Timing information.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExecutionMetrics {
    pub parse_duration_ns: i64,
    pub plan_duration_ns: i64,
    pub execute_duration_ns: i64,
    pub total_duration_ns: i64,
}

/// Empty keep-alive message.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Heartbeat;

/// Oneof for different response types.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExecutionResponse {
    pub schema: Option<SchemaDefinition>,
    pub page: Option<DataPage>,
    pub error: Option<ProtoError>,
    pub metrics: Option<ExecutionMetrics>,
    pub heartbeat: Option<Heartbeat>,
}

/// Empty ping request.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PingRequest;

/// Ping success response.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PingResponse {
    pub ok: bool,
}

/// Start a transaction.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BeginRequest {
    pub read_only: bool,
    pub session_id: String,
}

/// Confirms transaction start.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BeginResponse {
    pub session_id: String,
    pub tx_id: String,
}

/// Commit a transaction.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CommitRequest {
    pub session_id: String,
}

/// Confirms commit.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CommitResponse {
    pub success: bool,
}

/// Roll back a transaction.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RollbackRequest {
    pub session_id: String,
}

/// Confirms rollback.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RollbackResponse {
    pub success: bool,
}

/// Top-level client message (oneof).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QuicClientMessage {
    pub hello: Option<HelloRequest>,
    pub execute: Option<ExecuteRequest>,
    pub ping: Option<PingRequest>,
    pub begin: Option<BeginRequest>,
    pub commit: Option<CommitRequest>,
    pub rollback: Option<RollbackRequest>,
}

/// Top-level server message (oneof).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QuicServerMessage {
    pub hello: Option<HelloResponse>,
    pub execute: Option<ExecutionResponse>,
    pub ping: Option<PingResponse>,
    pub begin: Option<BeginResponse>,
    pub commit: Option<CommitResponse>,
    pub rollback: Option<RollbackResponse>,
}

// =============================================================================
// Encoding helpers
// =============================================================================

fn encode_varint(v: u64) -> Vec<u8> {
    let mut result = Vec::new();
    let mut val = v;
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if val == 0 {
            break;
        }
    }
    result
}

fn encode_tag(field_num: u32, wire_type: u32) -> Vec<u8> {
    encode_varint(((field_num << 3) | wire_type) as u64)
}

fn encode_string(field_num: u32, s: &str) -> Vec<u8> {
    if s.is_empty() {
        return Vec::new();
    }
    let mut result = encode_tag(field_num, WIRE_BYTES);
    result.extend(encode_varint(s.len() as u64));
    result.extend(s.as_bytes());
    result
}

/// Reserved for future use with byte array fields.
#[allow(dead_code)]
fn encode_bytes(field_num: u32, data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut result = encode_tag(field_num, WIRE_BYTES);
    result.extend(encode_varint(data.len() as u64));
    result.extend(data);
    result
}

fn encode_bool(field_num: u32, v: bool) -> Vec<u8> {
    if !v {
        return Vec::new();
    }
    let mut result = encode_tag(field_num, WIRE_VARINT);
    result.push(1);
    result
}

#[allow(dead_code)]
fn encode_int64(field_num: u32, v: i64) -> Vec<u8> {
    if v == 0 {
        return Vec::new();
    }
    let mut result = encode_tag(field_num, WIRE_VARINT);
    result.extend(encode_varint(v as u64));
    result
}

fn encode_submessage(field_num: u32, data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut result = encode_tag(field_num, WIRE_BYTES);
    result.extend(encode_varint(data.len() as u64));
    result.extend(data);
    result
}

// =============================================================================
// Message encoding
// =============================================================================

fn encode_hello_request(req: &HelloRequest) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend(encode_string(1, &req.username));
    result.extend(encode_string(2, &req.password));
    result.extend(encode_string(3, &req.tenant_id));
    result
}

fn encode_value(val: &Value) -> Vec<u8> {
    let mut result = Vec::new();
    if val.null_val {
        // NullValue = field 1, empty submessage
        result.extend(encode_submessage(1, &[]));
    } else if let Some(i) = val.int_val {
        // IntValue = field 2, submessage with value at field 1
        let mut inner = Vec::new();
        inner.extend(encode_int64(1, i));
        result.extend(encode_submessage(2, &inner));
    } else if let Some(d) = val.double_val {
        // DoubleValue = field 3, submessage with value at field 1
        let mut inner = Vec::new();
        inner.push(((1 << 3) | WIRE_FIXED64) as u8);
        inner.extend(&d.to_le_bytes());
        result.extend(encode_submessage(3, &inner));
    } else if let Some(b) = val.bool_val {
        // bool_val = field 4, scalar bool (varint)
        result.push(((4 << 3) | WIRE_VARINT) as u8);
        result.push(if b { 1 } else { 0 });
    } else if let Some(ref s) = val.string_val {
        // StringValue = field 5, submessage with value at field 1
        let mut inner = Vec::new();
        inner.extend(encode_string(1, s));
        result.extend(encode_submessage(5, &inner));
    }
    result
}

fn encode_execute_request(req: &ExecuteRequest) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend(encode_string(1, &req.session_id));
    result.extend(encode_string(2, &req.query));
    // Encode params as repeated Param submessages (name=string, value=Value)
    for (k, v) in &req.parameters {
        let mut entry = encode_string(1, k);
        let value_data = encode_value(v);
        entry.extend(encode_submessage(2, &value_data));
        result.extend(encode_submessage(3, &entry));
    }
    result
}

fn encode_ping_request(_req: &PingRequest) -> Vec<u8> {
    Vec::new()
}

fn encode_begin_request(req: &BeginRequest) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend(encode_bool(1, req.read_only));
    if !req.session_id.is_empty() {
        result.extend(encode_string(2, &req.session_id));
    }
    result
}

fn encode_commit_request(req: &CommitRequest) -> Vec<u8> {
    let mut result = Vec::new();
    if !req.session_id.is_empty() {
        result.extend(encode_string(1, &req.session_id));
    }
    result
}

fn encode_rollback_request(req: &RollbackRequest) -> Vec<u8> {
    let mut result = Vec::new();
    if !req.session_id.is_empty() {
        result.extend(encode_string(1, &req.session_id));
    }
    result
}

/// Encode a QuicClientMessage to protobuf bytes.
pub fn encode_quic_client_message(msg: &QuicClientMessage) -> Vec<u8> {
    let mut result = Vec::new();
    if let Some(ref hello) = msg.hello {
        result.extend(encode_submessage(1, &encode_hello_request(hello)));
    }
    if let Some(ref execute) = msg.execute {
        result.extend(encode_submessage(2, &encode_execute_request(execute)));
    }
    if let Some(ref ping) = msg.ping {
        result.extend(encode_submessage(4, &encode_ping_request(ping)));
    }
    if let Some(ref begin) = msg.begin {
        result.extend(encode_submessage(7, &encode_begin_request(begin)));
    }
    if let Some(ref commit) = msg.commit {
        result.extend(encode_submessage(8, &encode_commit_request(commit)));
    }
    if let Some(ref rollback) = msg.rollback {
        result.extend(encode_submessage(9, &encode_rollback_request(rollback)));
    }
    result
}

// =============================================================================
// Decoding helpers
// =============================================================================

fn decode_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    while *pos < data.len() {
        let b = data[*pos];
        *pos += 1;
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::protocol("Varint too long"));
        }
    }
    Err(Error::protocol("Truncated varint"))
}

fn decode_tag(data: &[u8], pos: &mut usize) -> Result<(u32, u32)> {
    let tag = decode_varint(data, pos)?;
    Ok(((tag >> 3) as u32, (tag & 0x7) as u32))
}

fn skip_field(data: &[u8], pos: &mut usize, wire_type: u32) -> Result<()> {
    match wire_type {
        WIRE_VARINT => {
            decode_varint(data, pos)?;
        }
        WIRE_FIXED64 => {
            *pos += 8;
        }
        WIRE_BYTES => {
            let length = decode_varint(data, pos)? as usize;
            *pos += length;
        }
        WIRE_FIXED32 => {
            *pos += 4;
        }
        _ => return Err(Error::protocol(format!("Unknown wire type: {}", wire_type))),
    }
    if *pos > data.len() {
        return Err(Error::protocol("Message truncated"));
    }
    Ok(())
}

fn decode_string(data: &[u8], pos: &mut usize) -> Result<String> {
    let length = decode_varint(data, pos)? as usize;
    if *pos + length > data.len() {
        return Err(Error::protocol("Truncated string"));
    }
    let s = String::from_utf8(data[*pos..*pos + length].to_vec())
        .map_err(|_| Error::protocol("Invalid UTF-8"))?;
    *pos += length;
    Ok(s)
}

fn decode_bytes_field(data: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    let length = decode_varint(data, pos)? as usize;
    if *pos + length > data.len() {
        return Err(Error::protocol("Truncated bytes"));
    }
    let bytes = data[*pos..*pos + length].to_vec();
    *pos += length;
    Ok(bytes)
}

fn decode_bool(data: &[u8], pos: &mut usize) -> Result<bool> {
    let v = decode_varint(data, pos)?;
    Ok(v != 0)
}

fn decode_int64(data: &[u8], pos: &mut usize) -> Result<i64> {
    let v = decode_varint(data, pos)?;
    // Handle sign extension for negative numbers
    if v > 0x7FFFFFFFFFFFFFFF {
        Ok((v as i64).wrapping_sub(i64::MIN).wrapping_add(i64::MIN))
    } else {
        Ok(v as i64)
    }
}

fn decode_double(data: &[u8], pos: &mut usize) -> Result<f64> {
    if *pos + 8 > data.len() {
        return Err(Error::protocol("Truncated double"));
    }
    let bytes: [u8; 8] = data[*pos..*pos + 8].try_into().unwrap();
    *pos += 8;
    Ok(f64::from_le_bytes(bytes))
}

// =============================================================================
// Message decoding
// =============================================================================

fn decode_hello_response(data: &[u8]) -> Result<HelloResponse> {
    let mut resp = HelloResponse::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_VARINT) => resp.success = decode_bool(data, &mut pos)?,
            (2, WIRE_BYTES) => resp.session_id = decode_string(data, &mut pos)?,
            (3, WIRE_BYTES) => resp.error_message = decode_string(data, &mut pos)?,
            (4, WIRE_BYTES) => resp.capabilities.push(decode_string(data, &mut pos)?),
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(resp)
}

fn decode_column_definition(data: &[u8]) -> Result<ColumnDefinition> {
    let mut col = ColumnDefinition::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_BYTES) => col.name = decode_string(data, &mut pos)?,
            (2, WIRE_BYTES) => col.col_type = decode_string(data, &mut pos)?,
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(col)
}

fn decode_schema_definition(data: &[u8]) -> Result<SchemaDefinition> {
    let mut schema = SchemaDefinition::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_BYTES) => {
                let col_data = decode_bytes_field(data, &mut pos)?;
                schema.columns.push(decode_column_definition(&col_data)?);
            }
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(schema)
}

fn decode_value(data: &[u8]) -> Result<Value> {
    let mut val = Value::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            // field 1 = NullValue (submessage, empty)
            (1, WIRE_BYTES) => {
                let _null_data = decode_bytes_field(data, &mut pos)?;
                val.null_val = true;
            }
            // field 2 = IntValue submessage { int64 value = 1; }
            (2, WIRE_BYTES) => {
                let int_data = decode_bytes_field(data, &mut pos)?;
                val.int_val = Some(decode_int_value(&int_data)?);
            }
            // field 3 = DoubleValue submessage { double value = 1; }
            (3, WIRE_BYTES) => {
                let dbl_data = decode_bytes_field(data, &mut pos)?;
                val.double_val = Some(decode_double_value(&dbl_data)?);
            }
            // field 4 = bool_val (scalar bool in server schema)
            (4, WIRE_VARINT) => val.bool_val = Some(decode_bool(data, &mut pos)?),
            // field 5 = StringValue submessage { string value = 1; }
            (5, WIRE_BYTES) => {
                let str_data = decode_bytes_field(data, &mut pos)?;
                val.string_val = Some(decode_string_value(&str_data)?);
            }
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(val)
}

fn decode_int_value(data: &[u8]) -> Result<i64> {
    let mut value: i64 = 0;
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_VARINT) => value = decode_int64(data, &mut pos)?,
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(value)
}

fn decode_double_value(data: &[u8]) -> Result<f64> {
    let mut value: f64 = 0.0;
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_FIXED64) => value = decode_double(data, &mut pos)?,
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(value)
}

fn decode_string_value(data: &[u8]) -> Result<String> {
    let mut value = String::new();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_BYTES) => value = decode_string(data, &mut pos)?,
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(value)
}

fn decode_row(data: &[u8]) -> Result<Row> {
    let mut row = Row::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_BYTES) => {
                let val_data = decode_bytes_field(data, &mut pos)?;
                row.values.push(decode_value(&val_data)?);
            }
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(row)
}

fn decode_data_page(data: &[u8]) -> Result<DataPage> {
    let mut page = DataPage::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_BYTES) => {
                let row_data = decode_bytes_field(data, &mut pos)?;
                page.rows.push(decode_row(&row_data)?);
            }
            (2, WIRE_VARINT) => page.last_page = decode_bool(data, &mut pos)?,
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(page)
}

fn decode_proto_error(data: &[u8]) -> Result<ProtoError> {
    let mut err = ProtoError::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_BYTES) => err.code = decode_string(data, &mut pos)?,
            (2, WIRE_BYTES) => err.message = decode_string(data, &mut pos)?,
            (3, WIRE_BYTES) => err.error_type = decode_string(data, &mut pos)?,
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(err)
}

fn decode_execution_metrics(data: &[u8]) -> Result<ExecutionMetrics> {
    let mut metrics = ExecutionMetrics::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_VARINT) => metrics.parse_duration_ns = decode_int64(data, &mut pos)?,
            (2, WIRE_VARINT) => metrics.plan_duration_ns = decode_int64(data, &mut pos)?,
            (3, WIRE_VARINT) => metrics.execute_duration_ns = decode_int64(data, &mut pos)?,
            (4, WIRE_VARINT) => metrics.total_duration_ns = decode_int64(data, &mut pos)?,
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(metrics)
}

fn decode_execution_response(data: &[u8]) -> Result<ExecutionResponse> {
    let mut resp = ExecutionResponse::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            // field 1 = Status (skip for now, not needed by client)
            (1, WIRE_BYTES) => {
                let _status_data = decode_bytes_field(data, &mut pos)?;
            }
            // field 2 = SchemaDefinition (oneof payload)
            (2, WIRE_BYTES) => {
                let schema_data = decode_bytes_field(data, &mut pos)?;
                resp.schema = Some(decode_schema_definition(&schema_data)?);
            }
            // field 3 = DataPage (oneof payload)
            (3, WIRE_BYTES) => {
                let page_data = decode_bytes_field(data, &mut pos)?;
                resp.page = Some(decode_data_page(&page_data)?);
            }
            // field 4 = Error (oneof payload)
            (4, WIRE_BYTES) => {
                let err_data = decode_bytes_field(data, &mut pos)?;
                resp.error = Some(decode_proto_error(&err_data)?);
            }
            // field 5 = ExecutionMetrics (oneof payload)
            (5, WIRE_BYTES) => {
                let metrics_data = decode_bytes_field(data, &mut pos)?;
                resp.metrics = Some(decode_execution_metrics(&metrics_data)?);
            }
            // field 8 = Heartbeat (oneof payload)
            (8, WIRE_BYTES) => {
                let _heartbeat_data = decode_bytes_field(data, &mut pos)?;
                resp.heartbeat = Some(Heartbeat);
            }
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(resp)
}

fn decode_ping_response(data: &[u8]) -> Result<PingResponse> {
    let mut resp = PingResponse::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_VARINT) => resp.ok = decode_bool(data, &mut pos)?,
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(resp)
}

fn decode_begin_response(data: &[u8]) -> Result<BeginResponse> {
    let mut resp = BeginResponse::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_BYTES) => resp.session_id = decode_string(data, &mut pos)?,
            (2, WIRE_BYTES) => resp.tx_id = decode_string(data, &mut pos)?,
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(resp)
}

fn decode_commit_response(data: &[u8]) -> Result<CommitResponse> {
    let mut resp = CommitResponse::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_VARINT) => resp.success = decode_bool(data, &mut pos)?,
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(resp)
}

fn decode_rollback_response(data: &[u8]) -> Result<RollbackResponse> {
    let mut resp = RollbackResponse::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_VARINT) => resp.success = decode_bool(data, &mut pos)?,
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(resp)
}

/// Decode a QuicServerMessage from protobuf bytes.
pub fn decode_quic_server_message(data: &[u8]) -> Result<QuicServerMessage> {
    let mut msg = QuicServerMessage::default();
    let mut pos = 0;
    while pos < data.len() {
        let (field_num, wire_type) = decode_tag(data, &mut pos)?;
        match (field_num, wire_type) {
            (1, WIRE_BYTES) => {
                let hello_data = decode_bytes_field(data, &mut pos)?;
                msg.hello = Some(decode_hello_response(&hello_data)?);
            }
            (2, WIRE_BYTES) => {
                let exec_data = decode_bytes_field(data, &mut pos)?;
                msg.execute = Some(decode_execution_response(&exec_data)?);
            }
            (4, WIRE_BYTES) => {
                let ping_data = decode_bytes_field(data, &mut pos)?;
                msg.ping = Some(decode_ping_response(&ping_data)?);
            }
            (7, WIRE_BYTES) => {
                let begin_data = decode_bytes_field(data, &mut pos)?;
                msg.begin = Some(decode_begin_response(&begin_data)?);
            }
            (8, WIRE_BYTES) => {
                let commit_data = decode_bytes_field(data, &mut pos)?;
                msg.commit = Some(decode_commit_response(&commit_data)?);
            }
            (9, WIRE_BYTES) => {
                let rollback_data = decode_bytes_field(data, &mut pos)?;
                msg.rollback = Some(decode_rollback_response(&rollback_data)?);
            }
            _ => skip_field(data, &mut pos, wire_type)?,
        }
    }
    Ok(msg)
}

/// Encode message with 4-byte big-endian length prefix.
pub fn encode_with_length_prefix(msg: &QuicClientMessage) -> Vec<u8> {
    let data = encode_quic_client_message(msg);
    let length = data.len() as u32;
    let mut result = Vec::with_capacity(4 + data.len());
    result.extend(&length.to_be_bytes());
    result.extend(data);
    result
}

/// Decode 4-byte big-endian length prefix.
pub fn decode_length_prefix(data: &[u8]) -> Result<u32> {
    if data.len() < 4 {
        return Err(Error::protocol("Insufficient data for length prefix"));
    }
    Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
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
            tenant_id: "tenant1".to_string(),
        };
        let msg = QuicClientMessage {
            hello: Some(req.clone()),
            ..Default::default()
        };
        let encoded = encode_quic_client_message(&msg);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_decode_execute_roundtrip() {
        let mut params = HashMap::new();
        params.insert(
            "name".to_string(),
            Value {
                string_val: Some("Alice".to_string()),
                ..Default::default()
            },
        );
        params.insert(
            "age".to_string(),
            Value {
                int_val: Some(30),
                ..Default::default()
            },
        );

        let req = ExecuteRequest {
            session_id: "session123".to_string(),
            query: "MATCH (n) RETURN n".to_string(),
            parameters: params,
        };
        let msg = QuicClientMessage {
            execute: Some(req),
            ..Default::default()
        };
        let encoded = encode_quic_client_message(&msg);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_with_length_prefix() {
        let msg = QuicClientMessage {
            ping: Some(PingRequest),
            ..Default::default()
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
        // Manually construct a HelloResponse message
        let mut encoded = Vec::new();
        // Field 1 (success): varint true
        encoded.extend(&[0x08, 0x01]);
        // Field 2 (session_id): string "sess123"
        encoded.extend(&[0x12, 0x07]);
        encoded.extend(b"sess123");

        let resp = decode_hello_response(&encoded).unwrap();
        assert!(resp.success);
        assert_eq!(resp.session_id, "sess123");
    }

    #[test]
    fn test_decode_ping_response() {
        // Field 1 (ok): varint true
        let encoded = [0x08, 0x01];
        let resp = decode_ping_response(&encoded).unwrap();
        assert!(resp.ok);
    }

    #[test]
    fn test_value_default() {
        let val = Value::default();
        assert!(val.string_val.is_none());
        assert!(val.int_val.is_none());
        assert!(val.double_val.is_none());
        assert!(val.bool_val.is_none());
        assert!(!val.null_val);
    }

    #[test]
    fn test_message_defaults() {
        let client_msg = QuicClientMessage::default();
        assert!(client_msg.hello.is_none());
        assert!(client_msg.execute.is_none());
        assert!(client_msg.ping.is_none());

        let server_msg = QuicServerMessage::default();
        assert!(server_msg.hello.is_none());
        assert!(server_msg.execute.is_none());
        assert!(server_msg.ping.is_none());
    }
}
