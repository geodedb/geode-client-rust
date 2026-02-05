//! gRPC transport implementation for Geode.
//!
//! This module provides gRPC client functionality using tonic.
//! It connects to the Geode server's gRPC service as defined in geode.proto.

use std::collections::HashMap;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Streaming};

use crate::client::{Column, Page};
use crate::dsn::Dsn;
use crate::error::{Error, Result};
use crate::types::Value;

/// gRPC client for Geode.
///
/// Provides gRPC-based connection to the Geode database server.
pub struct GrpcClient {
    channel: Channel,
    session_id: String,
}

impl GrpcClient {
    /// Connect to a Geode server using gRPC.
    ///
    /// # Arguments
    ///
    /// * `dsn` - Parsed DSN with gRPC transport
    ///
    /// # Example
    ///
    /// ```no_run
    /// use geode_client::dsn::Dsn;
    /// use geode_client::grpc::GrpcClient;
    ///
    /// # async fn example() -> geode_client::Result<()> {
    /// let dsn = Dsn::parse("grpc://localhost:50051")?;
    /// let client = GrpcClient::connect(&dsn).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(dsn: &Dsn) -> Result<Self> {
        let addr = if dsn.tls_enabled() {
            format!("https://{}", dsn.address())
        } else {
            format!("http://{}", dsn.address())
        };

        let endpoint = Endpoint::from_shared(addr.clone())
            .map_err(|e| Error::connection(format!("Invalid endpoint: {}", e)))?;

        // Configure TLS if needed
        let endpoint = if dsn.tls_enabled() && dsn.skip_verify() {
            // Skip TLS verification (insecure - for development only)
            endpoint
                .tls_config(tonic::transport::ClientTlsConfig::new().with_enabled_roots())
                .map_err(|e| Error::tls(format!("TLS config error: {}", e)))?
        } else {
            endpoint
        };

        let channel = endpoint
            .connect()
            .await
            .map_err(|e| Error::connection(format!("gRPC connection failed to {}: {}", addr, e)))?;

        let mut client = Self {
            channel,
            session_id: String::new(),
        };

        // Perform handshake
        client.handshake(dsn.username(), dsn.password()).await?;

        Ok(client)
    }

    /// Perform authentication handshake.
    async fn handshake(&mut self, username: Option<&str>, password: Option<&str>) -> Result<()> {
        let request = GrpcHelloRequest {
            username: username.unwrap_or("").to_string(),
            password: password.unwrap_or("").to_string(),
            tenant_id: None,
        };

        // Send handshake via gRPC
        // Note: This is a simplified implementation. The actual gRPC call
        // depends on the server's service definition.
        let mut grpc_client = GeodeServiceClient::new(self.channel.clone());

        let response = grpc_client
            .handshake(Request::new(request))
            .await
            .map_err(|e| Error::connection(format!("Handshake failed: {}", e)))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(Error::auth(resp.error_message));
        }

        self.session_id = resp.session_id;
        Ok(())
    }

    /// Execute a GQL query.
    pub async fn query(&mut self, gql: &str) -> Result<(Page, Option<String>)> {
        self.query_with_params(gql, &HashMap::new()).await
    }

    /// Execute a GQL query with parameters.
    pub async fn query_with_params(
        &mut self,
        gql: &str,
        params: &HashMap<String, Value>,
    ) -> Result<(Page, Option<String>)> {
        let params_map: HashMap<String, String> = params
            .iter()
            .map(|(k, v)| (k.clone(), v.to_proto_string()))
            .collect();

        let request = GrpcExecuteRequest {
            session_id: self.session_id.clone(),
            query: gql.to_string(),
            parameters: params_map,
        };

        let mut grpc_client = GeodeServiceClient::new(self.channel.clone());

        let response = grpc_client
            .execute(Request::new(request))
            .await
            .map_err(|e| Error::query(format!("Query execution failed: {}", e)))?;

        // Process streaming response
        let mut stream = response.into_inner();
        let mut columns = Vec::new();
        let mut rows = Vec::new();
        let mut final_page = true;

        while let Some(exec_resp) = stream
            .message()
            .await
            .map_err(|e| Error::query(format!("Failed to read response: {}", e)))?
        {
            match exec_resp.result {
                Some(GrpcExecutionResult::Schema(schema)) => {
                    columns = schema
                        .columns
                        .into_iter()
                        .map(|c| Column {
                            name: c.name,
                            col_type: c.r#type,
                        })
                        .collect();
                }
                Some(GrpcExecutionResult::Page(page)) => {
                    for row in page.rows {
                        let mut row_map = HashMap::new();
                        for (i, col) in columns.iter().enumerate() {
                            let value = if i < row.values.len() {
                                Self::convert_proto_value(&row.values[i])
                            } else {
                                Value::null()
                            };
                            row_map.insert(col.name.clone(), value);
                        }
                        rows.push(row_map);
                    }
                    final_page = page.last_page;
                }
                Some(GrpcExecutionResult::Error(err)) => {
                    return Err(Error::Query {
                        code: err.code,
                        message: err.message,
                    });
                }
                Some(GrpcExecutionResult::Metrics(_)) => {
                    // Metrics received, continue
                }
                Some(GrpcExecutionResult::Heartbeat(_)) => {
                    // Heartbeat received, continue
                }
                None => {}
            }
        }

        Ok((
            Page {
                columns,
                rows,
                ordered: false,
                order_keys: Vec::new(),
                final_page,
            },
            None,
        ))
    }

    /// Convert a proto Value to our Value type.
    fn convert_proto_value(proto_val: &GrpcValue) -> Value {
        match &proto_val.kind {
            Some(GrpcValueKind::StringVal(s)) => Value::string(s.clone()),
            Some(GrpcValueKind::IntVal(i)) => Value::int(*i),
            Some(GrpcValueKind::DoubleVal(d)) => {
                Value::decimal(rust_decimal::Decimal::from_f64_retain(*d).unwrap_or_default())
            }
            Some(GrpcValueKind::BoolVal(b)) => Value::bool(*b),
            Some(GrpcValueKind::NullVal(true)) => Value::null(),
            _ => Value::null(),
        }
    }

    /// Begin a transaction.
    pub async fn begin(&mut self) -> Result<()> {
        // gRPC transaction support would go here
        // For now, return an error as gRPC transactions may need different handling
        Err(Error::connection("gRPC transactions not yet implemented"))
    }

    /// Commit a transaction.
    pub async fn commit(&mut self) -> Result<()> {
        Err(Error::connection("gRPC transactions not yet implemented"))
    }

    /// Rollback a transaction.
    pub async fn rollback(&mut self) -> Result<()> {
        Err(Error::connection("gRPC transactions not yet implemented"))
    }

    /// Send a ping request.
    pub async fn ping(&mut self) -> Result<bool> {
        let mut grpc_client = GeodeServiceClient::new(self.channel.clone());

        let response = grpc_client
            .ping(Request::new(GrpcPingRequest {}))
            .await
            .map_err(|e| Error::connection(format!("Ping failed: {}", e)))?;

        Ok(response.into_inner().ok)
    }

    /// Close the connection.
    pub fn close(&mut self) -> Result<()> {
        // gRPC channels are automatically closed when dropped
        // No explicit close action needed
        Ok(())
    }
}

// =============================================================================
// gRPC Message Types (matching geode.proto service definitions)
// =============================================================================

/// gRPC HelloRequest message
#[derive(Clone, PartialEq, Debug)]
pub struct GrpcHelloRequest {
    pub username: String,
    pub password: String,
    pub tenant_id: Option<String>,
}

/// gRPC HelloResponse message
#[derive(Clone, PartialEq, Debug)]
pub struct GrpcHelloResponse {
    pub success: bool,
    pub session_id: String,
    pub error_message: String,
    pub capabilities: Vec<String>,
}

/// gRPC ExecuteRequest message
#[derive(Clone, PartialEq, Debug)]
pub struct GrpcExecuteRequest {
    pub session_id: String,
    pub query: String,
    pub parameters: HashMap<String, String>,
}

/// gRPC ExecutionResponse result variants
#[derive(Clone, PartialEq, Debug)]
pub enum GrpcExecutionResult {
    Schema(GrpcSchemaDefinition),
    Page(GrpcDataPage),
    Error(GrpcError),
    Metrics(GrpcExecutionMetrics),
    Heartbeat(GrpcHeartbeat),
}

/// gRPC ExecutionResponse message
#[derive(Clone, PartialEq, Debug)]
pub struct GrpcExecutionResponse {
    pub result: Option<GrpcExecutionResult>,
}

/// gRPC SchemaDefinition message
#[derive(Clone, PartialEq, Debug)]
pub struct GrpcSchemaDefinition {
    pub columns: Vec<GrpcColumnDefinition>,
}

/// gRPC ColumnDefinition message
#[derive(Clone, PartialEq, Debug)]
pub struct GrpcColumnDefinition {
    pub name: String,
    pub r#type: String,
}

/// gRPC DataPage message
#[derive(Clone, PartialEq, Debug)]
pub struct GrpcDataPage {
    pub rows: Vec<GrpcRow>,
    pub last_page: bool,
}

/// gRPC Row message
#[derive(Clone, PartialEq, Debug)]
pub struct GrpcRow {
    pub values: Vec<GrpcValue>,
}

/// gRPC Value kind variants
#[derive(Clone, PartialEq, Debug)]
pub enum GrpcValueKind {
    StringVal(String),
    IntVal(i64),
    DoubleVal(f64),
    BoolVal(bool),
    NullVal(bool),
}

/// gRPC Value message
#[derive(Clone, PartialEq, Debug, Default)]
pub struct GrpcValue {
    pub kind: Option<GrpcValueKind>,
}

/// gRPC Error message
#[derive(Clone, PartialEq, Debug)]
pub struct GrpcError {
    pub code: String,
    pub message: String,
    pub r#type: String,
}

/// gRPC ExecutionMetrics message
#[derive(Clone, PartialEq, Debug)]
pub struct GrpcExecutionMetrics {
    pub parse_duration_ns: i64,
    pub plan_duration_ns: i64,
    pub execute_duration_ns: i64,
    pub total_duration_ns: i64,
}

/// gRPC Heartbeat message
#[derive(Clone, PartialEq, Debug, Default)]
pub struct GrpcHeartbeat;

/// gRPC PingRequest message
#[derive(Clone, PartialEq, Debug, Default)]
pub struct GrpcPingRequest;

/// gRPC PingResponse message
#[derive(Clone, PartialEq, Debug)]
pub struct GrpcPingResponse {
    pub ok: bool,
}

// =============================================================================
// gRPC Service Client (manual implementation matching geode.proto)
// =============================================================================

/// GeodeService gRPC client
///
/// Note: This is a stub implementation. The `inner` field is reserved
/// for future use when full gRPC support is implemented.
#[allow(dead_code)]
pub struct GeodeServiceClient<T> {
    inner: T,
}

impl GeodeServiceClient<Channel> {
    /// Create a new GeodeServiceClient from a channel
    pub fn new(channel: Channel) -> Self {
        Self { inner: channel }
    }

    /// Perform handshake RPC
    ///
    /// Note: This is a stub implementation. Full gRPC support requires
    /// proper protobuf code generation with prost-build.
    pub async fn handshake(
        &mut self,
        _request: Request<GrpcHelloRequest>,
    ) -> std::result::Result<tonic::Response<GrpcHelloResponse>, tonic::Status> {
        // TODO: Implement proper gRPC handshake using prost-generated types
        Err(tonic::Status::unimplemented(
            "gRPC client not fully implemented",
        ))
    }

    /// Execute query RPC (streaming response)
    ///
    /// Note: This is a stub implementation.
    pub async fn execute(
        &mut self,
        _request: Request<GrpcExecuteRequest>,
    ) -> std::result::Result<tonic::Response<Streaming<GrpcExecutionResponse>>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "gRPC client not fully implemented",
        ))
    }

    /// Ping RPC
    ///
    /// Note: This is a stub implementation.
    pub async fn ping(
        &mut self,
        _request: Request<GrpcPingRequest>,
    ) -> std::result::Result<tonic::Response<GrpcPingResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "gRPC client not fully implemented",
        ))
    }
}

/// Helper to encode HelloRequest for gRPC.
/// Reserved for future use when full gRPC encoding is implemented.
#[allow(dead_code)]
fn encode_grpc_hello_request(req: &GrpcHelloRequest, buf: &mut Vec<u8>) {
    // Field 1: username
    if !req.username.is_empty() {
        buf.push(0x0a); // tag 1, wire type 2 (length-delimited)
        encode_varint(req.username.len() as u64, buf);
        buf.extend(req.username.as_bytes());
    }
    // Field 2: password
    if !req.password.is_empty() {
        buf.push(0x12); // tag 2, wire type 2
        encode_varint(req.password.len() as u64, buf);
        buf.extend(req.password.as_bytes());
    }
    // Field 3: tenant_id (optional)
    if let Some(ref tenant) = req.tenant_id {
        if !tenant.is_empty() {
            buf.push(0x1a); // tag 3, wire type 2
            encode_varint(tenant.len() as u64, buf);
            buf.extend(tenant.as_bytes());
        }
    }
}

/// Encode a varint for protobuf encoding.
#[allow(dead_code)]
fn encode_varint(mut v: u64, buf: &mut Vec<u8>) {
    while v >= 0x80 {
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_value_default() {
        let val = GrpcValue::default();
        assert!(val.kind.is_none());
    }

    #[test]
    fn test_convert_proto_value_string() {
        let proto_val = GrpcValue {
            kind: Some(GrpcValueKind::StringVal("hello".to_string())),
        };
        let val = GrpcClient::convert_proto_value(&proto_val);
        assert_eq!(val.as_string().unwrap(), "hello");
    }

    #[test]
    fn test_convert_proto_value_int() {
        let proto_val = GrpcValue {
            kind: Some(GrpcValueKind::IntVal(42)),
        };
        let val = GrpcClient::convert_proto_value(&proto_val);
        assert_eq!(val.as_int().unwrap(), 42);
    }

    #[test]
    fn test_convert_proto_value_bool() {
        let proto_val = GrpcValue {
            kind: Some(GrpcValueKind::BoolVal(true)),
        };
        let val = GrpcClient::convert_proto_value(&proto_val);
        assert!(val.as_bool().unwrap());
    }

    #[test]
    fn test_convert_proto_value_null() {
        let proto_val = GrpcValue {
            kind: Some(GrpcValueKind::NullVal(true)),
        };
        let val = GrpcClient::convert_proto_value(&proto_val);
        assert!(val.is_null());
    }

    #[test]
    fn test_convert_proto_value_none() {
        let proto_val = GrpcValue { kind: None };
        let val = GrpcClient::convert_proto_value(&proto_val);
        assert!(val.is_null());
    }
}
