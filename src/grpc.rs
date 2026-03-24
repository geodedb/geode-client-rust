//! gRPC transport implementation for Geode.
//!
//! This module provides gRPC client functionality using the tonic-generated
//! `GeodeServiceClient` from `crate::proto::geode_service_client`.

use std::collections::HashMap;

use tonic::Request;
use tonic::transport::{Channel, Endpoint};

use crate::client::{Column, Page};
use crate::dsn::Dsn;
use crate::error::{Error, Result};
use crate::proto;
use crate::proto::execution_response::Payload;
use crate::proto::geode_service_client::GeodeServiceClient;
use crate::types::Value;

/// gRPC client for Geode.
///
/// Provides gRPC-based connection to the Geode database server using the
/// tonic-generated service client.
pub struct GrpcClient {
    client: GeodeServiceClient<Channel>,
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

        let grpc_client = GeodeServiceClient::new(channel);

        let mut client = Self {
            client: grpc_client,
            session_id: String::new(),
        };

        // Perform handshake
        client.handshake(dsn.username(), dsn.password()).await?;

        Ok(client)
    }

    /// Perform authentication handshake.
    async fn handshake(&mut self, username: Option<&str>, password: Option<&str>) -> Result<()> {
        let request = proto::HelloRequest {
            username: username.unwrap_or("").to_string(),
            password: password.unwrap_or("").to_string(),
            tenant_id: None,
            client_name: "geode-rust".to_string(),
            client_version: crate::VERSION.to_string(),
            wanted_conformance: "minimum".to_string(),
        };

        let response = self
            .client
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
        let proto_params: Vec<proto::Param> = params
            .iter()
            .map(|(k, v)| proto::Param {
                name: k.clone(),
                value: Some(v.to_proto_value()),
            })
            .collect();

        let request = proto::ExecuteRequest {
            session_id: self.session_id.clone(),
            query: gql.to_string(),
            params: proto_params,
        };

        let response = self
            .client
            .execute(Request::new(request))
            .await
            .map_err(|e| Error::query(format!("Query execution failed: {}", e)))?;

        // Process streaming response
        let mut stream = response.into_inner();
        let mut columns = Vec::new();
        let mut rows = Vec::new();
        let mut final_page = true;
        let mut ordered = false;
        let mut order_keys = Vec::new();

        while let Some(exec_resp) = stream
            .message()
            .await
            .map_err(|e| Error::query(format!("Failed to read response: {}", e)))?
        {
            if let Some(payload) = exec_resp.payload {
                match payload {
                    Payload::Schema(schema) => {
                        columns = schema
                            .columns
                            .into_iter()
                            .map(|c| Column {
                                name: c.name,
                                col_type: c.r#type,
                            })
                            .collect();
                    }
                    Payload::Page(page) => {
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
                        final_page = page.r#final;
                        ordered = page.ordered;
                        order_keys = page.order_keys;
                    }
                    Payload::Error(err) => {
                        return Err(Error::Query {
                            code: err.code,
                            message: err.message,
                        });
                    }
                    Payload::Metrics(_) | Payload::Heartbeat(_) => {
                        // Informational payloads, continue
                    }
                    Payload::Explain(_) | Payload::Profile(_) => {
                        // Plan/profile payloads, continue
                    }
                }
            }
        }

        Ok((
            Page {
                columns,
                rows,
                ordered,
                order_keys,
                final_page,
            },
            None,
        ))
    }

    /// Maximum recursion depth for converting nested protobuf values (CWE-674).
    const MAX_PROTO_RECURSION_DEPTH: usize = 64;

    /// Convert a proto Value to our Value type.
    /// Delegates to the depth-limited variant starting at depth 0.
    fn convert_proto_value(proto_val: &proto::Value) -> Value {
        Self::convert_proto_value_with_depth(proto_val, 0)
    }

    /// Depth-limited conversion of protobuf Value to our Value type.
    /// Returns `Value::null()` when recursion exceeds `MAX_PROTO_RECURSION_DEPTH`
    /// to prevent stack overflow from deeply nested or malicious payloads (CWE-674).
    fn convert_proto_value_with_depth(proto_val: &proto::Value, depth: usize) -> Value {
        if depth > Self::MAX_PROTO_RECURSION_DEPTH {
            return Value::null();
        }

        let next_depth = depth + 1;
        use crate::proto::value::Kind;
        match &proto_val.kind {
            Some(Kind::StringVal(s)) => Value::string(s.value.clone()),
            Some(Kind::IntVal(i)) => Value::int(i.value),
            Some(Kind::DoubleVal(d)) => {
                Value::decimal(rust_decimal::Decimal::from_f64_retain(d.value).unwrap_or_default())
            }
            Some(Kind::BoolVal(b)) => Value::bool(*b),
            Some(Kind::NullVal(_)) => Value::null(),
            Some(Kind::ListVal(list)) => {
                let values = list
                    .values
                    .iter()
                    .map(|v| Self::convert_proto_value_with_depth(v, next_depth))
                    .collect();
                Value::array(values)
            }
            Some(Kind::MapVal(map)) => {
                let mut obj = HashMap::new();
                for entry in &map.entries {
                    if let Some(ref val) = entry.value {
                        obj.insert(
                            entry.key.clone(),
                            Self::convert_proto_value_with_depth(val, next_depth),
                        );
                    }
                }
                Value::object(obj)
            }
            Some(Kind::DecimalVal(d)) => {
                if let Ok(dec) = d.coeff.parse::<rust_decimal::Decimal>() {
                    Value::decimal(dec)
                } else {
                    Value::string(d.orig_repr.clone())
                }
            }
            Some(Kind::BytesVal(b)) => Value::string(format!("\\x{}", hex::encode(&b.value))),
            _ => Value::null(),
        }
    }

    /// Begin a transaction.
    pub async fn begin(&mut self) -> Result<()> {
        let request = proto::BeginRequest {
            read_only: false,
            session_id: self.session_id.clone(),
        };

        self.client
            .begin(Request::new(request))
            .await
            .map_err(|e| Error::connection(format!("Begin transaction failed: {}", e)))?;

        Ok(())
    }

    /// Commit a transaction.
    pub async fn commit(&mut self) -> Result<()> {
        let request = proto::CommitRequest {
            session_id: self.session_id.clone(),
        };

        self.client
            .commit(Request::new(request))
            .await
            .map_err(|e| Error::connection(format!("Commit failed: {}", e)))?;

        Ok(())
    }

    /// Rollback a transaction.
    pub async fn rollback(&mut self) -> Result<()> {
        let request = proto::RollbackRequest {
            session_id: self.session_id.clone(),
        };

        self.client
            .rollback(Request::new(request))
            .await
            .map_err(|e| Error::connection(format!("Rollback failed: {}", e)))?;

        Ok(())
    }

    /// Send a ping request.
    pub async fn ping(&mut self) -> Result<bool> {
        let response = self
            .client
            .ping(Request::new(proto::PingRequest {}))
            .await
            .map_err(|e| Error::connection(format!("Ping failed: {}", e)))?;

        Ok(response.into_inner().ok)
    }

    /// Close the connection.
    pub fn close(&mut self) -> Result<()> {
        // gRPC channels are automatically closed when dropped
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto;

    #[test]
    fn test_convert_proto_value_string() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::StringVal(proto::StringValue {
                value: "hello".to_string(),
                kind: 0,
            })),
        };
        let val = GrpcClient::convert_proto_value(&proto_val);
        assert_eq!(val.as_string().unwrap(), "hello");
    }

    #[test]
    fn test_convert_proto_value_int() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::IntVal(proto::IntValue {
                value: 42,
                kind: 0,
            })),
        };
        let val = GrpcClient::convert_proto_value(&proto_val);
        assert_eq!(val.as_int().unwrap(), 42);
    }

    #[test]
    fn test_convert_proto_value_bool() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::BoolVal(true)),
        };
        let val = GrpcClient::convert_proto_value(&proto_val);
        assert!(val.as_bool().unwrap());
    }

    #[test]
    fn test_convert_proto_value_null() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::NullVal(proto::NullValue {})),
        };
        let val = GrpcClient::convert_proto_value(&proto_val);
        assert!(val.is_null());
    }

    #[test]
    fn test_convert_proto_value_none() {
        let proto_val = proto::Value { kind: None };
        let val = GrpcClient::convert_proto_value(&proto_val);
        assert!(val.is_null());
    }

    #[test]
    fn test_convert_proto_value_double() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::DoubleVal(proto::DoubleValue {
                value: 3.15,
                kind: 0,
            })),
        };
        let val = GrpcClient::convert_proto_value(&proto_val);
        assert!(val.as_decimal().is_ok());
    }

    #[test]
    fn test_convert_proto_value_list() {
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
        let val = GrpcClient::convert_proto_value(&proto_val);
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_int().unwrap(), 1);
        assert_eq!(arr[1].as_int().unwrap(), 2);
    }

    #[test]
    fn test_convert_proto_value_map() {
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
        let val = GrpcClient::convert_proto_value(&proto_val);
        let obj = val.as_object().unwrap();
        assert_eq!(obj.get("name").unwrap().as_string().unwrap(), "Alice");
    }
}
