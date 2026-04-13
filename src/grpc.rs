//! gRPC transport implementation for Geode.
//!
//! This module provides gRPC client functionality using the tonic-generated
//! `GeodeServiceClient` from `crate::proto::geode_service_client`.

use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::Uri;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector as RustlsConnector;
use tonic::Request;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tower_service::Service;

use crate::client::{Column, Page};
use crate::dsn::Dsn;
use crate::error::{Error, Result};
use crate::proto;
use crate::proto::execution_response::Payload;
use crate::proto::geode_service_client::GeodeServiceClient;
use crate::types::Value;

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[derive(Clone)]
struct InsecureTlsConnector {
    config: Arc<rustls::ClientConfig>,
    server_name: rustls::pki_types::ServerName<'static>,
}

impl Service<Uri> for InsecureTlsConnector {
    type Response = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let addr = match (uri.host(), uri.port_u16()) {
            (Some(host), Some(port)) => format!("{host}:{port}"),
            (Some(host), None) => format!("{host}:443"),
            _ => {
                return Box::pin(async {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "missing host in URI",
                    ))
                });
            }
        };
        let connector = RustlsConnector::from(self.config.clone());
        let server_name = self.server_name.clone();

        Box::pin(async move {
            let stream = TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            let tls = connector
                .connect(server_name, stream)
                .await
                .map_err(std::io::Error::other)?;
            Ok(TokioIo::new(tls))
        })
    }
}

/// gRPC client for Geode.
///
/// Provides gRPC-based connection to the Geode database server using the
/// tonic-generated service client.
pub struct GrpcClient {
    dsn: Dsn,
    session_id: String,
}

impl GrpcClient {
    async fn connect_channel(dsn: &Dsn) -> Result<Channel> {
        // tonic/rustls TLS setup requires a process-wide crypto provider.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let addr = if dsn.tls_enabled() && !dsn.skip_verify() {
            format!("https://{}", dsn.address())
        } else {
            format!("http://{}", dsn.address())
        };

        let mut endpoint = Endpoint::from_shared(addr.clone())
            .map_err(|e| Error::connection(format!("Invalid endpoint: {}", e)))?;

        let tls_server_name =
            dsn.server_name()
                .map(str::to_string)
                .or_else(|| match dsn.host().parse::<IpAddr>() {
                    Ok(_) => Some("localhost".to_string()),
                    Err(_) => None,
                });

        if dsn.tls_enabled() {
            if let Some(server_name) = &tls_server_name {
                let origin = format!("https://{}:{}", server_name, dsn.port())
                    .parse()
                    .map_err(|e| Error::tls(format!("Invalid TLS origin: {}", e)))?;
                endpoint = endpoint.origin(origin);
            }
        }

        if dsn.tls_enabled() && dsn.skip_verify() {
            let mut client_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_no_client_auth();
            client_config.alpn_protocols.push(b"h2".to_vec());

            let server_name = tls_server_name
                .unwrap_or_else(|| dsn.host().to_string())
                .try_into()
                .map_err(|e| Error::tls(format!("Invalid TLS server name: {}", e)))?;

            endpoint
                .connect_with_connector(InsecureTlsConnector {
                    config: Arc::new(client_config),
                    server_name,
                })
                .await
                .map_err(|e| {
                    Error::connection(format!(
                        "gRPC connection failed to {}: {} ({:?})",
                        addr, e, e
                    ))
                })
        } else if dsn.tls_enabled() {
            let mut tls = ClientTlsConfig::new()
                .with_enabled_roots()
                .assume_http2(true);

            if let Some(server_name) = tls_server_name {
                tls = tls.domain_name(server_name);
            }

            if let Some(ca_cert_path) = dsn.ca_cert() {
                let ca_pem = fs::read(ca_cert_path).map_err(|e| {
                    Error::tls(format!(
                        "Failed to read CA certificate {}: {}",
                        ca_cert_path, e
                    ))
                })?;
                tls = tls.ca_certificate(Certificate::from_pem(ca_pem));
            }

            endpoint
                .tls_config(tls)
                .map_err(|e| Error::tls(format!("TLS config error: {}", e)))?
                .connect()
                .await
                .map_err(|e| {
                    Error::connection(format!(
                        "gRPC connection failed to {}: {} ({:?})",
                        addr, e, e
                    ))
                })
        } else {
            endpoint.connect().await.map_err(|e| {
                Error::connection(format!(
                    "gRPC connection failed to {}: {} ({:?})",
                    addr, e, e
                ))
            })
        }
    }

    async fn connect_service(dsn: &Dsn) -> Result<GeodeServiceClient<Channel>> {
        let channel = Self::connect_channel(dsn).await?;
        Ok(GeodeServiceClient::new(channel))
    }

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
        let mut grpc_client = Self::connect_service(dsn).await?;
        let session_id = Self::handshake(
            &mut grpc_client,
            dsn.username(),
            dsn.password(),
            dsn.graph(),
        )
        .await?;

        Ok(Self {
            dsn: dsn.clone(),
            session_id,
        })
    }

    /// Perform authentication handshake.
    async fn handshake(
        client: &mut GeodeServiceClient<Channel>,
        username: Option<&str>,
        password: Option<&str>,
        graph: Option<&str>,
    ) -> Result<String> {
        let request = proto::HelloRequest {
            username: username.unwrap_or("").to_string(),
            password: password.unwrap_or("").to_string(),
            tenant_id: None,
            client_name: "geode-rust".to_string(),
            client_version: crate::VERSION.to_string(),
            wanted_conformance: "minimum".to_string(),
            graph: graph.map(String::from),
        };

        let response = client
            .handshake(Request::new(request))
            .await
            .map_err(|e| Error::connection(format!("Handshake failed: {}", e)))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(Error::auth(resp.error_message));
        }

        Ok(resp.session_id)
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

        // The current server can leave tonic channels in a bad state after
        // previous RPCs. Use a fresh channel per RPC and keep only the
        // server-side session stable via session_id.
        let mut client = Self::connect_service(&self.dsn).await?;
        let response = client
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
                                    crate::convert::proto_to_value(&row.values[i])
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

    /// Begin a transaction.
    pub async fn begin(&mut self) -> Result<()> {
        let request = proto::BeginRequest {
            read_only: false,
            session_id: self.session_id.clone(),
        };

        let mut client = Self::connect_service(&self.dsn).await?;
        client
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

        let mut client = Self::connect_service(&self.dsn).await?;
        client
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

        let mut client = Self::connect_service(&self.dsn).await?;
        client
            .rollback(Request::new(request))
            .await
            .map_err(|e| Error::connection(format!("Rollback failed: {}", e)))?;

        Ok(())
    }

    /// Create a savepoint within the current transaction.
    ///
    /// Note: Savepoints are not yet supported via the gRPC service definition.
    /// This method will return an error until the gRPC service is updated.
    pub async fn savepoint(&mut self, _name: &str) -> Result<()> {
        Err(Error::connection(
            "savepoint is not yet supported via gRPC transport",
        ))
    }

    /// Roll back to a previously created savepoint.
    ///
    /// Note: Rollback-to-savepoint is not yet supported via the gRPC service definition.
    /// This method will return an error until the gRPC service is updated.
    pub async fn rollback_to(&mut self, _name: &str) -> Result<()> {
        Err(Error::connection(
            "rollback_to is not yet supported via gRPC transport",
        ))
    }

    /// Send a ping request.
    pub async fn ping(&mut self) -> Result<bool> {
        let mut client = Self::connect_service(&self.dsn).await?;
        let response = client
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
    use crate::proto;

    #[test]
    fn test_convert_proto_value_string() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::StringVal(proto::StringValue {
                value: "hello".to_string(),
                kind: 0,
            })),
        };
        let val = crate::convert::proto_to_value(&proto_val);
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
        let val = crate::convert::proto_to_value(&proto_val);
        assert_eq!(val.as_int().unwrap(), 42);
    }

    #[test]
    fn test_convert_proto_value_bool() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::BoolVal(true)),
        };
        let val = crate::convert::proto_to_value(&proto_val);
        assert!(val.as_bool().unwrap());
    }

    #[test]
    fn test_convert_proto_value_null() {
        let proto_val = proto::Value {
            kind: Some(proto::value::Kind::NullVal(proto::NullValue {})),
        };
        let val = crate::convert::proto_to_value(&proto_val);
        assert!(val.is_null());
    }

    #[test]
    fn test_convert_proto_value_none() {
        let proto_val = proto::Value { kind: None };
        let val = crate::convert::proto_to_value(&proto_val);
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
        let val = crate::convert::proto_to_value(&proto_val);
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
        let val = crate::convert::proto_to_value(&proto_val);
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
        let val = crate::convert::proto_to_value(&proto_val);
        let obj = val.as_object().unwrap();
        assert_eq!(obj.get("name").unwrap().as_string().unwrap(), "Alice");
    }
}
