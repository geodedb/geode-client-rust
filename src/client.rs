//! Geode client implementation using Quinn library for QUIC transport.
//! Switched back to Quinn from Quiche for better MsQuic compatibility.

use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName as RustlsServerName};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{timeout, Duration};

use crate::error::{Error, Result};
use crate::types::Value;

const GEODE_ALPN: &[u8] = b"geode/1";

/// Column in a result set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    #[serde(rename = "type")]
    pub col_type: String,
}

/// Page of query results
#[derive(Debug, Clone)]
pub struct Page {
    pub columns: Vec<Column>,
    pub rows: Vec<HashMap<String, Value>>,
    pub ordered: bool,
    pub order_keys: Vec<String>,
    pub final_page: bool,
}

/// Savepoint within a transaction
#[derive(Debug, Clone)]
pub struct Savepoint {
    pub name: String,
}

/// Geode database client using Quinn
#[derive(Clone)]
pub struct Client {
    host: String,
    port: u16,
    skip_verify: bool,
    page_size: usize,
    hello_name: String,
    hello_ver: String,
    conformance: String,
}

impl Client {
    /// Create a new QUIC client
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            skip_verify: false,
            page_size: 1000,
            hello_name: "geode-rust-quinn".to_string(),
            hello_ver: "0.1.0".to_string(),
            conformance: "min".to_string(),
        }
    }

    /// Skip TLS verification (insecure, for development only)
    pub fn skip_verify(mut self, skip: bool) -> Self {
        self.skip_verify = skip;
        self
    }

    /// Set page size for queries
    pub fn page_size(mut self, size: usize) -> Self {
        self.page_size = size;
        self
    }

    /// Set client name
    pub fn client_name(mut self, name: impl Into<String>) -> Self {
        self.hello_name = name.into();
        self
    }

    /// Set client version
    pub fn client_version(mut self, version: impl Into<String>) -> Self {
        self.hello_ver = version.into();
        self
    }

    /// Set GQL conformance level
    pub fn conformance(mut self, level: impl Into<String>) -> Self {
        self.conformance = level.into();
        self
    }

    /// Connect to the database (async with Quinn)
    pub async fn connect(&self) -> Result<Connection> {
        Connection::new(
            &self.host,
            self.port,
            self.skip_verify,
            self.page_size,
            &self.hello_name,
            &self.hello_ver,
            &self.conformance,
        )
        .await
    }
}

/// A single connection to Geode via QUIC (using Quinn)
pub struct Connection {
    conn: quinn::Connection,
    page_size: usize,
    send: quinn::SendStream,
    reader: BufReader<quinn::RecvStream>,
    next_request_id: u64,
}

impl Connection {
    async fn new(
        host: &str,
        port: u16,
        skip_verify: bool,
        page_size: usize,
        hello_name: &str,
        hello_ver: &str,
        conformance: &str,
    ) -> Result<Self> {
        let mut last_err: Option<Error> = None;

        for attempt in 1..=3 {
            match Self::connect_once(
                host,
                port,
                skip_verify,
                page_size,
                hello_name,
                hello_ver,
                conformance,
            )
            .await
            {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    last_err = Some(e);
                    if attempt < 3 {
                        eprintln!(
                            "[QUINN] Connection attempt {} failed, retrying...",
                            attempt
                        );
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| Error::connection("Failed to connect")))
    }

    async fn connect_once(
        host: &str,
        port: u16,
        skip_verify: bool,
        page_size: usize,
        hello_name: &str,
        hello_ver: &str,
        conformance: &str,
    ) -> Result<Self> {
        eprintln!("[QUINN] Creating connection to {}:{}", host, port);

        // Install default crypto provider for rustls
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Build Quinn client config with TLS 1.3 explicitly (QUIC requires TLS 1.3)
        let mut client_crypto = if skip_verify {
            eprintln!("[QUINN] Skipping certificate verification (insecure)");
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth()
        };

        // Set ALPN protocols
        client_crypto.alpn_protocols = vec![GEODE_ALPN.to_vec()];

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .map_err(|e| Error::connection(&format!("Failed to create QUIC config: {}", e)))?
        ));

        // Configure QUIC transport parameters to match Python/Go clients
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        client_config.transport_config(Arc::new(transport));

        // Create endpoint
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| Error::connection(&format!("Failed to create endpoint: {}", e)))?;
        endpoint.set_default_client_config(client_config);

        // Resolve server address (supports hostnames as well as IP literals)
        let mut resolved_addrs = format!("{}:{}", host, port)
            .to_socket_addrs()
            .map_err(|e| Error::connection(&format!("Failed to resolve address {}:{} - {}", host, port, e)))?;

        let server_addr: SocketAddr = resolved_addrs
            .find(|addr| matches!(addr, SocketAddr::V4(_) | SocketAddr::V6(_)))
            .ok_or_else(|| Error::connection("Invalid address: could not resolve host"))?;

        eprintln!("[QUINN] Connecting to {}", server_addr);

        // When skipping verification, don't use actual hostname for SNI
        // This matches Python client behavior which avoids server_name when skip_verify=True
        let server_name = if skip_verify {
            "localhost"  // Use generic name when skipping verification
        } else {
            host
        };

        eprintln!("[QUINN] Using server name: {}", server_name);

        let conn = timeout(
            Duration::from_secs(10),
            endpoint.connect(server_addr, server_name)
                .map_err(|e| Error::connection(&format!("Connection failed: {}", e)))?
        )
        .await
        .map_err(|_| Error::connection("Connection timeout"))?
        .map_err(|e| Error::connection(&format!("Failed to establish connection: {}", e)))?;

        eprintln!("[QUINN] ✓ Connection established!");

        // Open a single bidirectional stream used for the entire session.
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::connection(&format!("Failed to open stream: {}", e)))?;

        // Send HELLO message following Python/Go clients (newline-delimited JSON)
        let hello_msg = serde_json::json!({
            "type": "HELLO",
            "client_name": hello_name,
            "client_ver": hello_ver,
            "wanted_conformance": conformance,
        });

        let mut hello_line = serde_json::to_string(&hello_msg)
            .map_err(|e| Error::connection(&format!("Failed to serialize HELLO: {}", e)))?;
        hello_line.push('\n');

        send.write_all(hello_line.as_bytes())
            .await
            .map_err(|e| Error::connection(&format!("Failed to send HELLO: {}", e)))?;

        // Wait for HELLO response (line-delimited JSON)
        let mut reader = BufReader::new(recv);
        let mut response_line = String::new();
        let read_len = timeout(Duration::from_secs(5), reader.read_line(&mut response_line))
            .await
            .map_err(|_| Error::connection("HELLO response timeout"))?
            .map_err(|e| Error::connection(&format!("Failed to read HELLO response: {}", e)))?;

        if read_len == 0 {
            return Err(Error::connection("Connection closed before HELLO response"));
        }

        let hello_response: serde_json::Value = serde_json::from_str(&response_line)
            .map_err(|e| Error::connection(&format!("Invalid HELLO response: {}", e)))?;

        if hello_response.get("type").and_then(|t| t.as_str()) != Some("HELLO") {
            eprintln!("[QUINN] Unexpected HELLO response: {}", hello_response);
        }

        eprintln!("[QUINN] ✓ HELLO handshake complete");

        Ok(Self {
            conn,
            page_size,
            send,
            reader,
            next_request_id: 1,
        })
    }

    async fn send_json_line(&mut self, msg: &serde_json::Value) -> Result<()> {
        let mut line = serde_json::to_string(msg)
            .map_err(|e| Error::connection(&format!("Failed to serialize message: {}", e)))?;
        line.push('\n');
        self.send
            .write_all(line.as_bytes())
            .await
            .map_err(|e| Error::connection(&format!("Failed to send message: {}", e)))?;
        Ok(())
    }

    async fn read_json_line(&mut self, timeout_secs: u64) -> Result<serde_json::Value> {
        let mut line = String::new();
        let n = timeout(Duration::from_secs(timeout_secs), self.reader.read_line(&mut line))
            .await
            .map_err(|_| Error::timeout())?
            .map_err(|e| Error::connection(&format!("Failed to read response: {}", e)))?;

        if n == 0 {
            return Err(Error::connection("Connection closed"));
        }

        serde_json::from_str(&line)
            .map_err(|e| Error::connection(&format!("Invalid JSON response: {}", e)))
    }

    fn parse_rows(
        &self,
        rows_value: &serde_json::Value,
        columns: &[Column],
    ) -> Result<Vec<HashMap<String, Value>>> {
        let rows_array = rows_value
            .as_array()
            .ok_or_else(|| Error::query("Response rows is not an array"))?;

        let mut rows = Vec::new();
        for row_json in rows_array {
            let row_obj = row_json
                .as_object()
                .ok_or_else(|| Error::query("Row is not an object"))?;

            let mut row = HashMap::new();
            for (col_name, col_value) in row_obj {
                let col_type = columns
                    .iter()
                    .find(|c| &c.name == col_name)
                    .map(|c| c.col_type.as_str())
                    .unwrap_or("");

                let value = crate::types::decode_value(col_value, col_type)?;
                row.insert(col_name.clone(), value);
            }
            rows.push(row);
        }

        Ok(rows)
    }

    async fn send_control(&mut self, msg_type: &str) -> Result<()> {
        let msg = serde_json::json!({ "type": msg_type });
        self.send_json_line(&msg).await?;

        // Control frames typically echo back a STATUS/ACK result; treat ERROR specially.
        let resp = self.read_json_line(5).await?;
        if let Some(result) = resp.get("result") {
            if result
                .get("type")
                .and_then(|t| t.as_str())
                == Some("ERROR")
            {
                let code = result
                    .get("code")
                    .and_then(|c| c.as_str())
                    .unwrap_or("UNKNOWN");
                let message = result
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Command failed");
                return Err(Error::Query {
                    code: code.to_string(),
                    message: message.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Execute a GQL query
    pub async fn query(&mut self, gql: &str) -> Result<(Page, Option<String>)> {
        self.query_with_params(gql, &HashMap::new()).await
    }

    /// Execute a GQL query with parameters
    pub async fn query_with_params(
        &mut self,
        gql: &str,
        params: &HashMap<String, Value>,
    ) -> Result<(Page, Option<String>)> {
        let params_json: serde_json::Map<String, serde_json::Value> = params
            .iter()
            .map(|(k, v)| (k.clone(), v.to_json()))
            .collect();

        let run_msg = if params_json.is_empty() {
            serde_json::json!({
                "type": "RUN_GQL",
                "text": gql,
            })
        } else {
            serde_json::json!({
                "type": "RUN_GQL",
                "text": gql,
                "params": params_json,
            })
        };

        self.send_json_line(&run_msg)
            .await
            .map_err(|e| Error::query(format!("{}", e)))?;

        let schema_frame = self.read_json_line(10).await?;
        let result = schema_frame
            .get("result")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        let res_type = result
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("");

        if res_type == "ERROR" {
            let code = result.get("code").and_then(|c| c.as_str()).unwrap_or("UNKNOWN");
            let msg = result
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Query failed");
            return Err(Error::Query {
                code: code.to_string(),
                message: msg.to_string(),
            });
        }

        if res_type != "SCHEMA" {
            return Err(Error::protocol(format!(
                "Unexpected first frame: {}",
                res_type
            )));
        }

        let columns: Vec<Column> = serde_json::from_value(
            result
                .get("columns")
                .cloned()
                .unwrap_or_else(|| serde_json::Value::Array(vec![])),
        )
        .map_err(|e| Error::protocol(&format!("Failed to parse columns: {}", e)))?;

        if std::env::var("GEODE_RUST_DEBUG").is_ok() {
            eprintln!("[QUINN] Columns: {:?}", columns);
        }

        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);

        let pull_msg = serde_json::json!({
            "type": "PULL",
            "request_id": request_id,
            "page_size": self.page_size,
        });
        self.send_json_line(&pull_msg)
            .await
            .map_err(|e| Error::query(format!("{}", e)))?;

        let mut all_rows: Vec<HashMap<String, Value>> = Vec::new();
        let mut ordered = false;
        let mut order_keys: Vec<String> = Vec::new();
        let mut final_page = true;

        loop {
            let frame = self.read_json_line(30).await?;
            let result = frame
                .get("result")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));

            let r#type = result
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("");

            match r#type {
                "BINDINGS" => {
                    ordered = result
                        .get("ordered")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    order_keys = result
                        .get("order_keys")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    let rows = self.parse_rows(
                        result
                            .get("rows")
                            .unwrap_or(&serde_json::Value::Array(vec![])),
                        &columns,
                    )?;
                    all_rows.extend(rows);

                    final_page = result
                        .get("final")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if final_page {
                        break;
                    }

                    self.send_json_line(&pull_msg)
                        .await
                        .map_err(|e| Error::query(format!("{}", e)))?;
                }
                "RESULT" | "STATUS" | "PROFILE" => {
                    final_page = true;
                    break;
                }
                "ERROR" => {
                    let msg = result
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Query failed");
                    let code = result
                        .get("code")
                        .and_then(|c| c.as_str())
                        .unwrap_or("UNKNOWN");
                    return Err(Error::Query {
                        code: code.to_string(),
                        message: msg.to_string(),
                    });
                }
                other => {
                    return Err(Error::protocol(format!("Unexpected frame type: {}", other)));
                }
            }
        }

        let page = Page {
            columns,
            rows: all_rows,
            ordered,
            order_keys,
            final_page,
        };

        Ok((page, None))
    }

    /// Execute a query without parameters (synchronous-style blocking version for test runner)
    pub fn query_sync(&mut self, gql: &str, params: Option<HashMap<String, serde_json::Value>>) -> Result<Page> {
        let params_map = params.unwrap_or_default();
        let params_typed: HashMap<String, Value> = params_map
            .into_iter()
            .map(|(k, v)| {
                let typed_val = crate::types::Value::from_json(v);
                (k, typed_val)
            })
            .collect();

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let (page, _cursor) = handle.block_on(self.query_with_params(gql, &params_typed))?;
                Ok(page)
            }
            Err(_) => {
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| Error::query(&format!("Failed to create runtime: {}", e)))?;
                let (page, _cursor) = rt.block_on(self.query_with_params(gql, &params_typed))?;
                Ok(page)
            }
        }
    }

    /// Begin a transaction
    pub fn begin(&mut self) -> Result<()> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(self.send_control("BEGIN")),
            Err(_) => {
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| Error::query(&format!("Failed to create runtime: {}", e)))?;
                rt.block_on(self.send_control("BEGIN"))
            }
        }
    }

    /// Commit a transaction
    pub fn commit(&mut self) -> Result<()> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(self.send_control("COMMIT")),
            Err(_) => {
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| Error::query(&format!("Failed to create runtime: {}", e)))?;
                rt.block_on(self.send_control("COMMIT"))
            }
        }
    }

    /// Rollback a transaction
    pub fn rollback(&mut self) -> Result<()> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(self.send_control("ROLLBACK")),
            Err(_) => {
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| Error::query(&format!("Failed to create runtime: {}", e)))?;
                rt.block_on(self.send_control("ROLLBACK"))
            }
        }
    }

    /// Close the connection
    pub fn close(&mut self) -> Result<()> {
        self.conn.close(0u32.into(), b"client closing");
        // Small delay for close to be sent
        std::thread::sleep(std::time::Duration::from_millis(100));
        Ok(())
    }
}

/// Certificate verifier that skips all verification (INSECURE - for development only)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &RustlsServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
