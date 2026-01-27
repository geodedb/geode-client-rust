//! Geode client implementation using Quinn library for QUIC transport.
//! Switched back to Quinn from Quiche for better MsQuic compatibility.

use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName as RustlsServerName};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::{timeout, Duration};

use crate::error::{Error, Result};
use crate::types::Value;

const GEODE_ALPN: &[u8] = b"geode/1";

/// A column definition in a query result set.
///
/// Contains the column name and its GQL type as returned by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Column {
    /// The column name (or alias if specified in the query)
    pub name: String,
    /// The GQL type of the column (e.g., "INT", "STRING", "BOOL")
    #[serde(rename = "type")]
    pub col_type: String,
}

/// A page of query results.
///
/// Query results are returned in pages. Each page contains a slice of rows
/// along with metadata about the result set.
///
/// # Example
///
/// ```ignore
/// let (page, _) = conn.query("MATCH (n:Person) RETURN n.name, n.age").await?;
///
/// for row in &page.rows {
///     let name = row.get("name").unwrap().as_string()?;
///     let age = row.get("age").unwrap().as_int()?;
///     println!("{}: {}", name, age);
/// }
///
/// if !page.final_page {
///     // More results available, would need to pull next page
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Page {
    /// Column definitions for the result set
    pub columns: Vec<Column>,
    /// Result rows, each row is a map of column name to value
    pub rows: Vec<HashMap<String, Value>>,
    /// Whether results are ordered (ORDER BY was used)
    pub ordered: bool,
    /// The keys used for ordering, if any
    pub order_keys: Vec<String>,
    /// Whether this is the final page of results
    pub final_page: bool,
}

/// A named savepoint within a transaction.
///
/// Savepoints allow partial rollback within a transaction. They can be created
/// and managed via server-side GQL commands.
///
/// # Example
///
/// ```ignore
/// conn.begin().await?;
/// conn.query("CREATE (n:Node {id: 1})").await?;
///
/// let sp = conn.savepoint("before_risky_op")?;
/// match conn.query("CREATE (n:Node {id: 2})").await {
///     Ok(_) => {},
///     Err(_) => conn.rollback_to(&sp).await?,  // Undo only the second create
/// }
///
/// conn.commit().await?;  // First node is saved
/// ```
#[derive(Debug, Clone)]
pub struct Savepoint {
    /// The savepoint name
    pub name: String,
}

/// A prepared statement for efficient repeated query execution.
///
/// Prepared statements allow you to define a query once and execute it
/// multiple times with different parameters. This can improve performance
/// by allowing query plan caching on the server.
///
/// # Example
///
/// ```ignore
/// let stmt = conn.prepare("MATCH (p:Person {id: $id}) RETURN p").await?;
///
/// for id in 1..=100 {
///     let mut params = HashMap::new();
///     params.insert("id".to_string(), Value::int(id));
///     let (page, _) = stmt.execute(&mut conn, &params).await?;
///     // Process results...
/// }
/// ```
#[derive(Debug, Clone)]
pub struct PreparedStatement {
    /// The GQL query string
    query: String,
    /// Parameter names extracted from the query
    param_names: Vec<String>,
}

impl PreparedStatement {
    /// Create a new prepared statement.
    ///
    /// Extracts parameter names from the query (tokens starting with `$`).
    pub fn new(query: impl Into<String>) -> Self {
        let query = query.into();
        let param_names = Self::extract_param_names(&query);
        Self { query, param_names }
    }

    /// Extract parameter names from a query string.
    fn extract_param_names(query: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut chars = query.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '$' {
                let mut name = String::new();
                while let Some(&next) = chars.peek() {
                    if next.is_ascii_alphanumeric() || next == '_' {
                        name.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                if !name.is_empty() && !names.contains(&name) {
                    names.push(name);
                }
            }
        }

        names
    }

    /// Get the query string.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Get the parameter names expected by this statement.
    pub fn param_names(&self) -> &[String] {
        &self.param_names
    }

    /// Execute the prepared statement with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `conn` - The connection to execute on
    /// * `params` - Parameter values (must include all parameters in the query)
    ///
    /// # Returns
    ///
    /// A tuple of (`Page`, `Option<String>`) with results and optional warnings.
    ///
    /// # Errors
    ///
    /// Returns an error if required parameters are missing or if the query fails.
    pub async fn execute(
        &self,
        conn: &mut Connection,
        params: &HashMap<String, crate::types::Value>,
    ) -> crate::error::Result<(Page, Option<String>)> {
        // Validate all required parameters are provided
        for name in &self.param_names {
            if !params.contains_key(name) {
                return Err(crate::error::Error::validation(format!(
                    "Missing required parameter: {}",
                    name
                )));
            }
        }

        conn.query_with_params(&self.query, params).await
    }
}

/// An operation in a query execution plan.
#[derive(Debug, Clone)]
pub struct PlanOperation {
    /// Operation type (e.g., "NodeScan", "Filter", "Projection")
    pub op_type: String,
    /// Human-readable description
    pub description: String,
    /// Estimated row count for this operation
    pub estimated_rows: Option<u64>,
    /// Child operations
    pub children: Vec<PlanOperation>,
}

/// A query execution plan.
///
/// Shows how the database will execute a query without actually running it.
/// Useful for query optimization and understanding performance characteristics.
#[derive(Debug, Clone)]
pub struct QueryPlan {
    /// Root operations in the plan
    pub operations: Vec<PlanOperation>,
    /// Total estimated rows
    pub estimated_rows: u64,
    /// Raw plan from server (for advanced analysis)
    pub raw: serde_json::Value,
}

/// Query execution profile with timing information.
///
/// Includes the execution plan plus actual runtime statistics.
#[derive(Debug, Clone)]
pub struct QueryProfile {
    /// The execution plan
    pub plan: QueryPlan,
    /// Actual rows returned
    pub actual_rows: u64,
    /// Total execution time in milliseconds
    pub execution_time_ms: f64,
    /// Raw profile from server
    pub raw: serde_json::Value,
}

/// A Geode database client using QUIC transport.
///
/// Use the builder pattern to configure the client, then call [`connect`](Client::connect)
/// to establish a connection.
///
/// # Example
///
/// ```no_run
/// use geode_client::Client;
///
/// # async fn example() -> geode_client::Result<()> {
/// let client = Client::new("127.0.0.1", 3141)
///     .skip_verify(true)  // Development only!
///     .page_size(500)
///     .client_name("my-app");
///
/// let mut conn = client.connect().await?;
/// let (page, _) = conn.query("RETURN 1 AS x").await?;
/// conn.close()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Client {
    host: String,
    port: u16,
    skip_verify: bool,
    page_size: usize,
    hello_name: String,
    hello_ver: String,
    conformance: String,
    username: Option<String>,
    password: Option<String>,
}

impl Client {
    /// Create a new QUIC client for the specified host and port.
    ///
    /// # Arguments
    ///
    /// * `host` - The server hostname or IP address
    /// * `port` - The server port (typically 3141 for Geode)
    ///
    /// # Example
    ///
    /// ```
    /// use geode_client::Client;
    ///
    /// let client = Client::new("localhost", 3141);
    /// let client = Client::new("192.168.1.100", 8443);
    /// let client = Client::new(String::from("geode.example.com"), 3141);
    /// ```
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            skip_verify: false,
            page_size: 1000,
            hello_name: "geode-rust-quinn".to_string(),
            hello_ver: "0.1.0".to_string(),
            conformance: "min".to_string(),
            username: None,
            password: None,
        }
    }

    /// Create a new client from a DSN (Data Source Name) string.
    ///
    /// Supported formats:
    /// - `host:port` - Basic connection
    /// - `host:port?options` - With query parameters
    /// - `geode://host:port?options` - URL format
    /// - `geode://user:pass@host:port?options` - With authentication
    ///
    /// Supported options:
    /// - `page_size` - Results page size (default: 1000)
    /// - `hello_name` - Client name (default: "geode-rust-quinn")
    /// - `hello_ver` - Client version (default: "0.1.0")
    /// - `conformance` - GQL conformance level (default: "min")
    /// - `insecure` - Skip TLS verification (true/false, default: false)
    ///
    /// # Example
    ///
    /// ```
    /// use geode_client::Client;
    ///
    /// // Simple DSN
    /// let client = Client::from_dsn("localhost:3141").unwrap();
    ///
    /// // With options
    /// let client = Client::from_dsn("localhost:3141?insecure=true&page_size=500").unwrap();
    ///
    /// // URL format with auth
    /// let client = Client::from_dsn("geode://admin:secret@localhost:3141?insecure=true").unwrap();
    /// ```
    pub fn from_dsn(dsn: &str) -> Result<Self> {
        let dsn = dsn.trim();
        if dsn.is_empty() {
            return Err(Error::invalid_dsn("DSN cannot be empty"));
        }

        // Check for URL format
        if dsn.starts_with("geode://") {
            return Self::parse_url_dsn(dsn);
        }

        // Parse as host:port?options
        Self::parse_simple_dsn(dsn)
    }

    fn parse_url_dsn(dsn: &str) -> Result<Self> {
        use std::collections::HashMap;

        // Parse as URL
        let url = url::Url::parse(dsn)
            .map_err(|e| Error::invalid_dsn(format!("Invalid URL format: {}", e)))?;

        let host = url
            .host_str()
            .ok_or_else(|| Error::invalid_dsn("Host is required"))?
            .to_string();

        let port = url.port().unwrap_or(3141);

        // Extract username/password
        let username = if !url.username().is_empty() {
            Some(
                urlencoding::decode(url.username())
                    .map_err(|e| Error::invalid_dsn(format!("Invalid username encoding: {}", e)))?
                    .into_owned(),
            )
        } else {
            None
        };

        let password = url.password().map(|p| {
            urlencoding::decode(p)
                .map(|s| s.into_owned())
                .unwrap_or_else(|_| p.to_string())
        });

        // Parse query parameters
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();

        let mut client = Self::new(host, port);
        client.username = username;
        client.password = password;

        Self::apply_params(&mut client, &params)?;

        Ok(client)
    }

    fn parse_simple_dsn(dsn: &str) -> Result<Self> {
        use std::collections::HashMap;

        // Split off query string
        let (host_port, query_str) = if let Some(idx) = dsn.find('?') {
            (&dsn[..idx], Some(&dsn[idx + 1..]))
        } else {
            (dsn, None)
        };

        // Parse host:port
        let (host, port) = if let Some(idx) = host_port.rfind(':') {
            let host = &host_port[..idx];
            let port_str = &host_port[idx + 1..];
            let port = port_str
                .parse::<u16>()
                .map_err(|_| Error::invalid_dsn(format!("Invalid port: {}", port_str)))?;
            (host.to_string(), port)
        } else {
            (host_port.to_string(), 3141)
        };

        if host.is_empty() {
            return Err(Error::invalid_dsn("Host is required"));
        }

        let mut client = Self::new(host, port);

        // Parse query parameters
        if let Some(qs) = query_str {
            let params: HashMap<String, String> = qs
                .split('&')
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let key = parts.next()?;
                    let value = parts.next().unwrap_or("");
                    Some((key.to_string(), value.to_string()))
                })
                .collect();

            Self::apply_params(&mut client, &params)?;
        }

        Ok(client)
    }

    fn apply_params(
        client: &mut Self,
        params: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        for (key, value) in params {
            match key.as_str() {
                "page_size" => {
                    client.page_size = value
                        .parse()
                        .map_err(|_| Error::invalid_dsn(format!("Invalid page_size: {}", value)))?;
                }
                "hello_name" => {
                    client.hello_name = value.clone();
                }
                "hello_ver" => {
                    client.hello_ver = value.clone();
                }
                "conformance" => {
                    client.conformance = value.clone();
                }
                "insecure" => {
                    client.skip_verify = value == "true" || value == "1";
                }
                "username" | "user" => {
                    client.username = Some(value.clone());
                }
                "password" | "pass" => {
                    client.password = Some(value.clone());
                }
                _ => {
                    // Ignore unknown parameters for forward compatibility
                }
            }
        }
        Ok(())
    }

    /// Skip TLS certificate verification.
    ///
    /// # Security Warning
    ///
    /// **This should only be used in development environments.** Disabling
    /// certificate verification makes the connection vulnerable to
    /// man-in-the-middle attacks.
    ///
    /// # Arguments
    ///
    /// * `skip` - If true, skip certificate verification
    pub fn skip_verify(mut self, skip: bool) -> Self {
        self.skip_verify = skip;
        self
    }

    /// Set the page size for query results.
    ///
    /// Controls how many rows are returned per page when fetching results.
    /// Larger values reduce round-trips but use more memory.
    ///
    /// # Arguments
    ///
    /// * `size` - Number of rows per page (default: 1000)
    pub fn page_size(mut self, size: usize) -> Self {
        self.page_size = size;
        self
    }

    /// Set the client name sent to the server.
    ///
    /// This appears in server logs and can help with debugging.
    ///
    /// # Arguments
    ///
    /// * `name` - Client application name (default: "geode-rust-quinn")
    pub fn client_name(mut self, name: impl Into<String>) -> Self {
        self.hello_name = name.into();
        self
    }

    /// Set the client version sent to the server.
    ///
    /// # Arguments
    ///
    /// * `version` - Client version string (default: "0.1.0")
    pub fn client_version(mut self, version: impl Into<String>) -> Self {
        self.hello_ver = version.into();
        self
    }

    /// Set the GQL conformance level.
    ///
    /// # Arguments
    ///
    /// * `level` - Conformance level (default: "min")
    pub fn conformance(mut self, level: impl Into<String>) -> Self {
        self.conformance = level.into();
        self
    }

    /// Set the authentication username.
    ///
    /// # Arguments
    ///
    /// * `username` - The username for authentication
    ///
    /// # Example
    ///
    /// ```
    /// use geode_client::Client;
    ///
    /// let client = Client::new("localhost", 3141)
    ///     .username("admin")
    ///     .password("secret");
    /// ```
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the authentication password.
    ///
    /// # Arguments
    ///
    /// * `password` - The password for authentication
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Connect to the Geode database.
    ///
    /// Establishes a QUIC connection to the server, performs the TLS handshake,
    /// and sends the initial HELLO message.
    ///
    /// # Returns
    ///
    /// A [`Connection`] that can be used to execute queries.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The hostname cannot be resolved
    /// - The connection cannot be established
    /// - TLS verification fails (unless `skip_verify` is true)
    /// - The HELLO handshake fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use geode_client::Client;
    /// # async fn example() -> geode_client::Result<()> {
    /// let client = Client::new("localhost", 3141).skip_verify(true);
    /// let mut conn = client.connect().await?;
    /// // Use connection...
    /// conn.close()?;
    /// # Ok(())
    /// # }
    /// ```
    // CANARY: REQ=REQ-CLIENT-RUST-001; FEATURE="RustClientConnection"; ASPECT=HelloHandshake; STATUS=IMPL; OWNER=clients; UPDATED=2025-02-14
    pub async fn connect(&self) -> Result<Connection> {
        Connection::new(
            &self.host,
            self.port,
            self.skip_verify,
            self.page_size,
            &self.hello_name,
            &self.hello_ver,
            &self.conformance,
            self.username.as_deref(),
            self.password.as_deref(),
        )
        .await
    }
}

/// An active connection to a Geode database server.
///
/// A `Connection` represents a single QUIC connection with an open bidirectional
/// stream for communication. It provides methods for executing queries, managing
/// transactions, and controlling the connection lifecycle.
///
/// # Connection Lifecycle
///
/// 1. Create via [`Client::connect`]
/// 2. Execute queries with [`query`](Connection::query) or [`query_with_params`](Connection::query_with_params)
/// 3. Optionally use transactions with [`begin`](Connection::begin), [`commit`](Connection::commit), [`rollback`](Connection::rollback)
/// 4. Close with [`close`](Connection::close)
///
/// # Example
///
/// ```no_run
/// # use geode_client::Client;
/// # async fn example() -> geode_client::Result<()> {
/// let client = Client::new("localhost", 3141).skip_verify(true);
/// let mut conn = client.connect().await?;
///
/// // Execute queries
/// let (page, _) = conn.query("RETURN 42 AS answer").await?;
/// println!("Answer: {}", page.rows[0].get("answer").unwrap().as_int()?);
///
/// // Use transactions
/// conn.begin().await?;
/// conn.query("CREATE (n:Node {id: 1})").await?;
/// conn.commit().await?;
///
/// conn.close()?;
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// `Connection` is `!Sync` because the underlying QUIC stream is not thread-safe.
/// For concurrent access, use [`ConnectionPool`](crate::ConnectionPool).
pub struct Connection {
    conn: quinn::Connection,
    page_size: usize,
    send: quinn::SendStream,
    reader: BufReader<quinn::RecvStream>,
    next_request_id: u64,
}

impl Connection {
    #[allow(clippy::too_many_arguments)]
    async fn new(
        host: &str,
        port: u16,
        skip_verify: bool,
        page_size: usize,
        hello_name: &str,
        hello_ver: &str,
        conformance: &str,
        username: Option<&str>,
        password: Option<&str>,
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
                username,
                password,
            )
            .await
            {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    last_err = Some(e);
                    if attempt < 3 {
                        eprintln!("[QUINN] Connection attempt {} failed, retrying...", attempt);
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| Error::connection("Failed to connect")))
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_once(
        host: &str,
        port: u16,
        skip_verify: bool,
        page_size: usize,
        hello_name: &str,
        hello_ver: &str,
        conformance: &str,
        username: Option<&str>,
        password: Option<&str>,
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
                .map_err(|e| Error::connection(format!("Failed to create QUIC config: {}", e)))?,
        ));

        // Configure QUIC transport parameters to match Python/Go clients
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        client_config.transport_config(Arc::new(transport));

        // Create endpoint
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| Error::connection(format!("Failed to create endpoint: {}", e)))?;
        endpoint.set_default_client_config(client_config);

        // Resolve server address (supports hostnames as well as IP literals)
        let mut resolved_addrs = format!("{}:{}", host, port)
            .to_socket_addrs()
            .map_err(|e| {
                Error::connection(format!(
                    "Failed to resolve address {}:{} - {}",
                    host, port, e
                ))
            })?;

        let server_addr: SocketAddr = resolved_addrs
            .find(|addr| matches!(addr, SocketAddr::V4(_) | SocketAddr::V6(_)))
            .ok_or_else(|| Error::connection("Invalid address: could not resolve host"))?;

        eprintln!("[QUINN] Connecting to {}", server_addr);

        // When skipping verification, don't use actual hostname for SNI
        // This matches Python client behavior which avoids server_name when skip_verify=True
        let server_name = if skip_verify {
            "localhost" // Use generic name when skipping verification
        } else {
            host
        };

        eprintln!("[QUINN] Using server name: {}", server_name);

        let conn = timeout(
            Duration::from_secs(10),
            endpoint
                .connect(server_addr, server_name)
                .map_err(|e| Error::connection(format!("Connection failed: {}", e)))?,
        )
        .await
        .map_err(|_| Error::connection("Connection timeout"))?
        .map_err(|e| Error::connection(format!("Failed to establish connection: {}", e)))?;

        eprintln!("[QUINN] ✓ Connection established!");

        // Open a single bidirectional stream used for the entire session.
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::connection(format!("Failed to open stream: {}", e)))?;

        // Send HELLO message following Python/Go clients (newline-delimited JSON)
        let mut hello_msg = serde_json::json!({
            "type": "HELLO",
            "client_name": hello_name,
            "client_ver": hello_ver,
            "wanted_conformance": conformance,
        });

        // Add authentication credentials if provided
        if let Some(user) = username {
            hello_msg["username"] = serde_json::Value::String(user.to_string());
        }
        if let Some(pass) = password {
            hello_msg["password"] = serde_json::Value::String(pass.to_string());
        }

        let mut hello_line = serde_json::to_string(&hello_msg)
            .map_err(|e| Error::connection(format!("Failed to serialize HELLO: {}", e)))?;
        hello_line.push('\n');

        send.write_all(hello_line.as_bytes())
            .await
            .map_err(|e| Error::connection(format!("Failed to send HELLO: {}", e)))?;

        // Wait for HELLO response (line-delimited JSON)
        let mut reader = BufReader::new(recv);
        let mut response_line = String::new();
        let read_len = timeout(Duration::from_secs(5), reader.read_line(&mut response_line))
            .await
            .map_err(|_| Error::connection("HELLO response timeout"))?
            .map_err(|e| Error::connection(format!("Failed to read HELLO response: {}", e)))?;

        if read_len == 0 {
            return Err(Error::connection("Connection closed before HELLO response"));
        }

        let hello_response: serde_json::Value = serde_json::from_str(&response_line)
            .map_err(|e| Error::connection(format!("Invalid HELLO response: {}", e)))?;

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
            .map_err(|e| Error::connection(format!("Failed to serialize message: {}", e)))?;
        line.push('\n');
        self.send
            .write_all(line.as_bytes())
            .await
            .map_err(|e| Error::connection(format!("Failed to send message: {}", e)))?;
        Ok(())
    }

    async fn read_json_line(&mut self, timeout_secs: u64) -> Result<serde_json::Value> {
        let mut line = String::new();
        let n = timeout(
            Duration::from_secs(timeout_secs),
            self.reader.read_line(&mut line),
        )
        .await
        .map_err(|_| Error::timeout())?
        .map_err(|e| Error::connection(format!("Failed to read response: {}", e)))?;

        if n == 0 {
            return Err(Error::connection("Connection closed"));
        }

        serde_json::from_str(&line)
            .map_err(|e| Error::connection(format!("Invalid JSON response: {}", e)))
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
            if result.get("type").and_then(|t| t.as_str()) == Some("ERROR") {
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

    /// Execute a GQL query without parameters.
    ///
    /// # Arguments
    ///
    /// * `gql` - The GQL query string
    ///
    /// # Returns
    ///
    /// A tuple of (`Page`, `Option<String>`) where the page contains the results
    /// and the optional string contains any query warnings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Query`] if the query fails to execute.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use geode_client::Client;
    /// # async fn example() -> geode_client::Result<()> {
    /// # let client = Client::new("localhost", 3141).skip_verify(true);
    /// # let mut conn = client.connect().await?;
    /// let (page, _) = conn.query("MATCH (n:Person) RETURN n.name LIMIT 10").await?;
    /// for row in &page.rows {
    ///     println!("Name: {}", row.get("name").unwrap().as_string()?);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query(&mut self, gql: &str) -> Result<(Page, Option<String>)> {
        self.query_with_params(gql, &HashMap::new()).await
    }

    /// Execute a GQL query with parameters.
    ///
    /// Parameters are substituted for `$param_name` placeholders in the query.
    /// This is the recommended way to include dynamic values in queries, as it
    /// prevents injection attacks and allows query plan caching.
    ///
    /// # Arguments
    ///
    /// * `gql` - The GQL query string with parameter placeholders
    /// * `params` - A map of parameter names to values
    ///
    /// # Returns
    ///
    /// A tuple of (`Page`, `Option<String>`) where the page contains the results
    /// and the optional string contains any query warnings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Query`] if the query fails to execute.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use geode_client::{Client, Value};
    /// # use std::collections::HashMap;
    /// # async fn example() -> geode_client::Result<()> {
    /// # let client = Client::new("localhost", 3141).skip_verify(true);
    /// # let mut conn = client.connect().await?;
    /// let mut params = HashMap::new();
    /// params.insert("name".to_string(), Value::string("Alice"));
    /// params.insert("min_age".to_string(), Value::int(25));
    ///
    /// let (page, _) = conn.query_with_params(
    ///     "MATCH (p:Person {name: $name}) WHERE p.age >= $min_age RETURN p",
    ///     &params
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
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

        let res_type = result.get("type").and_then(|t| t.as_str()).unwrap_or("");

        if res_type == "ERROR" {
            let code = result
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("UNKNOWN");
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
        .map_err(|e| Error::protocol(format!("Failed to parse columns: {}", e)))?;

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
        let mut final_page;

        loop {
            let frame = self.read_json_line(30).await?;
            let result = frame
                .get("result")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));

            let r#type = result.get("type").and_then(|t| t.as_str()).unwrap_or("");

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
    pub fn query_sync(
        &mut self,
        gql: &str,
        params: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<Page> {
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
                let (page, _cursor) =
                    handle.block_on(self.query_with_params(gql, &params_typed))?;
                Ok(page)
            }
            Err(_) => {
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| Error::query(format!("Failed to create runtime: {}", e)))?;
                let (page, _cursor) = rt.block_on(self.query_with_params(gql, &params_typed))?;
                Ok(page)
            }
        }
    }

    /// Begin a new transaction.
    ///
    /// After calling `begin`, all queries will be part of the transaction until
    /// [`commit`](Connection::commit) or [`rollback`](Connection::rollback) is called.
    ///
    /// # Errors
    ///
    /// Returns an error if a transaction is already in progress or if the
    /// server rejects the request.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use geode_client::Client;
    /// # async fn example() -> geode_client::Result<()> {
    /// # let client = Client::new("localhost", 3141).skip_verify(true);
    /// # let mut conn = client.connect().await?;
    /// conn.begin().await?;
    /// conn.query("CREATE (n:Node {id: 1})").await?;
    /// conn.query("CREATE (n:Node {id: 2})").await?;
    /// conn.commit().await?;  // Both nodes are now persisted
    /// # Ok(())
    /// # }
    /// ```
    pub async fn begin(&mut self) -> Result<()> {
        self.send_control("BEGIN").await
    }

    /// Commit the current transaction.
    ///
    /// Persists all changes made since [`begin`](Connection::begin) was called.
    ///
    /// # Errors
    ///
    /// Returns an error if no transaction is in progress or if the server
    /// rejects the commit.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use geode_client::Client;
    /// # async fn example() -> geode_client::Result<()> {
    /// # let client = Client::new("localhost", 3141).skip_verify(true);
    /// # let mut conn = client.connect().await?;
    /// conn.begin().await?;
    /// conn.query("CREATE (n:Node)").await?;
    /// conn.commit().await?;  // Changes are now permanent
    /// # Ok(())
    /// # }
    /// ```
    pub async fn commit(&mut self) -> Result<()> {
        self.send_control("COMMIT").await
    }

    /// Rollback the current transaction.
    ///
    /// Discards all changes made since [`begin`](Connection::begin) was called.
    ///
    /// # Errors
    ///
    /// Returns an error if no transaction is in progress.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use geode_client::Client;
    /// # async fn example() -> geode_client::Result<()> {
    /// # let client = Client::new("localhost", 3141).skip_verify(true);
    /// # let mut conn = client.connect().await?;
    /// conn.begin().await?;
    /// match conn.query("CREATE (n:InvalidNode)").await {
    ///     Ok(_) => conn.commit().await?,
    ///     Err(_) => conn.rollback().await?,  // Undo everything
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn rollback(&mut self) -> Result<()> {
        self.send_control("ROLLBACK").await
    }

    /// Create a prepared statement for efficient repeated execution.
    ///
    /// Prepared statements allow you to define a query once and execute it
    /// multiple times with different parameters. The query text is parsed
    /// to extract parameter names (tokens starting with `$`).
    ///
    /// # Arguments
    ///
    /// * `query` - The GQL query string with parameter placeholders
    ///
    /// # Returns
    ///
    /// A [`PreparedStatement`] that can be executed multiple times.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use geode_client::{Client, Value};
    /// # use std::collections::HashMap;
    /// # async fn example() -> geode_client::Result<()> {
    /// # let client = Client::new("localhost", 3141).skip_verify(true);
    /// # let mut conn = client.connect().await?;
    /// let stmt = conn.prepare("MATCH (p:Person {id: $id}) RETURN p.name")?;
    ///
    /// for id in 1..=100 {
    ///     let mut params = HashMap::new();
    ///     params.insert("id".to_string(), Value::int(id));
    ///     let (page, _) = stmt.execute(&mut conn, &params).await?;
    ///     // Process results...
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn prepare(&self, query: &str) -> Result<PreparedStatement> {
        Ok(PreparedStatement::new(query))
    }

    /// Get the execution plan for a query without running it.
    ///
    /// This is useful for understanding how the database will execute a query
    /// and for identifying potential performance issues.
    ///
    /// # Arguments
    ///
    /// * `gql` - The GQL query string to explain
    ///
    /// # Returns
    ///
    /// A [`QueryPlan`] containing the execution plan details.
    ///
    /// # Errors
    ///
    /// Returns an error if the query is invalid or cannot be planned.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use geode_client::Client;
    /// # async fn example() -> geode_client::Result<()> {
    /// # let client = Client::new("localhost", 3141).skip_verify(true);
    /// # let mut conn = client.connect().await?;
    /// let plan = conn.explain("MATCH (p:Person)-[:KNOWS]->(f) RETURN f").await?;
    /// println!("Estimated rows: {}", plan.estimated_rows);
    /// for op in &plan.operations {
    ///     println!("  {} - {}", op.op_type, op.description);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn explain(&mut self, gql: &str) -> Result<QueryPlan> {
        let explain_msg = serde_json::json!({
            "type": "RUN_GQL",
            "text": gql,
            "explain": true,
        });

        self.send_json_line(&explain_msg)
            .await
            .map_err(|e| Error::query(format!("{}", e)))?;

        let response = self.read_json_line(10).await?;
        let result = response
            .get("result")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        let res_type = result.get("type").and_then(|t| t.as_str()).unwrap_or("");

        if res_type == "ERROR" {
            let code = result
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("UNKNOWN");
            let msg = result
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Explain failed");
            return Err(Error::Query {
                code: code.to_string(),
                message: msg.to_string(),
            });
        }

        // Parse the plan from the response
        let operations = Self::parse_plan_operations(&result);
        let estimated_rows = result
            .get("estimated_rows")
            .and_then(|r| r.as_u64())
            .unwrap_or(0);

        Ok(QueryPlan {
            operations,
            estimated_rows,
            raw: result,
        })
    }

    /// Execute a query and return the execution profile with timing information.
    ///
    /// This runs the query and collects detailed execution statistics including
    /// actual row counts and timing for each operation.
    ///
    /// # Arguments
    ///
    /// * `gql` - The GQL query string to profile
    ///
    /// # Returns
    ///
    /// A [`QueryProfile`] containing the execution plan and runtime statistics.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails to execute.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use geode_client::Client;
    /// # async fn example() -> geode_client::Result<()> {
    /// # let client = Client::new("localhost", 3141).skip_verify(true);
    /// # let mut conn = client.connect().await?;
    /// let profile = conn.profile("MATCH (p:Person) RETURN p LIMIT 100").await?;
    /// println!("Execution time: {:.2}ms", profile.execution_time_ms);
    /// println!("Actual rows: {}", profile.actual_rows);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn profile(&mut self, gql: &str) -> Result<QueryProfile> {
        let profile_msg = serde_json::json!({
            "type": "RUN_GQL",
            "text": gql,
            "profile": true,
        });

        self.send_json_line(&profile_msg)
            .await
            .map_err(|e| Error::query(format!("{}", e)))?;

        let response = self.read_json_line(30).await?;
        let result = response
            .get("result")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        let res_type = result.get("type").and_then(|t| t.as_str()).unwrap_or("");

        if res_type == "ERROR" {
            let code = result
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("UNKNOWN");
            let msg = result
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Profile failed");
            return Err(Error::Query {
                code: code.to_string(),
                message: msg.to_string(),
            });
        }

        // Parse the plan from the response
        let operations = Self::parse_plan_operations(&result);
        let estimated_rows = result
            .get("estimated_rows")
            .and_then(|r| r.as_u64())
            .unwrap_or(0);
        let actual_rows = result
            .get("actual_rows")
            .and_then(|r| r.as_u64())
            .unwrap_or(0);
        let execution_time_ms = result
            .get("execution_time_ms")
            .and_then(|t| t.as_f64())
            .unwrap_or(0.0);

        let plan = QueryPlan {
            operations,
            estimated_rows,
            raw: result.clone(),
        };

        Ok(QueryProfile {
            plan,
            actual_rows,
            execution_time_ms,
            raw: result,
        })
    }

    /// Execute multiple queries in a batch.
    ///
    /// This is more efficient than executing queries one at a time when you
    /// have multiple independent queries to run.
    ///
    /// # Arguments
    ///
    /// * `queries` - A slice of (query, optional params) tuples
    ///
    /// # Returns
    ///
    /// A `Vec<Page>` with results for each query, in the same order as input.
    ///
    /// # Errors
    ///
    /// Returns an error if any query fails. Queries are executed in order,
    /// so earlier queries may have completed before the error.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use geode_client::Client;
    /// # async fn example() -> geode_client::Result<()> {
    /// # let client = Client::new("localhost", 3141).skip_verify(true);
    /// # let mut conn = client.connect().await?;
    /// let results = conn.batch(&[
    ///     ("MATCH (n:Person) RETURN count(n)", None),
    ///     ("MATCH (n:Company) RETURN count(n)", None),
    ///     ("MATCH ()-[r:WORKS_AT]->() RETURN count(r)", None),
    /// ]).await?;
    ///
    /// for (i, page) in results.iter().enumerate() {
    ///     println!("Query {}: {} rows", i + 1, page.rows.len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn batch(
        &mut self,
        queries: &[(&str, Option<&HashMap<String, Value>>)],
    ) -> Result<Vec<Page>> {
        let mut results = Vec::with_capacity(queries.len());

        for (query, params) in queries {
            let (page, _) = match params {
                Some(p) => self.query_with_params(query, p).await?,
                None => self.query(query).await?,
            };
            results.push(page);
        }

        Ok(results)
    }

    /// Parse plan operations from a server response.
    fn parse_plan_operations(result: &serde_json::Value) -> Vec<PlanOperation> {
        let mut operations = Vec::new();

        if let Some(ops) = result.get("operations").and_then(|o| o.as_array()) {
            for op in ops {
                operations.push(Self::parse_single_operation(op));
            }
        } else if let Some(plan) = result.get("plan") {
            // Alternative format: single "plan" object
            operations.push(Self::parse_single_operation(plan));
        }

        operations
    }

    /// Parse a single operation from JSON.
    fn parse_single_operation(op: &serde_json::Value) -> PlanOperation {
        let op_type = op
            .get("type")
            .or_else(|| op.get("op_type"))
            .and_then(|t| t.as_str())
            .unwrap_or("Unknown")
            .to_string();

        let description = op
            .get("description")
            .or_else(|| op.get("desc"))
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();

        let estimated_rows = op
            .get("estimated_rows")
            .or_else(|| op.get("rows"))
            .and_then(|r| r.as_u64());

        let children = op
            .get("children")
            .and_then(|c| c.as_array())
            .map(|arr| arr.iter().map(Self::parse_single_operation).collect())
            .unwrap_or_default();

        PlanOperation {
            op_type,
            description,
            estimated_rows,
            children,
        }
    }

    /// Close the connection.
    ///
    /// Gracefully closes the QUIC connection. After calling this method,
    /// the connection can no longer be used.
    ///
    /// # Note
    ///
    /// It's good practice to explicitly close connections, but they will also
    /// be closed when dropped.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use geode_client::Client;
    /// # async fn example() -> geode_client::Result<()> {
    /// # let client = Client::new("localhost", 3141).skip_verify(true);
    /// let mut conn = client.connect().await?;
    /// // ... use connection ...
    /// conn.close()?;
    /// # Ok(())
    /// # }
    /// ```
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

#[cfg(test)]
mod tests {
    use super::*;

    // PreparedStatement tests

    #[test]
    fn test_prepared_statement_new() {
        let stmt = PreparedStatement::new("MATCH (n:Person {id: $id}) RETURN n");
        assert_eq!(stmt.query(), "MATCH (n:Person {id: $id}) RETURN n");
        assert_eq!(stmt.param_names(), &["id"]);
    }

    #[test]
    fn test_prepared_statement_multiple_params() {
        let stmt = PreparedStatement::new(
            "MATCH (p:Person {name: $name}) WHERE p.age > $min_age AND p.city = $city RETURN p",
        );
        assert!(stmt.query().contains("$name"));
        let names = stmt.param_names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"name".to_string()));
        assert!(names.contains(&"min_age".to_string()));
        assert!(names.contains(&"city".to_string()));
    }

    #[test]
    fn test_prepared_statement_no_params() {
        let stmt = PreparedStatement::new("MATCH (n) RETURN n LIMIT 10");
        assert!(stmt.param_names().is_empty());
    }

    #[test]
    fn test_prepared_statement_duplicate_params() {
        let stmt =
            PreparedStatement::new("MATCH (a {id: $id})-[:KNOWS]->(b {id: $id}) RETURN a, b");
        // Should deduplicate parameter names
        assert_eq!(stmt.param_names(), &["id"]);
    }

    #[test]
    fn test_prepared_statement_underscore_params() {
        let stmt = PreparedStatement::new("MATCH (n {user_id: $user_id}) RETURN n");
        assert_eq!(stmt.param_names(), &["user_id"]);
    }

    #[test]
    fn test_prepared_statement_numeric_params() {
        let stmt = PreparedStatement::new("RETURN $param1, $param2, $param123");
        let names = stmt.param_names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"param1".to_string()));
        assert!(names.contains(&"param2".to_string()));
        assert!(names.contains(&"param123".to_string()));
    }

    // PlanOperation tests

    #[test]
    fn test_plan_operation_struct() {
        let op = PlanOperation {
            op_type: "NodeScan".to_string(),
            description: "Scan Person nodes".to_string(),
            estimated_rows: Some(100),
            children: vec![],
        };
        assert_eq!(op.op_type, "NodeScan");
        assert_eq!(op.description, "Scan Person nodes");
        assert_eq!(op.estimated_rows, Some(100));
        assert!(op.children.is_empty());
    }

    #[test]
    fn test_plan_operation_with_children() {
        let child = PlanOperation {
            op_type: "Filter".to_string(),
            description: "Filter by age".to_string(),
            estimated_rows: Some(50),
            children: vec![],
        };
        let parent = PlanOperation {
            op_type: "Projection".to_string(),
            description: "Project name, age".to_string(),
            estimated_rows: Some(50),
            children: vec![child],
        };
        assert_eq!(parent.children.len(), 1);
        assert_eq!(parent.children[0].op_type, "Filter");
    }

    // QueryPlan tests

    #[test]
    fn test_query_plan_struct() {
        let plan = QueryPlan {
            operations: vec![PlanOperation {
                op_type: "NodeScan".to_string(),
                description: "Full scan".to_string(),
                estimated_rows: Some(1000),
                children: vec![],
            }],
            estimated_rows: 1000,
            raw: serde_json::json!({"type": "plan"}),
        };
        assert_eq!(plan.operations.len(), 1);
        assert_eq!(plan.estimated_rows, 1000);
    }

    // QueryProfile tests

    #[test]
    fn test_query_profile_struct() {
        let plan = QueryPlan {
            operations: vec![],
            estimated_rows: 100,
            raw: serde_json::json!({}),
        };
        let profile = QueryProfile {
            plan,
            actual_rows: 95,
            execution_time_ms: 12.5,
            raw: serde_json::json!({"type": "profile"}),
        };
        assert_eq!(profile.actual_rows, 95);
        assert!((profile.execution_time_ms - 12.5).abs() < 0.001);
    }

    // Page tests

    #[test]
    fn test_page_struct() {
        let page = Page {
            columns: vec![Column {
                name: "x".to_string(),
                col_type: "INT".to_string(),
            }],
            rows: vec![],
            ordered: false,
            order_keys: vec![],
            final_page: true,
        };
        assert_eq!(page.columns.len(), 1);
        assert!(page.rows.is_empty());
        assert!(page.final_page);
    }

    // Column tests

    #[test]
    fn test_column_struct() {
        let col = Column {
            name: "age".to_string(),
            col_type: "INT".to_string(),
        };
        assert_eq!(col.name, "age");
        assert_eq!(col.col_type, "INT");
    }

    // Savepoint tests

    #[test]
    fn test_savepoint_struct() {
        let sp = Savepoint {
            name: "before_update".to_string(),
        };
        assert_eq!(sp.name, "before_update");
    }

    // Client builder tests

    #[test]
    fn test_client_builder_defaults() {
        let _client = Client::new("localhost", 3141);
        // Test passes if it compiles - verifies defaults work
    }

    #[test]
    fn test_client_builder_chain() {
        let _client = Client::new("example.com", 8443)
            .skip_verify(true)
            .page_size(500)
            .client_name("test-app")
            .client_version("2.0.0")
            .conformance("full");
        // Test passes if it compiles - verifies builder chain works
    }

    #[test]
    fn test_client_clone() {
        let client = Client::new("localhost", 3141).skip_verify(true);
        let _cloned = client.clone();
        // Test passes if it compiles - verifies Clone is implemented
    }

    // parse_plan_operations tests

    #[test]
    fn test_parse_plan_operations_empty() {
        let result = serde_json::json!({});
        let ops = Connection::parse_plan_operations(&result);
        assert!(ops.is_empty());
    }

    #[test]
    fn test_parse_plan_operations_array() {
        let result = serde_json::json!({
            "operations": [
                {"type": "NodeScan", "description": "Scan nodes", "estimated_rows": 100},
                {"type": "Filter", "description": "Apply filter", "estimated_rows": 50}
            ]
        });
        let ops = Connection::parse_plan_operations(&result);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].op_type, "NodeScan");
        assert_eq!(ops[1].op_type, "Filter");
    }

    #[test]
    fn test_parse_plan_operations_single_plan() {
        let result = serde_json::json!({
            "plan": {"op_type": "FullScan", "desc": "Full table scan"}
        });
        let ops = Connection::parse_plan_operations(&result);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op_type, "FullScan");
        assert_eq!(ops[0].description, "Full table scan");
    }

    #[test]
    fn test_parse_single_operation() {
        let op_json = serde_json::json!({
            "type": "IndexScan",
            "description": "Use index on Person(name)",
            "estimated_rows": 25,
            "children": [
                {"type": "Filter", "description": "Filter results"}
            ]
        });
        let op = Connection::parse_single_operation(&op_json);
        assert_eq!(op.op_type, "IndexScan");
        assert_eq!(op.description, "Use index on Person(name)");
        assert_eq!(op.estimated_rows, Some(25));
        assert_eq!(op.children.len(), 1);
        assert_eq!(op.children[0].op_type, "Filter");
    }

    #[test]
    fn test_parse_single_operation_minimal() {
        let op_json = serde_json::json!({});
        let op = Connection::parse_single_operation(&op_json);
        assert_eq!(op.op_type, "Unknown");
        assert_eq!(op.description, "");
        assert_eq!(op.estimated_rows, None);
        assert!(op.children.is_empty());
    }

    #[test]
    fn test_parse_single_operation_alt_fields() {
        let op_json = serde_json::json!({
            "op_type": "Sort",
            "desc": "Sort by name ASC",
            "rows": 100
        });
        let op = Connection::parse_single_operation(&op_json);
        assert_eq!(op.op_type, "Sort");
        assert_eq!(op.description, "Sort by name ASC");
        assert_eq!(op.estimated_rows, Some(100));
    }
}
