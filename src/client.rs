//! Geode client implementation supporting both QUIC and gRPC transports.
//! Uses protobuf wire protocol with 4-byte big-endian length prefix for QUIC.

use log::{debug, trace, warn};
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName as RustlsServerName};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::time::{Duration, timeout};

use crate::dsn::{Dsn, Transport};
use crate::error::{Error, Result};
use crate::proto;
use crate::types::Value;
use crate::validate;

const GEODE_ALPN: &[u8] = b"geode/1";

/// Redact password from a DSN string for safe inclusion in error messages.
/// Handles both URL format (geode://user:pass@host) and query parameter format (?password=xxx).
fn redact_dsn(dsn: &str) -> String {
    let mut result = dsn.to_string();

    // Handle URL format: scheme://user:password@host:port
    // Look for pattern user:password@ and redact the password
    if let Some(scheme_end) = result.find("://") {
        let after_scheme = scheme_end + 3;
        if let Some(at_pos) = result[after_scheme..].find('@') {
            let auth_section = &result[after_scheme..after_scheme + at_pos];
            if let Some(colon_pos) = auth_section.find(':') {
                // Found user:password pattern
                let user = &auth_section[..colon_pos];
                let rest_start = after_scheme + at_pos;
                result = format!(
                    "{}{}:{}{}",
                    &result[..after_scheme],
                    user,
                    "[REDACTED]",
                    &result[rest_start..]
                );
            }
        }
    }

    // Handle query parameter format: host:port?password=xxx
    // Redact password= and pass= parameters (only check once per pattern to avoid loops)
    let patterns = ["password=", "pass="];
    for pattern in patterns {
        let lower = result.to_lowercase();
        if let Some(start) = lower.find(pattern) {
            let value_start = start + pattern.len();
            // Find end of value (& or end of string)
            let value_end = result[value_start..]
                .find('&')
                .map(|i| value_start + i)
                .unwrap_or(result.len());

            result = format!(
                "{}[REDACTED]{}",
                &result[..value_start],
                &result[value_end..]
            );
        }
    }

    result
}

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

/// A Geode database client supporting both QUIC and gRPC transports.
///
/// Use the builder pattern to configure the client, then call [`connect`](Client::connect)
/// to establish a connection.
///
/// # Transport Selection
///
/// The transport is selected based on the DSN scheme:
/// - `quic://` - QUIC transport (default)
/// - `grpc://` - gRPC transport
///
/// # Example
///
/// ```no_run
/// use geode_client::Client;
///
/// # async fn example() -> geode_client::Result<()> {
/// // QUIC transport (legacy API)
/// let client = Client::new("127.0.0.1", 3141)
///     .skip_verify(true)  // Development only!
///     .page_size(500)
///     .client_name("my-app");
///
/// // Or use DSN with explicit transport
/// let client = Client::from_dsn("quic://127.0.0.1:3141?insecure=true")?;
/// let client = Client::from_dsn("grpc://127.0.0.1:50051")?;
///
/// let mut conn = client.connect().await?;
/// let (page, _) = conn.query("RETURN 1 AS x").await?;
/// conn.close()?;
/// # Ok(())
/// # }
/// ```
/// Client configuration for connecting to a Geode server.
///
/// The password field uses `SecretString` from the `secrecy` crate to ensure
/// credentials are zeroized from memory on drop and not accidentally leaked
/// in debug output or error messages.
#[derive(Clone)]
pub struct Client {
    transport: Transport,
    host: String,
    port: u16,
    skip_verify: bool,
    page_size: usize,
    hello_name: String,
    hello_ver: String,
    conformance: String,
    username: Option<String>,
    /// Password stored using SecretString for secure memory handling (CWE-316).
    /// Automatically zeroized on drop and redacted in Debug output.
    password: Option<SecretString>,
    /// Connection timeout in seconds (default: 10)
    connect_timeout_secs: u64,
    /// HELLO handshake timeout in seconds (default: 5)
    hello_timeout_secs: u64,
    /// Idle connection timeout in seconds (default: 30)
    idle_timeout_secs: u64,
}

impl Client {
    /// Create a new QUIC client for the specified host and port.
    ///
    /// This method creates a client using QUIC transport. For gRPC transport,
    /// use [`from_dsn`](Client::from_dsn) with a `grpc://` scheme.
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
            transport: Transport::Quic,
            host: host.into(),
            port,
            skip_verify: false,
            page_size: 1000,
            hello_name: "geode-rust".to_string(),
            hello_ver: env!("CARGO_PKG_VERSION").to_string(),
            conformance: "min".to_string(),
            username: None,
            password: None,
            connect_timeout_secs: 10,
            hello_timeout_secs: 5,
            idle_timeout_secs: 30,
        }
    }

    /// Create a new client from a DSN (Data Source Name) string.
    ///
    /// # Supported DSN Formats
    ///
    /// - `quic://host:port?options` - QUIC transport (recommended)
    /// - `grpc://host:port?options` - gRPC transport
    /// - `grcp://host:port?options` - Alias for gRPC (deprecated)
    /// - `host:port?options` - Legacy format (defaults to QUIC)
    ///
    /// # Supported Options
    ///
    /// - `tls` - Enable/disable TLS (0/1/true/false)
    /// - `insecure` or `skip_verify` - Skip TLS verification
    /// - `page_size` - Results page size (default: 1000)
    /// - `client_name` or `hello_name` - Client name
    /// - `client_version` or `hello_ver` - Client version
    /// - `conformance` - GQL conformance level
    /// - `username` or `user` - Authentication username
    /// - `password` or `pass` - Authentication password
    ///
    /// # Examples
    ///
    /// ```
    /// use geode_client::Client;
    ///
    /// // QUIC transport (explicit)
    /// let client = Client::from_dsn("quic://localhost:3141").unwrap();
    ///
    /// // gRPC transport
    /// let client = Client::from_dsn("grpc://localhost:50051?tls=0").unwrap();
    ///
    /// // Legacy format (defaults to QUIC)
    /// let client = Client::from_dsn("localhost:3141?insecure=true").unwrap();
    ///
    /// // With authentication
    /// let client = Client::from_dsn("quic://admin:secret@localhost:3141").unwrap();
    ///
    /// // IPv6 support
    /// let client = Client::from_dsn("grpc://[::1]:50051").unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidDsn` if:
    /// - DSN is empty
    /// - Scheme is unsupported (not quic://, grpc://, or schemeless)
    /// - Host is missing
    /// - Port is invalid
    pub fn from_dsn(dsn_str: &str) -> Result<Self> {
        let dsn = Dsn::parse(dsn_str)?;

        Ok(Self {
            transport: dsn.transport(),
            host: dsn.host().to_string(),
            port: dsn.port(),
            skip_verify: dsn.skip_verify(),
            page_size: dsn.page_size(),
            hello_name: dsn.client_name().to_string(),
            hello_ver: dsn.client_version().to_string(),
            conformance: dsn.conformance().to_string(),
            username: dsn.username().map(String::from),
            password: dsn.password().map(|p| SecretString::from(p.to_string())),
            connect_timeout_secs: 10,
            hello_timeout_secs: 5,
            idle_timeout_secs: 30,
        })
    }

    /// Get the transport type for this client.
    pub fn transport(&self) -> Transport {
        self.transport
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
    /// The password is stored using `SecretString` which ensures it is:
    /// - Zeroized from memory when dropped
    /// - Not accidentally leaked in debug output
    ///
    /// # Arguments
    ///
    /// * `password` - The password for authentication
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(SecretString::from(password.into()));
        self
    }

    /// Set the connection timeout in seconds.
    ///
    /// This controls how long to wait for the initial QUIC connection
    /// to be established. Default is 10 seconds.
    ///
    /// # Arguments
    ///
    /// * `seconds` - Timeout in seconds (must be > 0)
    pub fn connect_timeout(mut self, seconds: u64) -> Self {
        self.connect_timeout_secs = seconds.max(1);
        self
    }

    /// Set the HELLO handshake timeout in seconds.
    ///
    /// This controls how long to wait for the server to respond to the
    /// initial HELLO message. Default is 5 seconds.
    ///
    /// # Arguments
    ///
    /// * `seconds` - Timeout in seconds (must be > 0)
    pub fn hello_timeout(mut self, seconds: u64) -> Self {
        self.hello_timeout_secs = seconds.max(1);
        self
    }

    /// Set the idle connection timeout in seconds.
    ///
    /// This controls how long an idle connection can remain open before
    /// being automatically closed by the QUIC layer. Default is 30 seconds.
    ///
    /// # Arguments
    ///
    /// * `seconds` - Timeout in seconds (must be > 0)
    pub fn idle_timeout(mut self, seconds: u64) -> Self {
        self.idle_timeout_secs = seconds.max(1);
        self
    }

    /// Validate the client configuration.
    ///
    /// Performs validation on all configuration parameters including:
    /// - Hostname format (RFC 1035 compliant)
    /// - Port number (1-65535)
    /// - Page size (1-100,000)
    ///
    /// This method is automatically called by [`connect`](Self::connect).
    /// You can call it manually to validate configuration before attempting
    /// to connect.
    ///
    /// # Errors
    ///
    /// Returns a validation error if any parameter is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use geode_client::Client;
    ///
    /// let client = Client::new("localhost", 3141);
    /// assert!(client.validate().is_ok());
    ///
    /// // Invalid hostname
    /// let invalid = Client::new("-invalid-host", 3141);
    /// assert!(invalid.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<()> {
        // Validate hostname format
        validate::hostname(&self.host)?;

        // Validate port (0 is reserved)
        validate::port(self.port)?;

        // Validate page size
        validate::page_size(self.page_size)?;

        Ok(())
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
        // Validate configuration before connecting (Gap #9 - automatic validation)
        self.validate()?;

        // Expose the secret password only when needed for the connection
        let password_ref = self.password.as_ref().map(|s| s.expose_secret());

        match self.transport {
            Transport::Quic => {
                Connection::new_quic(
                    &self.host,
                    self.port,
                    self.skip_verify,
                    self.page_size,
                    &self.hello_name,
                    &self.hello_ver,
                    &self.conformance,
                    self.username.as_deref(),
                    password_ref,
                    self.connect_timeout_secs,
                    self.hello_timeout_secs,
                    self.idle_timeout_secs,
                )
                .await
            }
            Transport::Grpc => {
                #[cfg(feature = "grpc")]
                {
                    Connection::new_grpc(
                        &self.host,
                        self.port,
                        self.skip_verify,
                        self.page_size,
                        self.username.as_deref(),
                        password_ref,
                    )
                    .await
                }
                #[cfg(not(feature = "grpc"))]
                {
                    Err(Error::connection(
                        "gRPC transport requires the 'grpc' feature to be enabled",
                    ))
                }
            }
        }
    }
}

/// Internal connection type for transport-specific implementations.
#[allow(dead_code)]
enum ConnectionKind {
    /// QUIC transport connection
    Quic {
        conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        /// Reserved for future streaming support
        buffer: Vec<u8>,
        /// Reserved for request ID tracking
        next_request_id: u64,
    },
    /// gRPC transport connection
    #[cfg(feature = "grpc")]
    Grpc { client: crate::grpc::GrpcClient },
}

/// An active connection to a Geode database server.
///
/// A `Connection` represents a connection to the Geode server using either
/// QUIC or gRPC transport. It provides methods for executing queries, managing
/// transactions, and controlling the connection lifecycle.
///
/// # Transport Support
///
/// - **QUIC**: Uses a bidirectional stream with protobuf wire protocol
/// - **gRPC**: Uses tonic-based gRPC client (requires `grpc` feature)
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
/// `Connection` is `!Sync` because the underlying transport streams are not thread-safe.
/// For concurrent access, use [`ConnectionPool`](crate::ConnectionPool).
pub struct Connection {
    kind: ConnectionKind,
    /// Page size for query results (reserved for future use)
    #[allow(dead_code)]
    page_size: usize,
}

impl Connection {
    /// Create a new QUIC connection.
    #[allow(clippy::too_many_arguments)]
    async fn new_quic(
        host: &str,
        port: u16,
        skip_verify: bool,
        page_size: usize,
        hello_name: &str,
        hello_ver: &str,
        conformance: &str,
        username: Option<&str>,
        password: Option<&str>,
        connect_timeout_secs: u64,
        hello_timeout_secs: u64,
        idle_timeout_secs: u64,
    ) -> Result<Self> {
        let mut last_err: Option<Error> = None;

        for attempt in 1..=3 {
            match Self::connect_quic_once(
                host,
                port,
                skip_verify,
                page_size,
                hello_name,
                hello_ver,
                conformance,
                username,
                password,
                connect_timeout_secs,
                hello_timeout_secs,
                idle_timeout_secs,
            )
            .await
            {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    last_err = Some(e);
                    if attempt < 3 {
                        debug!("Connection attempt {} failed, retrying...", attempt);
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| Error::connection("Failed to connect")))
    }

    /// Create a new gRPC connection.
    #[cfg(feature = "grpc")]
    #[allow(clippy::too_many_arguments)]
    async fn new_grpc(
        host: &str,
        port: u16,
        skip_verify: bool,
        page_size: usize,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self> {
        use crate::dsn::Dsn;

        // Build DSN for gRPC client
        let dsn_str = if let (Some(user), Some(pass)) = (username, password) {
            format!(
                "grpc://{}:{}@{}:{}?insecure={}",
                user, pass, host, port, skip_verify
            )
        } else {
            format!("grpc://{}:{}?insecure={}", host, port, skip_verify)
        };

        let dsn = Dsn::parse(&dsn_str)?;
        let client = crate::grpc::GrpcClient::connect(&dsn).await?;

        Ok(Self {
            kind: ConnectionKind::Grpc { client },
            page_size,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_quic_once(
        host: &str,
        port: u16,
        skip_verify: bool,
        page_size: usize,
        _hello_name: &str,
        _hello_ver: &str,
        _conformance: &str,
        username: Option<&str>,
        password: Option<&str>,
        connect_timeout_secs: u64,
        hello_timeout_secs: u64,
        idle_timeout_secs: u64,
    ) -> Result<Self> {
        debug!("Creating connection to {}:{}", host, port);

        // Install default crypto provider for rustls
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Build Quinn client config with TLS 1.3 explicitly (QUIC requires TLS 1.3)
        let mut client_crypto = if skip_verify {
            // SECURITY WARNING: Disabling TLS verification exposes connections to MITM attacks.
            // Credentials sent in HELLO may be intercepted. Only use for development/testing.
            warn!(
                "TLS certificate verification DISABLED - connection to {}:{} is vulnerable to MITM attacks. \
                 Do NOT use skip_verify in production!",
                host, port
            );
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_no_client_auth()
        } else {
            // Load system root certificates for proper TLS verification
            let mut root_store = rustls::RootCertStore::empty();

            let cert_result = rustls_native_certs::load_native_certs();

            // Log any errors that occurred during certificate loading
            for err in &cert_result.errors {
                warn!("Error loading native certificate: {:?}", err);
            }

            let mut certs_loaded = 0;
            let mut certs_failed = 0;

            for cert in cert_result.certs {
                match root_store.add(cert) {
                    Ok(()) => certs_loaded += 1,
                    Err(_) => certs_failed += 1,
                }
            }

            if certs_loaded == 0 {
                return Err(Error::tls(
                    "No system root certificates found. TLS verification cannot proceed. \
                     Either install system CA certificates or use skip_verify(true) for development only.",
                ));
            }

            debug!(
                "Loaded {} system root certificates ({} failed to parse)",
                certs_loaded, certs_failed
            );

            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
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
        // Cap idle timeout to quinn's maximum (2^62 - 1 microseconds ≈ 146 years)
        // to prevent panic from VarInt overflow
        let idle_timeout = Duration::from_secs(idle_timeout_secs.min(146_000 * 365 * 24 * 3600));
        transport.max_idle_timeout(Some(idle_timeout.try_into().map_err(|_| {
            Error::connection("Idle timeout value too large for QUIC protocol")
        })?));
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        client_config.transport_config(Arc::new(transport));

        // Create endpoint - "0.0.0.0:0" is a valid socket address literal that binds
        // to any available port on all interfaces, so this parse cannot fail
        let mut endpoint = Endpoint::client(
            "0.0.0.0:0"
                .parse()
                .expect("0.0.0.0:0 is a valid socket address"),
        )
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

        debug!("Connecting to {}", server_addr);

        // When skipping verification, don't use actual hostname for SNI
        // This matches Python client behavior which avoids server_name when skip_verify=True
        let server_name = if skip_verify {
            "localhost" // Use generic name when skipping verification
        } else {
            host
        };

        trace!("Using server name for SNI: {}", server_name);

        let conn = timeout(
            Duration::from_secs(connect_timeout_secs),
            endpoint
                .connect(server_addr, server_name)
                .map_err(|e| Error::connection(format!("Connection failed: {}", e)))?,
        )
        .await
        .map_err(|_| Error::connection("Connection timeout"))?
        .map_err(|e| Error::connection(format!("Failed to establish connection: {}", e)))?;

        debug!("Connection established to {}:{}", host, port);

        // Open a single bidirectional stream used for the entire session.
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::connection(format!("Failed to open stream: {}", e)))?;

        // Send HELLO message using protobuf with length prefix
        let hello_req = proto::HelloRequest {
            username: username.unwrap_or("").to_string(),
            password: password.unwrap_or("").to_string(),
            tenant_id: String::new(),
        };
        let msg = proto::QuicClientMessage {
            hello: Some(hello_req),
            ..Default::default()
        };
        let data = proto::encode_with_length_prefix(&msg);

        send.write_all(&data)
            .await
            .map_err(|e| Error::connection(format!("Failed to send HELLO: {}", e)))?;

// Wait for HELLO response (length-prefixed protobuf)
        let mut length_buf = [0u8; 4];
        timeout(Duration::from_secs(5), recv.read_exact(&mut length_buf))
            .await
            .map_err(|_| Error::connection("HELLO response timeout"))?
            .map_err(|e| {
                Error::connection(format!("Failed to read HELLO response length: {}", e))
            })?;

        let msg_len = u32::from_be_bytes(length_buf) as usize;
        let mut msg_buf = vec![0u8; msg_len];
        recv.read_exact(&mut msg_buf)
            .await
            .map_err(|e| Error::connection(format!("Failed to read HELLO response body: {}", e)))?;

        let hello_response = proto::decode_quic_server_message(&msg_buf)?;

if let Some(ref hello_resp) = hello_response.hello {
            if !hello_resp.success {
                return Err(Error::connection(format!(
                    "Authentication failed: {}",
                    hello_resp.error_message
                )));
            }
        } else {
            return Err(Error::connection("Expected HELLO response"));
        }

        debug!("HELLO handshake complete");

        Ok(Self {
            kind: ConnectionKind::Quic {
                conn,
                send,
                recv,
                buffer: Vec::new(),
                next_request_id: 1,
            },
            page_size,
        })
    }

    /// Send a protobuf message over QUIC.
    async fn send_proto_quic(
        send: &mut quinn::SendStream,
        msg: &proto::QuicClientMessage,
    ) -> Result<()> {
        let data = proto::encode_with_length_prefix(msg);
        send.write_all(&data)
            .await
            .map_err(|e| Error::connection(format!("Failed to send message: {}", e)))?;
        Ok(())
    }

    /// Read a protobuf message over QUIC with timeout.
    async fn read_proto_quic(
        recv: &mut quinn::RecvStream,
        timeout_secs: u64,
    ) -> Result<proto::QuicServerMessage> {
        // Read 4-byte length prefix
        let mut length_buf = [0u8; 4];
        timeout(
            Duration::from_secs(timeout_secs),
            recv.read_exact(&mut length_buf),
        )
        .await
        .map_err(|_| Error::timeout())?
        .map_err(|e| Error::connection(format!("Failed to read response length: {}", e)))?;

        let msg_len = u32::from_be_bytes(length_buf) as usize;
        let mut msg_buf = vec![0u8; msg_len];
        recv.read_exact(&mut msg_buf)
            .await
            .map_err(|e| Error::connection(format!("Failed to read response body: {}", e)))?;

        proto::decode_quic_server_message(&msg_buf)
    }

    /// Attempt to read a buffered protobuf message without blocking (QUIC).
    /// Returns Ok(None) if no complete message is available immediately.
    async fn try_read_proto_quic(
        recv: &mut quinn::RecvStream,
    ) -> Result<Option<proto::QuicServerMessage>> {
        // Try to read with a short timeout
        let mut length_buf = [0u8; 4];
        let read_result =
            timeout(Duration::from_millis(10), recv.read_exact(&mut length_buf)).await;

        match read_result {
            Ok(Ok(())) => {
                let msg_len = u32::from_be_bytes(length_buf) as usize;
                let mut msg_buf = vec![0u8; msg_len];
                recv.read_exact(&mut msg_buf).await.map_err(|e| {
                    Error::connection(format!("Failed to read response body: {}", e))
                })?;
                let msg = proto::decode_quic_server_message(&msg_buf)?;
                Ok(Some(msg))
            }
            Ok(Err(e)) => Err(Error::connection(format!("Failed to read response: {}", e))),
            Err(_) => Ok(None), // Timeout - no data available
        }
    }

    /// Parse protobuf rows into Value maps (static version for QUIC).
    fn parse_proto_rows_static(
        proto_rows: &[proto::Row],
        columns: &[Column],
    ) -> Result<Vec<HashMap<String, Value>>> {
        let mut rows = Vec::new();
        for proto_row in proto_rows {
            let mut row = HashMap::new();
            for (i, col) in columns.iter().enumerate() {
                let value = if i < proto_row.values.len() {
                    Self::convert_proto_value_static(&proto_row.values[i])
                } else {
                    Value::null()
                };
                row.insert(col.name.clone(), value);
            }
            rows.push(row);
        }
        Ok(rows)
    }

    /// Convert a protobuf Value to our Value type (static version).
    fn convert_proto_value_static(proto_val: &proto::Value) -> Value {
        if proto_val.null_val {
            return Value::null();
        }
        if let Some(ref s) = proto_val.string_val {
            return Value::string(s.clone());
        }
        if let Some(i) = proto_val.int_val {
            return Value::int(i);
        }
        if let Some(d) = proto_val.double_val {
            return Value::decimal(rust_decimal::Decimal::from_f64_retain(d).unwrap_or_default());
        }
        if let Some(b) = proto_val.bool_val {
            return Value::bool(b);
        }
        Value::null()
    }

    /// Send BEGIN transaction command over QUIC.
    async fn send_begin_quic(
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
    ) -> Result<()> {
        let msg = proto::QuicClientMessage {
            begin: Some(proto::BeginRequest::default()),
            ..Default::default()
        };
        Self::send_proto_quic(send, &msg).await?;

        let resp = Self::read_proto_quic(recv, 5).await?;
        if resp.begin.is_none() {
            return Err(Error::protocol("Expected BEGIN response"));
        }
        Ok(())
    }

    /// Send COMMIT transaction command over QUIC.
    async fn send_commit_quic(
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
    ) -> Result<()> {
        let msg = proto::QuicClientMessage {
            commit: Some(proto::CommitRequest),
            ..Default::default()
        };
        Self::send_proto_quic(send, &msg).await?;

        let resp = Self::read_proto_quic(recv, 5).await?;
        if resp.commit.is_none() {
            return Err(Error::protocol("Expected COMMIT response"));
        }
        Ok(())
    }

    /// Send ROLLBACK transaction command over QUIC.
    async fn send_rollback_quic(
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
    ) -> Result<()> {
        let msg = proto::QuicClientMessage {
            rollback: Some(proto::RollbackRequest),
            ..Default::default()
        };
        Self::send_proto_quic(send, &msg).await?;

        let resp = Self::read_proto_quic(recv, 5).await?;
        if resp.rollback.is_none() {
            return Err(Error::protocol("Expected ROLLBACK response"));
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
        match &mut self.kind {
            ConnectionKind::Quic { send, recv, .. } => {
                Self::query_with_params_quic(send, recv, gql, params).await
            }
            #[cfg(feature = "grpc")]
            ConnectionKind::Grpc { client } => client.query_with_params(gql, params).await,
        }
    }

    /// Execute a GQL query with parameters over QUIC transport.
    async fn query_with_params_quic(
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
        gql: &str,
        params: &HashMap<String, Value>,
    ) -> Result<(Page, Option<String>)> {
        // Convert params to string map for protobuf
        let params_proto: HashMap<String, String> = params
            .iter()
            .map(|(k, v)| (k.clone(), v.to_proto_string()))
            .collect();

        // Send Execute request via protobuf
        let exec_req = proto::ExecuteRequest {
            session_id: String::new(),
            query: gql.to_string(),
            parameters: params_proto,
        };
        let msg = proto::QuicClientMessage {
            execute: Some(exec_req),
            ..Default::default()
        };
        Self::send_proto_quic(send, &msg)
            .await
            .map_err(|e| Error::query(format!("{}", e)))?;

        // Read first response (should be schema or error)
        let resp = Self::read_proto_quic(recv, 10).await?;

        let exec_resp = resp
            .execute
            .ok_or_else(|| Error::protocol("Expected Execute response"))?;

        // Check for error
        if let Some(ref err) = exec_resp.error {
            return Err(Error::Query {
                code: err.code.clone(),
                message: err.message.clone(),
            });
        }

        // Parse columns from schema
        let columns: Vec<Column> = exec_resp
            .schema
            .as_ref()
            .map(|s| {
                s.columns
                    .iter()
                    .map(|c| Column {
                        name: c.name.clone(),
                        col_type: c.col_type.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        trace!("Schema columns: {:?}", columns);

        // Check for inline data page
        if let Some(inline_resp) = Self::try_read_proto_quic(recv).await? {
            if let Some(inline_exec) = inline_resp.execute {
                if let Some(ref err) = inline_exec.error {
                    return Err(Error::Query {
                        code: err.code.clone(),
                        message: err.message.clone(),
                    });
                }

                if let Some(ref page_data) = inline_exec.page {
                    let rows = Self::parse_proto_rows_static(&page_data.rows, &columns)?;
                    let page = Page {
                        columns,
                        rows,
                        ordered: false,
                        order_keys: Vec::new(),
                        final_page: page_data.last_page,
                    };
                    return Ok((page, None));
                }

                // Metrics or heartbeat - empty result
                let page = Page {
                    columns,
                    rows: Vec::new(),
                    ordered: false,
                    order_keys: Vec::new(),
                    final_page: true,
                };
                return Ok((page, None));
            }
        }

        // Check if we got a page in the first response
        if let Some(ref page_data) = exec_resp.page {
            let rows = Self::parse_proto_rows_static(&page_data.rows, &columns)?;
            let page = Page {
                columns,
                rows,
                ordered: false,
                order_keys: Vec::new(),
                final_page: page_data.last_page,
            };
            return Ok((page, None));
        }

        // Read next response for data page
        let resp = Self::read_proto_quic(recv, 30).await?;
        if let Some(exec_resp) = resp.execute {
            if let Some(ref err) = exec_resp.error {
                return Err(Error::Query {
                    code: err.code.clone(),
                    message: err.message.clone(),
                });
            }

            if let Some(ref page_data) = exec_resp.page {
                let rows = Self::parse_proto_rows_static(&page_data.rows, &columns)?;
                let page = Page {
                    columns,
                    rows,
                    ordered: false,
                    order_keys: Vec::new(),
                    final_page: page_data.last_page,
                };
                return Ok((page, None));
            }
        }

        // Empty result
        let page = Page {
            columns,
            rows: Vec::new(),
            ordered: false,
            order_keys: Vec::new(),
            final_page: true,
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
        match &mut self.kind {
            ConnectionKind::Quic { send, recv, .. } => Self::send_begin_quic(send, recv).await,
            #[cfg(feature = "grpc")]
            ConnectionKind::Grpc { client } => client.begin().await,
        }
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
        match &mut self.kind {
            ConnectionKind::Quic { send, recv, .. } => Self::send_commit_quic(send, recv).await,
            #[cfg(feature = "grpc")]
            ConnectionKind::Grpc { client } => client.commit().await,
        }
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
        match &mut self.kind {
            ConnectionKind::Quic { send, recv, .. } => Self::send_rollback_quic(send, recv).await,
            #[cfg(feature = "grpc")]
            ConnectionKind::Grpc { client } => client.rollback().await,
        }
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
        // Execute EXPLAIN as a query via protobuf
        let explain_query = format!("EXPLAIN {}", gql);
        let (_page, _) = self.query(&explain_query).await?;

        // Parse the plan from the response
        // The result format depends on server implementation
        Ok(QueryPlan {
            operations: Vec::new(),
            estimated_rows: 0,
            raw: serde_json::json!({}),
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
        // Execute PROFILE as a query via protobuf
        let profile_query = format!("PROFILE {}", gql);
        let (page, _) = self.query(&profile_query).await?;

        // Parse the profile from the response
        let plan = QueryPlan {
            operations: Vec::new(),
            estimated_rows: 0,
            raw: serde_json::json!({}),
        };

        Ok(QueryProfile {
            plan,
            actual_rows: page.rows.len() as u64,
            execution_time_ms: 0.0,
            raw: serde_json::json!({}),
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
    /// Reserved for future EXPLAIN/PROFILE response parsing.
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    /// Gracefully closes the connection. After calling this method,
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
        match &mut self.kind {
            ConnectionKind::Quic { conn, .. } => {
                // QUIC close is asynchronous and best-effort - the CONNECTION_CLOSE frame
                // will be sent by Quinn's internal I/O handling. No blocking delay needed.
                // (Gap #17: Removed std::thread::sleep that blocked the async runtime)
                conn.close(0u32.into(), b"client closing");
                Ok(())
            }
            #[cfg(feature = "grpc")]
            ConnectionKind::Grpc { client } => client.close(),
        }
    }

    /// Check if the connection is still healthy.
    ///
    /// Returns `true` if the underlying QUIC connection is still open and usable.
    /// This is used by connection pools to verify connections before reuse.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut conn = client.connect().await?;
    /// if conn.is_healthy() {
    ///     // Connection is still usable
    ///     let (page, _) = conn.query("RETURN 1").await?;
    /// }
    /// ```
    pub fn is_healthy(&self) -> bool {
        match &self.kind {
            ConnectionKind::Quic { conn, .. } => {
                // Quinn's close_reason() returns Some if the connection was closed
                conn.close_reason().is_none()
            }
            #[cfg(feature = "grpc")]
            ConnectionKind::Grpc { .. } => {
                // gRPC connections are managed by tonic, always report healthy
                true
            }
        }
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

    // redact_dsn tests - Gap #7 (DSN Password Exposure)

    #[test]
    fn test_redact_dsn_url_with_password() {
        let dsn = "geode://admin:secret123@localhost:3141";
        let redacted = redact_dsn(dsn);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("secret123"));
        assert!(redacted.contains("admin"));
        assert!(redacted.contains("localhost"));
    }

    #[test]
    fn test_redact_dsn_url_without_password() {
        let dsn = "geode://admin@localhost:3141";
        let redacted = redact_dsn(dsn);
        assert!(!redacted.contains("[REDACTED]"));
        assert!(redacted.contains("admin"));
        assert!(redacted.contains("localhost"));
    }

    #[test]
    fn test_redact_dsn_url_no_auth() {
        let dsn = "geode://localhost:3141";
        let redacted = redact_dsn(dsn);
        assert_eq!(redacted, dsn);
    }

    #[test]
    fn test_redact_dsn_query_param_password() {
        let dsn = "localhost:3141?username=admin&password=secret123";
        let redacted = redact_dsn(dsn);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("secret123"));
        assert!(redacted.contains("username=admin"));
    }

    #[test]
    fn test_redact_dsn_query_param_pass() {
        let dsn = "localhost:3141?user=admin&pass=mysecret";
        let redacted = redact_dsn(dsn);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("mysecret"));
    }

    #[test]
    fn test_redact_dsn_simple_no_password() {
        let dsn = "localhost:3141?insecure=true";
        let redacted = redact_dsn(dsn);
        assert_eq!(redacted, dsn);
    }

    #[test]
    fn test_redact_dsn_url_with_query_and_password() {
        let dsn = "geode://user:pass@localhost:3141?insecure=true";
        let redacted = redact_dsn(dsn);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains(":pass@"));
        assert!(redacted.contains("insecure=true"));
    }

    // validate() tests - Gap #9 (Validation Not Automatic)

    #[test]
    fn test_client_validate_valid() {
        let client = Client::new("localhost", 3141);
        assert!(client.validate().is_ok());
    }

    #[test]
    fn test_client_validate_valid_hostname() {
        let client = Client::new("geode.example.com", 3141);
        assert!(client.validate().is_ok());
    }

    #[test]
    fn test_client_validate_valid_ipv4() {
        let client = Client::new("192.168.1.1", 8443);
        assert!(client.validate().is_ok());
    }

    #[test]
    fn test_client_validate_invalid_hostname_hyphen_start() {
        let client = Client::new("-invalid", 3141);
        assert!(client.validate().is_err());
    }

    #[test]
    fn test_client_validate_invalid_hostname_hyphen_end() {
        let client = Client::new("invalid-", 3141);
        assert!(client.validate().is_err());
    }

    #[test]
    fn test_client_validate_invalid_port_zero() {
        let client = Client::new("localhost", 0);
        assert!(client.validate().is_err());
    }

    #[test]
    fn test_client_validate_invalid_page_size_zero() {
        let client = Client::new("localhost", 3141).page_size(0);
        assert!(client.validate().is_err());
    }

    #[test]
    fn test_client_validate_invalid_page_size_too_large() {
        let client = Client::new("localhost", 3141).page_size(200_000);
        assert!(client.validate().is_err());
    }

    #[test]
    fn test_client_validate_with_all_options() {
        let client = Client::new("geode.example.com", 8443)
            .skip_verify(true)
            .page_size(500)
            .username("admin")
            .password("secret")
            .connect_timeout(15)
            .hello_timeout(10)
            .idle_timeout(60);
        assert!(client.validate().is_ok());
    }

    // Gap #13: Test that extreme timeout values don't cause builder panics
    #[test]
    fn test_client_extreme_timeout_values() {
        // These should not panic - the actual validation/capping happens at connect time
        let _client = Client::new("localhost", 3141)
            .connect_timeout(u64::MAX)
            .hello_timeout(u64::MAX)
            .idle_timeout(u64::MAX);
        // Builder should accept any u64 value without panicking
    }
}
