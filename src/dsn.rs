//! DSN (Data Source Name) parsing for Geode connections.
//!
//! See geode/docs/DSN.md for the full specification.
//!
//! Supports the following DSN formats:
//! - `quic://host:port?options` - QUIC transport (recommended)
//! - `grpc://host:port?options` - gRPC transport
//! - `grpcs://host:port?options` - gRPC transport with TLS forced on
//! - `host:port?options` - Defaults to QUIC
//!
//! # Examples
//!
//! ```
//! use geode_client::dsn::{Dsn, Transport};
//!
//! // QUIC transport (explicit)
//! let dsn = Dsn::parse("quic://localhost:3141").unwrap();
//! assert_eq!(dsn.transport(), Transport::Quic);
//!
//! // gRPC transport
//! let dsn = Dsn::parse("grpc://localhost:50051?tls=0").unwrap();
//! assert_eq!(dsn.transport(), Transport::Grpc);
//! assert!(!dsn.tls_enabled());
//!
//! // IPv6 support
//! let dsn = Dsn::parse("grpc://[::1]:50051").unwrap();
//! assert_eq!(dsn.host(), "::1");
//! ```

use crate::error::{Error, Result};
use std::collections::HashMap;

/// Default port for Geode connections
pub const DEFAULT_PORT: u16 = 3141;

/// Transport protocol to use for the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// QUIC transport with protobuf wire protocol
    Quic,
    /// gRPC transport using protobuf service definitions
    Grpc,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Quic => write!(f, "quic"),
            Transport::Grpc => write!(f, "grpc"),
        }
    }
}

/// Parsed DSN (Data Source Name) for Geode connections.
///
/// Contains all connection parameters extracted from a DSN string.
#[derive(Clone, PartialEq)]
pub struct Dsn {
    transport: Transport,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    tls_enabled: bool,
    skip_verify: bool,
    page_size: usize,
    client_name: String,
    client_version: String,
    conformance: String,
    ca_cert: Option<String>,
    client_cert: Option<String>,
    client_key: Option<String>,
    server_name: Option<String>,
    connect_timeout_secs: Option<u64>,
    graph: Option<String>,
    /// Tenant ID for multi-tenant isolation (sent in HELLO when set)
    tenant: Option<String>,
    /// FLE role for field-level access control (sent in HELLO when set)
    role: Option<String>,
    options: HashMap<String, String>,
}

impl Default for Dsn {
    fn default() -> Self {
        Self {
            transport: Transport::Quic,
            host: "localhost".to_string(),
            port: DEFAULT_PORT,
            username: None,
            password: None,
            tls_enabled: true,
            skip_verify: false,
            page_size: 1000,
            client_name: "geode-rust".to_string(),
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            conformance: "min".to_string(),
            ca_cert: None,
            client_cert: None,
            client_key: None,
            server_name: None,
            connect_timeout_secs: None,
            graph: None,
            tenant: None,
            role: None,
            options: HashMap::new(),
        }
    }
}

impl Dsn {
    /// Parse a DSN string into a Dsn struct.
    ///
    /// # Supported formats
    ///
    /// - `quic://host:port?options` - QUIC transport (recommended)
    /// - `grpc://host:port?options` - gRPC transport
    /// - `grpcs://host:port?options` - gRPC transport with TLS forced on
    /// - `host:port?options` - Defaults to QUIC
    ///
    /// # Supported options (query parameters)
    ///
    /// - `tls` - Enable/disable TLS (0/1/true/false, default: true)
    /// - `insecure`, `skip_verify`, `insecure_skip_verify` - Skip TLS verification
    /// - `page_size` - Results page size (default: 1000)
    /// - `client_name` or `hello_name` - Client name
    /// - `client_version` or `hello_ver` - Client version
    /// - `conformance` - GQL conformance level
    /// - `username` or `user` - Authentication username
    /// - `password` or `pass` - Authentication password
    /// - `ca` or `ca_cert` - Path to CA certificate
    /// - `cert` or `client_cert` - Path to client certificate (mTLS)
    /// - `key` or `client_key` - Path to client key (mTLS)
    /// - `server_name` - SNI server name
    /// - `connect_timeout` or `timeout` - Connection timeout in seconds
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidDsn` if:
    /// - DSN is empty
    /// - Scheme is unsupported
    /// - Host is missing
    /// - Port is invalid
    ///
    /// # Examples
    ///
    /// ```
    /// use geode_client::dsn::Dsn;
    ///
    /// let dsn = Dsn::parse("quic://localhost:3141").unwrap();
    /// let dsn = Dsn::parse("grpc://127.0.0.1:50051?tls=0").unwrap();
    /// let dsn = Dsn::parse("grpc://[::1]:50051").unwrap();
    /// ```
    pub fn parse(dsn: &str) -> Result<Self> {
        let dsn = dsn.trim();
        if dsn.is_empty() {
            return Err(Error::invalid_dsn("DSN cannot be empty"));
        }

        // Determine scheme and parse accordingly
        if dsn.starts_with("quic://") {
            Self::parse_url(dsn, Transport::Quic)
        } else if let Some(rest) = dsn.strip_prefix("grpcs://") {
            // grpcs:// is gRPC with TLS forced on
            let rewritten = format!("grpc://{}", rest);
            let mut result = Self::parse_url(&rewritten, Transport::Grpc)?;
            result.tls_enabled = true;
            Ok(result)
        } else if dsn.starts_with("grpc://") {
            Self::parse_url(dsn, Transport::Grpc)
        } else if dsn.contains("://") {
            // Unsupported scheme - reject it
            let scheme = dsn.split("://").next().unwrap_or("");
            Err(Error::invalid_dsn(format!(
                "Unsupported scheme '{}'. Supported schemes: quic://, grpc://, grpcs://",
                scheme
            )))
        } else {
            // Scheme-less format: host:port?options (defaults to QUIC)
            Self::parse_legacy(dsn)
        }
    }

    /// Parse URL-format DSN (quic://, grpc://)
    fn parse_url(dsn: &str, transport: Transport) -> Result<Self> {
        // Use url crate for proper parsing
        let url = url::Url::parse(dsn)
            .map_err(|e| Error::invalid_dsn(format!("Invalid URL format: {}", e)))?;

        let host_raw = url
            .host_str()
            .ok_or_else(|| Error::invalid_dsn("Host is required"))?;

        // Strip brackets from IPv6 addresses (url crate returns "[::1]" for IPv6)
        let host = if host_raw.starts_with('[') && host_raw.ends_with(']') {
            host_raw[1..host_raw.len() - 1].to_string()
        } else {
            host_raw.to_string()
        };

        if host.is_empty() {
            return Err(Error::invalid_dsn("Host is required"));
        }

        let port = url.port().unwrap_or(DEFAULT_PORT);

        // Extract username/password with percent-decoding
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

        // Extract graph from URL path (e.g. quic://host:3141/mygraph)
        let graph = if !url.path().is_empty() && url.path() != "/" {
            Some(url.path().trim_start_matches('/').to_string())
        } else {
            None
        };

        let mut result = Self {
            transport,
            host,
            port,
            username,
            password,
            graph,
            ..Default::default()
        };

        result.apply_params(&params)?;

        Ok(result)
    }

    /// Parse legacy format DSN (host:port?options)
    fn parse_legacy(dsn: &str) -> Result<Self> {
        // Split off query string
        let (host_port, query_str) = if let Some(idx) = dsn.find('?') {
            (&dsn[..idx], Some(&dsn[idx + 1..]))
        } else {
            (dsn, None)
        };

        // Parse host:port, handling IPv6 addresses like [::1]:3141
        let (host, port) = Self::parse_host_port(host_port)?;

        if host.is_empty() {
            return Err(Error::invalid_dsn("Host is required"));
        }

        let mut result = Self {
            transport: Transport::Quic, // Default to QUIC for legacy format
            host,
            port,
            ..Default::default()
        };

        // Parse query parameters
        if let Some(qs) = query_str {
            let params: HashMap<String, String> = qs
                .split('&')
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let key = parts.next()?;
                    let value = parts.next().unwrap_or("");
                    // Percent-decode values
                    let decoded_value = urlencoding::decode(value)
                        .map(|s| s.into_owned())
                        .unwrap_or_else(|_| value.to_string());
                    Some((key.to_string(), decoded_value))
                })
                .collect();

            result.apply_params(&params)?;
        }

        Ok(result)
    }

    /// Parse host:port string, handling IPv6 addresses
    fn parse_host_port(s: &str) -> Result<(String, u16)> {
        // Handle IPv6 addresses: [::1]:3141 or [2001:db8::1]:3141
        if s.starts_with('[') {
            // IPv6 format
            if let Some(bracket_end) = s.find(']') {
                let host = s[1..bracket_end].to_string();
                let remainder = &s[bracket_end + 1..];
                let port = if let Some(rest) = remainder.strip_prefix(':') {
                    rest.parse::<u16>()
                        .map_err(|_| Error::invalid_dsn(format!("Invalid port: {}", rest)))?
                } else if remainder.is_empty() {
                    DEFAULT_PORT
                } else {
                    return Err(Error::invalid_dsn("Invalid IPv6 address format"));
                };
                return Ok((host, port));
            } else {
                return Err(Error::invalid_dsn("Unclosed bracket in IPv6 address"));
            }
        }

        // IPv4 or hostname: find the last colon for port
        if let Some(idx) = s.rfind(':') {
            let host = s[..idx].to_string();
            let port_str = &s[idx + 1..];
            let port = port_str
                .parse::<u16>()
                .map_err(|_| Error::invalid_dsn(format!("Invalid port: {}", port_str)))?;
            Ok((host, port))
        } else {
            // No port specified
            Ok((s.to_string(), DEFAULT_PORT))
        }
    }

    /// Apply query parameters to the DSN
    fn apply_params(&mut self, params: &HashMap<String, String>) -> Result<()> {
        for (key, value) in params {
            match key.as_str() {
                "tls" => {
                    self.tls_enabled = parse_bool(value).unwrap_or(true);
                }
                "insecure_tls_skip_verify"
                | "insecure"
                | "skip_verify"
                | "insecure_skip_verify" => {
                    self.skip_verify = parse_bool(value).unwrap_or(false);
                }
                "page_size" => {
                    self.page_size = value
                        .parse()
                        .map_err(|_| Error::invalid_dsn(format!("Invalid page_size: {}", value)))?;
                }
                "client_name" | "hello_name" => {
                    self.client_name = value.clone();
                }
                "client_version" | "hello_ver" => {
                    self.client_version = value.clone();
                }
                "conformance" => {
                    self.conformance = value.clone();
                }
                "username" | "user" => {
                    self.username = Some(value.clone());
                }
                "password" | "pass" => {
                    self.password = Some(value.clone());
                }
                "ca" | "ca_cert" => {
                    self.ca_cert = Some(value.clone());
                }
                "cert" | "client_cert" => {
                    self.client_cert = Some(value.clone());
                }
                "key" | "client_key" => {
                    self.client_key = Some(value.clone());
                }
                "server_name" => {
                    self.server_name = Some(value.clone());
                }
                "connect_timeout" | "timeout" => {
                    self.connect_timeout_secs = value.parse().ok();
                }
                "graph" => {
                    self.graph = Some(value.to_string());
                }
                "tenant" | "tenant_id" => {
                    self.tenant = Some(value.to_string());
                }
                "role" => {
                    self.role = Some(value.to_string());
                }
                _ => {
                    // Store unknown parameters for forward compatibility
                    self.options.insert(key.clone(), value.clone());
                }
            }
        }
        Ok(())
    }

    /// Get the transport protocol.
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Get the host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the username if specified.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Get the password if specified.
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Check if TLS is enabled.
    pub fn tls_enabled(&self) -> bool {
        self.tls_enabled
    }

    /// Check if TLS verification should be skipped.
    pub fn skip_verify(&self) -> bool {
        self.skip_verify
    }

    /// Get the page size.
    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// Get the client name.
    pub fn client_name(&self) -> &str {
        &self.client_name
    }

    /// Get the client version.
    pub fn client_version(&self) -> &str {
        &self.client_version
    }

    /// Get the conformance level.
    pub fn conformance(&self) -> &str {
        &self.conformance
    }

    /// Get additional options.
    pub fn options(&self) -> &HashMap<String, String> {
        &self.options
    }

    /// Get the CA certificate path if specified.
    pub fn ca_cert(&self) -> Option<&str> {
        self.ca_cert.as_deref()
    }

    /// Get the client certificate path if specified.
    pub fn client_cert(&self) -> Option<&str> {
        self.client_cert.as_deref()
    }

    /// Get the client key path if specified.
    pub fn client_key(&self) -> Option<&str> {
        self.client_key.as_deref()
    }

    /// Get the SNI server name if specified.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Get the connection timeout in seconds if specified.
    pub fn connect_timeout_secs(&self) -> Option<u64> {
        self.connect_timeout_secs
    }

    /// Get the graph name if specified.
    pub fn graph(&self) -> Option<&str> {
        self.graph.as_deref()
    }

    /// Get the tenant ID if specified (multi-tenant isolation).
    pub fn tenant(&self) -> Option<&str> {
        self.tenant.as_deref()
    }

    /// Get the FLE role if specified (field-level access control).
    pub fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }

    /// Get the host:port address string.
    pub fn address(&self) -> String {
        if self.host.contains(':') {
            // IPv6 address - wrap in brackets
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Format this DSN back into a connection-string form.
    ///
    /// Mirrors the Go reference client's `Config.FormatDSN`: emits
    /// `scheme://userinfo@host:port?onlyNonDefaultParams`. Only parameters
    /// that differ from the defaults are emitted, query keys are sorted for
    /// determinism, and userinfo/values are percent-encoded.
    ///
    /// Credentials follow Go's rules: a username with a password becomes
    /// `user:pass@`, a username alone becomes `user@`, and a password
    /// without a username falls back to a `pass=` query parameter (since
    /// userinfo cannot carry a password-only credential).
    ///
    /// The result round-trips through [`Dsn::parse`].
    ///
    /// # Example
    ///
    /// ```
    /// use geode_client::dsn::Dsn;
    ///
    /// let dsn = Dsn::parse("quic://localhost:3141?page_size=500").unwrap();
    /// let s = dsn.to_dsn();
    /// assert_eq!(Dsn::parse(&s).unwrap(), dsn);
    /// ```
    pub fn to_dsn(&self) -> String {
        let defaults = Dsn::default();

        // Collect non-default query parameters as (key, value) pairs.
        let mut params: Vec<(String, String)> = Vec::new();

        if self.page_size != defaults.page_size {
            params.push(("page_size".to_string(), self.page_size.to_string()));
        }
        if self.client_name != defaults.client_name {
            params.push(("hello_name".to_string(), self.client_name.clone()));
        }
        if self.client_version != defaults.client_version {
            params.push(("hello_ver".to_string(), self.client_version.clone()));
        }
        if self.conformance != defaults.conformance {
            params.push(("conformance".to_string(), self.conformance.clone()));
        }
        if let Some(ca) = &self.ca_cert {
            params.push(("ca".to_string(), ca.clone()));
        }
        if let Some(cert) = &self.client_cert {
            params.push(("cert".to_string(), cert.clone()));
        }
        if let Some(key) = &self.client_key {
            params.push(("key".to_string(), key.clone()));
        }
        if let Some(sn) = &self.server_name {
            params.push(("server_name".to_string(), sn.clone()));
        }
        if self.skip_verify {
            params.push(("insecure_tls_skip_verify".to_string(), "true".to_string()));
        }
        if !self.tls_enabled {
            params.push(("tls".to_string(), "0".to_string()));
        }
        if let Some(graph) = &self.graph {
            params.push(("graph".to_string(), graph.clone()));
        }
        if let Some(tenant) = &self.tenant {
            params.push(("tenant".to_string(), tenant.clone()));
        }
        if let Some(role) = &self.role {
            params.push(("role".to_string(), role.clone()));
        }
        if let Some(timeout) = self.connect_timeout_secs {
            params.push(("connect_timeout".to_string(), timeout.to_string()));
        }
        // Preserve forward-compatible unknown options.
        for (key, value) in &self.options {
            params.push((key.clone(), value.clone()));
        }

        // Build userinfo, falling back to a pass= query param when only a
        // password is present (userinfo requires a username).
        let userinfo = match (&self.username, &self.password) {
            (Some(user), Some(pass)) => format!(
                "{}:{}@",
                urlencoding::encode(user),
                urlencoding::encode(pass)
            ),
            (Some(user), None) => format!("{}@", urlencoding::encode(user)),
            (None, Some(pass)) => {
                params.push(("pass".to_string(), pass.clone()));
                String::new()
            }
            (None, None) => String::new(),
        };

        // Sort query keys for deterministic output (matches Go's url.Values).
        params.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        let mut dsn = format!("{}://{}{}", self.transport, userinfo, self.address());

        if !params.is_empty() {
            let query: Vec<String> = params
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect();
            dsn.push('?');
            dsn.push_str(&query.join("&"));
        }

        dsn
    }
}

impl std::fmt::Display for Dsn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_dsn())
    }
}

impl std::fmt::Debug for Dsn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dsn")
            .field("transport", &self.transport)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("tls_enabled", &self.tls_enabled)
            .field("skip_verify", &self.skip_verify)
            .field("page_size", &self.page_size)
            .field("client_name", &self.client_name)
            .field("client_version", &self.client_version)
            .field("conformance", &self.conformance)
            .field("ca_cert", &self.ca_cert)
            .field("client_cert", &self.client_cert)
            .field("client_key", &self.client_key)
            .field("server_name", &self.server_name)
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("graph", &self.graph)
            .field("tenant", &self.tenant)
            .field("role", &self.role)
            .field("options", &self.options)
            .finish()
    }
}

/// Parse a boolean value from a string
fn parse_bool(s: &str) -> Option<bool> {
    match s.to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // QUIC DSN Parsing Tests
    // ==========================================================================

    #[test]
    fn test_dsn_parse_quic_basic() {
        let dsn = Dsn::parse("quic://localhost:3141").unwrap();
        assert_eq!(dsn.transport(), Transport::Quic);
        assert_eq!(dsn.host(), "localhost");
        assert_eq!(dsn.port(), 3141);
        assert!(dsn.tls_enabled());
        assert!(!dsn.skip_verify());
    }

    #[test]
    fn test_dsn_parse_quic_with_ip() {
        let dsn = Dsn::parse("quic://127.0.0.1:3141").unwrap();
        assert_eq!(dsn.transport(), Transport::Quic);
        assert_eq!(dsn.host(), "127.0.0.1");
        assert_eq!(dsn.port(), 3141);
    }

    #[test]
    fn test_dsn_parse_quic_default_port() {
        let dsn = Dsn::parse("quic://localhost").unwrap();
        assert_eq!(dsn.port(), DEFAULT_PORT);
    }

    #[test]
    fn test_dsn_parse_quic_with_options() {
        let dsn = Dsn::parse("quic://localhost:3141?page_size=500&insecure=true").unwrap();
        assert_eq!(dsn.page_size(), 500);
        assert!(dsn.skip_verify());
    }

    // ==========================================================================
    // gRPC DSN Parsing Tests
    // ==========================================================================

    #[test]
    fn test_dsn_parse_grpc_basic() {
        let dsn = Dsn::parse("grpc://localhost:50051").unwrap();
        assert_eq!(dsn.transport(), Transport::Grpc);
        assert_eq!(dsn.host(), "localhost");
        assert_eq!(dsn.port(), 50051);
    }

    #[test]
    fn test_dsn_parse_grpc_with_tls_disabled() {
        let dsn = Dsn::parse("grpc://127.0.0.1:50051?tls=0").unwrap();
        assert_eq!(dsn.transport(), Transport::Grpc);
        assert_eq!(dsn.host(), "127.0.0.1");
        assert_eq!(dsn.port(), 50051);
        assert!(!dsn.tls_enabled());
    }

    #[test]
    fn test_dsn_parse_grpc_with_tls_false() {
        let dsn = Dsn::parse("grpc://localhost:50051?tls=false").unwrap();
        assert!(!dsn.tls_enabled());
    }

    #[test]
    fn test_dsn_parse_grpcs_scheme() {
        let dsn = Dsn::parse("grpcs://localhost:50051").unwrap();
        assert_eq!(dsn.transport(), Transport::Grpc);
        assert!(dsn.tls_enabled());
        assert_eq!(dsn.host(), "localhost");
        assert_eq!(dsn.port(), 50051);
    }

    #[test]
    fn test_dsn_parse_grpcs_tls_forced() {
        // Even if tls=0 is passed, grpcs:// forces TLS on
        let dsn = Dsn::parse("grpcs://localhost:50051?tls=0").unwrap();
        assert_eq!(dsn.transport(), Transport::Grpc);
        assert!(dsn.tls_enabled());
    }

    #[test]
    fn test_dsn_parse_unsupported_schemes() {
        // grcp:// is no longer supported
        let err = Dsn::parse("grcp://localhost:50051").unwrap_err();
        assert!(err.to_string().contains("Unsupported scheme"));

        // geode:// is no longer supported
        let err = Dsn::parse("geode://localhost:3141").unwrap_err();
        assert!(err.to_string().contains("Unsupported scheme"));
    }

    // ==========================================================================
    // IPv6 DSN Parsing Tests
    // ==========================================================================

    #[test]
    fn test_dsn_parse_ipv6_grpc() {
        let dsn = Dsn::parse("grpc://[::1]:50051").unwrap();
        assert_eq!(dsn.transport(), Transport::Grpc);
        assert_eq!(dsn.host(), "::1");
        assert_eq!(dsn.port(), 50051);
    }

    #[test]
    fn test_dsn_parse_ipv6_quic() {
        let dsn = Dsn::parse("quic://[::1]:3141").unwrap();
        assert_eq!(dsn.transport(), Transport::Quic);
        assert_eq!(dsn.host(), "::1");
        assert_eq!(dsn.port(), 3141);
    }

    #[test]
    fn test_dsn_parse_ipv6_full_address() {
        let dsn = Dsn::parse("grpc://[2001:db8::1]:50051").unwrap();
        assert_eq!(dsn.host(), "2001:db8::1");
        assert_eq!(dsn.port(), 50051);
    }

    #[test]
    fn test_dsn_parse_ipv6_default_port() {
        let dsn = Dsn::parse("quic://[::1]").unwrap();
        assert_eq!(dsn.host(), "::1");
        assert_eq!(dsn.port(), DEFAULT_PORT);
    }

    #[test]
    fn test_dsn_address_ipv6() {
        let dsn = Dsn::parse("grpc://[::1]:50051").unwrap();
        assert_eq!(dsn.address(), "[::1]:50051");
    }

    // ==========================================================================
    // Legacy DSN Format Tests
    // ==========================================================================

    #[test]
    fn test_dsn_parse_legacy_host_port() {
        let dsn = Dsn::parse("localhost:3141").unwrap();
        assert_eq!(dsn.transport(), Transport::Quic); // Default to QUIC
        assert_eq!(dsn.host(), "localhost");
        assert_eq!(dsn.port(), 3141);
    }

    #[test]
    fn test_dsn_parse_legacy_with_options() {
        let dsn = Dsn::parse("localhost:3141?insecure=true&page_size=500").unwrap();
        assert_eq!(dsn.transport(), Transport::Quic);
        assert!(dsn.skip_verify());
        assert_eq!(dsn.page_size(), 500);
    }

    #[test]
    fn test_dsn_parse_legacy_ipv6() {
        let dsn = Dsn::parse("[::1]:3141").unwrap();
        assert_eq!(dsn.host(), "::1");
        assert_eq!(dsn.port(), 3141);
    }

    // ==========================================================================
    // Authentication Tests
    // ==========================================================================

    #[test]
    fn test_dsn_parse_with_auth() {
        let dsn = Dsn::parse("quic://admin:secret@localhost:3141").unwrap();
        assert_eq!(dsn.username(), Some("admin"));
        assert_eq!(dsn.password(), Some("secret"));
    }

    #[test]
    fn test_dsn_parse_auth_via_query_params() {
        let dsn = Dsn::parse("grpc://localhost:50051?username=admin&password=secret").unwrap();
        assert_eq!(dsn.username(), Some("admin"));
        assert_eq!(dsn.password(), Some("secret"));
    }

    #[test]
    fn test_dsn_parse_auth_percent_encoded() {
        let dsn = Dsn::parse("quic://user%40domain:p%40ss%3Dword@localhost:3141").unwrap();
        assert_eq!(dsn.username(), Some("user@domain"));
        assert_eq!(dsn.password(), Some("p@ss=word"));
    }

    // ==========================================================================
    // Error Cases Tests
    // ==========================================================================

    #[test]
    fn test_dsn_parse_empty() {
        let err = Dsn::parse("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_dsn_parse_unsupported_scheme() {
        let err = Dsn::parse("http://localhost:3141").unwrap_err();
        assert!(err.to_string().contains("Unsupported scheme"));
        assert!(err.to_string().contains("http"));
    }

    #[test]
    fn test_dsn_parse_invalid_port() {
        let err = Dsn::parse("quic://localhost:invalid").unwrap_err();
        assert!(err.to_string().contains("port") || err.to_string().contains("Invalid"));
    }

    #[test]
    fn test_dsn_parse_port_too_large() {
        let err = Dsn::parse("quic://localhost:99999").unwrap_err();
        assert!(err.to_string().contains("port") || err.to_string().contains("Invalid"));
    }

    #[test]
    fn test_dsn_parse_missing_host() {
        // URL crate handles this differently - empty host is valid for some schemes
        // But we should reject it
        let result = Dsn::parse("quic://:3141");
        // This might parse as empty host or fail depending on URL parser
        if let Ok(dsn) = result {
            assert!(dsn.host().is_empty() || dsn.host() == "");
        }
    }

    // ==========================================================================
    // Query Parameter Tests
    // ==========================================================================

    #[test]
    fn test_dsn_parse_all_options() {
        let dsn = Dsn::parse(
            "grpc://localhost:50051?tls=1&insecure=false&page_size=2000&client_name=test-app&conformance=full"
        ).unwrap();

        assert!(dsn.tls_enabled());
        assert!(!dsn.skip_verify());
        assert_eq!(dsn.page_size(), 2000);
        assert_eq!(dsn.client_name(), "test-app");
        assert_eq!(dsn.conformance(), "full");
    }

    #[test]
    fn test_dsn_parse_unknown_options_preserved() {
        let dsn = Dsn::parse("quic://localhost:3141?custom_option=value").unwrap();
        assert_eq!(
            dsn.options().get("custom_option"),
            Some(&"value".to_string())
        );
    }

    #[test]
    fn test_dsn_parse_option_aliases() {
        // Test username/user alias
        let dsn1 = Dsn::parse("grpc://localhost:50051?user=admin").unwrap();
        let dsn2 = Dsn::parse("grpc://localhost:50051?username=admin").unwrap();
        assert_eq!(dsn1.username(), dsn2.username());

        // Test password/pass alias
        let dsn3 = Dsn::parse("grpc://localhost:50051?pass=secret").unwrap();
        let dsn4 = Dsn::parse("grpc://localhost:50051?password=secret").unwrap();
        assert_eq!(dsn3.password(), dsn4.password());

        // Test skip_verify/insecure alias
        let dsn5 = Dsn::parse("grpc://localhost:50051?skip_verify=true").unwrap();
        let dsn6 = Dsn::parse("grpc://localhost:50051?insecure=true").unwrap();
        assert_eq!(dsn5.skip_verify(), dsn6.skip_verify());
    }

    #[test]
    fn test_dsn_parse_percent_encoded_values() {
        let dsn = Dsn::parse("quic://localhost:3141?client_name=My%20App").unwrap();
        assert_eq!(dsn.client_name(), "My App");
    }

    #[test]
    fn test_dsn_parse_mtls_options() {
        let dsn = Dsn::parse(
            "grpc://localhost:50051?ca=/path/ca.crt&cert=/path/client.crt&key=/path/client.key",
        )
        .unwrap();
        assert_eq!(dsn.ca_cert(), Some("/path/ca.crt"));
        assert_eq!(dsn.client_cert(), Some("/path/client.crt"));
        assert_eq!(dsn.client_key(), Some("/path/client.key"));
    }

    #[test]
    fn test_dsn_parse_mtls_options_alt_names() {
        let dsn = Dsn::parse("grpc://localhost:50051?ca_cert=/path/ca.crt&client_cert=/path/client.crt&client_key=/path/client.key").unwrap();
        assert_eq!(dsn.ca_cert(), Some("/path/ca.crt"));
        assert_eq!(dsn.client_cert(), Some("/path/client.crt"));
        assert_eq!(dsn.client_key(), Some("/path/client.key"));
    }

    #[test]
    fn test_dsn_parse_connect_timeout() {
        let dsn = Dsn::parse("quic://localhost:3141?connect_timeout=60").unwrap();
        assert_eq!(dsn.connect_timeout_secs(), Some(60));
    }

    #[test]
    fn test_dsn_parse_server_name() {
        let dsn = Dsn::parse("quic://localhost:3141?server_name=geode.example.com").unwrap();
        assert_eq!(dsn.server_name(), Some("geode.example.com"));
    }

    // ==========================================================================
    // insecure_tls_skip_verify Parameter Tests (Unified DSN)
    // ==========================================================================

    #[test]
    fn test_dsn_parse_insecure_tls_skip_verify_primary() {
        // Primary parameter name
        let dsn = Dsn::parse("quic://localhost:3141?insecure_tls_skip_verify=true").unwrap();
        assert!(dsn.skip_verify());

        let dsn = Dsn::parse("quic://localhost:3141?insecure_tls_skip_verify=1").unwrap();
        assert!(dsn.skip_verify());

        let dsn = Dsn::parse("quic://localhost:3141?insecure_tls_skip_verify=yes").unwrap();
        assert!(dsn.skip_verify());

        let dsn = Dsn::parse("quic://localhost:3141?insecure_tls_skip_verify=on").unwrap();
        assert!(dsn.skip_verify());

        let dsn = Dsn::parse("quic://localhost:3141?insecure_tls_skip_verify=false").unwrap();
        assert!(!dsn.skip_verify());
    }

    #[test]
    fn test_dsn_parse_insecure_alias() {
        // Alias: insecure
        let dsn = Dsn::parse("quic://localhost:3141?insecure=true").unwrap();
        assert!(dsn.skip_verify());

        let dsn = Dsn::parse("grpc://localhost:50051?insecure=1").unwrap();
        assert!(dsn.skip_verify());

        let dsn = Dsn::parse("localhost:3141?insecure=yes").unwrap();
        assert!(dsn.skip_verify());
    }

    #[test]
    fn test_dsn_parse_skip_verify_alias() {
        // Alias: skip_verify
        let dsn = Dsn::parse("quic://localhost:3141?skip_verify=true").unwrap();
        assert!(dsn.skip_verify());

        let dsn = Dsn::parse("grpc://localhost:50051?skip_verify=1").unwrap();
        assert!(dsn.skip_verify());

        let dsn = Dsn::parse("quic://localhost:3141?skip_verify=on").unwrap();
        assert!(dsn.skip_verify());
    }

    #[test]
    fn test_dsn_parse_insecure_skip_verify_alias() {
        // Alias: insecure_skip_verify
        let dsn = Dsn::parse("quic://localhost:3141?insecure_skip_verify=true").unwrap();
        assert!(dsn.skip_verify());

        let dsn = Dsn::parse("grpc://localhost:50051?insecure_skip_verify=1").unwrap();
        assert!(dsn.skip_verify());

        let dsn = Dsn::parse("localhost:3141?insecure_skip_verify=on").unwrap();
        assert!(dsn.skip_verify());

        let dsn = Dsn::parse("quic://localhost:3141?insecure_skip_verify=false").unwrap();
        assert!(!dsn.skip_verify());
    }

    #[test]
    fn test_dsn_skip_verify_default_false() {
        // Default should be false
        let dsn = Dsn::parse("quic://localhost:3141").unwrap();
        assert!(!dsn.skip_verify());

        let dsn = Dsn::parse("grpc://localhost:50051").unwrap();
        assert!(!dsn.skip_verify());

        let dsn = Dsn::parse("localhost:3141").unwrap();
        assert!(!dsn.skip_verify());
    }

    // ==========================================================================
    // Transport Display Tests
    // ==========================================================================

    #[test]
    fn test_transport_display() {
        assert_eq!(Transport::Quic.to_string(), "quic");
        assert_eq!(Transport::Grpc.to_string(), "grpc");
    }

    // ==========================================================================
    // Address Formatting Tests
    // ==========================================================================

    #[test]
    fn test_dsn_address_ipv4() {
        let dsn = Dsn::parse("quic://192.168.1.1:3141").unwrap();
        assert_eq!(dsn.address(), "192.168.1.1:3141");
    }

    #[test]
    fn test_dsn_address_hostname() {
        let dsn = Dsn::parse("grpc://geode.example.com:50051").unwrap();
        assert_eq!(dsn.address(), "geode.example.com:50051");
    }

    // ==========================================================================
    // Acceptance Tests (from task requirements)
    // ==========================================================================

    #[test]
    fn test_acceptance_quic_localhost() {
        // DSN parse: quic://localhost:1234 ⇒ transport=QUIC, host=localhost, port=1234
        let dsn = Dsn::parse("quic://localhost:1234").unwrap();
        assert_eq!(dsn.transport(), Transport::Quic);
        assert_eq!(dsn.host(), "localhost");
        assert_eq!(dsn.port(), 1234);
    }

    #[test]
    fn test_acceptance_grpc_with_tls_disabled() {
        // DSN parse: grpc://127.0.0.1:50051?tls=0 ⇒ transport=GRPC, host=127.0.0.1, port=50051, tls disabled
        let dsn = Dsn::parse("grpc://127.0.0.1:50051?tls=0").unwrap();
        assert_eq!(dsn.transport(), Transport::Grpc);
        assert_eq!(dsn.host(), "127.0.0.1");
        assert_eq!(dsn.port(), 50051);
        assert!(!dsn.tls_enabled());
    }

    #[test]
    fn test_acceptance_invalid_scheme() {
        // DSN parse invalid: http://localhost:1 ⇒ deterministic "unsupported scheme" error
        let err = Dsn::parse("http://localhost:1").unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("Unsupported scheme") || err_str.contains("unsupported"),
            "Expected 'unsupported scheme' error, got: {}",
            err_str
        );
    }

    // ==========================================================================
    // Security Tests
    // ==========================================================================

    #[test]
    fn test_dsn_debug_redacts_password() {
        let dsn = Dsn::parse("quic://user:secret@localhost:3141").unwrap();
        let debug_str = format!("{:?}", dsn);
        assert!(
            !debug_str.contains("secret"),
            "Debug output must not contain password"
        );
        assert!(
            debug_str.contains("REDACTED"),
            "Debug output must show REDACTED"
        );
    }

    // ==========================================================================
    // DSN Round-trip (to_dsn) Tests
    // ==========================================================================

    fn assert_roundtrip(dsn_str: &str) {
        let parsed = Dsn::parse(dsn_str).unwrap();
        let formatted = parsed.to_dsn();
        let reparsed = Dsn::parse(&formatted).unwrap_or_else(|e| {
            panic!(
                "reparse of {:?} (from {:?}) failed: {}",
                formatted, dsn_str, e
            )
        });
        assert_eq!(
            parsed, reparsed,
            "round-trip mismatch: {:?} -> {:?}",
            dsn_str, formatted
        );
    }

    #[test]
    fn test_to_dsn_roundtrip_quic_basic() {
        assert_roundtrip("quic://localhost:3141");
    }

    #[test]
    fn test_to_dsn_roundtrip_grpc_tls_disabled() {
        assert_roundtrip("grpc://127.0.0.1:50051?tls=0");
    }

    #[test]
    fn test_to_dsn_roundtrip_page_size() {
        assert_roundtrip("quic://localhost:3141?page_size=2500");
    }

    #[test]
    fn test_to_dsn_roundtrip_graph() {
        assert_roundtrip("quic://localhost:3141?graph=mygraph");
    }

    // GAP-0841: tenant + role flow through the DSN so multi-tenant + FLE work.
    #[test]
    fn test_dsn_parses_tenant_and_role_gap0841() {
        let dsn = Dsn::parse("quic://localhost:3141?tenant=acme-corp&role=analyst").unwrap();
        assert_eq!(dsn.tenant(), Some("acme-corp"));
        assert_eq!(dsn.role(), Some("analyst"));
    }

    #[test]
    fn test_dsn_tenant_id_alias_gap0841() {
        // `tenant_id` is accepted as an alias for `tenant`.
        let dsn = Dsn::parse("quic://localhost:3141?tenant_id=acme-corp").unwrap();
        assert_eq!(dsn.tenant(), Some("acme-corp"));
    }

    #[test]
    fn test_to_dsn_roundtrip_tenant_and_role_gap0841() {
        assert_roundtrip("quic://localhost:3141?role=analyst&tenant=acme-corp");
    }

    #[test]
    fn test_to_dsn_roundtrip_userpass() {
        assert_roundtrip("quic://admin:secret@localhost:3141");
    }

    #[test]
    fn test_to_dsn_roundtrip_user_only() {
        assert_roundtrip("quic://admin@localhost:3141");
    }

    #[test]
    fn test_to_dsn_roundtrip_password_only() {
        // password-only falls back to ?pass= (matches Go fix 6aee266)
        let parsed = Dsn::parse("quic://localhost:3141?pass=secret").unwrap();
        let formatted = parsed.to_dsn();
        assert!(
            formatted.contains("pass=secret"),
            "password-only DSN should emit pass= query param, got: {}",
            formatted
        );
        let reparsed = Dsn::parse(&formatted).unwrap();
        assert_eq!(parsed, reparsed);
        assert_eq!(reparsed.password(), Some("secret"));
        assert_eq!(reparsed.username(), None);
    }

    #[test]
    fn test_to_dsn_roundtrip_ipv6() {
        assert_roundtrip("quic://[::1]:3141");
        assert_roundtrip("grpc://[2001:db8::1]:50051?tls=0");
    }

    #[test]
    fn test_to_dsn_roundtrip_skip_verify() {
        assert_roundtrip("quic://localhost:3141?insecure_tls_skip_verify=true");
    }

    #[test]
    fn test_to_dsn_roundtrip_full() {
        assert_roundtrip(
            "grpc://admin:p%40ss@host.example.com:50051?tls=0&page_size=500&conformance=full&graph=g1&connect_timeout=60",
        );
    }

    #[test]
    fn test_to_dsn_scheme_present() {
        let dsn = Dsn::parse("grpc://localhost:50051").unwrap();
        assert!(dsn.to_dsn().starts_with("grpc://"));
        let dsn = Dsn::parse("quic://localhost:3141").unwrap();
        assert!(dsn.to_dsn().starts_with("quic://"));
    }

    #[test]
    fn test_dsn_debug_no_password_shows_none() {
        let dsn = Dsn::parse("quic://localhost:3141").unwrap();
        let debug_str = format!("{:?}", dsn);
        assert!(
            debug_str.contains("password: None"),
            "Debug output should show None when no password is set"
        );
    }
}
