//! Error types for the Geode client.

use thiserror::Error;

/// Result type alias for Geode operations
pub type Result<T> = std::result::Result<T, Error>;

/// ISO/IEC 39075 status class for authorization errors.
pub const STATUS_AUTH: &str = "28000";
/// Geode-specific extension class for "password reset required".
pub const STATUS_PASSWORD_RESET: &str = "08P01";
/// ISO/IEC 39075 status class for syntax errors.
pub const STATUS_SYNTAX: &str = "42000";

/// Error types that can occur when using the Geode client
#[derive(Error, Debug)]
pub enum Error {
    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Query execution error
    #[error("Query error: {code} - {message}")]
    Query { code: String, message: String },

    /// Authentication error
    #[error("Authentication error: {0}")]
    Auth(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// QUIC connection error
    #[error("QUIC error: {0}")]
    Quic(String),

    /// TLS error
    #[error("TLS error: {0}")]
    Tls(String),

    /// Invalid DSN format
    #[error("Invalid DSN: {0}")]
    InvalidDsn(String),

    /// Type conversion error
    #[error("Type error: {0}")]
    Type(String),

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Pool error
    #[error("Pool error: {0}")]
    Pool(String),

    /// Input validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Client-side limit exceeded (frame size, rows, depth, etc.)
    #[error("Limit exceeded: {0}")]
    Limit(String),

    /// No rows returned by a query expected to return at least one row.
    ///
    /// Mirrors the Go reference client's `ErrNoRows` sentinel.
    #[error("no rows in result set")]
    NoRows,

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Create a connection error
    pub fn connection<S: Into<String>>(msg: S) -> Self {
        Error::Connection(msg.into())
    }

    /// Create a query error
    pub fn query<S: Into<String>>(msg: S) -> Self {
        Error::Query {
            code: "QUERY_ERROR".to_string(),
            message: msg.into(),
        }
    }

    /// Create a protocol error
    pub fn protocol<S: Into<String>>(msg: S) -> Self {
        Error::Connection(format!("Protocol error: {}", msg.into()))
    }

    /// Create a transaction error
    pub fn transaction<S: Into<String>>(msg: S) -> Self {
        Error::Connection(format!("Transaction error: {}", msg.into()))
    }

    /// Create a timeout error
    pub fn timeout() -> Self {
        Error::Timeout
    }

    /// Create an auth error
    pub fn auth<S: Into<String>>(msg: S) -> Self {
        Error::Auth(msg.into())
    }

    /// Create a QUIC error
    pub fn quic<S: Into<String>>(msg: S) -> Self {
        Error::Quic(msg.into())
    }

    /// Create a TLS error
    pub fn tls<S: Into<String>>(msg: S) -> Self {
        Error::Tls(msg.into())
    }

    /// Create a type error
    pub fn type_error<S: Into<String>>(msg: S) -> Self {
        Error::Type(msg.into())
    }

    /// Create a pool error
    pub fn pool<S: Into<String>>(msg: S) -> Self {
        Error::Pool(msg.into())
    }

    /// Create a validation error
    pub fn validation<S: Into<String>>(msg: S) -> Self {
        Error::Validation(msg.into())
    }

    /// Create a client limit error
    pub fn limit<S: Into<String>>(msg: S) -> Self {
        Error::Limit(msg.into())
    }

    /// Create an invalid DSN error
    pub fn invalid_dsn<S: Into<String>>(msg: S) -> Self {
        Error::InvalidDsn(msg.into())
    }

    /// Create a no-rows error.
    pub fn no_rows() -> Self {
        Error::NoRows
    }

    /// Check if the error is retryable
    ///
    /// Retryable errors are transient failures that may succeed on retry:
    /// - Connection errors (network issues)
    /// - Timeout errors
    /// - QUIC errors (connection reset, etc.)
    /// - Query errors with serialization failure codes (40001, 40P01)
    #[inline]
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Connection(_) => true,
            Error::Timeout => true,
            Error::Quic(_) => true,
            Error::Query { code, .. } => {
                // ISO/IEC 39075 retryable codes
                code == "40001" || code == "40P01" || code == "40502"
            }
            Error::Pool(_) => true,
            _ => false,
        }
    }

    /// Get the error code if this is a query error
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Query { code, .. } => Some(code),
            _ => None,
        }
    }

    /// Reports whether this is a Geode authentication or authorization
    /// failure.
    ///
    /// Returns `true` for query errors carrying the ISO/IEC 39075 status
    /// class `28000` (authorization error) or the Geode-specific `08P01`
    /// (password reset required) extension. Mirrors the Go reference
    /// client's `IsAuthError`.
    #[inline]
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            Error::Query { code, .. } if code == STATUS_AUTH || code == STATUS_PASSWORD_RESET
        )
    }

    /// Reports whether this is a GQL parse or syntax error (status class
    /// `42000`).
    ///
    /// The Geode engine returns `42000` for unrecognised statements,
    /// including admin DDL verbs not yet implemented in the connected
    /// server build, so handlers can use this to degrade gracefully.
    /// Mirrors the Go reference client's `IsSyntaxError`.
    #[inline]
    pub fn is_syntax_error(&self) -> bool {
        matches!(self, Error::Query { code, .. } if code == STATUS_SYNTAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_error_display_connection() {
        let err = Error::Connection("connection refused".to_string());
        assert_eq!(err.to_string(), "Connection error: connection refused");
    }

    #[test]
    fn test_error_display_query() {
        let err = Error::Query {
            code: "42000".to_string(),
            message: "syntax error".to_string(),
        };
        assert_eq!(err.to_string(), "Query error: 42000 - syntax error");
    }

    #[test]
    fn test_error_display_auth() {
        let err = Error::Auth("invalid credentials".to_string());
        assert_eq!(err.to_string(), "Authentication error: invalid credentials");
    }

    #[test]
    fn test_error_display_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err = Error::Io(io_err);
        assert!(err.to_string().starts_with("I/O error:"));
    }

    #[test]
    fn test_error_display_json() {
        let json_err: serde_json::Error = serde_json::from_str::<i32>("invalid").unwrap_err();
        let err = Error::Json(json_err);
        assert!(err.to_string().starts_with("JSON error:"));
    }

    #[test]
    fn test_error_display_quic() {
        let err = Error::Quic("connection reset".to_string());
        assert_eq!(err.to_string(), "QUIC error: connection reset");
    }

    #[test]
    fn test_error_display_tls() {
        let err = Error::Tls("certificate expired".to_string());
        assert_eq!(err.to_string(), "TLS error: certificate expired");
    }

    #[test]
    fn test_error_display_invalid_dsn() {
        let err = Error::InvalidDsn("missing host".to_string());
        assert_eq!(err.to_string(), "Invalid DSN: missing host");
    }

    #[test]
    fn test_error_display_type() {
        let err = Error::Type("cannot convert int to string".to_string());
        assert_eq!(err.to_string(), "Type error: cannot convert int to string");
    }

    #[test]
    fn test_error_display_timeout() {
        let err = Error::Timeout;
        assert_eq!(err.to_string(), "Operation timed out");
    }

    #[test]
    fn test_error_display_pool() {
        let err = Error::Pool("pool exhausted".to_string());
        assert_eq!(err.to_string(), "Pool error: pool exhausted");
    }

    #[test]
    fn test_error_display_limit() {
        let err = Error::Limit("frame too large".to_string());
        assert_eq!(err.to_string(), "Limit exceeded: frame too large");
    }

    #[test]
    fn test_error_display_other() {
        let err = Error::Other("unknown error".to_string());
        assert_eq!(err.to_string(), "unknown error");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn test_error_from_json() {
        let json_err: serde_json::Error = serde_json::from_str::<i32>("not_a_number").unwrap_err();
        let err: Error = json_err.into();
        assert!(matches!(err, Error::Json(_)));
    }

    #[test]
    fn test_error_helper_connection() {
        let err = Error::connection("test connection error");
        assert!(matches!(err, Error::Connection(msg) if msg == "test connection error"));
    }

    #[test]
    fn test_error_helper_query() {
        let err = Error::query("test query error");
        assert!(matches!(err, Error::Query { code, message }
            if code == "QUERY_ERROR" && message == "test query error"));
    }

    #[test]
    fn test_error_helper_protocol() {
        let err = Error::protocol("invalid frame");
        assert!(matches!(err, Error::Connection(msg) if msg.contains("Protocol error")));
    }

    #[test]
    fn test_error_helper_transaction() {
        let err = Error::transaction("rollback failed");
        assert!(matches!(err, Error::Connection(msg) if msg.contains("Transaction error")));
    }

    #[test]
    fn test_error_helper_timeout() {
        let err = Error::timeout();
        assert!(matches!(err, Error::Timeout));
    }

    #[test]
    fn test_error_helper_auth() {
        let err = Error::auth("bad token");
        assert!(matches!(err, Error::Auth(msg) if msg == "bad token"));
    }

    #[test]
    fn test_error_helper_quic() {
        let err = Error::quic("stream closed");
        assert!(matches!(err, Error::Quic(msg) if msg == "stream closed"));
    }

    #[test]
    fn test_error_helper_tls() {
        let err = Error::tls("handshake failed");
        assert!(matches!(err, Error::Tls(msg) if msg == "handshake failed"));
    }

    #[test]
    fn test_error_helper_type_error() {
        let err = Error::type_error("invalid cast");
        assert!(matches!(err, Error::Type(msg) if msg == "invalid cast"));
    }

    #[test]
    fn test_error_helper_pool() {
        let err = Error::pool("no connections available");
        assert!(matches!(err, Error::Pool(msg) if msg == "no connections available"));
    }

    #[test]
    fn test_error_helper_limit() {
        let err = Error::limit("max rows exceeded");
        assert!(matches!(err, Error::Limit(msg) if msg == "max rows exceeded"));
    }

    #[test]
    fn test_error_is_retryable_connection() {
        let err = Error::Connection("network error".to_string());
        assert!(err.is_retryable());
    }

    #[test]
    fn test_error_is_retryable_timeout() {
        let err = Error::Timeout;
        assert!(err.is_retryable());
    }

    #[test]
    fn test_error_is_retryable_quic() {
        let err = Error::Quic("reset".to_string());
        assert!(err.is_retryable());
    }

    #[test]
    fn test_error_is_retryable_pool() {
        let err = Error::Pool("exhausted".to_string());
        assert!(err.is_retryable());
    }

    #[test]
    fn test_error_is_retryable_serialization_failure() {
        let err = Error::Query {
            code: "40001".to_string(),
            message: "serialization failure".to_string(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn test_error_is_retryable_deadlock() {
        let err = Error::Query {
            code: "40P01".to_string(),
            message: "deadlock detected".to_string(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn test_error_is_retryable_transaction_deadlock() {
        let err = Error::Query {
            code: "40502".to_string(),
            message: "transaction deadlock".to_string(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn test_error_not_retryable_syntax() {
        let err = Error::Query {
            code: "42000".to_string(),
            message: "syntax error".to_string(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_error_not_retryable_auth() {
        let err = Error::Auth("invalid".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_error_not_retryable_tls() {
        let err = Error::Tls("cert error".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_error_not_retryable_dsn() {
        let err = Error::InvalidDsn("bad format".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_error_not_retryable_type() {
        let err = Error::Type("cast failed".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_is_auth_error_class_28000() {
        let err = Error::Query {
            code: "28000".to_string(),
            message: "invalid authorization specification".to_string(),
        };
        assert!(err.is_auth_error());
    }

    #[test]
    fn test_is_auth_error_geode_08p01() {
        let err = Error::Query {
            code: "08P01".to_string(),
            message: "password reset required".to_string(),
        };
        assert!(err.is_auth_error());
    }

    #[test]
    fn test_is_auth_error_false_for_other_codes() {
        let err = Error::Query {
            code: "42000".to_string(),
            message: "syntax error".to_string(),
        };
        assert!(!err.is_auth_error());

        let err = Error::Connection("network".to_string());
        assert!(!err.is_auth_error());
    }

    #[test]
    fn test_is_syntax_error_class_42000() {
        let err = Error::Query {
            code: "42000".to_string(),
            message: "syntax error".to_string(),
        };
        assert!(err.is_syntax_error());
    }

    #[test]
    fn test_is_syntax_error_false_for_other_codes() {
        let err = Error::Query {
            code: "28000".to_string(),
            message: "auth".to_string(),
        };
        assert!(!err.is_syntax_error());

        let err = Error::Validation("bad".to_string());
        assert!(!err.is_syntax_error());
    }

    #[test]
    fn test_error_code_query() {
        let err = Error::Query {
            code: "42000".to_string(),
            message: "syntax error".to_string(),
        };
        assert_eq!(err.code(), Some("42000"));
    }

    #[test]
    fn test_error_code_non_query() {
        let err = Error::Connection("test".to_string());
        assert_eq!(err.code(), None);
    }

    #[test]
    fn test_result_type_alias() {
        fn returns_result() -> Result<i32> {
            Ok(42)
        }
        assert_eq!(returns_result().unwrap(), 42);
    }

    #[test]
    fn test_result_type_alias_error() {
        fn returns_error() -> Result<i32> {
            Err(Error::Other("test".to_string()))
        }
        assert!(returns_error().is_err());
    }

    #[test]
    fn test_error_string_conversion() {
        // Test that Into<String> works for &str
        let err = Error::connection("test");
        assert!(matches!(err, Error::Connection(_)));

        // Test that Into<String> works for String
        let err = Error::connection(String::from("test"));
        assert!(matches!(err, Error::Connection(_)));
    }

    #[test]
    fn test_error_debug() {
        let err = Error::Connection("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Connection"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_no_rows() {
        let err = Error::no_rows();
        assert!(matches!(err, Error::NoRows));
        assert_eq!(err.to_string(), "no rows in result set");
        assert!(!err.is_retryable());
        assert!(!err.is_auth_error());
        assert!(!err.is_syntax_error());
    }
}
