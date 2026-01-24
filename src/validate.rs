//! Input validation utilities for the Geode client.
//!
//! This module provides validation functions for user-supplied inputs
//! to prevent injection attacks and ensure data integrity.

use crate::error::{Error, Result};

/// Maximum allowed query length in bytes
pub const MAX_QUERY_LENGTH: usize = 1_000_000; // 1 MB

/// Maximum allowed parameter name length
pub const MAX_PARAM_NAME_LENGTH: usize = 128;

/// Maximum allowed hostname length
pub const MAX_HOSTNAME_LENGTH: usize = 253;

/// Validate a GQL query string.
///
/// # Validation Rules
/// - Query must not be empty
/// - Query must not exceed MAX_QUERY_LENGTH bytes
/// - Query must be valid UTF-8 (enforced by Rust's String type)
///
/// # Examples
///
/// ```
/// use geode_client::validate;
///
/// assert!(validate::query("MATCH (n) RETURN n").is_ok());
/// assert!(validate::query("").is_err());
/// ```
pub fn query(q: &str) -> Result<()> {
    if q.is_empty() {
        return Err(Error::validation("Query cannot be empty"));
    }

    if q.len() > MAX_QUERY_LENGTH {
        return Err(Error::validation(format!(
            "Query exceeds maximum length of {} bytes",
            MAX_QUERY_LENGTH
        )));
    }

    // Check for null bytes which could cause issues with C-based libraries
    if q.contains('\0') {
        return Err(Error::validation("Query contains invalid null character"));
    }

    Ok(())
}

/// Validate a parameter name.
///
/// # Validation Rules
/// - Name must not be empty
/// - Name must not exceed MAX_PARAM_NAME_LENGTH
/// - Name must start with a letter or underscore
/// - Name can only contain letters, digits, and underscores
///
/// # Examples
///
/// ```
/// use geode_client::validate;
///
/// assert!(validate::param_name("user_id").is_ok());
/// assert!(validate::param_name("_private").is_ok());
/// assert!(validate::param_name("123invalid").is_err());
/// assert!(validate::param_name("").is_err());
/// ```
pub fn param_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::validation("Parameter name cannot be empty"));
    }

    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(Error::validation(format!(
            "Parameter name exceeds maximum length of {} characters",
            MAX_PARAM_NAME_LENGTH
        )));
    }

    let mut chars = name.chars();

    // First character must be letter or underscore
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        Some(c) => {
            return Err(Error::validation(format!(
                "Parameter name must start with a letter or underscore, found '{}'",
                c
            )));
        }
        None => unreachable!(), // Already checked for empty
    }

    // Rest must be alphanumeric or underscore
    for c in chars {
        if !c.is_ascii_alphanumeric() && c != '_' {
            return Err(Error::validation(format!(
                "Parameter name contains invalid character '{}'",
                c
            )));
        }
    }

    Ok(())
}

/// Validate a hostname.
///
/// # Validation Rules
/// - Hostname must not be empty
/// - Hostname must not exceed MAX_HOSTNAME_LENGTH (253 characters per RFC 1035)
/// - Each label (between dots) must be 1-63 characters
/// - Labels can only contain letters, digits, and hyphens
/// - Labels cannot start or end with a hyphen
/// - IP addresses (v4 and v6) are allowed
///
/// # Examples
///
/// ```
/// use geode_client::validate;
///
/// assert!(validate::hostname("localhost").is_ok());
/// assert!(validate::hostname("geode.example.com").is_ok());
/// assert!(validate::hostname("192.168.1.1").is_ok());
/// assert!(validate::hostname("::1").is_ok());
/// assert!(validate::hostname("").is_err());
/// ```
pub fn hostname(host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(Error::validation("Hostname cannot be empty"));
    }

    if host.len() > MAX_HOSTNAME_LENGTH {
        return Err(Error::validation(format!(
            "Hostname exceeds maximum length of {} characters",
            MAX_HOSTNAME_LENGTH
        )));
    }

    // Allow IPv6 addresses in brackets
    if host.starts_with('[') && host.ends_with(']') {
        let ipv6 = &host[1..host.len() - 1];
        return validate_ipv6(ipv6);
    }

    // Allow bare IPv6 addresses
    if host.contains(':') && !host.contains('.') {
        return validate_ipv6(host);
    }

    // Check if it's an IPv4 address
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return validate_ipv4(host);
    }

    // Validate as hostname
    validate_hostname_labels(host)
}

fn validate_ipv4(addr: &str) -> Result<()> {
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 {
        return Err(Error::validation("Invalid IPv4 address format"));
    }

    for part in parts {
        match part.parse::<u8>() {
            Ok(_) => {}
            Err(_) => {
                return Err(Error::validation(format!("Invalid IPv4 octet: {}", part)));
            }
        }
    }

    Ok(())
}

fn validate_ipv6(addr: &str) -> Result<()> {
    // Basic IPv6 validation - check for valid characters
    for c in addr.chars() {
        if !c.is_ascii_hexdigit() && c != ':' {
            return Err(Error::validation(format!(
                "Invalid character in IPv6 address: {}",
                c
            )));
        }
    }

    // Check for at least one colon
    if !addr.contains(':') {
        return Err(Error::validation("Invalid IPv6 address format"));
    }

    Ok(())
}

fn validate_hostname_labels(host: &str) -> Result<()> {
    let labels: Vec<&str> = host.split('.').collect();

    for label in labels {
        if label.is_empty() {
            return Err(Error::validation("Hostname contains empty label"));
        }

        if label.len() > 63 {
            return Err(Error::validation(format!(
                "Hostname label '{}' exceeds 63 characters",
                label
            )));
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::validation(format!(
                "Hostname label '{}' cannot start or end with hyphen",
                label
            )));
        }

        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' {
                return Err(Error::validation(format!(
                    "Hostname contains invalid character '{}'",
                    c
                )));
            }
        }
    }

    Ok(())
}

/// Validate a port number.
///
/// # Validation Rules
/// - Port must be in the range 1-65535
/// - Port 0 is not allowed (reserved)
///
/// # Examples
///
/// ```
/// use geode_client::validate;
///
/// assert!(validate::port(3141).is_ok());
/// assert!(validate::port(443).is_ok());
/// assert!(validate::port(0).is_err());
/// ```
pub fn port(p: u16) -> Result<()> {
    if p == 0 {
        return Err(Error::validation("Port 0 is reserved and cannot be used"));
    }
    Ok(())
}

/// Validate a page size.
///
/// # Validation Rules
/// - Page size must be at least 1
/// - Page size must not exceed 100,000
///
/// # Examples
///
/// ```
/// use geode_client::validate;
///
/// assert!(validate::page_size(100).is_ok());
/// assert!(validate::page_size(0).is_err());
/// assert!(validate::page_size(200_000).is_err());
/// ```
pub fn page_size(size: usize) -> Result<()> {
    if size == 0 {
        return Err(Error::validation("Page size must be at least 1"));
    }

    if size > 100_000 {
        return Err(Error::validation("Page size cannot exceed 100,000 rows"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Query Validation Tests ====================

    #[test]
    fn test_query_valid() {
        assert!(query("MATCH (n) RETURN n").is_ok());
        assert!(query("RETURN 1").is_ok());
        assert!(query("CREATE (n:Person {name: 'Alice'})").is_ok());
    }

    #[test]
    fn test_query_empty() {
        let result = query("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_query_too_long() {
        let long_query = "x".repeat(MAX_QUERY_LENGTH + 1);
        let result = query(&long_query);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum length"));
    }

    #[test]
    fn test_query_with_null() {
        let result = query("RETURN \0 AS x");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("null"));
    }

    #[test]
    fn test_query_unicode() {
        assert!(query("RETURN '日本語' AS text").is_ok());
        assert!(query("CREATE (n {emoji: '🚀'})").is_ok());
    }

    #[test]
    fn test_query_whitespace_only() {
        // Whitespace-only is technically valid (will fail at server)
        assert!(query("   ").is_ok());
    }

    // ==================== Parameter Name Tests ====================

    #[test]
    fn test_param_name_valid() {
        assert!(param_name("user_id").is_ok());
        assert!(param_name("_private").is_ok());
        assert!(param_name("x").is_ok());
        assert!(param_name("userName123").is_ok());
        assert!(param_name("_").is_ok());
        assert!(param_name("__double__").is_ok());
    }

    #[test]
    fn test_param_name_empty() {
        let result = param_name("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_param_name_starts_with_digit() {
        let result = param_name("123invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("start with"));
    }

    #[test]
    fn test_param_name_invalid_chars() {
        assert!(param_name("user-id").is_err()); // hyphen
        assert!(param_name("user.id").is_err()); // dot
        assert!(param_name("user id").is_err()); // space
        assert!(param_name("user@id").is_err()); // special char
    }

    #[test]
    fn test_param_name_too_long() {
        let long_name = "a".repeat(MAX_PARAM_NAME_LENGTH + 1);
        let result = param_name(&long_name);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum length"));
    }

    // ==================== Hostname Tests ====================

    #[test]
    fn test_hostname_valid() {
        assert!(hostname("localhost").is_ok());
        assert!(hostname("geode.example.com").is_ok());
        assert!(hostname("my-server").is_ok());
        assert!(hostname("server1").is_ok());
        assert!(hostname("a.b.c.d.e").is_ok());
    }

    #[test]
    fn test_hostname_empty() {
        let result = hostname("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_hostname_ipv4() {
        assert!(hostname("192.168.1.1").is_ok());
        assert!(hostname("127.0.0.1").is_ok());
        assert!(hostname("0.0.0.0").is_ok());
        assert!(hostname("255.255.255.255").is_ok());
    }

    #[test]
    fn test_hostname_ipv4_invalid() {
        assert!(hostname("256.1.1.1").is_err()); // octet > 255
        assert!(hostname("1.2.3").is_err()); // too few octets
        assert!(hostname("1.2.3.4.5").is_err()); // too many octets
    }

    #[test]
    fn test_hostname_ipv6() {
        assert!(hostname("::1").is_ok());
        assert!(hostname("fe80::1").is_ok());
        assert!(hostname("[::1]").is_ok());
        assert!(hostname("[fe80::1]").is_ok());
    }

    #[test]
    fn test_hostname_label_hyphen() {
        assert!(hostname("-invalid").is_err());
        assert!(hostname("invalid-").is_err());
        assert!(hostname("valid-host").is_ok());
    }

    #[test]
    fn test_hostname_label_too_long() {
        let long_label = "a".repeat(64);
        let result = hostname(&long_label);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("63"));
    }

    #[test]
    fn test_hostname_too_long() {
        let long_host = format!("{}.example.com", "a".repeat(250));
        let result = hostname(&long_host);
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_invalid_chars() {
        assert!(hostname("invalid_host").is_err()); // underscore
        assert!(hostname("invalid host").is_err()); // space
        assert!(hostname("invalid@host").is_err()); // special char
    }

    // ==================== Port Tests ====================

    #[test]
    fn test_port_valid() {
        assert!(port(1).is_ok());
        assert!(port(80).is_ok());
        assert!(port(443).is_ok());
        assert!(port(3141).is_ok());
        assert!(port(8443).is_ok());
        assert!(port(65535).is_ok());
    }

    #[test]
    fn test_port_zero() {
        let result = port(0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("reserved"));
    }

    // ==================== Page Size Tests ====================

    #[test]
    fn test_page_size_valid() {
        assert!(page_size(1).is_ok());
        assert!(page_size(100).is_ok());
        assert!(page_size(1000).is_ok());
        assert!(page_size(100_000).is_ok());
    }

    #[test]
    fn test_page_size_zero() {
        let result = page_size(0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least 1"));
    }

    #[test]
    fn test_page_size_too_large() {
        let result = page_size(100_001);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("100,000"));
    }
}
