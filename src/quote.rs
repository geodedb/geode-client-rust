//! GQL quoting and sanitization helpers.
//!
//! These mirror the Go reference client's `SanitizeGraphName`,
//! `QuoteIdent`, and `QuoteString` so that user-supplied names and string
//! literals can be inlined into GQL admin statements without opening an
//! injection vector.

use crate::error::{Error, Result};

/// Returns `name` stripped of any character that is not alphanumeric,
/// underscore, or hyphen, so it can be inlined safely into a `USE GRAPH`
/// statement without opening an injection vector.
///
/// # Example
///
/// ```
/// use geode_client::sanitize_graph_name;
///
/// assert_eq!(sanitize_graph_name("my graph!"), "mygraph");
/// assert_eq!(sanitize_graph_name("prod-db_01"), "prod-db_01");
/// ```
pub fn sanitize_graph_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            out.push(c);
        }
    }
    out
}

/// Validates and returns `name` in a form safe to inline into a GQL admin
/// statement that takes an identifier (`CREATE USER`, `ALTER USER`,
/// `CREATE MIGRATION`, etc.).
///
/// Valid identifiers consist of ASCII letters, digits, underscore, and
/// hyphen, and must not start with a hyphen. Digits are permitted at any
/// position, including the first character, because some upstream catalogs
/// use digit-prefixed names (e.g. migration names like `005_add_index`).
///
/// # Errors
///
/// Returns [`Error::Validation`] for empty strings or inputs containing
/// characters outside this set (including a leading hyphen).
///
/// # Example
///
/// ```
/// use geode_client::quote_ident;
///
/// assert_eq!(quote_ident("user_01").unwrap(), "user_01");
/// assert_eq!(quote_ident("005_add_index").unwrap(), "005_add_index");
/// assert!(quote_ident("-bad").is_err());
/// assert!(quote_ident("").is_err());
/// ```
pub fn quote_ident(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(Error::validation(
            "identifier contains forbidden characters",
        ));
    }
    let mut first = true;
    for c in name.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '_' => {
                // Always allowed.
            }
            '0'..='9' => {
                // Digits allowed anywhere, including the first character
                // (digit-prefixed migration/catalog names).
            }
            '-' => {
                // Hyphen allowed except as the first character to avoid
                // option-confusion if a downstream emitter splits args.
                if first {
                    return Err(Error::validation(
                        "identifier contains forbidden characters",
                    ));
                }
            }
            _ => {
                return Err(Error::validation(
                    "identifier contains forbidden characters",
                ));
            }
        }
        first = false;
    }
    Ok(name.to_string())
}

/// Returns `s` wrapped in GQL single quotes, with backslashes and single
/// quotes properly escaped.
///
/// Escape order matches the Go reference: backslash first (`\` → `\\`),
/// then single quotes (`'` becomes two single quotes `''`).
///
/// ASCII control characters (`< 0x20` or `0x7F`) are rejected rather than
/// escaped; this is intentional because `quote_string` is meant for
/// user-supplied data where control characters are almost always an error
/// (injection risk).
///
/// # Errors
///
/// Returns [`Error::Validation`] if `s` contains ASCII control characters.
///
/// # Example
///
/// ```
/// use geode_client::quote_string;
///
/// assert_eq!(quote_string("hello").unwrap(), "'hello'");
/// assert_eq!(quote_string("O'Brien").unwrap(), "'O''Brien'");
/// assert_eq!(quote_string("a\\b").unwrap(), "'a\\\\b'");
/// assert!(quote_string("bad\nline").is_err());
/// ```
pub fn quote_string(s: &str) -> Result<String> {
    for c in s.chars() {
        if (c as u32) < 0x20 || c == '\u{7f}' {
            return Err(Error::validation(
                "string literal contains forbidden characters",
            ));
        }
    }
    let escaped = s.replace('\\', "\\\\").replace('\'', "''");
    Ok(format!("'{}'", escaped))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_graph_name() {
        assert_eq!(sanitize_graph_name("mygraph"), "mygraph");
        assert_eq!(sanitize_graph_name("my graph!"), "mygraph");
        assert_eq!(sanitize_graph_name("prod-db_01"), "prod-db_01");
        assert_eq!(sanitize_graph_name("a;DROP GRAPH x"), "aDROPGRAPHx");
        assert_eq!(sanitize_graph_name(""), "");
        // Non-ASCII letters are stripped (matches Go's ASCII-only ranges).
        assert_eq!(sanitize_graph_name("café"), "caf");
    }

    #[test]
    fn test_quote_ident_valid() {
        assert_eq!(quote_ident("user").unwrap(), "user");
        assert_eq!(quote_ident("User_01").unwrap(), "User_01");
        assert_eq!(quote_ident("a-b-c").unwrap(), "a-b-c");
        assert_eq!(quote_ident("_private").unwrap(), "_private");
    }

    #[test]
    fn test_quote_ident_digit_prefix_allowed() {
        // Digit-prefixed identifiers are allowed (migration/catalog names).
        assert_eq!(quote_ident("123abc").unwrap(), "123abc");
        assert_eq!(quote_ident("005_add_index").unwrap(), "005_add_index");
        assert_eq!(quote_ident("9").unwrap(), "9");
    }

    #[test]
    fn test_quote_ident_leading_dash_rejected() {
        assert!(quote_ident("-bad").is_err());
        assert!(quote_ident("-").is_err());
    }

    #[test]
    fn test_quote_ident_empty_rejected() {
        assert!(quote_ident("").is_err());
    }

    #[test]
    fn test_quote_ident_invalid_chars_rejected() {
        assert!(quote_ident("has space").is_err());
        assert!(quote_ident("semi;colon").is_err());
        assert!(quote_ident("quote'here").is_err());
        // Control character.
        assert!(quote_ident("bad\u{0}").is_err());
        // Non-ASCII letter.
        assert!(quote_ident("café").is_err());
    }

    #[test]
    fn test_quote_string_basic() {
        assert_eq!(quote_string("hello").unwrap(), "'hello'");
        assert_eq!(quote_string("").unwrap(), "''");
    }

    #[test]
    fn test_quote_string_escapes_single_quote() {
        assert_eq!(quote_string("O'Brien").unwrap(), "'O''Brien'");
        assert_eq!(quote_string("''").unwrap(), "''''''");
    }

    #[test]
    fn test_quote_string_escapes_backslash() {
        assert_eq!(quote_string("a\\b").unwrap(), "'a\\\\b'");
        // Backslash is escaped first, then quotes: \' -> \\''
        assert_eq!(quote_string("\\'").unwrap(), "'\\\\'''");
    }

    #[test]
    fn test_quote_string_rejects_control_chars() {
        assert!(quote_string("bad\nline").is_err());
        assert!(quote_string("tab\there").is_err());
        assert!(quote_string("null\u{0}byte").is_err());
        assert!(quote_string("del\u{7f}").is_err());
    }
}
