//! GQL identifier and string-literal quoting helpers (port of Go quote.go).

use crate::error::{Error, Result};

/// Validate a GQL identifier. Returns the identifier unchanged when valid,
/// otherwise [`Error::InvalidIdent`].
///
/// Rules (matching the Go reference): non-empty; each character must be an
/// ASCII letter, digit, or `_` (allowed anywhere); `-` is allowed except as
/// the first character.
pub fn quote_ident(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(Error::invalid_ident("identifier is empty"));
    }
    for (i, ch) in name.chars().enumerate() {
        let ok =
            ch.is_ascii_alphabetic() || ch == '_' || ch.is_ascii_digit() || (ch == '-' && i != 0);
        if !ok {
            return Err(Error::invalid_ident(format!(
                "identifier contains forbidden character {:?}",
                ch
            )));
        }
    }
    Ok(name.to_string())
}

/// Quote a GQL string literal: rejects ASCII control characters, escapes
/// backslash then single-quote, and wraps the result in single quotes.
///
/// # Errors
/// Returns [`Error::InvalidString`] if `s` contains any character `< 0x20`
/// or `0x7f` (DEL).
pub fn quote_string(s: &str) -> Result<String> {
    for ch in s.chars() {
        let c = ch as u32;
        if c < 0x20 || c == 0x7f {
            return Err(Error::invalid_string(
                "string literal contains a control character",
            ));
        }
    }
    // Order matters: backslash first, then single-quote.
    let escaped = s.replace('\\', "\\\\").replace('\'', "''");
    Ok(format!("'{}'", escaped))
}

/// Sanitize a graph name by keeping only `[A-Za-z0-9_-]` and dropping every
/// other character (including all non-ASCII). Never fails.
pub fn sanitize_graph_name(name: &str) -> String {
    name.chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn test_quote_ident_valid() {
        for name in [
            "abc",
            "ABC",
            "_foo",
            "foo_bar",
            "foo-bar",
            "foo9",
            "9starts",
            "005_add_index",
        ] {
            assert_eq!(quote_ident(name).unwrap(), name);
        }
    }

    #[test]
    fn test_quote_ident_invalid() {
        for name in ["", "-starts", "has space", "has;semi", "has\0null"] {
            assert!(
                matches!(quote_ident(name), Err(Error::InvalidIdent(_))),
                "name={:?}",
                name
            );
        }
    }

    #[test]
    fn test_quote_string_basic() {
        assert_eq!(quote_string("hello").unwrap(), "'hello'");
        assert_eq!(quote_string("it's").unwrap(), "'it''s'");
    }

    #[test]
    fn test_quote_string_backslash_then_quote() {
        // backslash doubled FIRST, then quote doubled.
        assert_eq!(quote_string("back\\slash").unwrap(), "'back\\\\slash'");
        assert_eq!(quote_string("back\\'quote").unwrap(), "'back\\\\''quote'");
    }

    #[test]
    fn test_quote_string_rejects_control_chars() {
        for s in ["a\nb", "a\rb", "a\tb", "a\0b", "a\x1fb", "a\x7fb"] {
            assert!(
                matches!(quote_string(s), Err(Error::InvalidString(_))),
                "s={:?}",
                s
            );
        }
    }

    #[test]
    fn test_sanitize_graph_name() {
        assert_eq!(sanitize_graph_name("myGraph"), "myGraph");
        assert_eq!(sanitize_graph_name("my-graph_01"), "my-graph_01");
        assert_eq!(sanitize_graph_name("bad name!"), "badname");
        assert_eq!(sanitize_graph_name(""), "");
        assert_eq!(sanitize_graph_name("有害"), "");
        assert_eq!(sanitize_graph_name("   "), "");
    }
}
