//! Schema file parsing, port of the Go driver's ParseSchemaFS.

use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use crate::types::Value;

/// A single schema statement to execute. Mirrors the Go driver's `Statement`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Statement {
    /// The GQL query text.
    pub query: String,
    /// Positional arguments (unused for schema parsing; mirrors Go `Args`).
    pub args: Vec<Value>,
}

impl Statement {
    /// Create a statement with no arguments.
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            args: Vec::new(),
        }
    }
}

/// GQL keywords that mark a line as a real schema statement (case-insensitive
/// prefix match on the trimmed line), matching the Go reference exactly.
const GQL_KEYWORDS: [&str; 4] = ["CREATE", "MERGE", "MATCH", "DELETE"];

/// Parse `.gql` files in `dir` into a list of [`Statement`]s.
///
/// Reads direct children only (no recursion), keeping files whose name ends
/// with `.gql` (case-sensitive). Each file is split on newlines; each line is
/// trimmed, comment lines (`//`, `--`) and blank lines are skipped, and only
/// lines starting (case-insensitively) with CREATE/MERGE/MATCH/DELETE are kept.
/// Kept lines are split on `;` into individual statements.
///
/// # Errors
/// Returns [`Error::Other`] if the directory cannot be read, or [`Error::Io`]
/// if a directory entry cannot be accessed.
pub fn parse_schema_fs(dir: impl AsRef<Path>) -> Result<Vec<Statement>> {
    let dir = dir.as_ref();
    let entries = fs::read_dir(dir).map_err(|e| {
        Error::Other(format!(
            "geode: parse_schema_fs: read dir {}: {}",
            dir.display(),
            e
        ))
    })?;

    let mut names: Vec<std::path::PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(Error::Io)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(Error::Io)?;
        if file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".gql") {
            continue;
        }
        names.push(path);
    }
    // Deterministic order across platforms.
    names.sort();

    let mut statements = Vec::new();
    for path in names {
        let content = fs::read_to_string(&path).map_err(|e| {
            Error::Other(format!(
                "geode: parse_schema_fs: read {}: {}",
                path.display(),
                e
            ))
        })?;

        for line in content.split('\n') {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("--") {
                continue;
            }
            let upper = trimmed.to_uppercase();
            if !GQL_KEYWORDS.iter().any(|kw| upper.starts_with(kw)) {
                continue;
            }
            for part in trimmed.split(';') {
                let part = part.trim();
                if !part.is_empty() {
                    statements.push(Statement::new(part));
                }
            }
        }
    }

    Ok(statements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_schema_fs_keeps_gql_statements() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/schema");
        let stmts = parse_schema_fs(dir).unwrap();
        let queries: Vec<&str> = stmts.iter().map(|s| s.query.as_str()).collect();
        // CREATE x2 from 01, MATCH...MERGE x1 + DELETE x1 from 02. USE/SET dropped, .txt ignored.
        assert!(queries.iter().any(|q| q.starts_with("CREATE (a:Person")));
        assert!(queries.iter().any(|q| q.starts_with("CREATE (b:Person")));
        assert!(queries.iter().any(|q| q.contains("MERGE")));
        assert!(queries.iter().any(|q| q.starts_with("DELETE (x)")));
        assert!(!queries.iter().any(|q| q.starts_with("USE")));
        assert!(!queries.iter().any(|q| q.starts_with("SET")));
        assert_eq!(queries.len(), 4);
    }

    #[test]
    fn test_parse_schema_fs_splits_on_semicolon() {
        let dir = std::env::temp_dir().join("geode_schema_split_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.gql"), "CREATE (a); CREATE (b); CREATE (c)\n").unwrap();
        let stmts = parse_schema_fs(&dir).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(stmts.len(), 3);
        assert_eq!(stmts[0].query, "CREATE (a)");
        assert_eq!(stmts[2].query, "CREATE (c)");
    }

    #[test]
    fn test_parse_schema_fs_missing_dir_errors() {
        let err = parse_schema_fs("/nonexistent/geode/schema/dir").unwrap_err();
        assert!(matches!(err, crate::error::Error::Io(_)) || err.to_string().contains("read dir"));
    }

    #[test]
    fn test_parse_schema_fs_empty_dir_ok() {
        let dir = std::env::temp_dir().join("geode_schema_empty_test");
        std::fs::create_dir_all(&dir).unwrap();
        let stmts = parse_schema_fs(&dir).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert!(stmts.is_empty());
    }
}
