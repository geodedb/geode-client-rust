//! Geode Rust Client Library
//!
//! A high-performance async Rust client for Geode graph database with full GQL support via QUIC+TLS.
//!
//! # Features
//!
//! - 🚀 Fully async using tokio with type safety
//! - 🔒 QUIC + TLS 1.3 for secure, high-performance networking
//! - 📝 Full GQL (ISO/IEC 39075:2024) support
//! - 🏗️ Query builders for programmatic query construction
//! - 🔐 Authentication & RBAC with RLS policies
//! - 🏊 Connection pooling for concurrent workloads
//! - 📊 Rich type system with Decimal, temporal types
//!
//! # Example
//!
//! ```no_run
//! use geode_client::{Client, Result};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Create QUIC client
//!     let client = Client::new("127.0.0.1", 3141)
//!         .skip_verify(true);
//!
//!     // Connect via QUIC
//!     let mut conn = client.connect().await?;
//!
//!     // Execute query
//!     let (page, _) = conn.query("RETURN 1 AS x").await?;
//!     println!("Result: {:?}", page);
//!
//!     // Close connection
//!     conn.close()?;
//!
//!     Ok(())
//! }
//! ```

pub mod auth;
pub mod client;
pub mod error;
pub mod pool;
pub mod query_builder;
pub mod types;
pub mod validate;

// Re-export main types
pub use auth::{AuthClient, Permission, RLSPolicy, Role, SessionInfo, User};
pub use client::{
    Client, Column, Connection, Page, PlanOperation, PreparedStatement, QueryPlan, QueryProfile,
    Savepoint,
};
pub use error::{Error, Result};
pub use pool::ConnectionPool;
pub use query_builder::{EdgeDirection, PatternBuilder, PredicateBuilder, QueryBuilder};
pub use types::{Range, Value, ValueKind};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
