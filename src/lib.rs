//! Geode Rust Client Library
//!
//! A high-performance async Rust client for Geode graph database with full GQL support.
//! Supports both QUIC and gRPC transports using protobuf wire protocol.
//!
//! # Features
//!
//! - 🚀 Fully async using tokio with type safety
//! - 🔒 QUIC + TLS 1.3 or gRPC for flexible networking
//! - 📝 Full GQL (ISO/IEC 39075:2024) support
//! - 🏗️ Query builders for programmatic query construction
//! - 🔐 Authentication & RBAC with RLS policies
//! - 🏊 Connection pooling for concurrent workloads
//! - 📊 Rich type system with Decimal, temporal types
//!
//! # Transport Options
//!
//! ## QUIC Transport (default)
//!
//! ```no_run
//! use geode_client::{Client, Result};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Connect via QUIC using DSN
//!     let client = Client::from_dsn("quic://127.0.0.1:3141?insecure=true")?;
//!     let mut conn = client.connect().await?;
//!     let (page, _) = conn.query("RETURN 1 AS x").await?;
//!     conn.close()?;
//!     Ok(())
//! }
//! ```
//!
//! ## gRPC Transport
//!
//! ```no_run
//! use geode_client::{Client, Result};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Connect via gRPC using DSN
//!     let client = Client::from_dsn("grpc://127.0.0.1:50051")?;
//!     let mut conn = client.connect().await?;
//!     let (page, _) = conn.query("RETURN 1 AS x").await?;
//!     conn.close()?;
//!     Ok(())
//! }
//! ```
//!
//! # DSN Formats
//!
//! - `quic://host:port?options` - QUIC transport (default port: 3141)
//! - `grpc://host:port?options` - gRPC transport
//! - `host:port?options` - Legacy format, defaults to QUIC

pub mod auth;
pub mod client;
pub mod dsn;
pub mod error;
pub mod pool;
pub mod proto;
pub mod query_builder;
pub mod types;
pub mod validate;

// gRPC transport module
#[cfg(feature = "grpc")]
pub mod grpc;

// Re-export main types
pub use auth::{AuthClient, Permission, RLSPolicy, Role, SessionInfo, User};
pub use client::{
    Client, Column, Connection, Page, PlanOperation, PreparedStatement, QueryPlan, QueryProfile,
    Savepoint,
};
pub use dsn::{DEFAULT_PORT, Dsn, Transport};
pub use error::{Error, Result};
pub use pool::ConnectionPool;
pub use query_builder::{EdgeDirection, PatternBuilder, PredicateBuilder, QueryBuilder};
pub use types::{Range, Value, ValueKind};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
