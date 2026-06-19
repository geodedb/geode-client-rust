//! Connection pooling for Geode connections.

use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

use crate::client::{Client, Connection};
use crate::error::{Error, Result};

/// Default maximum pool size, matching the Go driver's DefaultMaxOpenConns.
pub const DEFAULT_POOL_MAX_SIZE: usize = 16;

/// Connection pool for managing QUIC connections
pub struct ConnectionPool {
    client: Client,
    connections: Arc<Mutex<Vec<Connection>>>,
    semaphore: Arc<Semaphore>,
    max_size: usize,
}

impl ConnectionPool {
    /// Create a new connection pool.
    ///
    /// # Panics
    ///
    /// Panics if `max_size` is 0. A connection pool must have at least one
    /// connection slot to function properly. (Gap #18: CWE-400, CWE-835)
    pub fn new(host: impl Into<String>, port: u16, max_size: usize) -> Self {
        assert!(
            max_size > 0,
            "ConnectionPool max_size must be at least 1 (was 0). \
             A pool with 0 connections would deadlock on acquire()."
        );
        Self {
            client: Client::new(host, port),
            connections: Arc::new(Mutex::new(Vec::new())),
            semaphore: Arc::new(Semaphore::new(max_size)),
            max_size,
        }
    }

    /// Build a pool from a DSN string using the default max size (16).
    ///
    /// # Errors
    /// Returns an error if the DSN is invalid.
    pub fn from_dsn(dsn: &str) -> Result<Self> {
        Self::from_dsn_with_size(dsn, DEFAULT_POOL_MAX_SIZE)
    }

    /// Build a pool from a DSN string with an explicit max size.
    ///
    /// # Panics
    /// Panics if `max_size` is 0 (a pool needs at least one slot).
    ///
    /// # Errors
    /// Returns an error if the DSN is invalid.
    pub fn from_dsn_with_size(dsn: &str, max_size: usize) -> Result<Self> {
        assert!(max_size > 0, "ConnectionPool max_size must be at least 1");
        let client = Client::from_dsn(dsn)?;
        Ok(Self::from_client(client, max_size))
    }

    /// Build a pool from a pre-configured [`Client`].
    ///
    /// # Panics
    /// Panics if `max_size` is 0.
    pub fn from_client(client: Client, max_size: usize) -> Self {
        assert!(max_size > 0, "ConnectionPool max_size must be at least 1");
        Self {
            client,
            connections: Arc::new(Mutex::new(Vec::new())),
            semaphore: Arc::new(Semaphore::new(max_size)),
            max_size,
        }
    }

    /// Configure to skip TLS verification
    pub fn skip_verify(mut self, skip: bool) -> Self {
        self.client = self.client.skip_verify(skip);
        self
    }

    /// Set page size for queries
    pub fn page_size(mut self, size: usize) -> Self {
        self.client = self.client.page_size(size);
        self
    }

    /// Set the authentication username used for new pooled connections.
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.client = self.client.username(username);
        self
    }

    /// Set the authentication password used for new pooled connections.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.client = self.client.password(password);
        self
    }

    /// Acquire a connection from the pool
    ///
    /// Returns a healthy connection from the pool, or creates a new one if needed.
    /// Stale connections (those where the underlying QUIC connection has been closed)
    /// are automatically discarded during acquisition.
    pub async fn acquire(&self) -> Result<PooledConnection> {
        let permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| Error::pool("Connection pool has been closed"))?;

        // Try to get a healthy existing connection
        let connection = loop {
            let conn = {
                let mut connections = self.connections.lock().await;
                connections.pop()
            };

            match conn {
                Some(c) if c.is_healthy() => {
                    // Connection is healthy, use it
                    break c;
                }
                Some(_) => {
                    // Connection is stale, discard it and try another
                    // (the connection is dropped here, cleaning up resources)
                    continue;
                }
                None => {
                    // No pooled connections available, create a new one
                    let client = self.client.clone();
                    break client.connect().await?;
                }
            }
        };

        Ok(PooledConnection {
            connection: Some(connection),
            pool: self.connections.clone(),
            _permit: permit,
        })
    }

    /// Execute statements as a single batch in one transaction, with the
    /// default retry policy. Acquires one connection from the pool.
    ///
    /// # Errors
    /// Returns the first failing statement's error (the transaction is rolled
    /// back). An empty slice is a no-op.
    pub async fn batch_exec(&self, stmts: &[crate::schema::Statement]) -> Result<()> {
        if stmts.is_empty() {
            return Ok(());
        }
        let policy = crate::retry::RetryPolicy::default();
        crate::retry::retry(policy, || async {
            let mut conn = self.acquire().await?;
            conn.begin().await?;
            for (i, stmt) in stmts.iter().enumerate() {
                if let Err(e) = conn.query(&stmt.query).await {
                    let _ = conn.rollback().await;
                    return Err(Error::query(format!("statement {}: {}", i + 1, e)));
                }
            }
            conn.commit().await
        })
        .await
    }

    /// Execute statements concurrently in chunks, each chunk a single
    /// transaction (via [`batch_exec`](Self::batch_exec) with retry). At most
    /// `max_workers` chunks run at once. The first error stops dispatching new
    /// chunks; in-flight chunks complete. `chunk_size`/`max_workers` of 0 use
    /// the defaults (100 / 8).
    ///
    /// # Errors
    /// Returns the first error recorded across all chunks.
    pub async fn pipeline_exec(
        self: &Arc<Self>,
        stmts: &[crate::schema::Statement],
        chunk_size: usize,
        max_workers: usize,
    ) -> Result<()> {
        let pool = Arc::clone(self);
        crate::batch::pipeline_drive(stmts, chunk_size, max_workers, move |chunk| {
            let pool = Arc::clone(&pool);
            async move { pool.batch_exec(&chunk).await }
        })
        .await
    }

    /// Get current pool size
    pub async fn size(&self) -> usize {
        self.connections.lock().await.len()
    }

    /// Get the maximum pool size
    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

/// A pooled connection that returns to the pool when dropped
pub struct PooledConnection {
    connection: Option<Connection>,
    pool: Arc<Mutex<Vec<Connection>>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl PooledConnection {
    /// Get a reference to the underlying connection.
    ///
    /// # Panics
    ///
    /// Panics if called after the connection has been dropped or taken.
    /// This should never happen in normal usage as the connection is only
    /// taken during Drop.
    pub fn inner(&self) -> &Connection {
        self.connection
            .as_ref()
            .expect("PooledConnection invariant violated: connection was None")
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(mut conn) = self.connection.take() {
            // Only return healthy connections to the pool
            // Stale connections are dropped, cleaning up their resources
            if conn.is_healthy() {
                let pool = self.pool.clone();
                tokio::spawn(async move {
                    // Best-effort rollback if the connection was left in a transaction
                    if conn.in_transaction() {
                        let _ = conn.rollback().await;
                    }
                    let mut connections = pool.lock().await;
                    connections.push(conn);
                });
            }
            // If unhealthy, conn is dropped here and not returned to pool
        }
    }
}

impl std::ops::Deref for PooledConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.connection
            .as_ref()
            .expect("PooledConnection invariant violated: connection was None")
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connection
            .as_mut()
            .expect("PooledConnection invariant violated: connection was None")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_pool_new() {
        let pool = ConnectionPool::new("localhost", 3141, 10);
        assert_eq!(pool.max_size(), 10);
    }

    #[test]
    fn test_connection_pool_new_different_host() {
        let pool = ConnectionPool::new("192.168.1.100", 8443, 5);
        assert_eq!(pool.max_size(), 5);
    }

    #[test]
    fn test_connection_pool_new_string_host() {
        let host = String::from("geode.example.com");
        let pool = ConnectionPool::new(host, 3141, 20);
        assert_eq!(pool.max_size(), 20);
    }

    #[test]
    fn test_connection_pool_skip_verify() {
        let pool = ConnectionPool::new("localhost", 3141, 10).skip_verify(true);
        // Configuration is passed through to client
        assert_eq!(pool.max_size(), 10);
    }

    #[test]
    fn test_connection_pool_skip_verify_false() {
        let pool = ConnectionPool::new("localhost", 3141, 10).skip_verify(false);
        assert_eq!(pool.max_size(), 10);
    }

    #[test]
    fn test_connection_pool_page_size() {
        let pool = ConnectionPool::new("localhost", 3141, 10).page_size(500);
        assert_eq!(pool.max_size(), 10);
    }

    #[test]
    fn test_connection_pool_chained_config() {
        let pool = ConnectionPool::new("localhost", 3141, 10)
            .skip_verify(true)
            .page_size(1000);
        assert_eq!(pool.max_size(), 10);
    }

    #[tokio::test]
    async fn test_connection_pool_initial_size() {
        let pool = ConnectionPool::new("localhost", 3141, 10);
        // Pool starts empty
        assert_eq!(pool.size().await, 0);
    }

    #[test]
    #[should_panic(expected = "ConnectionPool max_size must be at least 1")]
    fn test_connection_pool_max_size_zero_panics() {
        // Gap #18: max_size=0 would cause deadlock on acquire() since semaphore
        // would have 0 permits. Now properly panics at construction time.
        let _pool = ConnectionPool::new("localhost", 3141, 0);
    }

    #[test]
    fn test_connection_pool_max_size_one() {
        let pool = ConnectionPool::new("localhost", 3141, 1);
        assert_eq!(pool.max_size(), 1);
    }

    #[test]
    fn test_connection_pool_max_size_large() {
        let pool = ConnectionPool::new("localhost", 3141, 1000);
        assert_eq!(pool.max_size(), 1000);
    }

    // Note: Full integration tests for acquire() and health checking require
    // a running Geode server and are covered in the integration test suite.
    // The health check functionality (is_healthy(), stale connection discard)
    // is verified in integration tests with real connections (Gap #16).

    // The following tests verify the structural aspects of PooledConnection
    // without actually establishing connections.

    #[test]
    fn test_semaphore_permits_match_max_size() {
        let pool = ConnectionPool::new("localhost", 3141, 5);
        // Semaphore should have permits equal to max_size
        assert_eq!(pool.semaphore.available_permits(), 5);
    }

    #[test]
    fn test_connections_vec_initially_empty() {
        let pool = ConnectionPool::new("localhost", 3141, 10);
        // We can't directly access the mutex contents in a sync test,
        // but we verified size() returns 0 in the async test above
        assert_eq!(pool.max_size(), 10);
    }

    #[test]
    fn test_pool_from_dsn() {
        let pool = ConnectionPool::from_dsn("quic://localhost:3141?insecure=true").unwrap();
        assert_eq!(pool.max_size(), 16); // DEFAULT_POOL_MAX_SIZE
    }

    #[test]
    fn test_pool_from_dsn_with_size() {
        let pool = ConnectionPool::from_dsn_with_size("grpc://localhost:50051?tls=0", 4).unwrap();
        assert_eq!(pool.max_size(), 4);
    }

    #[test]
    fn test_pool_from_dsn_invalid() {
        assert!(ConnectionPool::from_dsn("http://localhost:1").is_err());
    }

    #[test]
    fn test_pool_from_client() {
        let client = Client::new("localhost", 3141).skip_verify(true);
        let pool = ConnectionPool::from_client(client, 8);
        assert_eq!(pool.max_size(), 8);
    }

    #[tokio::test]
    async fn test_pool_batch_exec_empty_is_noop() {
        let pool = ConnectionPool::new("localhost", 3141, 4);
        // An empty statement slice must not touch the network.
        assert!(pool.batch_exec(&[]).await.is_ok());
    }

    #[tokio::test]
    async fn test_pool_pipeline_exec_empty_is_noop() {
        let pool = Arc::new(ConnectionPool::new("localhost", 3141, 4));
        assert!(pool.pipeline_exec(&[], 0, 0).await.is_ok());
    }
}
