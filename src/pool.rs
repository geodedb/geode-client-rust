//! Connection pooling for Geode connections.

use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

use crate::client::{Client, Connection};
use crate::error::{Error, Result};

/// Connection pool for managing QUIC connections
pub struct ConnectionPool {
    client: Client,
    connections: Arc<Mutex<Vec<Connection>>>,
    semaphore: Arc<Semaphore>,
    max_size: usize,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(host: impl Into<String>, port: u16, max_size: usize) -> Self {
        Self {
            client: Client::new(host, port),
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

    /// Acquire a connection from the pool
    pub async fn acquire(&self) -> Result<PooledConnection> {
        let permit = Arc::clone(&self.semaphore).acquire_owned().await.unwrap();

        // Try to get an existing connection
        let conn = {
            let mut connections = self.connections.lock().await;
            connections.pop()
        };

        let connection = match conn {
            Some(c) => c,
            None => {
                let client = self.client.clone();
                // Quinn is async, directly await
                client.connect().await?
            }
        };

        Ok(PooledConnection {
            connection: Some(connection),
            pool: self.connections.clone(),
            _permit: permit,
        })
    }

    /// Get current pool size
    pub async fn size(&self) -> usize {
        self.connections.lock().await.len()
    }
}

/// A pooled connection that returns to the pool when dropped
pub struct PooledConnection {
    connection: Option<Connection>,
    pool: Arc<Mutex<Vec<Connection>>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl PooledConnection {
    /// Get a reference to the underlying connection
    pub fn as_ref(&self) -> &Connection {
        self.connection.as_ref().unwrap()
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            let pool = self.pool.clone();
            tokio::spawn(async move {
                let mut connections = pool.lock().await;
                connections.push(conn);
            });
        }
    }
}

impl std::ops::Deref for PooledConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.connection.as_ref().unwrap()
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connection.as_mut().unwrap()
    }
}
