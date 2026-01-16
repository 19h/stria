//! Connection pooling for TCP-based protocols.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::Mutex;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// Connection pool configuration.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum connections per upstream.
    pub max_connections: usize,

    /// Minimum idle connections to maintain.
    pub min_idle: usize,

    /// Connection timeout.
    pub connect_timeout: Duration,

    /// Idle timeout before closing.
    pub idle_timeout: Duration,

    /// Maximum connection lifetime.
    pub max_lifetime: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_idle: 2,
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(3600),
        }
    }
}

/// A pooled connection.
pub struct PooledConnection {
    stream: TcpStream,
    created_at: Instant,
    last_used: Instant,
}

impl PooledConnection {
    fn new(stream: TcpStream) -> Self {
        let now = Instant::now();
        Self {
            stream,
            created_at: now,
            last_used: now,
        }
    }

    /// Returns true if the connection has exceeded its lifetime.
    pub fn is_expired(&self, max_lifetime: Duration) -> bool {
        self.created_at.elapsed() > max_lifetime
    }

    /// Returns true if the connection has been idle too long.
    pub fn is_idle(&self, idle_timeout: Duration) -> bool {
        self.last_used.elapsed() > idle_timeout
    }

    /// Returns the underlying stream.
    pub fn stream(&mut self) -> &mut TcpStream {
        self.last_used = Instant::now();
        &mut self.stream
    }
}

/// Connection pool for a single upstream.
struct UpstreamPool {
    address: SocketAddr,
    config: PoolConfig,
    connections: Mutex<Vec<PooledConnection>>,
    semaphore: Semaphore,
}

impl UpstreamPool {
    fn new(address: SocketAddr, config: PoolConfig) -> Self {
        let permits = config.max_connections;
        Self {
            address,
            config,
            connections: Mutex::new(Vec::new()),
            semaphore: Semaphore::new(permits),
        }
    }

    /// Acquires a connection from the pool.
    async fn acquire(&self) -> std::io::Result<PooledConnection> {
        // Try to get an existing connection
        {
            let mut conns = self.connections.lock();
            while let Some(conn) = conns.pop() {
                if !conn.is_expired(self.config.max_lifetime)
                    && !conn.is_idle(self.config.idle_timeout)
                {
                    return Ok(conn);
                }
                // Connection is stale, drop it
            }
        }

        // Create a new connection
        let stream = tokio::time::timeout(
            self.config.connect_timeout,
            TcpStream::connect(self.address),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;

        Ok(PooledConnection::new(stream))
    }

    /// Returns a connection to the pool.
    fn release(&self, conn: PooledConnection) {
        if conn.is_expired(self.config.max_lifetime) {
            return; // Don't return expired connections
        }

        let mut conns = self.connections.lock();
        if conns.len() < self.config.max_connections {
            conns.push(conn);
        }
    }
}

/// Multi-upstream connection pool.
pub struct ConnectionPool {
    config: PoolConfig,
    pools: Mutex<HashMap<SocketAddr, Arc<UpstreamPool>>>,
}

impl ConnectionPool {
    /// Creates a new connection pool.
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            pools: Mutex::new(HashMap::new()),
        }
    }

    /// Gets or creates a pool for the given address.
    fn get_pool(&self, address: SocketAddr) -> Arc<UpstreamPool> {
        let mut pools = self.pools.lock();
        pools
            .entry(address)
            .or_insert_with(|| Arc::new(UpstreamPool::new(address, self.config.clone())))
            .clone()
    }

    /// Acquires a connection to the given address.
    pub async fn acquire(&self, address: SocketAddr) -> std::io::Result<PooledConnection> {
        let pool = self.get_pool(address);
        pool.acquire().await
    }

    /// Releases a connection back to the pool.
    pub fn release(&self, address: SocketAddr, conn: PooledConnection) {
        if let Some(pool) = self.pools.lock().get(&address) {
            pool.release(conn);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.min_idle, 2);
    }
}
