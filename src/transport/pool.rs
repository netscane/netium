//! Connection Pool with timeout management
//!
//! Provides connection pooling and reuse for keep-alive connections.
//! Supports idle timeout and max connections per host.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Semaphore;
use tracing::{debug, trace};

use crate::common::{Address, Result, Stream};

/// Default idle timeout for pooled connections (90 seconds)
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Default max connections per host
const DEFAULT_MAX_CONNS_PER_HOST: usize = 6;

/// Default max total connections
const DEFAULT_MAX_TOTAL_CONNS: usize = 100;

/// A pooled connection with metadata
struct PooledConnection {
    stream: Stream,
    created_at: Instant,
    last_used: Instant,
}

impl PooledConnection {
    fn new(stream: Stream) -> Self {
        let now = Instant::now();
        Self {
            stream,
            created_at: now,
            last_used: now,
        }
    }

    fn is_expired(&self, idle_timeout: Duration) -> bool {
        self.last_used.elapsed() > idle_timeout
    }
}

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Idle timeout for connections
    pub idle_timeout: Duration,
    /// Max connections per host
    pub max_conns_per_host: usize,
    /// Max total connections
    pub max_total_conns: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_conns_per_host: DEFAULT_MAX_CONNS_PER_HOST,
            max_total_conns: DEFAULT_MAX_TOTAL_CONNS,
        }
    }
}

/// Connection pool for reusing connections
pub struct ConnectionPool {
    config: PoolConfig,
    /// Pooled connections by host key
    connections: Mutex<HashMap<String, Vec<PooledConnection>>>,
    /// Semaphore for limiting total connections
    total_semaphore: Arc<Semaphore>,
    /// Semaphores for per-host limits
    host_semaphores: Mutex<HashMap<String, Arc<Semaphore>>>,
}

impl ConnectionPool {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            total_semaphore: Arc::new(Semaphore::new(config.max_total_conns)),
            connections: Mutex::new(HashMap::new()),
            host_semaphores: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Get a pooled connection for the given address
    pub fn get(&self, addr: &Address) -> Option<Stream> {
        let key = addr.to_string();
        let mut conns = self.connections.lock();

        if let Some(pool) = conns.get_mut(&key) {
            // Remove expired connections
            pool.retain(|c| !c.is_expired(self.config.idle_timeout));

            // Get a connection from the pool
            if let Some(mut conn) = pool.pop() {
                conn.last_used = Instant::now();
                debug!(
                    "Pool: reusing connection to {} (age: {:?})",
                    key,
                    conn.created_at.elapsed()
                );
                return Some(conn.stream);
            }
        }

        trace!("Pool: no available connection for {}", key);
        None
    }

    /// Return a connection to the pool
    pub fn put(&self, addr: &Address, stream: Stream) {
        let key = addr.to_string();
        let mut conns = self.connections.lock();

        let pool = conns.entry(key.clone()).or_insert_with(Vec::new);

        // Check if we have room
        if pool.len() < self.config.max_conns_per_host {
            debug!("Pool: returning connection to {} (pool size: {})", key, pool.len() + 1);
            pool.push(PooledConnection::new(stream));
        } else {
            debug!("Pool: discarding connection to {} (pool full)", key);
            // Connection will be dropped
        }
    }

    /// Acquire a permit to create a new connection
    pub async fn acquire_permit(&self, addr: &Address) -> Result<PoolPermit> {
        let key = addr.to_string();

        // Get or create per-host semaphore
        let host_sem = {
            let mut sems = self.host_semaphores.lock();
            sems.entry(key.clone())
                .or_insert_with(|| Arc::new(Semaphore::new(self.config.max_conns_per_host)))
                .clone()
        };

        // Acquire both permits
        let _total_permit = self.total_semaphore.clone().acquire_owned().await
            .map_err(|_| crate::error::Error::Transport("Connection pool closed".into()))?;
        let _host_permit = host_sem.acquire_owned().await
            .map_err(|_| crate::error::Error::Transport("Connection pool closed".into()))?;

        Ok(PoolPermit {
            _total_permit,
            _host_permit,
        })
    }

    /// Clean up expired connections
    pub fn cleanup(&self) {
        let mut conns = self.connections.lock();
        let mut removed = 0;

        for (_, pool) in conns.iter_mut() {
            let before = pool.len();
            pool.retain(|c| !c.is_expired(self.config.idle_timeout));
            removed += before - pool.len();
        }

        // Remove empty pools
        conns.retain(|_, pool| !pool.is_empty());

        if removed > 0 {
            debug!("Pool: cleaned up {} expired connections", removed);
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        let conns = self.connections.lock();
        let total: usize = conns.values().map(|p| p.len()).sum();
        let hosts = conns.len();

        PoolStats {
            total_connections: total,
            hosts,
            available_permits: self.total_semaphore.available_permits(),
        }
    }
}

/// Permit for creating a new connection
pub struct PoolPermit {
    _total_permit: tokio::sync::OwnedSemaphorePermit,
    _host_permit: tokio::sync::OwnedSemaphorePermit,
}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub hosts: usize,
    pub available_permits: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn test_addr() -> Address {
        Address::Socket("127.0.0.1:8080".parse::<SocketAddr>().unwrap())
    }

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.idle_timeout, DEFAULT_IDLE_TIMEOUT);
        assert_eq!(config.max_conns_per_host, DEFAULT_MAX_CONNS_PER_HOST);
    }

    #[tokio::test]
    async fn test_pool_get_empty() {
        let pool = ConnectionPool::new(PoolConfig::default());
        assert!(pool.get(&test_addr()).is_none());
    }
}
