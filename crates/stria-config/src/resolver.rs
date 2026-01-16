//! Resolver configuration.

use super::{ConfigError, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// Resolver configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResolverConfig {
    /// Resolver mode.
    pub mode: ResolverMode,

    /// Upstream servers (for forwarding mode).
    pub upstreams: Vec<UpstreamConfig>,

    /// Root hints file (for recursive mode).
    pub root_hints: Option<String>,

    /// Query timeout (milliseconds).
    pub timeout_ms: u64,

    /// Maximum retries.
    pub retries: u32,

    /// Enable query name minimization (RFC 7816).
    pub qname_minimization: bool,

    /// Enable 0x20 bit encoding.
    pub enable_0x20: bool,

    /// Maximum recursion depth.
    pub max_recursion_depth: u8,

    /// Connection pool configuration.
    pub pool: ConnectionPoolConfig,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            mode: ResolverMode::Recursive,
            upstreams: Vec::new(),
            root_hints: None,
            timeout_ms: 5000,
            retries: 3,
            qname_minimization: true,
            enable_0x20: true,
            max_recursion_depth: 16,
            pool: ConnectionPoolConfig::default(),
        }
    }
}

impl ResolverConfig {
    pub fn validate(&self) -> Result<()> {
        if self.mode == ResolverMode::Forward && self.upstreams.is_empty() {
            return Err(ConfigError::Validation(
                "Forward mode requires at least one upstream".to_string(),
            ));
        }

        if self.max_recursion_depth == 0 {
            return Err(ConfigError::InvalidValue {
                field: "resolver.max_recursion_depth".to_string(),
                message: "must be at least 1".to_string(),
            });
        }

        Ok(())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

/// Resolver mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolverMode {
    /// Full recursive resolution from root.
    Recursive,

    /// Forward queries to upstream servers.
    Forward,

    /// Authoritative only (no recursion).
    Authoritative,
}

impl Default for ResolverMode {
    fn default() -> Self {
        Self::Recursive
    }
}

/// Upstream server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Server address.
    pub address: SocketAddr,

    /// Protocol to use.
    pub protocol: UpstreamProtocol,

    /// TLS server name (for DoT/DoH/DoQ).
    pub tls_name: Option<String>,

    /// Path (for DoH).
    pub path: Option<String>,

    /// Bootstrap addresses (for hostnames).
    pub bootstrap: Vec<SocketAddr>,

    /// Weight for load balancing.
    pub weight: u32,

    /// Health check interval (seconds).
    pub health_check_interval: u64,
}

/// Upstream protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    /// Plain DNS over UDP.
    Udp,

    /// Plain DNS over TCP.
    Tcp,

    /// DNS over TLS.
    Dot,

    /// DNS over HTTPS.
    Doh,

    /// DNS over QUIC.
    Doq,
}

impl Default for UpstreamProtocol {
    fn default() -> Self {
        Self::Udp
    }
}

/// Connection pool configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionPoolConfig {
    /// Maximum connections per upstream.
    pub max_connections: usize,

    /// Minimum idle connections.
    pub min_idle: usize,

    /// Connection timeout (milliseconds).
    pub connect_timeout_ms: u64,

    /// Idle timeout (seconds).
    pub idle_timeout_secs: u64,

    /// Maximum lifetime (seconds).
    pub max_lifetime_secs: u64,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            min_idle: 10,
            connect_timeout_ms: 5000,
            idle_timeout_secs: 60,
            max_lifetime_secs: 3600,
        }
    }
}

impl ConnectionPoolConfig {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }

    pub fn max_lifetime(&self) -> Duration {
        Duration::from_secs(self.max_lifetime_secs)
    }
}
