//! # Stria DNS Server
//!
//! High-performance async DNS server infrastructure with UDP/TCP/DoT/DoH/DoQ support.
//!
//! ## Architecture
//!
//! The server uses an event-driven architecture built on Tokio:
//!
//! - **UDP Server**: Multi-threaded with SO_REUSEPORT for load distribution
//! - **TCP Server**: Connection pooling with idle timeout management
//! - **DoT Server**: TLS termination with modern cipher suites
//! - **DoH Server**: HTTP/2 with connection coalescing
//! - **DoQ Server**: QUIC with 0-RTT support
//!
//! ## Features
//!
//! - Lock-free query processing where possible
//! - Zero-copy packet handling
//! - Graceful shutdown with connection draining
//! - Connection tracking and rate limiting

use async_trait::async_trait;
use stria_proto::Message;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};

pub mod handler;
pub mod listener;
pub mod tcp;
pub mod udp;

#[cfg(feature = "dot")]
pub mod dot;

#[cfg(feature = "doh")]
pub mod doh;

#[cfg(feature = "doq")]
pub mod doq;

pub mod rrl;
pub mod stats;

#[cfg(feature = "doh")]
pub mod control;

pub use handler::{QueryContext, QueryHandler};
pub use rrl::RateLimiter;
pub use tcp::TcpServer;
pub use udp::UdpServer;

#[cfg(feature = "dot")]
pub use dot::DotServer;

#[cfg(feature = "doh")]
pub use doh::DohServer;

#[cfg(feature = "doq")]
pub use doq::{DoqServer, DoqErrorCode};

#[cfg(feature = "doh")]
pub use control::{
    ControlServer, ControlState, 
    CacheProvider, FilterProvider, FilterTestResult,
    ListenerStatus, BlocklistInfo, QueryLogEntry,
};

/// Server error types.
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Shutdown in progress")]
    Shutdown,
}

/// Result type for server operations.
pub type Result<T> = std::result::Result<T, ServerError>;

/// DNS transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Plain UDP.
    Udp,
    /// Plain TCP.
    Tcp,
    /// DNS over TLS.
    Dot,
    /// DNS over HTTPS.
    Doh,
    /// DNS over QUIC.
    Doq,
}

impl Protocol {
    /// Returns the default port for this protocol.
    pub const fn default_port(&self) -> u16 {
        match self {
            Protocol::Udp | Protocol::Tcp => 53,
            Protocol::Dot | Protocol::Doq => 853,
            Protocol::Doh => 443,
        }
    }

    /// Returns true if this protocol uses encryption.
    pub const fn is_encrypted(&self) -> bool {
        matches!(self, Protocol::Dot | Protocol::Doh | Protocol::Doq)
    }

    /// Returns the protocol name.
    pub const fn name(&self) -> &'static str {
        match self {
            Protocol::Udp => "UDP",
            Protocol::Tcp => "TCP",
            Protocol::Dot => "DoT",
            Protocol::Doh => "DoH",
            Protocol::Doq => "DoQ",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// UDP configuration.
    pub udp: Option<UdpConfig>,

    /// TCP configuration.
    pub tcp: Option<TcpConfig>,

    /// DoT configuration.
    #[cfg(feature = "dot")]
    pub dot: Option<DotConfig>,

    /// DoH configuration.
    #[cfg(feature = "doh")]
    pub doh: Option<DohConfig>,

    /// DoQ configuration.
    #[cfg(feature = "doq")]
    pub doq: Option<DoqConfig>,

    /// Rate limiting configuration.
    pub rrl: Option<RrlConfig>,

    /// Graceful shutdown timeout.
    pub shutdown_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            udp: Some(UdpConfig::default()),
            tcp: Some(TcpConfig::default()),
            #[cfg(feature = "dot")]
            dot: None,
            #[cfg(feature = "doh")]
            doh: None,
            #[cfg(feature = "doq")]
            doq: None,
            rrl: Some(RrlConfig::default()),
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

/// UDP server configuration.
#[derive(Debug, Clone)]
pub struct UdpConfig {
    /// Listen addresses.
    pub listen: Vec<SocketAddr>,

    /// Enable SO_REUSEPORT.
    pub reuseport: bool,

    /// Receive buffer size.
    pub recv_buffer: usize,

    /// Send buffer size.
    pub send_buffer: usize,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            listen: vec!["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()],
            reuseport: true,
            recv_buffer: 4 * 1024 * 1024,
            send_buffer: 4 * 1024 * 1024,
        }
    }
}

/// TCP server configuration.
#[derive(Debug, Clone)]
pub struct TcpConfig {
    /// Listen addresses.
    pub listen: Vec<SocketAddr>,

    /// Connection backlog.
    pub backlog: u32,

    /// Idle connection timeout.
    pub idle_timeout: Duration,

    /// Maximum concurrent connections.
    pub max_connections: usize,

    /// Enable TCP Fast Open.
    pub tcp_fastopen: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            listen: vec!["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()],
            backlog: 1024,
            idle_timeout: Duration::from_secs(10),
            max_connections: 10_000,
            tcp_fastopen: true,
        }
    }
}

/// DoT server configuration.
#[cfg(feature = "dot")]
#[derive(Debug, Clone)]
pub struct DotConfig {
    /// Listen addresses.
    pub listen: Vec<SocketAddr>,

    /// TLS certificate path.
    pub cert_path: std::path::PathBuf,

    /// TLS key path.
    pub key_path: std::path::PathBuf,

    /// Connection backlog.
    pub backlog: u32,

    /// Idle timeout.
    pub idle_timeout: Duration,
}

/// DoH server configuration.
#[cfg(feature = "doh")]
#[derive(Debug, Clone)]
pub struct DohConfig {
    /// Listen addresses.
    pub listen: Vec<SocketAddr>,

    /// TLS certificate path.
    pub cert_path: std::path::PathBuf,

    /// TLS key path.
    pub key_path: std::path::PathBuf,

    /// HTTP path for DNS queries.
    pub path: String,

    /// Enable HTTP/2.
    pub http2: bool,
}

/// DoQ server configuration.
#[cfg(feature = "doq")]
#[derive(Debug, Clone)]
pub struct DoqConfig {
    /// Listen addresses.
    pub listen: Vec<SocketAddr>,

    /// TLS certificate path.
    pub cert_path: std::path::PathBuf,

    /// TLS key path.
    pub key_path: std::path::PathBuf,

    /// Idle timeout.
    pub idle_timeout: Duration,
}

/// Rate limiting configuration.
#[derive(Debug, Clone)]
pub struct RrlConfig {
    /// Enable rate limiting.
    pub enabled: bool,

    /// Responses per second threshold.
    pub responses_per_second: u32,

    /// Window size.
    pub window: Duration,

    /// Slip ratio.
    pub slip: u32,

    /// IPv4 prefix for grouping.
    pub ipv4_prefix: u8,

    /// IPv6 prefix for grouping.
    pub ipv6_prefix: u8,
}

impl Default for RrlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            responses_per_second: 5,
            window: Duration::from_secs(15),
            slip: 2,
            ipv4_prefix: 24,
            ipv6_prefix: 56,
        }
    }
}

/// DNS server instance.
pub struct DnsServer {
    config: ServerConfig,
    handler: Arc<dyn QueryHandler>,
    shutdown_tx: broadcast::Sender<()>,
}

impl DnsServer {
    /// Creates a new DNS server.
    pub fn new(config: ServerConfig, handler: Arc<dyn QueryHandler>) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            config,
            handler,
            shutdown_tx,
        }
    }

    /// Starts all configured listeners.
    pub async fn run(&self) -> Result<()> {
        let mut handles = Vec::new();

        // Start UDP servers
        if let Some(udp_config) = &self.config.udp {
            for addr in &udp_config.listen {
                let server = udp::UdpServer::bind(*addr, self.handler.clone()).await?;
                let mut shutdown_rx = self.shutdown_tx.subscribe();
                handles.push(tokio::spawn(async move {
                    tokio::select! {
                        result = server.run() => result,
                        _ = shutdown_rx.recv() => Ok(()),
                    }
                }));
            }
        }

        // Start TCP servers
        if let Some(tcp_config) = &self.config.tcp {
            for addr in &tcp_config.listen {
                let server = tcp::TcpServer::bind(*addr, self.handler.clone()).await?;
                let mut shutdown_rx = self.shutdown_tx.subscribe();
                handles.push(tokio::spawn(async move {
                    tokio::select! {
                        result = server.run() => result,
                        _ = shutdown_rx.recv() => Ok(()),
                    }
                }));
            }
        }

        // Start DoT servers
        #[cfg(feature = "dot")]
        if let Some(dot_config) = &self.config.dot {
            let tls_config = dot::DotServer::load_tls_config(
                &dot_config.cert_path,
                &dot_config.key_path,
            )?;
            
            for addr in &dot_config.listen {
                let server = dot::DotServer::bind(
                    *addr,
                    tls_config.clone(),
                    self.handler.clone(),
                ).await?;
                let mut shutdown_rx = self.shutdown_tx.subscribe();
                handles.push(tokio::spawn(async move {
                    tokio::select! {
                        result = server.run() => result,
                        _ = shutdown_rx.recv() => Ok(()),
                    }
                }));
            }
        }

        // Start DoH servers
        #[cfg(feature = "doh")]
        if let Some(doh_config) = &self.config.doh {
            let tls_config = doh::DohServer::load_tls_config(
                &doh_config.cert_path,
                &doh_config.key_path,
            )?;
            
            for addr in &doh_config.listen {
                let server = doh::DohServer::bind_with_path(
                    *addr,
                    tls_config.clone(),
                    self.handler.clone(),
                    &doh_config.path,
                ).await?;
                let mut shutdown_rx = self.shutdown_tx.subscribe();
                handles.push(tokio::spawn(async move {
                    tokio::select! {
                        result = server.run() => result,
                        _ = shutdown_rx.recv() => Ok(()),
                    }
                }));
            }
        }

        // Start DoQ servers
        #[cfg(feature = "doq")]
        if let Some(doq_config) = &self.config.doq {
            let quinn_config = doq::DoqServer::build_server_config(
                &doq_config.cert_path,
                &doq_config.key_path,
            )?;
            
            for addr in &doq_config.listen {
                let server = doq::DoqServer::bind(
                    *addr,
                    quinn_config.clone(),
                    self.handler.clone(),
                ).await?;
                let mut shutdown_rx = self.shutdown_tx.subscribe();
                handles.push(tokio::spawn(async move {
                    tokio::select! {
                        result = server.run() => result,
                        _ = shutdown_rx.recv() => Ok(()),
                    }
                }));
            }
        }

        // Wait for all servers
        for handle in handles {
            handle.await.map_err(|e| ServerError::Io(std::io::Error::other(e)))??;
        }

        Ok(())
    }

    /// Initiates graceful shutdown.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_defaults() {
        assert_eq!(Protocol::Udp.default_port(), 53);
        assert_eq!(Protocol::Dot.default_port(), 853);
        assert_eq!(Protocol::Doh.default_port(), 443);
    }

    #[test]
    fn test_protocol_encryption() {
        assert!(!Protocol::Udp.is_encrypted());
        assert!(!Protocol::Tcp.is_encrypted());
        assert!(Protocol::Dot.is_encrypted());
        assert!(Protocol::Doh.is_encrypted());
        assert!(Protocol::Doq.is_encrypted());
    }
}
