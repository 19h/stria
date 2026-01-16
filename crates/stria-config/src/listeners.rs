//! Listener configuration.

use super::{ConfigError, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

/// Network listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ListenerConfig {
    /// UDP listeners.
    pub udp: Vec<UdpListener>,

    /// TCP listeners.
    pub tcp: Vec<TcpListener>,

    /// DNS over TLS listeners.
    pub dot: Vec<DotListener>,

    /// DNS over HTTPS listeners.
    pub doh: Vec<DohListener>,

    /// DNS over QUIC listeners.
    pub doq: Vec<DoqListener>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            udp: vec![UdpListener::default()],
            tcp: vec![TcpListener::default()],
            dot: Vec::new(),
            doh: Vec::new(),
            doq: Vec::new(),
        }
    }
}

impl ListenerConfig {
    pub fn validate(&self) -> Result<()> {
        for listener in &self.dot {
            listener.validate()?;
        }

        for listener in &self.doh {
            listener.validate()?;
        }

        for listener in &self.doq {
            listener.validate()?;
        }

        Ok(())
    }
}

/// UDP listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UdpListener {
    /// Listen address.
    pub address: SocketAddr,

    /// Enable SO_REUSEPORT.
    pub reuseport: bool,

    /// Receive buffer size.
    pub recv_buffer: Option<usize>,

    /// Send buffer size.
    pub send_buffer: Option<usize>,
}

impl Default for UdpListener {
    fn default() -> Self {
        Self {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53),
            reuseport: true,
            recv_buffer: Some(4 * 1024 * 1024), // 4 MB
            send_buffer: Some(4 * 1024 * 1024),
        }
    }
}

/// TCP listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TcpListener {
    /// Listen address.
    pub address: SocketAddr,

    /// Enable SO_REUSEPORT.
    pub reuseport: bool,

    /// TCP backlog.
    pub backlog: u32,

    /// Idle timeout (seconds).
    pub idle_timeout: u64,

    /// Enable TCP Fast Open.
    pub tcp_fastopen: bool,

    /// TCP Fast Open queue length.
    pub tcp_fastopen_queue: u32,
}

impl Default for TcpListener {
    fn default() -> Self {
        Self {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53),
            reuseport: true,
            backlog: 1024,
            idle_timeout: 10,
            tcp_fastopen: true,
            tcp_fastopen_queue: 256,
        }
    }
}

/// TLS configuration (shared by DoT, DoH, DoQ).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Certificate file (PEM).
    pub cert: PathBuf,

    /// Private key file (PEM).
    pub key: PathBuf,

    /// CA certificates for client authentication.
    pub ca: Option<PathBuf>,

    /// Require client certificates.
    pub client_auth: bool,

    /// Minimum TLS version.
    pub min_version: String,

    /// ALPN protocols.
    pub alpn: Vec<String>,
}

impl TlsConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.cert.exists() {
            return Err(ConfigError::NotFound(self.cert.clone()));
        }

        if !self.key.exists() {
            return Err(ConfigError::NotFound(self.key.clone()));
        }

        Ok(())
    }
}

/// DNS over TLS listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotListener {
    /// Listen address.
    pub address: SocketAddr,

    /// TLS configuration.
    pub tls: TlsConfig,

    /// Enable SO_REUSEPORT.
    pub reuseport: bool,

    /// TCP backlog.
    pub backlog: u32,

    /// Idle timeout (seconds).
    pub idle_timeout: u64,
}

impl DotListener {
    pub fn validate(&self) -> Result<()> {
        self.tls.validate()
    }
}

/// DNS over HTTPS listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DohListener {
    /// Listen address.
    pub address: SocketAddr,

    /// TLS configuration.
    pub tls: TlsConfig,

    /// HTTP path.
    pub path: String,

    /// Enable HTTP/2.
    pub http2: bool,

    /// Enable SO_REUSEPORT.
    pub reuseport: bool,

    /// TCP backlog.
    pub backlog: u32,

    /// Idle timeout (seconds).
    pub idle_timeout: u64,
}

impl Default for DohListener {
    fn default() -> Self {
        Self {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443),
            tls: TlsConfig {
                cert: PathBuf::from("/etc/stria/cert.pem"),
                key: PathBuf::from("/etc/stria/key.pem"),
                ca: None,
                client_auth: false,
                min_version: "1.2".to_string(),
                alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            },
            path: "/dns-query".to_string(),
            http2: true,
            reuseport: true,
            backlog: 1024,
            idle_timeout: 30,
        }
    }
}

impl DohListener {
    pub fn validate(&self) -> Result<()> {
        self.tls.validate()
    }
}

/// DNS over QUIC listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoqListener {
    /// Listen address.
    pub address: SocketAddr,

    /// TLS configuration.
    pub tls: TlsConfig,

    /// Enable SO_REUSEPORT.
    pub reuseport: bool,

    /// Idle timeout (seconds).
    pub idle_timeout: u64,

    /// Maximum concurrent streams.
    pub max_streams: u32,
}

impl DoqListener {
    pub fn validate(&self) -> Result<()> {
        self.tls.validate()
    }
}
