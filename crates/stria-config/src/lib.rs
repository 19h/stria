//! # Stria DNS Configuration
//!
//! Intuitive YAML-based configuration system for Stria DNS server.
//!
//! ## Design Philosophy
//!
//! The configuration system is designed to be:
//! - **Intuitive**: Sensible defaults with clear, well-documented options
//! - **Type-safe**: Strong typing with validation
//! - **Hot-reloadable**: Configuration can be updated without restart
//! - **Flexible**: Support for YAML, JSON, and TOML formats

use arc_swap::ArcSwap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use url::Url;

pub mod filter;
pub mod listeners;
pub mod nice;
pub mod resolver;
pub mod security;
pub mod watch;

pub use filter::FilterConfig;
pub use listeners::ListenerConfig;
pub use resolver::ResolverConfig;
pub use security::SecurityConfig;

/// Configuration error.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid value for {field}: {message}")]
    InvalidValue { field: String, message: String },

    #[error("File not found: {0}")]
    NotFound(PathBuf),
}

/// Result type for configuration operations.
pub type Result<T> = std::result::Result<T, ConfigError>;

/// Main configuration for Stria DNS server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Server identification and metadata.
    pub server: ServerConfig,

    /// Network listeners (UDP, TCP, DoT, DoH, DoQ).
    pub listeners: ListenerConfig,

    /// Resolver configuration.
    pub resolver: ResolverConfig,

    /// Cache configuration.
    pub cache: CacheConfig,

    /// DNSSEC configuration.
    pub dnssec: DnssecConfig,

    /// Security and rate limiting.
    pub security: SecurityConfig,

    /// Filtering configuration.
    pub filter: FilterConfig,

    /// Metrics and observability.
    pub metrics: MetricsConfig,

    /// Logging configuration.
    pub logging: LoggingConfig,

    /// Zone configuration.
    pub zones: Vec<ZoneConfig>,

    /// Control server configuration.
    pub control: ControlConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            listeners: ListenerConfig::default(),
            resolver: ResolverConfig::default(),
            cache: CacheConfig::default(),
            dnssec: DnssecConfig::default(),
            security: SecurityConfig::default(),
            filter: FilterConfig::default(),
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
            zones: Vec::new(),
            control: ControlConfig::default(),
        }
    }
}

impl Config {
    /// Loads configuration from a file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }

        let content = std::fs::read_to_string(path)?;

        let config = match path.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => serde_yaml::from_str(&content)?,
            Some("json") => serde_json::from_str(&content)?,
            Some("toml") => toml::from_str(&content)?,
            _ => serde_yaml::from_str(&content)?, // Default to YAML
        };

        Ok(config)
    }

    /// Loads configuration from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate listeners
        self.listeners.validate()?;

        // Validate resolver
        self.resolver.validate()?;

        // Validate cache
        self.cache.validate()?;

        // Validate security
        self.security.validate()?;

        // Validate filter
        self.filter.validate()?;

        Ok(())
    }

    /// Serializes to YAML.
    pub fn to_yaml(&self) -> Result<String> {
        Ok(serde_yaml::to_string(self)?)
    }
}

/// Server identification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Server name (for NSID, logs, etc.).
    pub name: String,

    /// Server version string.
    pub version: String,

    /// Hostname (for version.bind queries).
    pub hostname: Option<String>,

    /// Number of worker threads (0 = auto-detect).
    pub workers: usize,

    /// User to run as after binding ports.
    pub user: Option<String>,

    /// Group to run as after binding ports.
    pub group: Option<String>,

    /// Working directory.
    pub directory: Option<PathBuf>,

    /// PID file location.
    pub pid_file: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: "stria".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            hostname: None,
            workers: 0, // Auto-detect
            user: None,
            group: None,
            directory: None,
            pid_file: None,
        }
    }
}

/// Cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Enable caching.
    pub enabled: bool,

    /// Maximum number of cached records.
    pub max_entries: usize,

    /// Maximum memory usage (bytes).
    pub max_memory: usize,

    /// Minimum TTL for cached records (seconds).
    pub min_ttl: u32,

    /// Maximum TTL for cached records (seconds).
    pub max_ttl: u32,

    /// Negative cache TTL (seconds).
    pub negative_ttl: u32,

    /// Enable serve-stale (RFC 8767).
    pub serve_stale: bool,

    /// How long to serve stale records (seconds).
    pub stale_ttl: u32,

    /// Enable prefetch for expiring records.
    pub prefetch: bool,

    /// Prefetch threshold (percent of TTL remaining).
    pub prefetch_threshold: u8,

    /// L2 cache (shared memory) configuration.
    pub l2: Option<L2CacheConfig>,

    /// L3 cache (Redis) configuration.
    pub l3: Option<L3CacheConfig>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 100_000,
            max_memory: 256 * 1024 * 1024, // 256 MB
            min_ttl: 30,
            max_ttl: 86400 * 7, // 7 days
            negative_ttl: 900,  // 15 minutes
            serve_stale: true,
            stale_ttl: 86400, // 1 day
            prefetch: true,
            prefetch_threshold: 10, // 10% TTL remaining
            l2: None,
            l3: None,
        }
    }
}

impl CacheConfig {
    fn validate(&self) -> Result<()> {
        if self.min_ttl > self.max_ttl {
            return Err(ConfigError::InvalidValue {
                field: "cache.min_ttl".to_string(),
                message: "min_ttl cannot be greater than max_ttl".to_string(),
            });
        }

        if self.prefetch_threshold > 100 {
            return Err(ConfigError::InvalidValue {
                field: "cache.prefetch_threshold".to_string(),
                message: "must be 0-100".to_string(),
            });
        }

        Ok(())
    }
}

/// L2 (shared memory) cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2CacheConfig {
    /// Shared memory size (bytes).
    pub size: usize,
}

/// L3 (Redis) cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L3CacheConfig {
    /// Redis URL.
    pub url: String,

    /// Connection pool size.
    pub pool_size: usize,

    /// Key prefix.
    pub prefix: String,
}

/// DNSSEC configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnssecConfig {
    /// Enable DNSSEC validation.
    pub validation: bool,

    /// Trust anchors file (RFC 5011).
    pub trust_anchors: Option<PathBuf>,

    /// Negative trust anchors.
    pub negative_trust_anchors: Vec<String>,

    /// Supported algorithms.
    pub algorithms: Vec<String>,

    /// Supported digest types.
    pub digest_types: Vec<String>,

    /// Enable aggressive NSEC caching (RFC 8198).
    pub aggressive_nsec: bool,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            validation: true,
            trust_anchors: None,
            negative_trust_anchors: Vec::new(),
            algorithms: vec![
                "ECDSAP256SHA256".to_string(),
                "ECDSAP384SHA384".to_string(),
                "ED25519".to_string(),
                "RSASHA256".to_string(),
            ],
            digest_types: vec!["SHA-256".to_string(), "SHA-384".to_string()],
            aggressive_nsec: true,
        }
    }
}

/// Metrics and observability configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Enable metrics collection.
    pub enabled: bool,

    /// Prometheus endpoint.
    pub prometheus: Option<PrometheusConfig>,

    /// OpenTelemetry configuration.
    pub otlp: Option<OtlpConfig>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prometheus: Some(PrometheusConfig::default()),
            otlp: None,
        }
    }
}

/// Prometheus configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrometheusConfig {
    /// Enable Prometheus endpoint.
    pub enabled: bool,

    /// Listen address.
    pub listen: SocketAddr,

    /// Endpoint path.
    pub path: String,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9153),
            path: "/metrics".to_string(),
        }
    }
}

/// OpenTelemetry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpConfig {
    /// OTLP endpoint URL.
    pub endpoint: String,

    /// Service name.
    pub service_name: String,

    /// Additional headers.
    pub headers: HashMap<String, String>,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level.
    pub level: String,

    /// Log format (text, json).
    pub format: String,

    /// Output (stdout, stderr, file path).
    pub output: String,

    /// Enable query logging.
    pub query_log: bool,

    /// Query log file.
    pub query_log_file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "text".to_string(),
            output: "stdout".to_string(),
            query_log: false,
            query_log_file: None,
        }
    }
}

/// Zone configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneConfig {
    /// Zone name.
    pub name: String,

    /// Zone type (primary, secondary, forward, stub).
    pub zone_type: ZoneType,

    /// Zone file path (for file-backed zones).
    pub file: Option<PathBuf>,

    /// Primary servers (for secondary zones).
    pub primaries: Vec<SocketAddr>,

    /// Forward targets (for forward zones).
    pub forwarders: Vec<SocketAddr>,

    /// TSIG key name.
    pub tsig_key: Option<String>,

    /// Allow zone transfers to these addresses.
    pub allow_transfer: Vec<ipnet::IpNet>,

    /// Allow dynamic updates from these addresses.
    pub allow_update: Vec<ipnet::IpNet>,

    /// DNSSEC signing configuration.
    pub dnssec: Option<ZoneDnssecConfig>,
}

/// Zone type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZoneType {
    Primary,
    Secondary,
    Forward,
    Stub,
}

/// Zone DNSSEC configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneDnssecConfig {
    /// Enable signing.
    pub enabled: bool,

    /// KSK algorithm.
    pub ksk_algorithm: String,

    /// ZSK algorithm.
    pub zsk_algorithm: String,

    /// Key directory.
    pub key_directory: PathBuf,

    /// NSEC3 configuration.
    pub nsec3: Option<Nsec3Config>,
}

/// NSEC3 configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nsec3Config {
    /// Hash iterations.
    pub iterations: u16,

    /// Salt (hex encoded).
    pub salt: String,

    /// Enable opt-out.
    pub opt_out: bool,
}

/// Thread-safe configuration holder with hot-reload support.
pub struct ConfigHolder {
    config: ArcSwap<Config>,
    path: RwLock<Option<PathBuf>>,
}

impl ConfigHolder {
    /// Creates a new configuration holder.
    pub fn new(config: Config) -> Self {
        Self {
            config: ArcSwap::new(Arc::new(config)),
            path: RwLock::new(None),
        }
    }

    /// Creates a holder from a file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let config = Config::from_file(path)?;
        Ok(Self {
            config: ArcSwap::new(Arc::new(config)),
            path: RwLock::new(Some(path.to_path_buf())),
        })
    }

    /// Returns the current configuration.
    pub fn get(&self) -> Arc<Config> {
        self.config.load_full()
    }

    /// Reloads configuration from the file.
    pub fn reload(&self) -> Result<()> {
        let path = self.path.read();
        if let Some(p) = path.as_ref() {
            let config = Config::from_file(p)?;
            config.validate()?;
            self.config.store(Arc::new(config));
        }
        Ok(())
    }

    /// Updates the configuration.
    pub fn update(&self, config: Config) {
        self.config.store(Arc::new(config));
    }
}

impl Default for ConfigHolder {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

/// Control server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlConfig {
    /// Enable the control server.
    pub enabled: bool,

    /// Unix socket path for the control server.
    pub socket_path: Option<PathBuf>,

    /// HTTP endpoint (alternative to Unix socket).
    pub http_listen: Option<SocketAddr>,

    /// Path to persist custom block/allow rules.
    pub rules_file: Option<PathBuf>,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket_path: Some(PathBuf::from("/var/run/stria/control.sock")),
            http_listen: None,
            rules_file: Some(PathBuf::from("/var/lib/stria/custom_rules.json")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_yaml_roundtrip() {
        let config = Config::default();
        let yaml = config.to_yaml().unwrap();
        let parsed = Config::from_yaml(&yaml).unwrap();
        assert_eq!(config.server.name, parsed.server.name);
    }

    #[test]
    fn test_config_holder() {
        let holder = ConfigHolder::new(Config::default());
        let config = holder.get();
        assert_eq!(config.server.name, "stria");
    }
}
