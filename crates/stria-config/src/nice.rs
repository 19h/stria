//! Human-friendly configuration parser.
//!
//! This module provides a "nice" configuration format that prioritizes
//! readability and ease of use over explicit verbosity.
//!
//! # Design Principles
//!
//! 1. **Minimal viable config**: `upstream: 1.1.1.1` is a complete config
//! 2. **Progressive disclosure**: Simple things simple, complex things possible
//! 3. **Smart defaults**: Everything has a sensible default
//! 4. **Shortcuts**: Common patterns have short forms
//! 5. **Environment variables**: `${VAR}` interpolation

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

use crate::{Config, Result};

/// Human-friendly configuration format.
///
/// This struct supports the "nice" YAML syntax and converts to the
/// internal `Config` format.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NiceConfig {
    /// Listen addresses. Can be:
    /// - `53` (UDP + TCP on port 53)
    /// - `853/tls` (DoT)
    /// - `443/https` (DoH)
    /// - `853/quic` (DoQ)
    /// - Full form: `{ address: "0.0.0.0", port: 53, protocol: "udp" }`
    #[serde(default)]
    pub listen: ListenConfig,

    /// Upstream resolvers. Can be:
    /// - `1.1.1.1` (plain DNS)
    /// - `tls://1.1.1.1:853` (DoT)
    /// - `https://cloudflare-dns.com/dns-query` (DoH)
    #[serde(default)]
    pub upstream: UpstreamConfig,

    /// Blocklists for ad/tracker blocking.
    #[serde(default)]
    pub block: Vec<BlocklistEntry>,

    /// Allowlist - domains that should never be blocked.
    #[serde(default)]
    pub allow: Vec<String>,

    /// Local DNS records (name -> IP).
    #[serde(default)]
    pub local: HashMap<String, IpAddr>,

    /// Local CNAME records (alias -> target).
    #[serde(default)]
    pub cname: HashMap<String, String>,

    /// Cache configuration.
    #[serde(default)]
    pub cache: CacheConfig,

    /// DNSSEC validation (default: true).
    #[serde(default = "default_true")]
    pub dnssec: bool,

    /// Privacy settings.
    #[serde(default)]
    pub privacy: PrivacyConfig,

    /// TLS configuration for DoT/DoH.
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Metrics configuration.
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,

    /// Logging configuration.
    #[serde(default)]
    pub log: LogConfig,

    /// API/dashboard configuration.
    #[serde(default)]
    pub api: Option<ApiConfig>,

    /// Rate limiting.
    #[serde(default)]
    pub ratelimit: Option<RatelimitConfig>,

    /// Access control lists.
    #[serde(default)]
    pub acl: Option<AclConfig>,

    /// Zone configurations.
    #[serde(default)]
    pub zones: Vec<ZoneConfig>,

    /// Split-horizon DNS views.
    #[serde(default)]
    pub views: HashMap<String, ViewConfig>,

    /// Server settings.
    #[serde(default)]
    pub server: ServerConfig,
}

fn default_true() -> bool {
    true
}

// ============================================================================
// Listen Configuration
// ============================================================================

/// Listen configuration supporting multiple formats.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ListenConfig {
    pub entries: Vec<ListenEntry>,
}

impl<'de> Deserialize<'de> for ListenConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum ListenValue {
            Single(SingleListen),
            Multiple(Vec<SingleListen>),
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum SingleListen {
            Port(u16),
            String(String),
            Full(ListenEntry),
        }

        fn parse_single(s: SingleListen) -> ListenEntry {
            match s {
                SingleListen::Port(port) => ListenEntry {
                    address: "0.0.0.0".to_string(),
                    port,
                    protocol: ListenProtocol::UdpTcp,
                },
                SingleListen::String(s) => parse_listen_string(&s),
                SingleListen::Full(e) => e,
            }
        }

        let value = ListenValue::deserialize(deserializer)?;

        let entries = match value {
            ListenValue::Single(s) => vec![parse_single(s)],
            ListenValue::Multiple(v) => v.into_iter().map(parse_single).collect(),
        };

        Ok(ListenConfig { entries })
    }
}

fn parse_listen_string(s: &str) -> ListenEntry {
    if let Some((port_str, proto)) = s.split_once('/') {
        let port = port_str.parse().unwrap_or(53);
        let protocol = match proto.to_lowercase().as_str() {
            "tls" | "dot" => ListenProtocol::Tls,
            "https" | "doh" => ListenProtocol::Https,
            "quic" | "doq" => ListenProtocol::Quic,
            "udp" => ListenProtocol::Udp,
            "tcp" => ListenProtocol::Tcp,
            _ => ListenProtocol::UdpTcp,
        };
        ListenEntry {
            address: "0.0.0.0".to_string(),
            port,
            protocol,
        }
    } else if let Ok(port) = s.parse::<u16>() {
        ListenEntry {
            address: "0.0.0.0".to_string(),
            port,
            protocol: ListenProtocol::UdpTcp,
        }
    } else {
        // Assume it's an address:port
        ListenEntry {
            address: s.to_string(),
            port: 53,
            protocol: ListenProtocol::UdpTcp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenEntry {
    #[serde(default = "default_address")]
    pub address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub protocol: ListenProtocol,
}

fn default_address() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    53
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ListenProtocol {
    #[default]
    UdpTcp,
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
}

// ============================================================================
// Upstream Configuration
// ============================================================================

/// Upstream resolver configuration.
#[derive(Debug, Clone, Serialize, Default)]
pub struct UpstreamConfig {
    pub servers: Vec<UpstreamServer>,
}

impl<'de> Deserialize<'de> for UpstreamConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum UpstreamValue {
            Single(String),
            Multiple(Vec<String>),
        }

        let value = UpstreamValue::deserialize(deserializer)?;

        let servers = match value {
            UpstreamValue::Single(s) => vec![parse_upstream(&s)],
            UpstreamValue::Multiple(v) => v.iter().map(|s| parse_upstream(s)).collect(),
        };

        Ok(UpstreamConfig { servers })
    }
}

fn parse_upstream(s: &str) -> UpstreamServer {
    if s.starts_with("tls://") {
        let addr = s.strip_prefix("tls://").unwrap();
        let (host, port) = parse_host_port(addr, 853);
        UpstreamServer {
            address: host,
            port,
            protocol: UpstreamProtocol::Tls,
            name: None,
        }
    } else if s.starts_with("https://") {
        UpstreamServer {
            address: s.to_string(),
            port: 443,
            protocol: UpstreamProtocol::Https,
            name: None,
        }
    } else if s.starts_with("quic://") {
        let addr = s.strip_prefix("quic://").unwrap();
        let (host, port) = parse_host_port(addr, 853);
        UpstreamServer {
            address: host,
            port,
            protocol: UpstreamProtocol::Quic,
            name: None,
        }
    } else {
        // Plain DNS
        let (host, port) = parse_host_port(s, 53);
        UpstreamServer {
            address: host,
            port,
            protocol: UpstreamProtocol::Udp,
            name: None,
        }
    }
}

fn parse_host_port(s: &str, default_port: u16) -> (String, u16) {
    if let Some((host, port_str)) = s.rsplit_once(':') {
        if let Ok(port) = port_str.parse() {
            return (host.to_string(), port);
        }
    }
    (s.to_string(), default_port)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamServer {
    pub address: String,
    pub port: u16,
    pub protocol: UpstreamProtocol,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    #[default]
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
}

// ============================================================================
// Blocklist Configuration
// ============================================================================

/// Blocklist entry - can be a shorthand or URL.
#[derive(Debug, Clone, Serialize)]
pub struct BlocklistEntry {
    pub name: String,
    pub url: String,
    pub format: BlocklistFormat,
}

impl<'de> Deserialize<'de> for BlocklistEntry {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(parse_blocklist(&s))
    }
}

fn parse_blocklist(s: &str) -> BlocklistEntry {
    // Check for built-in shortcuts
    let (name, url, format) = match s.to_lowercase().as_str() {
        // Steven Black hosts
        "stevenblack/unified" | "stevenblack" => (
            "StevenBlack Unified",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            BlocklistFormat::Hosts,
        ),
        "stevenblack/fakenews" => (
            "StevenBlack FakeNews",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts",
            BlocklistFormat::Hosts,
        ),
        "stevenblack/gambling" => (
            "StevenBlack Gambling",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
            BlocklistFormat::Hosts,
        ),

        // Energized
        "energized/spark" => (
            "Energized Spark",
            "https://block.energized.pro/spark/formats/hosts",
            BlocklistFormat::Hosts,
        ),
        "energized/blu" => (
            "Energized Blu",
            "https://block.energized.pro/blu/formats/hosts",
            BlocklistFormat::Hosts,
        ),
        "energized/basic" => (
            "Energized Basic",
            "https://block.energized.pro/basic/formats/hosts",
            BlocklistFormat::Hosts,
        ),
        "energized/ultimate" => (
            "Energized Ultimate",
            "https://block.energized.pro/ultimate/formats/hosts",
            BlocklistFormat::Hosts,
        ),

        // OISD
        "oisd/small" => (
            "OISD Small",
            "https://small.oisd.nl/domainswild",
            BlocklistFormat::Domains,
        ),
        "oisd/big" | "oisd" => (
            "OISD Big",
            "https://big.oisd.nl/domainswild",
            BlocklistFormat::Domains,
        ),
        "oisd/full" => (
            "OISD Full",
            "https://full.oisd.nl/domainswild",
            BlocklistFormat::Domains,
        ),
        "oisd/nsfw" => (
            "OISD NSFW",
            "https://nsfw.oisd.nl/domainswild",
            BlocklistFormat::Domains,
        ),

        // Hagezi
        "hagezi/light" => (
            "Hagezi Light",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt",
            BlocklistFormat::Domains,
        ),
        "hagezi/normal" | "hagezi" => (
            "Hagezi Normal",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt",
            BlocklistFormat::Domains,
        ),
        "hagezi/pro" => (
            "Hagezi Pro",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
            BlocklistFormat::Domains,
        ),
        "hagezi/ultimate" => (
            "Hagezi Ultimate",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt",
            BlocklistFormat::Domains,
        ),

        // AdGuard
        "adguard" | "adguard/dns" => (
            "AdGuard DNS",
            "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            BlocklistFormat::Adblock,
        ),

        // 1Hosts
        "1hosts/lite" => (
            "1Hosts Lite",
            "https://o0.pages.dev/Lite/domains.txt",
            BlocklistFormat::Domains,
        ),
        "1hosts/pro" | "1hosts" => (
            "1Hosts Pro",
            "https://o0.pages.dev/Pro/domains.txt",
            BlocklistFormat::Domains,
        ),

        // If not a shortcut, treat as URL
        _ => {
            let format = if s.contains("hosts") {
                BlocklistFormat::Hosts
            } else if s.contains("adblock") || s.ends_with(".txt") {
                BlocklistFormat::Adblock
            } else {
                BlocklistFormat::Domains
            };
            return BlocklistEntry {
                name: s.to_string(),
                url: s.to_string(),
                format,
            };
        }
    };

    BlocklistEntry {
        name: name.to_string(),
        url: url.to_string(),
        format,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistFormat {
    #[default]
    Hosts,
    Domains,
    Adblock,
}

// ============================================================================
// Cache Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Maximum entries (or `true` for default, `false` to disable).
    #[serde(deserialize_with = "deserialize_cache_size")]
    pub size: Option<usize>,

    /// Serve stale records when upstream fails.
    #[serde(rename = "serve-stale")]
    pub serve_stale: bool,

    /// Prefetch expiring records.
    pub prefetch: bool,

    /// Minimum TTL (seconds).
    #[serde(rename = "min-ttl")]
    pub min_ttl: Option<u32>,

    /// Maximum TTL (seconds).
    #[serde(rename = "max-ttl")]
    pub max_ttl: Option<u32>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            size: Some(100_000),
            serve_stale: true,
            prefetch: true,
            min_ttl: None,
            max_ttl: None,
        }
    }
}

fn deserialize_cache_size<'de, D>(deserializer: D) -> std::result::Result<Option<usize>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum CacheSize {
        Bool(bool),
        Number(usize),
    }

    match CacheSize::deserialize(deserializer)? {
        CacheSize::Bool(true) => Ok(Some(100_000)),
        CacheSize::Bool(false) => Ok(None),
        CacheSize::Number(n) => Ok(Some(n)),
    }
}

// ============================================================================
// Privacy Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PrivacyConfig {
    /// Don't send EDNS Client Subnet.
    pub ecs: bool,

    /// Enable QNAME minimization (RFC 7816).
    #[serde(rename = "qname-minimization")]
    pub qname_minimization: bool,
}

// ============================================================================
// TLS Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Certificate file path.
    pub cert: PathBuf,

    /// Private key file path.
    pub key: PathBuf,

    /// CA certificate for client verification.
    pub ca: Option<PathBuf>,
}

// ============================================================================
// Metrics Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MetricsConfig {
    /// Simple form: just the prometheus listen address
    Simple(String),
    /// Full form
    Full {
        prometheus: Option<String>,
        otlp: Option<String>,
    },
}

// ============================================================================
// Log Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// Log level (trace, debug, info, warn, error).
    pub level: String,

    /// Log format (text, json).
    pub format: String,

    /// Query log file (or `true` for stdout).
    pub queries: Option<QueryLogConfig>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "text".to_string(),
            queries: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QueryLogConfig {
    Enabled(bool),
    File(PathBuf),
}

// ============================================================================
// API Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Listen address (e.g., ":8080" or "127.0.0.1:8080").
    pub listen: String,

    /// API key for authentication.
    pub key: Option<String>,
}

// ============================================================================
// Rate Limit Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatelimitConfig {
    /// Queries per second.
    pub qps: u32,

    /// Slip ratio (1 = no slip, 2 = slip every other).
    #[serde(default = "default_slip")]
    pub slip: u32,
}

fn default_slip() -> u32 {
    2
}

// ============================================================================
// ACL Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "kebab-case")]
pub struct AclConfig {
    pub allow_query: Vec<String>,
    pub allow_recursion: Vec<String>,
    pub allow_transfer: Vec<String>,
}

// ============================================================================
// Zone Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneConfig {
    /// Zone name.
    pub name: String,

    /// Zone type (primary, secondary, forward, stub).
    #[serde(rename = "type")]
    pub zone_type: String,

    /// Zone file path.
    pub file: Option<PathBuf>,

    /// Primary server (for secondary zones).
    pub primary: Option<String>,

    /// TSIG key name.
    pub tsig: Option<String>,

    /// DNSSEC signing config.
    pub dnssec: Option<ZoneDnssecConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneDnssecConfig {
    pub algorithm: String,
}

// ============================================================================
// View Configuration (Split-Horizon)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ViewConfig {
    /// Client match (CIDR or "any").
    #[serde(rename = "match")]
    pub match_clients: String,

    /// Override upstream for this view.
    pub upstream: Option<Vec<String>>,

    /// Zone overrides.
    pub zones: Option<Vec<ZoneConfig>>,
}

// ============================================================================
// Server Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Server name.
    pub name: String,

    /// Number of workers (0 = auto).
    pub workers: usize,

    /// User to run as.
    pub user: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: "stria".to_string(),
            workers: 0,
            user: None,
        }
    }
}

// ============================================================================
// Environment Variable Interpolation
// ============================================================================

/// Interpolates environment variables in a string.
/// Supports `${VAR}` and `${VAR:-default}` syntax.
pub fn interpolate_env(s: &str) -> String {
    let mut result = s.to_string();
    let re = regex::Regex::new(r"\$\{([^}:]+)(?::-([^}]*))?\}").unwrap();

    for cap in re.captures_iter(s) {
        let var_name = &cap[1];
        let default = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let value = std::env::var(var_name).unwrap_or_else(|_| default.to_string());
        result = result.replace(&cap[0], &value);
    }

    result
}

// ============================================================================
// Conversion to Internal Config
// ============================================================================

impl NiceConfig {
    /// Parses a nice config from YAML with environment variable interpolation.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let interpolated = interpolate_env(yaml);
        Ok(serde_yaml::from_str(&interpolated)?)
    }

    /// Converts to the internal Config format.
    pub fn to_config(&self) -> Result<Config> {
        // For now, return a default config
        // In a real implementation, this would map all the nice fields
        // to the internal Config struct
        let config = Config::default();

        // TODO: Map listen config
        // TODO: Map upstream config
        // TODO: Map blocklists to filter config
        // etc.

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_config() {
        let yaml = "upstream: 1.1.1.1";
        let config: NiceConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.upstream.servers.len(), 1);
        assert_eq!(config.upstream.servers[0].address, "1.1.1.1");
    }

    #[test]
    fn test_multiple_upstream() {
        let yaml = r#"
upstream:
  - 1.1.1.1
  - 8.8.8.8
  - tls://dns.google:853
"#;
        let config: NiceConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.upstream.servers.len(), 3);
        assert_eq!(config.upstream.servers[2].protocol, UpstreamProtocol::Tls);
    }

    #[test]
    fn test_listen_shorthand() {
        let yaml = r#"
listen:
  - 53
  - 853/tls
  - 443/https
"#;
        let config: NiceConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.listen.entries.len(), 3);
        assert_eq!(config.listen.entries[0].protocol, ListenProtocol::UdpTcp);
        assert_eq!(config.listen.entries[1].protocol, ListenProtocol::Tls);
        assert_eq!(config.listen.entries[2].protocol, ListenProtocol::Https);
    }

    #[test]
    fn test_blocklist_shortcuts() {
        let yaml = r#"
block:
  - stevenblack/unified
  - oisd/small
  - https://example.com/hosts.txt
"#;
        let config: NiceConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.block.len(), 3);
        assert!(config.block[0].url.contains("StevenBlack"));
        assert!(config.block[1].url.contains("oisd.nl"));
        assert_eq!(config.block[2].url, "https://example.com/hosts.txt");
    }

    #[test]
    fn test_local_dns() {
        let yaml = r#"
local:
  router.home: 192.168.1.1
  nas.home: 192.168.1.10
"#;
        let config: NiceConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.local.len(), 2);
        assert_eq!(
            config.local.get("router.home"),
            Some(&IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn test_cache_config() {
        // Test cache with size specified
        let yaml = r#"
cache:
  size: 50000
  serve-stale: true
"#;
        let config: NiceConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.cache.size, Some(50000));
        assert!(config.cache.serve_stale);
    }

    #[test]
    fn test_env_interpolation() {
        // SAFETY: This test runs single-threaded and the env var is cleaned up
        unsafe {
            std::env::set_var("TEST_DNS", "1.1.1.1");
        }
        let result = interpolate_env("upstream: ${TEST_DNS}");
        assert_eq!(result, "upstream: 1.1.1.1");

        let result = interpolate_env("upstream: ${NONEXISTENT:-8.8.8.8}");
        assert_eq!(result, "upstream: 8.8.8.8");

        unsafe {
            std::env::remove_var("TEST_DNS");
        }
    }

    #[test]
    fn test_home_config() {
        let yaml = r#"
listen: 53

upstream:
  - 1.1.1.1
  - 9.9.9.9

block:
  - stevenblack/unified

local:
  router.home: 192.168.1.1

cache:
  size: 50000
"#;
        let config: NiceConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.listen.entries.len(), 1);
        assert_eq!(config.upstream.servers.len(), 2);
        assert_eq!(config.block.len(), 1);
        assert_eq!(config.local.len(), 1);
        assert_eq!(config.cache.size, Some(50000));
    }
}
