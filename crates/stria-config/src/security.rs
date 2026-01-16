//! Security configuration.

use super::{ConfigError, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Security configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Response Rate Limiting.
    pub rrl: RrlConfig,

    /// Access control lists.
    pub acl: AclConfig,

    /// DNS Cookie support (RFC 7873).
    pub cookies: CookieConfig,

    /// Query limits.
    pub limits: LimitsConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            rrl: RrlConfig::default(),
            acl: AclConfig::default(),
            cookies: CookieConfig::default(),
            limits: LimitsConfig::default(),
        }
    }
}

impl SecurityConfig {
    pub fn validate(&self) -> Result<()> {
        self.rrl.validate()?;
        self.limits.validate()?;
        Ok(())
    }
}

/// Response Rate Limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RrlConfig {
    /// Enable RRL.
    pub enabled: bool,

    /// Responses per second threshold.
    pub responses_per_second: u32,

    /// Window size (seconds).
    pub window: u32,

    /// Slip ratio (1 = slip every response, 2 = slip every other, etc.).
    pub slip: u32,

    /// IPv4 prefix length for rate limiting.
    pub ipv4_prefix: u8,

    /// IPv6 prefix length for rate limiting.
    pub ipv6_prefix: u8,

    /// Maximum entries in the rate limit table.
    pub max_table_size: usize,

    /// Exempt addresses from RRL.
    pub exempt: Vec<IpNet>,
}

impl Default for RrlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            responses_per_second: 5,
            window: 15,
            slip: 2,
            ipv4_prefix: 24,
            ipv6_prefix: 56,
            max_table_size: 100_000,
            exempt: Vec::new(),
        }
    }
}

impl RrlConfig {
    pub fn validate(&self) -> Result<()> {
        if self.ipv4_prefix > 32 {
            return Err(ConfigError::InvalidValue {
                field: "security.rrl.ipv4_prefix".to_string(),
                message: "must be 0-32".to_string(),
            });
        }

        if self.ipv6_prefix > 128 {
            return Err(ConfigError::InvalidValue {
                field: "security.rrl.ipv6_prefix".to_string(),
                message: "must be 0-128".to_string(),
            });
        }

        Ok(())
    }
}

/// Access Control List configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AclConfig {
    /// Default action (allow/deny).
    pub default_action: AclAction,

    /// Allow recursion from these networks.
    pub allow_recursion: Vec<IpNet>,

    /// Allow queries from these networks.
    pub allow_query: Vec<IpNet>,

    /// Deny queries from these networks.
    pub deny_query: Vec<IpNet>,

    /// Allow zone transfers from these networks.
    pub allow_transfer: Vec<IpNet>,

    /// Allow dynamic updates from these networks.
    pub allow_update: Vec<IpNet>,
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            default_action: AclAction::Allow,
            allow_recursion: vec![
                "127.0.0.0/8".parse().unwrap(),
                "10.0.0.0/8".parse().unwrap(),
                "172.16.0.0/12".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
                "::1/128".parse().unwrap(),
                "fc00::/7".parse().unwrap(),
            ],
            allow_query: Vec::new(), // Empty = allow all
            deny_query: Vec::new(),
            allow_transfer: vec!["127.0.0.1/32".parse().unwrap(), "::1/128".parse().unwrap()],
            allow_update: Vec::new(),
        }
    }
}

/// ACL action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    Allow,
    Deny,
}

/// DNS Cookie configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CookieConfig {
    /// Enable DNS cookies.
    pub enabled: bool,

    /// Server secret (hex encoded).
    pub secret: Option<String>,

    /// Require cookies from known sources.
    pub require: bool,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            secret: None, // Auto-generate
            require: false,
        }
    }
}

/// Query limits configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    /// Maximum UDP response size.
    pub max_udp_size: u16,

    /// Maximum TCP message size.
    pub max_tcp_size: u32,

    /// Maximum concurrent TCP connections.
    pub max_tcp_connections: usize,

    /// Maximum concurrent TCP connections per client.
    pub max_tcp_per_client: usize,

    /// Maximum queries per TCP connection.
    pub max_queries_per_tcp: usize,

    /// Maximum outstanding queries per client.
    pub max_outstanding_per_client: usize,

    /// TCP idle timeout (seconds).
    pub tcp_idle_timeout: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_udp_size: 4096,
            max_tcp_size: 65535,
            max_tcp_connections: 10000,
            max_tcp_per_client: 100,
            max_queries_per_tcp: 100,
            max_outstanding_per_client: 100,
            tcp_idle_timeout: 10,
        }
    }
}

impl LimitsConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_udp_size < 512 {
            return Err(ConfigError::InvalidValue {
                field: "security.limits.max_udp_size".to_string(),
                message: "must be at least 512".to_string(),
            });
        }

        Ok(())
    }
}
