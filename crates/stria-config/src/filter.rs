//! Filtering configuration.

use super::{ConfigError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use url::Url;

/// Filtering configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterConfig {
    /// Enable filtering.
    pub enabled: bool,

    /// Blocklists.
    pub blocklists: Vec<BlocklistEntry>,

    /// Local rules.
    pub rules: Vec<String>,

    /// Exceptions (allowlist).
    pub exceptions: Vec<String>,

    /// Exclusions (additional blocks).
    pub exclusions: Vec<String>,

    /// Custom block rules (domains to always block).
    pub custom_block: Vec<String>,

    /// Custom allow rules (domains to never block).
    pub custom_allow: Vec<String>,

    /// Blocked response type.
    pub blocked_response: BlockedResponse,

    /// Custom blocked IP (for IP response type).
    pub blocked_ip: Option<String>,

    /// CNAME cloaking protection.
    pub cname_protection: bool,

    /// Safe search enforcement.
    pub safe_search: SafeSearchConfig,

    /// Parental controls.
    pub parental: ParentalConfig,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            blocklists: Vec::new(),
            rules: Vec::new(),
            exceptions: Vec::new(),
            exclusions: Vec::new(),
            custom_block: Vec::new(),
            custom_allow: Vec::new(),
            blocked_response: BlockedResponse::NxDomain,
            blocked_ip: None,
            cname_protection: true,
            safe_search: SafeSearchConfig::default(),
            parental: ParentalConfig::default(),
        }
    }
}

impl FilterConfig {
    pub fn validate(&self) -> Result<()> {
        for blocklist in &self.blocklists {
            blocklist.validate()?;
        }

        if self.blocked_response == BlockedResponse::Ip && self.blocked_ip.is_none() {
            return Err(ConfigError::Validation(
                "blocked_ip required when blocked_response is 'ip'".to_string(),
            ));
        }

        Ok(())
    }
}

/// Blocklist entry (simplified configuration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistEntry {
    /// Blocklist name.
    pub name: String,

    /// Source URL or file path.
    pub url: String,

    /// Format of the blocklist.
    #[serde(default)]
    pub format: Option<String>,

    /// Enable this blocklist.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl BlocklistEntry {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(ConfigError::Validation(
                "Blocklist name cannot be empty".to_string(),
            ));
        }
        if self.url.is_empty() {
            return Err(ConfigError::Validation(
                "Blocklist URL cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// Blocklist source configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistSource {
    /// Source name.
    pub name: String,

    /// Source URL or file path.
    pub source: BlocklistSourceType,

    /// Format of the blocklist.
    pub format: BlocklistFormat,

    /// Update interval (seconds).
    pub update_interval: u64,

    /// Enable this blocklist.
    pub enabled: bool,
}

impl BlocklistSource {
    pub fn validate(&self) -> Result<()> {
        match &self.source {
            BlocklistSourceType::File(path) => {
                if !path.exists() {
                    return Err(ConfigError::NotFound(path.clone()));
                }
            }
            BlocklistSourceType::Url(url) => {
                if url.parse::<Url>().is_err() {
                    return Err(ConfigError::InvalidValue {
                        field: "filter.blocklists.source".to_string(),
                        message: format!("Invalid URL: {}", url),
                    });
                }
            }
        }
        Ok(())
    }

    pub fn update_duration(&self) -> Duration {
        Duration::from_secs(self.update_interval)
    }
}

/// Blocklist source type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistSourceType {
    /// Local file.
    File(PathBuf),

    /// Remote URL.
    Url(String),
}

/// Blocklist format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistFormat {
    /// Hosts file format.
    Hosts,

    /// Domain list (one per line).
    Domains,

    /// AdGuard/ABP filter format.
    Adblock,

    /// Dnsmasq format.
    Dnsmasq,

    /// RPZ format.
    Rpz,
}

impl Default for BlocklistFormat {
    fn default() -> Self {
        Self::Domains
    }
}

/// Response type for blocked queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockedResponse {
    /// Return NXDOMAIN.
    NxDomain,

    /// Return NODATA (empty response).
    NoData,

    /// Return REFUSED.
    Refused,

    /// Return custom IP address.
    Ip,

    /// Return null address (0.0.0.0 / ::).
    Null,
}

impl Default for BlockedResponse {
    fn default() -> Self {
        Self::NxDomain
    }
}

/// Safe search configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SafeSearchConfig {
    /// Enable safe search enforcement.
    pub enabled: bool,

    /// Google safe search.
    pub google: bool,

    /// Bing safe search.
    pub bing: bool,

    /// DuckDuckGo safe search.
    pub duckduckgo: bool,

    /// YouTube restricted mode.
    pub youtube: bool,

    /// Pixabay safe search.
    pub pixabay: bool,
}

impl Default for SafeSearchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            google: true,
            bing: true,
            duckduckgo: true,
            youtube: true,
            pixabay: true,
        }
    }
}

/// Parental control configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ParentalConfig {
    /// Enable parental controls.
    pub enabled: bool,

    /// Sensitivity level (0-4).
    pub level: u8,
}

impl Default for ParentalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            level: 2,
        }
    }
}
