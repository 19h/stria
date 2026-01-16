//! # Stria DNS Filtering Engine
//!
//! High-performance DNS filtering engine with blocklist support, pattern matching,
//! and CNAME cloaking protection for the Stria DNS server.
//!
//! ## Features
//!
//! - **Multiple blocklist formats**: Hosts, Domains, AdBlock Plus, dnsmasq, RPZ
//! - **Efficient pattern matching**: O(1) exact match, Aho-Corasick for substrings
//! - **Suffix trie**: Fast domain suffix matching for wildcard rules
//! - **Regex support**: Full regex pattern matching when needed
//! - **Hot-reload**: Update blocklists without server restart
//! - **Thread-safe**: Designed for high-concurrency DNS serving
//!
//! ## Example
//!
//! ```rust,ignore
//! use stria_filter::{FilterEngine, BlocklistFormat, Rule, RuleType, FilterAction};
//! use stria_proto::Name;
//! use std::str::FromStr;
//!
//! // Create a filter engine
//! let mut engine = FilterEngine::new();
//!
//! // Add a rule
//! let rule = Rule::new("ads.example.com", RuleType::Exact, FilterAction::Block);
//! engine.add_rule(rule);
//!
//! // Check a domain
//! let name = Name::from_str("ads.example.com").unwrap();
//! let result = engine.check(&name);
//! assert!(result.is_blocked());
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::HashSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{self, BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use compact_str::CompactString;
use dashmap::DashMap;
use futures::future::BoxFuture;
use hashbrown::HashMap;
use memchr::memchr;
use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};

use stria_proto::Name;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during filtering operations.
#[derive(Error, Debug)]
pub enum FilterError {
    /// IO error while reading blocklist.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Failed to parse a rule.
    #[error("Failed to parse rule at line {line}: {message}")]
    ParseError {
        /// Line number where the error occurred.
        line: usize,
        /// Error message.
        message: String,
    },

    /// Invalid blocklist format.
    #[error("Invalid blocklist format: {0}")]
    InvalidFormat(String),

    /// Invalid regex pattern.
    #[error("Invalid regex pattern '{pattern}': {source}")]
    InvalidRegex {
        /// The invalid pattern.
        pattern: String,
        /// The underlying regex error.
        #[source]
        source: regex::Error,
    },

    /// HTTP error while fetching blocklist.
    #[cfg(feature = "http")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// HTTP error when http feature is disabled.
    #[cfg(not(feature = "http"))]
    #[error("HTTP support not enabled - compile with 'http' feature")]
    HttpNotEnabled,

    /// Invalid URL.
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Blocklist not found.
    #[error("Blocklist not found: {0}")]
    NotFound(String),

    /// Failed to build Aho-Corasick automaton.
    #[error("Failed to build pattern matcher: {0}")]
    PatternBuildError(String),

    /// Invalid domain name.
    #[error("Invalid domain name: {0}")]
    InvalidDomain(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Reload error.
    #[error("Reload error: {0}")]
    Reload(String),
}

/// Result type for filter operations.
pub type Result<T> = std::result::Result<T, FilterError>;

// ============================================================================
// Filter Action
// ============================================================================

/// Action to take when a domain matches a filter rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    /// Allow the query (whitelist).
    Allow,

    /// Block the query.
    Block,

    /// Redirect to a specific IP address.
    Redirect(IpAddr),

    /// Rewrite to a CNAME.
    Cname(CompactString),
}

impl FilterAction {
    /// Returns true if this action blocks the query.
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Block | Self::Redirect(_))
    }

    /// Returns true if this action allows the query.
    pub fn is_allowing(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

impl Default for FilterAction {
    fn default() -> Self {
        Self::Block
    }
}

impl fmt::Display for FilterAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Block => write!(f, "block"),
            Self::Redirect(ip) => write!(f, "redirect:{ip}"),
            Self::Cname(name) => write!(f, "cname:{name}"),
        }
    }
}

// ============================================================================
// Rule Type
// ============================================================================

/// Type of pattern matching for a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleType {
    /// Exact match (e.g., "ads.example.com").
    Exact,

    /// Suffix match (e.g., ".example.com" matches "sub.example.com").
    Suffix,

    /// Prefix match (e.g., "ads." matches "ads.anything.com").
    Prefix,

    /// Substring match (e.g., "tracking" matches "any-tracking-domain.com").
    Substring,

    /// Regular expression match.
    Regex,

    /// Wildcard match (e.g., "*.example.com").
    Wildcard,
}

impl RuleType {
    /// Returns true if this rule type requires compilation.
    pub fn requires_compilation(&self) -> bool {
        matches!(self, Self::Regex)
    }
}

impl Default for RuleType {
    fn default() -> Self {
        Self::Exact
    }
}

impl fmt::Display for RuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact => write!(f, "exact"),
            Self::Suffix => write!(f, "suffix"),
            Self::Prefix => write!(f, "prefix"),
            Self::Substring => write!(f, "substring"),
            Self::Regex => write!(f, "regex"),
            Self::Wildcard => write!(f, "wildcard"),
        }
    }
}

// ============================================================================
// Blocklist Format
// ============================================================================

/// Format of a blocklist file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistFormat {
    /// Hosts file format (e.g., "0.0.0.0 ads.example.com").
    Hosts,

    /// Domain list format (one domain per line).
    Domains,

    /// AdBlock Plus / AdGuard filter format.
    AdblockPlus,

    /// dnsmasq domains format (e.g., "address=/example.com/").
    DnsmasqDomains,

    /// Response Policy Zone format.
    Rpz,
}

impl BlocklistFormat {
    /// Parses a line according to this format and returns the domain if valid.
    pub fn parse_line(&self, line: &str) -> Option<ParsedRule> {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() {
            return None;
        }

        match self {
            Self::Hosts => Self::parse_hosts_line(line),
            Self::Domains => Self::parse_domains_line(line),
            Self::AdblockPlus => Self::parse_adblock_line(line),
            Self::DnsmasqDomains => Self::parse_dnsmasq_line(line),
            Self::Rpz => Self::parse_rpz_line(line),
        }
    }

    /// Parses a hosts file line.
    fn parse_hosts_line(line: &str) -> Option<ParsedRule> {
        // Skip comments
        if line.starts_with('#') {
            return None;
        }

        // Format: IP DOMAIN [DOMAIN...]
        // We only care about the domain(s)
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        // First part should be an IP (0.0.0.0, 127.0.0.1, ::, etc.)
        let ip = parts[0];
        if !ip.starts_with("0.0.0.0")
            && !ip.starts_with("127.0.0.1")
            && !ip.starts_with("::")
            && !ip.starts_with("0:0:0:0:0:0:0:0")
        {
            return None;
        }

        // Second part is the domain
        let domain = parts[1];

        // Skip localhost entries
        if domain == "localhost"
            || domain == "localhost.localdomain"
            || domain == "local"
            || domain.is_empty()
        {
            return None;
        }

        // Strip inline comment
        let domain = domain.split('#').next().unwrap_or(domain).trim();

        if domain.is_empty() {
            return None;
        }

        Some(ParsedRule {
            pattern: normalize_domain(domain),
            rule_type: RuleType::Exact,
            action: FilterAction::Block,
            is_exception: false,
        })
    }

    /// Parses a domains list line.
    fn parse_domains_line(line: &str) -> Option<ParsedRule> {
        // Skip comments
        if line.starts_with('#') || line.starts_with('!') || line.starts_with(';') {
            return None;
        }

        // Strip inline comments
        let domain = line.split('#').next().unwrap_or(line);
        let domain = domain.split('!').next().unwrap_or(domain).trim();

        if domain.is_empty() {
            return None;
        }

        // Check for exception marker
        let (domain, is_exception) = if let Some(d) = domain.strip_prefix("@@") {
            (d.trim(), true)
        } else {
            (domain, false)
        };

        // Handle wildcard prefix
        let (pattern, rule_type) = if let Some(suffix) = domain.strip_prefix("*.") {
            (normalize_domain(suffix), RuleType::Suffix)
        } else if domain.starts_with('.') {
            (normalize_domain(&domain[1..]), RuleType::Suffix)
        } else {
            (normalize_domain(domain), RuleType::Exact)
        };

        Some(ParsedRule {
            pattern,
            rule_type,
            action: if is_exception {
                FilterAction::Allow
            } else {
                FilterAction::Block
            },
            is_exception,
        })
    }

    /// Parses an AdBlock Plus / AdGuard line.
    fn parse_adblock_line(line: &str) -> Option<ParsedRule> {
        // Skip comments
        if line.starts_with('!') || line.starts_with('[') {
            return None;
        }

        // Check for exception
        let (line, is_exception) = if let Some(l) = line.strip_prefix("@@") {
            (l, true)
        } else {
            (line, false)
        };

        // Basic domain rules: ||domain.com^
        if let Some(rest) = line.strip_prefix("||") {
            // Find the end of the domain (^ or $ or end of line)
            let end = rest
                .find(|c| c == '^' || c == '$' || c == '/')
                .unwrap_or(rest.len());
            let domain = &rest[..end];

            // Skip rules with complex modifiers
            if rest.contains('$') && rest.contains("domain=") {
                return None;
            }

            // Skip if it's a regex
            if domain.contains('*') && domain.contains('.') {
                // Simple wildcard at start: *.domain.com
                if let Some(suffix) = domain.strip_prefix("*.") {
                    return Some(ParsedRule {
                        pattern: normalize_domain(suffix),
                        rule_type: RuleType::Suffix,
                        action: if is_exception {
                            FilterAction::Allow
                        } else {
                            FilterAction::Block
                        },
                        is_exception,
                    });
                }
                return None;
            }

            if domain.is_empty() || domain.contains('/') {
                return None;
            }

            return Some(ParsedRule {
                pattern: normalize_domain(domain),
                rule_type: RuleType::Exact,
                action: if is_exception {
                    FilterAction::Allow
                } else {
                    FilterAction::Block
                },
                is_exception,
            });
        }

        // Exact domain match: |domain.com|
        if line.starts_with('|') && line.ends_with('|') && line.len() > 2 {
            let domain = &line[1..line.len() - 1];
            if !domain.contains('/') && !domain.contains('*') {
                return Some(ParsedRule {
                    pattern: normalize_domain(domain),
                    rule_type: RuleType::Exact,
                    action: if is_exception {
                        FilterAction::Allow
                    } else {
                        FilterAction::Block
                    },
                    is_exception,
                });
            }
        }

        None
    }

    /// Parses a dnsmasq domains line.
    fn parse_dnsmasq_line(line: &str) -> Option<ParsedRule> {
        // Skip comments
        if line.starts_with('#') {
            return None;
        }

        // Format: address=/domain.com/ or address=/domain.com/0.0.0.0
        // Also: server=/domain.com/
        if let Some(rest) = line
            .strip_prefix("address=/")
            .or_else(|| line.strip_prefix("server=/"))
        {
            // Find the domain between the slashes
            let end = rest.find('/').unwrap_or(rest.len());
            let domain = &rest[..end];

            if domain.is_empty() {
                return None;
            }

            // Leading dot means suffix match
            let (pattern, rule_type) = if domain.starts_with('.') {
                (normalize_domain(&domain[1..]), RuleType::Suffix)
            } else {
                (normalize_domain(domain), RuleType::Exact)
            };

            return Some(ParsedRule {
                pattern,
                rule_type,
                action: FilterAction::Block,
                is_exception: false,
            });
        }

        None
    }

    /// Parses an RPZ (Response Policy Zone) line.
    fn parse_rpz_line(line: &str) -> Option<ParsedRule> {
        // Skip comments and special records
        if line.starts_with(';') || line.starts_with('$') {
            return None;
        }

        // RPZ format: owner-name TTL CLASS CNAME rpz-action
        // Example: bad.example.com CNAME .
        //          *.bad.example.com CNAME rpz-passthru.
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        let owner = parts[0];

        // Skip SOA, NS records
        if parts.iter().any(|&p| p == "SOA" || p == "NS") {
            return None;
        }

        // Determine action from CNAME target
        let action = if let Some(pos) = parts.iter().position(|&p| p == "CNAME") {
            if pos + 1 < parts.len() {
                let target = parts[pos + 1];
                if target == "." || target == "rpz-drop." || target == "rpz-nxdomain." {
                    FilterAction::Block
                } else if target == "rpz-passthru." {
                    FilterAction::Allow
                } else if let Some(name) = target.strip_prefix("rpz-local-data.") {
                    // CNAME rewrite
                    FilterAction::Cname(CompactString::from(name))
                } else {
                    FilterAction::Block
                }
            } else {
                FilterAction::Block
            }
        } else {
            // No CNAME, check for A/AAAA records (rewrite rules)
            if parts.iter().any(|&p| p == "A" || p == "AAAA") {
                if let Some(pos) = parts.iter().position(|&p| p == "A" || p == "AAAA") {
                    if pos + 1 < parts.len() {
                        if let Ok(ip) = parts[pos + 1].parse::<IpAddr>() {
                            FilterAction::Redirect(ip)
                        } else {
                            FilterAction::Block
                        }
                    } else {
                        FilterAction::Block
                    }
                } else {
                    FilterAction::Block
                }
            } else {
                return None;
            }
        };

        // Parse owner name
        let (pattern, rule_type) = if let Some(suffix) = owner.strip_prefix("*.") {
            (normalize_domain(suffix), RuleType::Suffix)
        } else {
            (normalize_domain(owner), RuleType::Exact)
        };

        Some(ParsedRule {
            pattern,
            rule_type,
            action: action.clone(),
            is_exception: action == FilterAction::Allow,
        })
    }
}

impl Default for BlocklistFormat {
    fn default() -> Self {
        Self::Domains
    }
}

impl fmt::Display for BlocklistFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hosts => write!(f, "hosts"),
            Self::Domains => write!(f, "domains"),
            Self::AdblockPlus => write!(f, "adblock"),
            Self::DnsmasqDomains => write!(f, "dnsmasq"),
            Self::Rpz => write!(f, "rpz"),
        }
    }
}

/// Result of parsing a single line from a blocklist.
#[derive(Debug, Clone)]
pub struct ParsedRule {
    /// The pattern (domain).
    pub pattern: CompactString,
    /// Type of match.
    pub rule_type: RuleType,
    /// Action to take.
    pub action: FilterAction,
    /// Whether this is an exception (whitelist) rule.
    pub is_exception: bool,
}

// ============================================================================
// Rule
// ============================================================================

/// A filter rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// The pattern to match.
    pub pattern: CompactString,

    /// Type of pattern matching.
    pub rule_type: RuleType,

    /// Action to take when matched.
    pub action: FilterAction,

    /// Rule priority (higher = more important).
    pub priority: i32,

    /// Whether the rule is enabled.
    pub enabled: bool,

    /// Optional comment or description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<CompactString>,

    /// Source blocklist name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CompactString>,
}

impl Rule {
    /// Creates a new rule with default settings.
    pub fn new(pattern: impl Into<CompactString>, rule_type: RuleType, action: FilterAction) -> Self {
        Self {
            pattern: pattern.into(),
            rule_type,
            action,
            priority: 0,
            enabled: true,
            comment: None,
            source: None,
        }
    }

    /// Creates a new blocking rule.
    pub fn block(pattern: impl Into<CompactString>, rule_type: RuleType) -> Self {
        Self::new(pattern, rule_type, FilterAction::Block)
    }

    /// Creates a new allowing rule.
    pub fn allow(pattern: impl Into<CompactString>, rule_type: RuleType) -> Self {
        Self::new(pattern, rule_type, FilterAction::Allow)
    }

    /// Sets the rule priority.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Sets the rule source.
    pub fn with_source(mut self, source: impl Into<CompactString>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Sets the rule comment.
    pub fn with_comment(mut self, comment: impl Into<CompactString>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Enables or disables the rule.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Returns the normalized pattern for matching.
    pub fn normalized_pattern(&self) -> CompactString {
        normalize_domain(&self.pattern)
    }

    /// Returns true if this is an exception (allow) rule.
    pub fn is_exception(&self) -> bool {
        matches!(self.action, FilterAction::Allow)
    }
}

impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern && self.rule_type == other.rule_type
    }
}

impl Eq for Rule {}

impl Hash for Rule {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pattern.hash(state);
        self.rule_type.hash(state);
    }
}

// ============================================================================
// Blocklist
// ============================================================================

/// A blocklist containing filter rules.
#[derive(Debug, Clone)]
pub struct Blocklist {
    /// Blocklist name.
    pub name: CompactString,

    /// Source URL or file path.
    pub source: BlocklistSource,

    /// Blocklist format.
    pub format: BlocklistFormat,

    /// Update interval.
    pub update_interval: Duration,

    /// Rules in this blocklist.
    rules: Vec<Rule>,

    /// Last update timestamp.
    pub last_updated: Option<DateTime<Utc>>,

    /// Number of rules loaded.
    pub rule_count: usize,

    /// Whether the blocklist is enabled.
    pub enabled: bool,
}

/// Source of a blocklist.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlocklistSource {
    /// Local file path.
    File(PathBuf),

    /// Remote URL.
    Url(String),
}

impl BlocklistSource {
    /// Returns true if this is a file source.
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }

    /// Returns true if this is a URL source.
    pub fn is_url(&self) -> bool {
        matches!(self, Self::Url(_))
    }

    /// Returns the path if this is a file source.
    pub fn as_path(&self) -> Option<&Path> {
        match self {
            Self::File(p) => Some(p),
            Self::Url(_) => None,
        }
    }

    /// Returns the URL if this is a URL source.
    pub fn as_url(&self) -> Option<&str> {
        match self {
            Self::File(_) => None,
            Self::Url(u) => Some(u),
        }
    }
}

impl fmt::Display for BlocklistSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(p) => write!(f, "{}", p.display()),
            Self::Url(u) => write!(f, "{u}"),
        }
    }
}

impl Blocklist {
    /// Creates a new blocklist.
    pub fn new(
        name: impl Into<CompactString>,
        source: BlocklistSource,
        format: BlocklistFormat,
    ) -> Self {
        Self {
            name: name.into(),
            source,
            format,
            update_interval: Duration::from_secs(86400), // 24 hours default
            rules: Vec::new(),
            last_updated: None,
            rule_count: 0,
            enabled: true,
        }
    }

    /// Creates a blocklist from a local file.
    pub fn from_file(
        name: impl Into<CompactString>,
        path: impl Into<PathBuf>,
        format: BlocklistFormat,
    ) -> Self {
        Self::new(name, BlocklistSource::File(path.into()), format)
    }

    /// Creates a blocklist from a URL.
    pub fn from_url(
        name: impl Into<CompactString>,
        url: impl Into<String>,
        format: BlocklistFormat,
    ) -> Self {
        Self::new(name, BlocklistSource::Url(url.into()), format)
    }

    /// Sets the update interval.
    pub fn with_update_interval(mut self, interval: Duration) -> Self {
        self.update_interval = interval;
        self
    }

    /// Enables or disables the blocklist.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Returns the rules in this blocklist.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Returns a mutable reference to the rules.
    pub fn rules_mut(&mut self) -> &mut Vec<Rule> {
        &mut self.rules
    }

    /// Adds a rule to this blocklist.
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
        self.rule_count = self.rules.len();
    }

    /// Checks if the blocklist needs updating.
    pub fn needs_update(&self) -> bool {
        match self.last_updated {
            None => true,
            Some(last) => {
                let elapsed = Utc::now().signed_duration_since(last);
                elapsed.num_seconds() as u64 > self.update_interval.as_secs()
            }
        }
    }

    /// Parses rules from content.
    pub fn parse_content(&mut self, content: &str) -> Result<usize> {
        self.rules.clear();
        let mut count = 0;

        for (line_num, line) in content.lines().enumerate() {
            if let Some(parsed) = self.format.parse_line(line) {
                let mut rule = Rule::new(parsed.pattern, parsed.rule_type, parsed.action);
                rule.source = Some(self.name.clone());

                self.rules.push(rule);
                count += 1;
            } else {
                trace!(line = line_num + 1, "Skipped line: {}", line);
            }
        }

        self.rule_count = count;
        self.last_updated = Some(Utc::now());

        info!(
            blocklist = %self.name,
            rules = count,
            "Parsed blocklist"
        );

        Ok(count)
    }
}

// ============================================================================
// Suffix Trie
// ============================================================================

/// A trie optimized for domain suffix matching.
///
/// Domains are stored in reverse order (e.g., "com.example.www") for efficient
/// suffix matching. This allows O(k) lookup where k is the number of labels.
#[derive(Debug, Clone, Default)]
struct SuffixTrie {
    root: TrieNode,
    size: usize,
}

#[derive(Debug, Clone, Default)]
struct TrieNode {
    children: HashMap<CompactString, TrieNode>,
    rule_idx: Option<usize>,
    is_terminal: bool,
}

impl SuffixTrie {
    /// Creates a new empty suffix trie.
    fn new() -> Self {
        Self {
            root: TrieNode::default(),
            size: 0,
        }
    }

    /// Inserts a domain suffix into the trie.
    fn insert(&mut self, domain: &str, rule_idx: usize) {
        let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();

        let mut node = &mut self.root;
        // Insert in reverse order for suffix matching
        for label in labels.iter().rev() {
            let label = CompactString::from(label.to_ascii_lowercase());
            node = node.children.entry(label).or_default();
        }

        node.is_terminal = true;
        node.rule_idx = Some(rule_idx);
        self.size += 1;
    }

    /// Looks up a domain and returns the matching rule index if found.
    ///
    /// This performs suffix matching: if "example.com" is in the trie,
    /// then "sub.example.com" will also match.
    fn lookup(&self, domain: &str) -> Option<usize> {
        let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();

        let mut node = &self.root;
        let mut best_match: Option<usize> = None;

        // Traverse in reverse order
        for label in labels.iter().rev() {
            let label_lower = label.to_ascii_lowercase();

            if let Some(child) = node.children.get(label_lower.as_str()) {
                if child.is_terminal {
                    best_match = child.rule_idx;
                }
                node = child;
            } else {
                break;
            }
        }

        best_match
    }

    /// Returns the number of entries in the trie.
    fn len(&self) -> usize {
        self.size
    }

    /// Returns true if the trie is empty.
    fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Clears the trie.
    fn clear(&mut self) {
        self.root = TrieNode::default();
        self.size = 0;
    }
}

// ============================================================================
// Compiled Patterns
// ============================================================================

/// Compiled pattern matchers for efficient matching.
#[derive(Default)]
struct CompiledPatterns {
    /// Aho-Corasick automaton for substring matching.
    substring_matcher: Option<AhoCorasick>,

    /// Substring patterns with their rule indices.
    substring_patterns: Vec<(CompactString, usize)>,

    /// Compiled regex patterns with their rule indices.
    regex_patterns: Vec<(Regex, usize)>,

    /// Prefix patterns with their rule indices (sorted by length desc).
    prefix_patterns: Vec<(CompactString, usize)>,
}

impl CompiledPatterns {
    fn new() -> Self {
        Self::default()
    }

    /// Builds the Aho-Corasick automaton from substring patterns.
    fn build_automaton(&mut self) -> Result<()> {
        if self.substring_patterns.is_empty() {
            self.substring_matcher = None;
            return Ok(());
        }

        let patterns: Vec<&str> = self
            .substring_patterns
            .iter()
            .map(|(p, _)| p.as_str())
            .collect();

        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&patterns)
            .map_err(|e| FilterError::PatternBuildError(e.to_string()))?;

        self.substring_matcher = Some(ac);
        Ok(())
    }

    /// Adds a substring pattern.
    fn add_substring(&mut self, pattern: CompactString, rule_idx: usize) {
        self.substring_patterns.push((pattern, rule_idx));
    }

    /// Adds a regex pattern.
    fn add_regex(&mut self, pattern: &str, rule_idx: usize) -> Result<()> {
        let regex = Regex::new(pattern).map_err(|e| FilterError::InvalidRegex {
            pattern: pattern.to_string(),
            source: e,
        })?;
        self.regex_patterns.push((regex, rule_idx));
        Ok(())
    }

    /// Adds a prefix pattern.
    fn add_prefix(&mut self, pattern: CompactString, rule_idx: usize) {
        self.prefix_patterns.push((pattern, rule_idx));
        // Keep sorted by length (longest first) for correct matching
        self.prefix_patterns.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    }

    /// Finds a substring match.
    fn find_substring(&self, domain: &str) -> Option<usize> {
        if let Some(ref ac) = self.substring_matcher {
            if let Some(mat) = ac.find(domain) {
                return Some(self.substring_patterns[mat.pattern().as_usize()].1);
            }
        }
        None
    }

    /// Finds a regex match.
    fn find_regex(&self, domain: &str) -> Option<usize> {
        for (regex, idx) in &self.regex_patterns {
            if regex.is_match(domain) {
                return Some(*idx);
            }
        }
        None
    }

    /// Finds a prefix match.
    fn find_prefix(&self, domain: &str) -> Option<usize> {
        for (prefix, idx) in &self.prefix_patterns {
            if domain.starts_with(prefix.as_str()) {
                return Some(*idx);
            }
        }
        None
    }

    /// Clears all compiled patterns.
    fn clear(&mut self) {
        self.substring_matcher = None;
        self.substring_patterns.clear();
        self.regex_patterns.clear();
        self.prefix_patterns.clear();
    }
}

impl fmt::Debug for CompiledPatterns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledPatterns")
            .field("substring_count", &self.substring_patterns.len())
            .field("regex_count", &self.regex_patterns.len())
            .field("prefix_count", &self.prefix_patterns.len())
            .finish()
    }
}

// ============================================================================
// Filter Result
// ============================================================================

/// Result of checking a domain against the filter engine.
#[derive(Debug, Clone)]
pub struct FilterResult {
    /// The action to take.
    pub action: FilterAction,

    /// The matched rule, if any.
    pub matched_rule: Option<Arc<Rule>>,

    /// Name of the blocklist that matched.
    pub blocklist_name: Option<CompactString>,

    /// Time taken to perform the check.
    pub check_duration: Duration,

    /// Whether this was a cached result.
    pub cached: bool,
}

impl FilterResult {
    /// Creates a new filter result.
    fn new(action: FilterAction, duration: Duration) -> Self {
        Self {
            action,
            matched_rule: None,
            blocklist_name: None,
            check_duration: duration,
            cached: false,
        }
    }

    /// Creates an allow result.
    fn allow(duration: Duration) -> Self {
        Self::new(FilterAction::Allow, duration)
    }

    /// Creates a block result.
    fn block(duration: Duration) -> Self {
        Self::new(FilterAction::Block, duration)
    }

    /// Sets the matched rule.
    fn with_rule(mut self, rule: Arc<Rule>) -> Self {
        self.matched_rule = Some(rule);
        self
    }

    /// Sets the blocklist name.
    fn with_blocklist(mut self, name: CompactString) -> Self {
        self.blocklist_name = Some(name);
        self
    }

    /// Marks this result as cached.
    fn with_cached(mut self, cached: bool) -> Self {
        self.cached = cached;
        self
    }

    /// Returns true if the result indicates blocking.
    pub fn is_blocked(&self) -> bool {
        self.action.is_blocking()
    }

    /// Returns true if the result indicates allowing.
    pub fn is_allowed(&self) -> bool {
        self.action.is_allowing()
    }
}

impl Default for FilterResult {
    fn default() -> Self {
        Self::allow(Duration::ZERO)
    }
}

// ============================================================================
// Filter Engine Statistics
// ============================================================================

/// Statistics for the filter engine.
#[derive(Debug, Clone, Default)]
pub struct FilterStats {
    /// Total number of rules loaded.
    pub total_rules: usize,

    /// Number of exact match rules.
    pub exact_rules: usize,

    /// Number of suffix rules.
    pub suffix_rules: usize,

    /// Number of prefix rules.
    pub prefix_rules: usize,

    /// Number of substring rules.
    pub substring_rules: usize,

    /// Number of regex rules.
    pub regex_rules: usize,

    /// Number of wildcard rules.
    pub wildcard_rules: usize,

    /// Number of blocklists loaded.
    pub blocklist_count: usize,

    /// Total queries checked.
    pub queries_checked: u64,

    /// Total queries blocked.
    pub queries_blocked: u64,

    /// Total queries allowed (explicit whitelist).
    pub queries_allowed: u64,

    /// Cache hits.
    pub cache_hits: u64,

    /// Cache misses.
    pub cache_misses: u64,

    /// Average check duration in microseconds.
    pub avg_check_duration_us: u64,

    /// Last reload timestamp.
    pub last_reload: Option<DateTime<Utc>>,
}

impl FilterStats {
    /// Returns the cache hit rate as a percentage.
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            (self.cache_hits as f64 / total as f64) * 100.0
        }
    }

    /// Returns the block rate as a percentage.
    pub fn block_rate(&self) -> f64 {
        if self.queries_checked == 0 {
            0.0
        } else {
            (self.queries_blocked as f64 / self.queries_checked as f64) * 100.0
        }
    }
}

// ============================================================================
// Filter Engine
// ============================================================================

/// High-performance DNS filter engine.
///
/// The engine uses multiple data structures optimized for different match types:
/// - `DashMap` for O(1) exact match lookups
/// - Suffix trie for efficient domain suffix matching
/// - Aho-Corasick automaton for fast substring matching
/// - Compiled regex patterns for complex rules
///
/// The engine is thread-safe and designed for concurrent access from multiple
/// DNS handler threads.
pub struct FilterEngine {
    /// All rules (master list).
    rules: RwLock<Vec<Arc<Rule>>>,

    /// Exact match lookup table.
    exact_matches: DashMap<CompactString, usize>,

    /// Suffix trie for domain suffix matching.
    suffix_trie: RwLock<SuffixTrie>,

    /// Compiled patterns (substring, regex, prefix).
    compiled: RwLock<CompiledPatterns>,

    /// Exception (allow) rules - checked first for priority.
    exceptions: DashMap<CompactString, usize>,

    /// Exception suffix trie.
    exception_suffix_trie: RwLock<SuffixTrie>,

    /// Loaded blocklists.
    blocklists: RwLock<Vec<Blocklist>>,

    /// Result cache for frequently queried domains.
    cache: DashMap<CompactString, CachedResult>,

    /// Maximum cache size.
    cache_max_size: usize,

    /// Statistics counters.
    stats: FilterEngineStats,

    /// Configuration for the engine.
    config: ArcSwap<FilterEngineConfig>,
}

/// Internal statistics counters.
struct FilterEngineStats {
    queries_checked: AtomicU64,
    queries_blocked: AtomicU64,
    queries_allowed: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    total_check_duration_ns: AtomicU64,
}

impl Default for FilterEngineStats {
    fn default() -> Self {
        Self {
            queries_checked: AtomicU64::new(0),
            queries_blocked: AtomicU64::new(0),
            queries_allowed: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            total_check_duration_ns: AtomicU64::new(0),
        }
    }
}

/// Cached filter result.
#[derive(Debug, Clone)]
struct CachedResult {
    action: FilterAction,
    rule_idx: Option<usize>,
    blocklist_name: Option<CompactString>,
    created: Instant,
}

/// Configuration for the filter engine.
#[derive(Debug, Clone)]
pub struct FilterEngineConfig {
    /// Enable result caching.
    pub cache_enabled: bool,

    /// Maximum cache entries.
    pub cache_max_entries: usize,

    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,

    /// Enable CNAME cloaking protection.
    pub cname_protection: bool,
}

impl Default for FilterEngineConfig {
    fn default() -> Self {
        Self {
            cache_enabled: true,
            cache_max_entries: 100_000,
            cache_ttl_secs: 300, // 5 minutes
            cname_protection: true,
        }
    }
}

impl FilterEngine {
    /// Creates a new filter engine with default configuration.
    pub fn new() -> Self {
        Self::with_config(FilterEngineConfig::default())
    }

    /// Creates a new filter engine with the given configuration.
    pub fn with_config(config: FilterEngineConfig) -> Self {
        let cache_max = config.cache_max_entries;
        Self {
            rules: RwLock::new(Vec::new()),
            exact_matches: DashMap::new(),
            suffix_trie: RwLock::new(SuffixTrie::new()),
            compiled: RwLock::new(CompiledPatterns::new()),
            exceptions: DashMap::new(),
            exception_suffix_trie: RwLock::new(SuffixTrie::new()),
            blocklists: RwLock::new(Vec::new()),
            cache: DashMap::new(),
            cache_max_size: cache_max,
            stats: FilterEngineStats::default(),
            config: ArcSwap::new(Arc::new(config)),
        }
    }

    /// Adds a rule to the engine.
    #[instrument(skip(self), fields(pattern = %rule.pattern, rule_type = %rule.rule_type))]
    pub fn add_rule(&self, rule: Rule) -> Result<()> {
        if !rule.enabled {
            return Ok(());
        }

        let rule = Arc::new(rule);
        let pattern = rule.normalized_pattern();

        let mut rules = self.rules.write();
        let rule_idx = rules.len();
        rules.push(Arc::clone(&rule));
        drop(rules);

        // Add to appropriate data structure based on rule type and action
        if rule.is_exception() {
            self.add_exception_rule(&pattern, rule_idx, &rule)?;
        } else {
            self.add_blocking_rule(&pattern, rule_idx, &rule)?;
        }

        // Invalidate cache when rules change
        self.cache.clear();

        Ok(())
    }

    /// Adds an exception (allow) rule.
    fn add_exception_rule(&self, pattern: &str, rule_idx: usize, rule: &Rule) -> Result<()> {
        match rule.rule_type {
            RuleType::Exact => {
                self.exceptions.insert(CompactString::from(pattern), rule_idx);
            }
            RuleType::Suffix | RuleType::Wildcard => {
                let mut trie = self.exception_suffix_trie.write();
                trie.insert(pattern, rule_idx);
            }
            _ => {
                // For other types, we still add to exceptions map but they'll be
                // checked differently
                self.exceptions.insert(CompactString::from(pattern), rule_idx);
            }
        }
        Ok(())
    }

    /// Adds a blocking rule.
    fn add_blocking_rule(&self, pattern: &str, rule_idx: usize, rule: &Rule) -> Result<()> {
        match rule.rule_type {
            RuleType::Exact => {
                self.exact_matches.insert(CompactString::from(pattern), rule_idx);
            }
            RuleType::Suffix | RuleType::Wildcard => {
                let mut trie = self.suffix_trie.write();
                trie.insert(pattern, rule_idx);
            }
            RuleType::Prefix => {
                let mut compiled = self.compiled.write();
                compiled.add_prefix(CompactString::from(pattern), rule_idx);
            }
            RuleType::Substring => {
                let mut compiled = self.compiled.write();
                compiled.add_substring(CompactString::from(pattern), rule_idx);
            }
            RuleType::Regex => {
                let mut compiled = self.compiled.write();
                compiled.add_regex(pattern, rule_idx)?;
            }
        }
        Ok(())
    }

    /// Adds a blocklist to the engine.
    pub fn add_blocklist(&self, mut blocklist: Blocklist) -> Result<()> {
        // Mark the source for each rule
        let blocklist_name = blocklist.name.clone();

        for rule in blocklist.rules_mut() {
            rule.source = Some(blocklist_name.clone());
        }

        // Add all rules from the blocklist
        for rule in blocklist.rules().iter().cloned() {
            self.add_rule(rule)?;
        }

        // Store the blocklist
        let mut blocklists = self.blocklists.write();
        blocklists.push(blocklist);

        info!(
            name = %blocklist_name,
            "Added blocklist"
        );

        Ok(())
    }

    /// Removes a blocklist by name.
    pub fn remove_blocklist(&self, name: &str) -> Result<bool> {
        let mut blocklists = self.blocklists.write();
        let initial_len = blocklists.len();
        blocklists.retain(|b| b.name != name);

        if blocklists.len() < initial_len {
            // Need to rebuild the engine since we removed rules
            drop(blocklists);
            self.rebuild()?;

            info!(name = name, "Removed blocklist");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Rebuilds the entire filter engine from loaded blocklists.
    pub fn rebuild(&self) -> Result<()> {
        // Clear all data structures
        self.rules.write().clear();
        self.exact_matches.clear();
        self.suffix_trie.write().clear();
        self.compiled.write().clear();
        self.exceptions.clear();
        self.exception_suffix_trie.write().clear();
        self.cache.clear();

        // Re-add all rules from blocklists
        let blocklists = self.blocklists.read();
        for blocklist in blocklists.iter() {
            if !blocklist.enabled {
                continue;
            }

            for rule in blocklist.rules() {
                if let Err(e) = self.add_rule(rule.clone()) {
                    warn!(
                        blocklist = %blocklist.name,
                        pattern = %rule.pattern,
                        error = %e,
                        "Failed to add rule"
                    );
                }
            }
        }
        drop(blocklists);

        // Rebuild the Aho-Corasick automaton
        self.compiled.write().build_automaton()?;

        info!("Rebuilt filter engine");
        Ok(())
    }

    /// Reloads all blocklists from their sources.
    pub async fn reload(&self) -> Result<()> {
        let blocklists = self.blocklists.read().clone();
        drop(self.blocklists.read());

        let mut new_blocklists = Vec::with_capacity(blocklists.len());

        for mut blocklist in blocklists {
            if !blocklist.enabled {
                new_blocklists.push(blocklist);
                continue;
            }

            match &blocklist.source {
                BlocklistSource::File(path) => {
                    let loader = FileLoader;
                    match loader.load(path).await {
                        Ok(content) => {
                            if let Err(e) = blocklist.parse_content(&content) {
                                error!(
                                    blocklist = %blocklist.name,
                                    error = %e,
                                    "Failed to parse blocklist"
                                );
                            }
                        }
                        Err(e) => {
                            error!(
                                blocklist = %blocklist.name,
                                path = %path.display(),
                                error = %e,
                                "Failed to load blocklist file"
                            );
                        }
                    }
                }
                #[cfg(feature = "http")]
                BlocklistSource::Url(url) => {
                    let loader = HttpLoader::new();
                    match loader.load(url).await {
                        Ok(content) => {
                            if let Err(e) = blocklist.parse_content(&content) {
                                error!(
                                    blocklist = %blocklist.name,
                                    error = %e,
                                    "Failed to parse blocklist"
                                );
                            }
                        }
                        Err(e) => {
                            error!(
                                blocklist = %blocklist.name,
                                url = %url,
                                error = %e,
                                "Failed to load blocklist from URL"
                            );
                        }
                    }
                }
                #[cfg(not(feature = "http"))]
                BlocklistSource::Url(url) => {
                    warn!(
                        blocklist = %blocklist.name,
                        url = %url,
                        "HTTP support not enabled, skipping URL blocklist"
                    );
                }
            }

            new_blocklists.push(blocklist);
        }

        // Replace blocklists and rebuild
        *self.blocklists.write() = new_blocklists;
        self.rebuild()?;

        Ok(())
    }

    /// Checks a domain name against the filter rules.
    #[instrument(skip(self), level = "trace")]
    pub fn check(&self, name: &Name) -> FilterResult {
        let start = Instant::now();
        let domain = name.to_string();
        let normalized = normalize_domain(&domain);

        // Update stats
        self.stats.queries_checked.fetch_add(1, Ordering::Relaxed);

        // Check cache first
        let config = self.config.load();
        if config.cache_enabled {
            if let Some(cached) = self.cache.get(&normalized) {
                if cached.created.elapsed().as_secs() < config.cache_ttl_secs {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);

                    let duration = start.elapsed();
                    let mut result = FilterResult::new(cached.action.clone(), duration);
                    result.blocklist_name = cached.blocklist_name.clone();
                    result.cached = true;

                    if let Some(idx) = cached.rule_idx {
                        if let Some(rule) = self.rules.read().get(idx) {
                            result.matched_rule = Some(Arc::clone(rule));
                        }
                    }

                    return result;
                }
            }
            self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        }

        // Check exceptions first (highest priority)
        if let Some(result) = self.check_exceptions(&normalized, start) {
            self.cache_result(&normalized, &result);
            self.stats.queries_allowed.fetch_add(1, Ordering::Relaxed);
            return result;
        }

        // Check exact matches (O(1))
        if let Some(idx_ref) = self.exact_matches.get(&normalized) {
            let idx = *idx_ref;
            let duration = start.elapsed();
            let result = self.make_result(idx, duration);
            self.cache_result(&normalized, &result);
            self.stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
            return result;
        }

        // Check suffix trie
        {
            let trie = self.suffix_trie.read();
            if let Some(idx) = trie.lookup(&normalized) {
                let duration = start.elapsed();
                let result = self.make_result(idx, duration);
                self.cache_result(&normalized, &result);
                self.stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
                return result;
            }
        }

        // Check compiled patterns (substring, prefix, regex)
        {
            let compiled = self.compiled.read();

            // Substring (Aho-Corasick)
            if let Some(idx) = compiled.find_substring(&normalized) {
                let duration = start.elapsed();
                let result = self.make_result(idx, duration);
                drop(compiled);
                self.cache_result(&normalized, &result);
                self.stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
                return result;
            }

            // Prefix
            if let Some(idx) = compiled.find_prefix(&normalized) {
                let duration = start.elapsed();
                let result = self.make_result(idx, duration);
                drop(compiled);
                self.cache_result(&normalized, &result);
                self.stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
                return result;
            }

            // Regex (slowest, check last)
            if let Some(idx) = compiled.find_regex(&normalized) {
                let duration = start.elapsed();
                let result = self.make_result(idx, duration);
                drop(compiled);
                self.cache_result(&normalized, &result);
                self.stats.queries_blocked.fetch_add(1, Ordering::Relaxed);
                return result;
            }
        }

        // No match - allow
        let duration = start.elapsed();
        self.stats
            .total_check_duration_ns
            .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);

        let result = FilterResult::allow(duration);
        self.cache_result(&normalized, &result);
        result
    }

    /// Checks exceptions (whitelist rules).
    fn check_exceptions(&self, normalized: &str, start: Instant) -> Option<FilterResult> {
        // Check exact exceptions
        if let Some(idx_ref) = self.exceptions.get(normalized) {
            let idx = *idx_ref;
            let duration = start.elapsed();
            return Some(self.make_result(idx, duration));
        }

        // Check suffix exceptions
        let trie = self.exception_suffix_trie.read();
        if let Some(idx) = trie.lookup(normalized) {
            let duration = start.elapsed();
            return Some(self.make_result(idx, duration));
        }

        None
    }

    /// Creates a filter result from a rule index.
    fn make_result(&self, rule_idx: usize, duration: Duration) -> FilterResult {
        let rules = self.rules.read();
        if let Some(rule) = rules.get(rule_idx) {
            let mut result = FilterResult::new(rule.action.clone(), duration);
            result.matched_rule = Some(Arc::clone(rule));
            result.blocklist_name = rule.source.clone();
            result
        } else {
            FilterResult::block(duration)
        }
    }

    /// Caches a filter result.
    fn cache_result(&self, domain: &CompactString, result: &FilterResult) {
        let config = self.config.load();
        if !config.cache_enabled {
            return;
        }

        // Simple cache eviction: clear half when full
        if self.cache.len() >= self.cache_max_size {
            let to_remove: Vec<_> = self
                .cache
                .iter()
                .take(self.cache_max_size / 2)
                .map(|r| r.key().clone())
                .collect();
            for key in to_remove {
                self.cache.remove(&key);
            }
        }

        let cached = CachedResult {
            action: result.action.clone(),
            rule_idx: result.matched_rule.as_ref().and_then(|r| {
                let rules = self.rules.read();
                rules.iter().position(|stored| Arc::ptr_eq(stored, r))
            }),
            blocklist_name: result.blocklist_name.clone(),
            created: Instant::now(),
        };

        self.cache.insert(domain.clone(), cached);
    }

    /// Returns statistics about the filter engine.
    pub fn stats(&self) -> FilterStats {
        let rules = self.rules.read();
        let compiled = self.compiled.read();
        let suffix_trie = self.suffix_trie.read();
        let blocklists = self.blocklists.read();

        let queries_checked = self.stats.queries_checked.load(Ordering::Relaxed);
        let total_duration = self.stats.total_check_duration_ns.load(Ordering::Relaxed);
        let avg_duration = if queries_checked > 0 {
            total_duration / queries_checked / 1000 // Convert to microseconds
        } else {
            0
        };

        FilterStats {
            total_rules: rules.len(),
            exact_rules: self.exact_matches.len(),
            suffix_rules: suffix_trie.len(),
            prefix_rules: compiled.prefix_patterns.len(),
            substring_rules: compiled.substring_patterns.len(),
            regex_rules: compiled.regex_patterns.len(),
            wildcard_rules: 0, // Wildcard rules are stored in suffix_trie
            blocklist_count: blocklists.len(),
            queries_checked,
            queries_blocked: self.stats.queries_blocked.load(Ordering::Relaxed),
            queries_allowed: self.stats.queries_allowed.load(Ordering::Relaxed),
            cache_hits: self.stats.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.stats.cache_misses.load(Ordering::Relaxed),
            avg_check_duration_us: avg_duration,
            last_reload: None,
        }
    }

    /// Clears the result cache.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Returns the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.read().len()
    }

    /// Returns the number of loaded blocklists.
    pub fn blocklist_count(&self) -> usize {
        self.blocklists.read().len()
    }

    /// Returns the names of loaded blocklists.
    pub fn blocklist_names(&self) -> Vec<CompactString> {
        self.blocklists.read().iter().map(|b| b.name.clone()).collect()
    }

    /// Updates the engine configuration.
    pub fn update_config(&self, config: FilterEngineConfig) {
        self.config.store(Arc::new(config));
    }
}

impl Default for FilterEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FilterEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilterEngine")
            .field("rule_count", &self.rule_count())
            .field("blocklist_count", &self.blocklist_count())
            .field("cache_size", &self.cache.len())
            .finish()
    }
}

// ============================================================================
// Blocklist Loader Trait
// ============================================================================

/// Trait for loading blocklist content from various sources.
pub trait BlocklistLoader: Send + Sync {
    /// Loads the blocklist content.
    fn load<'a>(&'a self, source: &'a str) -> BoxFuture<'a, Result<String>>;
}

/// Loads blocklists from local files.
#[derive(Debug, Clone, Default)]
pub struct FileLoader;

impl FileLoader {
    /// Creates a new file loader.
    pub fn new() -> Self {
        Self
    }

    /// Loads content from a file path.
    pub async fn load(&self, path: &Path) -> Result<String> {
        tokio::fs::read_to_string(path)
            .await
            .map_err(FilterError::Io)
    }
}

impl BlocklistLoader for FileLoader {
    fn load<'a>(&'a self, source: &'a str) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            let path = Path::new(source);
            self.load(path).await
        })
    }
}

/// Loads blocklists from HTTP/HTTPS URLs.
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct HttpLoader {
    client: reqwest::Client,
}

#[cfg(feature = "http")]
impl HttpLoader {
    /// Creates a new HTTP loader with default settings.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent(concat!("stria-filter/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Creates a new HTTP loader with a custom client.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Loads content from a URL.
    pub async fn load(&self, url: &str) -> Result<String> {
        let response = self.client.get(url).send().await?;

        if !response.status().is_success() {
            return Err(FilterError::InvalidUrl(format!(
                "HTTP {} for {}",
                response.status(),
                url
            )));
        }

        Ok(response.text().await?)
    }
}

#[cfg(feature = "http")]
impl Default for HttpLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "http")]
impl BlocklistLoader for HttpLoader {
    fn load<'a>(&'a self, source: &'a str) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { self.load(source).await })
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Normalizes a domain name for consistent matching.
///
/// - Converts to lowercase
/// - Removes trailing dot
/// - Trims whitespace
fn normalize_domain(domain: &str) -> CompactString {
    let domain = domain.trim().to_ascii_lowercase();
    let domain = domain.strip_suffix('.').unwrap_or(&domain);
    CompactString::from(domain)
}

/// Checks if a string looks like a valid domain.
fn is_valid_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }

    // Must contain at least one dot (or be a TLD)
    // Must not start or end with a dot
    if s.starts_with('.') || s.ends_with('.') {
        return false;
    }

    // Check each label
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        // Labels must start with alphanumeric
        if !label.chars().next().map_or(false, |c| c.is_ascii_alphanumeric()) {
            return false;
        }
        // Labels must end with alphanumeric
        if !label.chars().last().map_or(false, |c| c.is_ascii_alphanumeric()) {
            // Allow ending with dash for punycode
            if !label.ends_with('-') || !label.starts_with("xn--") {
                return false;
            }
        }
    }

    true
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn test_filter_action() {
        assert!(FilterAction::Block.is_blocking());
        assert!(FilterAction::Redirect("127.0.0.1".parse().unwrap()).is_blocking());
        assert!(FilterAction::Allow.is_allowing());
        assert!(!FilterAction::Block.is_allowing());
    }

    #[test]
    fn test_rule_creation() {
        let rule = Rule::new("ads.example.com", RuleType::Exact, FilterAction::Block);
        assert_eq!(rule.pattern, "ads.example.com");
        assert_eq!(rule.rule_type, RuleType::Exact);
        assert!(rule.action.is_blocking());
        assert!(rule.enabled);
    }

    #[test]
    fn test_rule_builder() {
        let rule = Rule::block("tracking.com", RuleType::Suffix)
            .with_priority(10)
            .with_source("my-blocklist")
            .with_comment("Block all tracking.com subdomains");

        assert_eq!(rule.priority, 10);
        assert_eq!(rule.source.as_deref(), Some("my-blocklist"));
        assert!(rule.comment.is_some());
    }

    #[test]
    fn test_exact_match() {
        let engine = FilterEngine::new();
        engine.add_rule(Rule::block("ads.example.com", RuleType::Exact)).unwrap();

        let result = engine.check(&test_name("ads.example.com"));
        assert!(result.is_blocked());

        let result = engine.check(&test_name("other.example.com"));
        assert!(!result.is_blocked());

        let result = engine.check(&test_name("sub.ads.example.com"));
        assert!(!result.is_blocked());
    }

    #[test]
    fn test_suffix_match() {
        let engine = FilterEngine::new();
        engine.add_rule(Rule::block("doubleclick.net", RuleType::Suffix)).unwrap();

        let result = engine.check(&test_name("ad.doubleclick.net"));
        assert!(result.is_blocked());

        let result = engine.check(&test_name("stats.ad.doubleclick.net"));
        assert!(result.is_blocked());

        let result = engine.check(&test_name("doubleclick.com"));
        assert!(!result.is_blocked());
    }

    #[test]
    fn test_exception_rules() {
        let engine = FilterEngine::new();

        // Block all of example.com
        engine.add_rule(Rule::block("example.com", RuleType::Suffix)).unwrap();

        // But allow safe.example.com
        engine.add_rule(Rule::allow("safe.example.com", RuleType::Exact)).unwrap();

        let result = engine.check(&test_name("ads.example.com"));
        assert!(result.is_blocked());

        let result = engine.check(&test_name("safe.example.com"));
        assert!(result.is_allowed());
    }

    #[test]
    fn test_hosts_format_parsing() {
        let lines = [
            "0.0.0.0 ads.example.com",
            "127.0.0.1 tracking.example.com",
            "# This is a comment",
            "0.0.0.0 localhost", // Should be skipped
            "",
        ];

        let format = BlocklistFormat::Hosts;
        let parsed: Vec<_> = lines.iter().filter_map(|l| format.parse_line(l)).collect();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].pattern, "ads.example.com");
        assert_eq!(parsed[1].pattern, "tracking.example.com");
    }

    #[test]
    fn test_domains_format_parsing() {
        let lines = [
            "ads.example.com",
            "*.tracking.com",
            "# comment",
            "@@safe.example.com", // Exception
        ];

        let format = BlocklistFormat::Domains;
        let parsed: Vec<_> = lines.iter().filter_map(|l| format.parse_line(l)).collect();

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].rule_type, RuleType::Exact);
        assert_eq!(parsed[1].rule_type, RuleType::Suffix);
        assert!(parsed[2].is_exception);
    }

    #[test]
    fn test_adblock_format_parsing() {
        let lines = [
            "||ads.example.com^",
            "||tracking.example.com^$important",
            "@@||safe.example.com^",
            "! comment",
            "[Adblock Plus 2.0]",
        ];

        let format = BlocklistFormat::AdblockPlus;
        let parsed: Vec<_> = lines.iter().filter_map(|l| format.parse_line(l)).collect();

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].pattern, "ads.example.com");
        assert!(parsed[2].is_exception);
    }

    #[test]
    fn test_dnsmasq_format_parsing() {
        let lines = [
            "address=/ads.example.com/",
            "address=/.tracking.com/0.0.0.0",
            "server=/blocked.net/",
            "# comment",
        ];

        let format = BlocklistFormat::DnsmasqDomains;
        let parsed: Vec<_> = lines.iter().filter_map(|l| format.parse_line(l)).collect();

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].pattern, "ads.example.com");
        assert_eq!(parsed[0].rule_type, RuleType::Exact);
        assert_eq!(parsed[1].pattern, "tracking.com");
        assert_eq!(parsed[1].rule_type, RuleType::Suffix);
    }

    #[test]
    fn test_blocklist_creation() {
        let blocklist = Blocklist::from_file("test", "/path/to/list.txt", BlocklistFormat::Hosts)
            .with_update_interval(Duration::from_secs(3600));

        assert_eq!(blocklist.name, "test");
        assert!(blocklist.source.is_file());
        assert_eq!(blocklist.update_interval, Duration::from_secs(3600));
    }

    #[test]
    fn test_blocklist_parsing() {
        let mut blocklist = Blocklist::new(
            "test",
            BlocklistSource::File(PathBuf::from("test.txt")),
            BlocklistFormat::Domains,
        );

        let content = "ads.example.com\ntracking.example.com\n# comment\n*.malware.com";
        let count = blocklist.parse_content(content).unwrap();

        assert_eq!(count, 3);
        assert_eq!(blocklist.rules().len(), 3);
    }

    #[test]
    fn test_suffix_trie() {
        let mut trie = SuffixTrie::new();

        trie.insert("example.com", 0);
        trie.insert("tracking.net", 1);

        assert_eq!(trie.lookup("example.com"), Some(0));
        assert_eq!(trie.lookup("sub.example.com"), Some(0));
        assert_eq!(trie.lookup("deep.sub.example.com"), Some(0));
        assert_eq!(trie.lookup("tracking.net"), Some(1));
        assert!(trie.lookup("other.com").is_none());
    }

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("Example.COM"), "example.com");
        assert_eq!(normalize_domain("example.com."), "example.com");
        assert_eq!(normalize_domain("  example.com  "), "example.com");
        assert_eq!(normalize_domain("EXAMPLE.COM."), "example.com");
    }

    #[test]
    fn test_filter_stats() {
        let engine = FilterEngine::new();
        engine.add_rule(Rule::block("ads.example.com", RuleType::Exact)).unwrap();
        engine.add_rule(Rule::block("tracking.com", RuleType::Suffix)).unwrap();

        let stats = engine.stats();
        assert_eq!(stats.total_rules, 2);
        assert_eq!(stats.exact_rules, 1);
        assert_eq!(stats.suffix_rules, 1);
    }

    #[test]
    fn test_cache_behavior() {
        let config = FilterEngineConfig {
            cache_enabled: true,
            cache_max_entries: 100,
            cache_ttl_secs: 60,
            cname_protection: true,
        };
        let engine = FilterEngine::with_config(config);
        engine.add_rule(Rule::block("ads.example.com", RuleType::Exact)).unwrap();

        // First check - cache miss
        let result1 = engine.check(&test_name("ads.example.com"));
        assert!(result1.is_blocked());
        assert!(!result1.cached);

        // Second check - cache hit
        let result2 = engine.check(&test_name("ads.example.com"));
        assert!(result2.is_blocked());
        assert!(result2.cached);

        // Verify cache stats
        let stats = engine.stats();
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
    }

    #[test]
    fn test_filter_result_properties() {
        let result = FilterResult::block(Duration::from_micros(100));
        assert!(result.is_blocked());
        assert!(!result.is_allowed());

        let result = FilterResult::allow(Duration::from_micros(50));
        assert!(!result.is_blocked());
        assert!(result.is_allowed());
    }

    #[test]
    fn test_multiple_blocklists() {
        let engine = FilterEngine::new();

        let mut list1 = Blocklist::new(
            "list1",
            BlocklistSource::File(PathBuf::from("list1.txt")),
            BlocklistFormat::Domains,
        );
        list1.parse_content("ads.example.com").unwrap();

        let mut list2 = Blocklist::new(
            "list2",
            BlocklistSource::File(PathBuf::from("list2.txt")),
            BlocklistFormat::Domains,
        );
        list2.parse_content("tracking.example.com").unwrap();

        engine.add_blocklist(list1).unwrap();
        engine.add_blocklist(list2).unwrap();

        assert_eq!(engine.blocklist_count(), 2);
        assert!(engine.check(&test_name("ads.example.com")).is_blocked());
        assert!(engine.check(&test_name("tracking.example.com")).is_blocked());
    }

    #[test]
    fn test_case_insensitivity() {
        let engine = FilterEngine::new();
        engine.add_rule(Rule::block("ADS.EXAMPLE.COM", RuleType::Exact)).unwrap();

        assert!(engine.check(&test_name("ads.example.com")).is_blocked());
        assert!(engine.check(&test_name("ADS.EXAMPLE.COM")).is_blocked());
        assert!(engine.check(&test_name("Ads.Example.Com")).is_blocked());
    }
}
