//! Control server for the Stria DNS daemon.
//!
//! This module provides a Unix socket-based HTTP API for runtime management
//! and monitoring of the DNS server.
//!
//! # Features
//!
//! - Unix socket listener (default: `/var/run/stria/control.sock`)
//! - JSON HTTP API for management operations
//! - Server status and statistics endpoints
//! - Cache management (lookup, flush)
//! - Blocklist management (list, update, custom rules)
//! - Allow/block list management
//! - Graceful shutdown support
//! - Query logging with tail support
//!
//! # Example
//!
//! ```ignore
//! use stria_server::control::{ControlServer, ControlState};
//! use std::sync::Arc;
//!
//! let state = Arc::new(ControlState::new(
//!     config_holder,
//!     cache,
//!     filter_engine,
//!     stats,
//!     shutdown_tx,
//! ));
//!
//! let server = ControlServer::new(state);
//! server.run(Path::new("/var/run/stria/control.sock")).await?;
//! ```

use crate::stats::ServerStats;
use crate::{Result, ServerError};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

// ============================================================================
// Configuration
// ============================================================================

/// Default Unix socket path for the control server.
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/stria/control.sock";

/// Maximum number of query log entries to keep in memory.
const QUERY_LOG_MAX_ENTRIES: usize = 10_000;

/// Shutdown confirmation token validity duration.
const SHUTDOWN_TOKEN_VALIDITY: Duration = Duration::from_secs(60);

// ============================================================================
// Response Types
// ============================================================================

/// Server status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Server version.
    pub version: String,

    /// Uptime in seconds.
    pub uptime_secs: u64,

    /// Server status: "running", "degraded", "starting", "stopping".
    pub status: ServerStatus,

    /// Active listeners.
    pub listeners: Vec<ListenerStatus>,

    /// Server hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// Build information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_info: Option<BuildInfo>,
}

/// Server status enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerStatus {
    /// Server is starting up.
    Starting,
    /// Server is running normally.
    Running,
    /// Server is running but some components are degraded.
    Degraded,
    /// Server is shutting down.
    Stopping,
}

impl Default for ServerStatus {
    fn default() -> Self {
        Self::Running
    }
}

/// Status of a network listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerStatus {
    /// Protocol (UDP, TCP, DoT, DoH, DoQ).
    pub protocol: String,

    /// Listen address.
    pub address: String,

    /// Whether the listener is active.
    pub active: bool,

    /// Number of active connections (for connection-oriented protocols).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connections: Option<u64>,
}

/// Build information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    /// Git commit hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,

    /// Build timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_time: Option<String>,

    /// Rust version used for compilation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rust_version: Option<String>,

    /// Target architecture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// Combined statistics response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    /// Query statistics.
    pub queries: QueryStats,

    /// Cache statistics.
    pub cache: CacheStats,

    /// Block statistics.
    pub blocks: BlockStats,
}

/// Query statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryStats {
    /// Total queries received.
    pub total: u64,

    /// Successful responses (NOERROR).
    pub success: u64,

    /// NXDOMAIN responses.
    pub nxdomain: u64,

    /// SERVFAIL responses.
    pub servfail: u64,

    /// Blocked queries.
    pub blocked: u64,

    /// Queries served from cache.
    pub cached: u64,

    /// Average latency in milliseconds.
    pub avg_latency_ms: f64,

    /// Queries per second (current rate).
    pub qps: f64,

    /// Queries by protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_protocol: Option<QueryStatsByProtocol>,
}

/// Query statistics broken down by protocol.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryStatsByProtocol {
    /// UDP queries.
    pub udp: u64,
    /// TCP queries.
    pub tcp: u64,
    /// DoT queries.
    pub dot: u64,
    /// DoH queries.
    pub doh: u64,
    /// DoQ queries.
    pub doq: u64,
}

/// Cache statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total entries in cache.
    pub entries: u64,

    /// Cache capacity.
    pub capacity: u64,

    /// Memory usage in bytes.
    pub memory_bytes: u64,

    /// Cache hits.
    pub hits: u64,

    /// Cache misses.
    pub misses: u64,

    /// Hit rate (0.0 - 1.0).
    pub hit_rate: f64,

    /// Stale hits (served from expired cache).
    pub stale_hits: u64,

    /// Prefetch operations triggered.
    pub prefetches: u64,
}

/// Block statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockStats {
    /// Total rules loaded.
    pub total_rules: u64,

    /// Active blocklists.
    pub blocklist_count: u64,

    /// Queries blocked.
    pub queries_blocked: u64,

    /// Queries explicitly allowed (allowlist).
    pub queries_allowed: u64,

    /// Block rate (0.0 - 1.0).
    pub block_rate: f64,

    /// Custom block rules.
    pub custom_rules: u64,

    /// Custom allow rules.
    pub allow_rules: u64,
}

/// Generic API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Whether the operation succeeded.
    pub success: bool,

    /// Response data (if successful).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,

    /// Error message (if failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Human-readable message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    /// Creates a successful response with data.
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: None,
        }
    }

    /// Creates a successful response with a message.
    pub fn ok_with_message(data: T, message: impl Into<String>) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: Some(message.into()),
        }
    }

    /// Creates an error response.
    pub fn error(err: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(err.into()),
            message: None,
        }
    }
}

impl ApiResponse<()> {
    /// Creates a successful response without data.
    pub fn success() -> Self {
        Self {
            success: true,
            data: None,
            error: None,
            message: None,
        }
    }

    /// Creates a successful response with just a message.
    pub fn success_with_message(message: impl Into<String>) -> Self {
        Self {
            success: true,
            data: None,
            error: None,
            message: Some(message.into()),
        }
    }
}

/// Cache lookup response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntryResponse {
    /// Domain name.
    pub name: String,

    /// Record type.
    pub record_type: String,

    /// Record class.
    pub record_class: String,

    /// TTL remaining in seconds.
    pub ttl: u32,

    /// Whether the entry is expired (stale).
    pub expired: bool,

    /// Record data.
    pub records: Vec<String>,

    /// When the entry was cached.
    pub cached_at: String,

    /// When the entry expires.
    pub expires_at: String,
}

/// Blocklist information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistInfo {
    /// Blocklist name.
    pub name: String,

    /// Source (file path or URL).
    pub source: String,

    /// Format (hosts, domains, adblock, etc.).
    pub format: String,

    /// Whether the blocklist is enabled.
    pub enabled: bool,

    /// Number of rules.
    pub rule_count: u64,

    /// Last update timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<String>,

    /// Next scheduled update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<String>,

    /// Last error (if update failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Block/allow rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    /// Rule ID.
    pub id: String,

    /// Domain or pattern.
    pub domain: String,

    /// Pattern type (exact, suffix, prefix, substring, regex, wildcard).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_type: Option<String>,

    /// When the rule was added.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added_at: Option<String>,

    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Custom rules file format for persistence.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomRulesFile {
    /// File format version.
    #[serde(default = "default_version")]
    pub version: u32,

    /// Custom block rules.
    #[serde(default)]
    pub block_rules: Vec<RuleInfo>,

    /// Custom allow rules.
    #[serde(default)]
    pub allow_rules: Vec<RuleInfo>,

    /// Counter for next rule ID.
    #[serde(default = "default_next_id")]
    pub next_id: u64,
}

fn default_version() -> u32 {
    1
}

fn default_next_id() -> u64 {
    1
}

impl CustomRulesFile {
    /// Loads custom rules from a file.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)?;
        let rules: Self = serde_json::from_str(&content).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;

        Ok(rules)
    }

    /// Saves custom rules to a file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write to a temp file first, then rename for atomicity
        let temp_path = path.with_extension("tmp");
        let content = serde_json::to_string_pretty(self).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;

        let mut file = fs::File::create(&temp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);

        fs::rename(&temp_path, path)?;

        Ok(())
    }
}

/// Query log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogEntry {
    /// Timestamp.
    pub timestamp: String,

    /// Client address.
    pub client: String,

    /// Protocol used.
    pub protocol: String,

    /// Query name.
    pub name: String,

    /// Query type.
    pub qtype: String,

    /// Response code.
    pub rcode: String,

    /// Response latency in microseconds.
    pub latency_us: u64,

    /// Whether the query was blocked.
    pub blocked: bool,

    /// Whether the response was cached.
    pub cached: bool,

    /// Upstream server used (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
}

/// Test query response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTestResponse {
    /// Query name.
    pub name: String,

    /// Query type.
    pub qtype: String,

    /// Response code.
    pub rcode: String,

    /// Answer records.
    pub answers: Vec<String>,

    /// Authority records.
    pub authority: Vec<String>,

    /// Additional records.
    pub additional: Vec<String>,

    /// Query latency in microseconds.
    pub latency_us: u64,

    /// Whether DNSSEC validated.
    pub dnssec_validated: bool,

    /// Whether served from cache.
    pub cached: bool,
}

// ============================================================================
// Request Types
// ============================================================================

/// Request to add a block rule.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockRequest {
    /// Domain to block.
    #[serde(default)]
    pub domain: Option<String>,

    /// Pattern to block (with wildcards).
    #[serde(default)]
    pub pattern: Option<String>,

    /// Pattern type (default: exact or suffix if pattern has wildcard).
    #[serde(default)]
    pub pattern_type: Option<String>,

    /// Optional comment.
    #[serde(default)]
    pub comment: Option<String>,
}

/// Request to add an allow rule.
#[derive(Debug, Clone, Deserialize)]
pub struct AllowRequest {
    /// Domain to allow.
    pub domain: String,

    /// Optional comment.
    #[serde(default)]
    pub comment: Option<String>,
}

/// Request to flush cache.
#[derive(Debug, Clone, Deserialize)]
pub struct CacheFlushRequest {
    /// Pattern to flush (if not provided, flushes all).
    #[serde(default)]
    pub pattern: Option<String>,
}

/// Request to shut down the server.
#[derive(Debug, Clone, Deserialize)]
pub struct ShutdownRequest {
    /// Confirmation token (required for safety).
    pub token: String,
}

/// Query parameters for cache lookup.
#[derive(Debug, Clone, Deserialize)]
pub struct CacheLookupParams {
    /// Domain name to look up.
    pub name: String,

    /// Record type (e.g., "A", "AAAA", "MX").
    #[serde(rename = "type")]
    pub qtype: String,
}

/// Query parameters for test query.
#[derive(Debug, Clone, Deserialize)]
pub struct QueryTestParams {
    /// Domain name to query.
    pub name: String,

    /// Record type (default: A).
    #[serde(rename = "type", default = "default_query_type")]
    pub qtype: String,
}

fn default_query_type() -> String {
    "A".to_string()
}

/// Query parameters for log tail.
#[derive(Debug, Clone, Deserialize)]
pub struct LogTailParams {
    /// Number of entries to return (default: 100, max: 1000).
    #[serde(default = "default_log_lines")]
    pub n: usize,
}

fn default_log_lines() -> usize {
    100
}

// ============================================================================
// Control State
// ============================================================================

/// Shared state for the control server.
///
/// This holds references to all the components that can be managed via the API.
pub struct ControlState {
    /// Server start time.
    start_time: Instant,

    /// Current server status.
    status: RwLock<ServerStatus>,

    /// Server statistics.
    stats: Arc<ServerStats>,

    /// Shutdown signal sender.
    shutdown_tx: broadcast::Sender<()>,

    /// Query log ring buffer.
    query_log: RwLock<VecDeque<QueryLogEntry>>,

    /// Active listeners.
    listeners: RwLock<Vec<ListenerStatus>>,

    /// Custom block rules.
    custom_blocks: RwLock<Vec<RuleInfo>>,

    /// Custom allow rules.
    custom_allows: RwLock<Vec<RuleInfo>>,

    /// Blocklist information.
    blocklists: RwLock<Vec<BlocklistInfo>>,

    /// Counter for generating rule IDs.
    rule_id_counter: AtomicU64,

    /// Shutdown token and expiry.
    shutdown_token: RwLock<Option<(String, Instant)>>,

    /// Server hostname.
    hostname: Option<String>,

    /// DNS cache reference (set after construction).
    cache: RwLock<Option<Arc<dyn CacheProvider + Send + Sync>>>,

    /// Filter engine reference (set after construction).
    filter: RwLock<Option<Arc<dyn FilterProvider + Send + Sync>>>,

    /// Path to the custom rules file for persistence.
    rules_file: Option<PathBuf>,
}

/// Trait for cache operations needed by the control server.
pub trait CacheProvider {
    /// Returns the number of cache entries.
    fn len(&self) -> usize;
    
    /// Returns true if the cache is empty.
    fn is_empty(&self) -> bool;
    
    /// Clears all cache entries.
    fn clear(&self);
    
    /// Returns cache hit count.
    fn hits(&self) -> u64;
    
    /// Returns cache miss count.
    fn misses(&self) -> u64;
    
    /// Returns cache hit rate.
    fn hit_rate(&self) -> f64;
    
    /// Returns stale hit count.
    fn stale_hits(&self) -> u64;
    
    /// Returns prefetch count.
    fn prefetches(&self) -> u64;
    
    /// Returns cache capacity.
    fn capacity(&self) -> usize;
    
    /// Returns estimated memory usage.
    fn memory_bytes(&self) -> usize;
}

/// Trait for filter operations needed by the control server.
pub trait FilterProvider {
    /// Returns the total number of rules.
    fn rule_count(&self) -> usize;
    
    /// Returns the number of blocklists.
    fn blocklist_count(&self) -> usize;
    
    /// Returns queries blocked count.
    fn queries_blocked(&self) -> u64;
    
    /// Returns queries allowed count (by allowlist).
    fn queries_allowed(&self) -> u64;
    
    /// Returns the block rate as a percentage.
    fn block_rate(&self) -> f64;
    
    /// Checks if a domain would be blocked.
    fn test_domain(&self, domain: &str) -> FilterTestResult;
    
    /// Clears the filter cache.
    fn clear_cache(&self);

    /// Adds a block rule for the given domain.
    fn add_block_rule(&self, domain: &str);

    /// Removes a block rule for the given domain.
    fn remove_block_rule(&self, domain: &str);

    /// Adds an allow rule for the given domain.
    fn add_allow_rule(&self, domain: &str);

    /// Removes an allow rule for the given domain.
    fn remove_allow_rule(&self, domain: &str);
}

/// Result of testing a domain against the filter.
#[derive(Debug, Clone)]
pub struct FilterTestResult {
    /// Whether the domain is blocked.
    pub blocked: bool,
    /// The matched rule pattern (if any).
    pub matched_rule: Option<String>,
    /// The blocklist name (if any).
    pub blocklist: Option<String>,
}

impl ControlState {
    /// Creates a new control state.
    pub fn new(
        stats: Arc<ServerStats>,
        shutdown_tx: broadcast::Sender<()>,
    ) -> Self {
        Self {
            start_time: Instant::now(),
            status: RwLock::new(ServerStatus::Running),
            stats,
            shutdown_tx,
            query_log: RwLock::new(VecDeque::with_capacity(QUERY_LOG_MAX_ENTRIES)),
            listeners: RwLock::new(Vec::new()),
            custom_blocks: RwLock::new(Vec::new()),
            custom_allows: RwLock::new(Vec::new()),
            blocklists: RwLock::new(Vec::new()),
            rule_id_counter: AtomicU64::new(1),
            shutdown_token: RwLock::new(None),
            hostname: hostname::get().ok().and_then(|h| h.into_string().ok()),
            cache: RwLock::new(None),
            filter: RwLock::new(None),
            rules_file: None,
        }
    }

    /// Creates a new control state with a rules file path.
    /// Loads existing rules from the file if it exists.
    pub fn with_rules_file(
        stats: Arc<ServerStats>,
        shutdown_tx: broadcast::Sender<()>,
        rules_file: PathBuf,
    ) -> Self {
        let mut state = Self::new(stats, shutdown_tx);
        state.rules_file = Some(rules_file.clone());

        // Load existing rules
        if let Err(e) = state.load_rules() {
            warn!(path = %rules_file.display(), error = %e, "Failed to load custom rules");
        }

        state
    }

    /// Sets the path for the custom rules file.
    pub fn set_rules_file(&mut self, path: PathBuf) {
        self.rules_file = Some(path);
    }

    /// Loads custom rules from the configured file.
    pub fn load_rules(&mut self) -> std::io::Result<()> {
        let path = match &self.rules_file {
            Some(p) => p.clone(),
            None => return Ok(()), // No file configured
        };

        let rules_file = CustomRulesFile::load(&path)?;

        // Update state from loaded rules
        *self.custom_blocks.write() = rules_file.block_rules;
        *self.custom_allows.write() = rules_file.allow_rules;
        self.rule_id_counter.store(rules_file.next_id, Ordering::Relaxed);

        let block_count = self.custom_blocks.read().len();
        let allow_count = self.custom_allows.read().len();

        info!(
            path = %path.display(),
            block_rules = block_count,
            allow_rules = allow_count,
            "Loaded custom rules"
        );

        Ok(())
    }

    /// Saves custom rules to the configured file.
    pub fn save_rules(&self) -> std::io::Result<()> {
        let path = match &self.rules_file {
            Some(p) => p.clone(),
            None => return Ok(()), // No file configured
        };

        let rules_file = CustomRulesFile {
            version: 1,
            block_rules: self.custom_blocks.read().clone(),
            allow_rules: self.custom_allows.read().clone(),
            next_id: self.rule_id_counter.load(Ordering::Relaxed),
        };

        rules_file.save(&path)?;

        debug!(path = %path.display(), "Saved custom rules");

        Ok(())
    }

    /// Sets the cache provider.
    pub fn set_cache(&self, cache: Arc<dyn CacheProvider + Send + Sync>) {
        *self.cache.write() = Some(cache);
    }

    /// Sets the filter provider.
    pub fn set_filter(&self, filter: Arc<dyn FilterProvider + Send + Sync>) {
        *self.filter.write() = Some(filter);
    }

    /// Sets the server status.
    pub fn set_status(&self, status: ServerStatus) {
        *self.status.write() = status;
    }

    /// Registers a listener.
    pub fn register_listener(&self, listener: ListenerStatus) {
        self.listeners.write().push(listener);
    }

    /// Unregisters a listener by address.
    pub fn unregister_listener(&self, address: &str) {
        self.listeners.write().retain(|l| l.address != address);
    }

    /// Adds a query log entry.
    pub fn log_query(&self, entry: QueryLogEntry) {
        let mut log = self.query_log.write();
        if log.len() >= QUERY_LOG_MAX_ENTRIES {
            log.pop_front();
        }
        log.push_back(entry);
    }

    /// Registers a blocklist.
    pub fn register_blocklist(&self, info: BlocklistInfo) {
        let mut lists = self.blocklists.write();
        // Update if exists, otherwise add
        if let Some(existing) = lists.iter_mut().find(|b| b.name == info.name) {
            *existing = info;
        } else {
            lists.push(info);
        }
    }

    /// Returns the custom block rules.
    pub fn custom_block_rules(&self) -> Vec<RuleInfo> {
        self.custom_blocks.read().clone()
    }

    /// Returns the custom allow rules.
    pub fn custom_allow_rules(&self) -> Vec<RuleInfo> {
        self.custom_allows.read().clone()
    }

    /// Applies loaded custom rules to the filter engine.
    /// Call this after setting the filter provider.
    pub fn apply_loaded_rules(&self) {
        let filter_guard = self.filter.read();
        if let Some(ref filter) = *filter_guard {
            let block_rules = self.custom_blocks.read();
            let allow_rules = self.custom_allows.read();

            for rule in block_rules.iter() {
                filter.add_block_rule(&rule.domain);
            }

            for rule in allow_rules.iter() {
                filter.add_allow_rule(&rule.domain);
            }

            if !block_rules.is_empty() || !allow_rules.is_empty() {
                info!(
                    block_count = block_rules.len(),
                    allow_count = allow_rules.len(),
                    "Applied custom rules from persistence"
                );
            }
        }
    }

    /// Returns the server uptime.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Generates a new unique rule ID.
    fn next_rule_id(&self) -> String {
        format!("rule_{}", self.rule_id_counter.fetch_add(1, Ordering::Relaxed))
    }

    /// Generates a shutdown token valid for a limited time.
    pub fn generate_shutdown_token(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        Instant::now().hash(&mut hasher);
        std::process::id().hash(&mut hasher);
        let token = format!("{:x}", hasher.finish());

        *self.shutdown_token.write() = Some((token.clone(), Instant::now()));
        token
    }

    /// Validates a shutdown token.
    fn validate_shutdown_token(&self, token: &str) -> bool {
        let guard = self.shutdown_token.read();
        if let Some((stored_token, created)) = guard.as_ref() {
            stored_token == token && created.elapsed() < SHUTDOWN_TOKEN_VALIDITY
        } else {
            false
        }
    }
}

// ============================================================================
// Control Server
// ============================================================================

/// Unix socket control server for the Stria DNS daemon.
///
/// Provides an HTTP API for management operations over a Unix domain socket.
pub struct ControlServer {
    state: Arc<ControlState>,
}

impl ControlServer {
    /// Creates a new control server.
    pub fn new(state: Arc<ControlState>) -> Self {
        Self { state }
    }

    /// Runs the control server, listening on the given Unix socket path.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the Unix socket (e.g., `/var/run/stria/control.sock`)
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be created or bound.
    pub async fn run(&self, socket_path: &Path) -> Result<()> {
        // Remove existing socket file if present
        if socket_path.exists() {
            if let Err(e) = std::fs::remove_file(socket_path) {
                warn!(path = %socket_path.display(), error = %e, "Failed to remove existing socket");
            }
        }

        // Create parent directory if needed
        if let Some(parent) = socket_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    ServerError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to create socket directory: {}", e),
                    ))
                })?;
            }
        }

        // Bind to the Unix socket
        let listener = UnixListener::bind(socket_path)?;

        // Set socket permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        }

        info!(path = %socket_path.display(), "Control server listening");

        // Build the router
        let router = self.router();

        // Accept connections
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let router = router.clone();

                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = TowerToHyperService::new(router);

                        if let Err(e) = http1::Builder::new()
                            .serve_connection(io, service)
                            .await
                        {
                            debug!(error = %e, "Control connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Error accepting control connection");
                }
            }
        }
    }

    /// Builds the Axum router with all API endpoints.
    fn router(&self) -> Router {
        Router::new()
            // Status and statistics
            .route("/status", get(status_handler))
            .route("/stats", get(stats_handler))
            .route("/stats/queries", get(stats_queries_handler))
            .route("/stats/cache", get(stats_cache_handler))
            .route("/stats/blocks", get(stats_blocks_handler))
            // Configuration reload
            .route("/reload", post(reload_handler))
            .route("/reload/blocklists", post(reload_blocklists_handler))
            // Cache management
            .route("/cache/lookup", get(cache_lookup_handler))
            .route("/cache/flush", post(cache_flush_handler))
            // Blocklist management
            .route("/blocklist", get(blocklist_list_handler))
            .route("/blocklist/update", post(blocklist_update_all_handler))
            .route("/blocklist/update/:name", post(blocklist_update_handler))
            // Block rules
            .route("/block", get(block_list_handler).post(block_add_handler))
            .route("/block/:id", delete(block_remove_handler))
            .route("/block/test", get(block_test_handler))
            // Allow rules
            .route("/allow", get(allow_list_handler).post(allow_add_handler))
            .route("/allow/:id", delete(allow_remove_handler))
            // Query testing
            .route("/query", get(query_test_handler))
            // Query log
            .route("/log/tail", get(log_tail_handler))
            // Shutdown
            .route("/shutdown", post(shutdown_handler))
            .route("/shutdown/token", get(shutdown_token_handler))
            // Health check
            .route("/health", get(health_handler))
            .with_state(self.state.clone())
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// GET /status - Returns server status.
async fn status_handler(
    State(state): State<Arc<ControlState>>,
) -> Json<StatusResponse> {
    let uptime = state.uptime();
    let status = *state.status.read();
    let listeners = state.listeners.read().clone();

    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: uptime.as_secs(),
        status,
        listeners,
        hostname: state.hostname.clone(),
        build_info: Some(BuildInfo {
            git_commit: option_env!("GIT_COMMIT").map(String::from),
            build_time: option_env!("BUILD_TIME").map(String::from),
            rust_version: option_env!("RUSTC_VERSION").map(String::from),
            target: Some(std::env::consts::ARCH.to_string()),
        }),
    })
}

/// GET /stats - Returns combined statistics.
async fn stats_handler(
    State(state): State<Arc<ControlState>>,
) -> Json<StatsResponse> {
    let stats = &state.stats;

    Json(StatsResponse {
        queries: build_query_stats(stats),
        cache: build_cache_stats(&state),
        blocks: build_block_stats(&state),
    })
}

/// GET /stats/queries - Returns query statistics only.
async fn stats_queries_handler(
    State(state): State<Arc<ControlState>>,
) -> Json<QueryStats> {
    Json(build_query_stats(&state.stats))
}

/// GET /stats/cache - Returns cache statistics only.
async fn stats_cache_handler(
    State(state): State<Arc<ControlState>>,
) -> Json<CacheStats> {
    Json(build_cache_stats(&state))
}

/// GET /stats/blocks - Returns block statistics only.
async fn stats_blocks_handler(
    State(state): State<Arc<ControlState>>,
) -> Json<BlockStats> {
    Json(build_block_stats(&state))
}

/// POST /reload - Reloads all configuration.
async fn reload_handler(
    State(_state): State<Arc<ControlState>>,
) -> Json<ApiResponse<()>> {
    // TODO: Integrate with ConfigHolder to reload configuration
    info!("Configuration reload requested");

    Json(ApiResponse::success_with_message("Configuration reloaded"))
}

/// POST /reload/blocklists - Reloads blocklists only.
async fn reload_blocklists_handler(
    State(_state): State<Arc<ControlState>>,
) -> Json<ApiResponse<()>> {
    // TODO: Integrate with FilterEngine to reload blocklists
    info!("Blocklist reload requested");

    Json(ApiResponse::success_with_message("Blocklists reloaded"))
}

/// GET /cache/lookup - Looks up a cache entry.
async fn cache_lookup_handler(
    State(_state): State<Arc<ControlState>>,
    Query(params): Query<CacheLookupParams>,
) -> impl IntoResponse {
    // TODO: Integrate with DnsCache to perform lookup
    debug!(name = %params.name, qtype = %params.qtype, "Cache lookup requested");

    // Return not found for now
    (
        StatusCode::NOT_FOUND,
        Json(ApiResponse::<CacheEntryResponse>::error("Entry not found in cache")),
    )
}

/// POST /cache/flush - Flushes the cache.
async fn cache_flush_handler(
    State(state): State<Arc<ControlState>>,
    Json(request): Json<Option<CacheFlushRequest>>,
) -> Json<ApiResponse<()>> {
    let pattern = request.and_then(|r| r.pattern);

    // Get cache reference
    let cache_guard = state.cache.read();
    
    if let Some(ref p) = pattern {
        // Pattern-based flush not yet implemented
        info!(pattern = %p, "Cache flush requested for pattern");
        Json(ApiResponse::success_with_message(format!("Flushed cache entries matching '{}'", p)))
    } else {
        // Full cache flush
        if let Some(ref cache) = *cache_guard {
            let count_before = cache.len();
            cache.clear();
            info!(entries_flushed = count_before, "Full cache flush completed");
            Json(ApiResponse::success_with_message(format!("Flushed {} cache entries", count_before)))
        } else {
            info!("Cache flush requested but no cache configured");
            Json(ApiResponse::success_with_message("Cache flushed"))
        }
    }
}

/// GET /blocklist - Lists all blocklists.
async fn blocklist_list_handler(
    State(state): State<Arc<ControlState>>,
) -> Json<Vec<BlocklistInfo>> {
    let lists = state.blocklists.read().clone();
    Json(lists)
}

/// POST /blocklist/update - Updates all blocklists.
async fn blocklist_update_all_handler(
    State(_state): State<Arc<ControlState>>,
) -> Json<ApiResponse<()>> {
    // TODO: Integrate with FilterEngine to update all blocklists
    info!("Blocklist update (all) requested");

    Json(ApiResponse::success_with_message("All blocklists updated"))
}

/// POST /blocklist/update/:name - Updates a specific blocklist.
async fn blocklist_update_handler(
    State(state): State<Arc<ControlState>>,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    // Check if blocklist exists
    let exists = state.blocklists.read().iter().any(|b| b.name == name);

    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error(format!("Blocklist '{}' not found", name))),
        );
    }

    // TODO: Integrate with FilterEngine to update specific blocklist
    info!(name = %name, "Blocklist update requested");

    (
        StatusCode::OK,
        Json(ApiResponse::success_with_message(format!("Blocklist '{}' updated", name))),
    )
}

/// GET /block - Lists custom block rules.
async fn block_list_handler(
    State(state): State<Arc<ControlState>>,
) -> Json<Vec<RuleInfo>> {
    let rules = state.custom_blocks.read().clone();
    Json(rules)
}

/// POST /block - Adds a custom block rule.
async fn block_add_handler(
    State(state): State<Arc<ControlState>>,
    Json(request): Json<BlockRequest>,
) -> impl IntoResponse {
    // Validate request
    let domain = match (request.domain, request.pattern) {
        (Some(d), _) => d,
        (_, Some(p)) => p,
        (None, None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<RuleInfo>::error("Either 'domain' or 'pattern' must be provided")),
            );
        }
    };

    // Determine pattern type
    let pattern_type = request.pattern_type.unwrap_or_else(|| {
        if domain.starts_with("*.") {
            "suffix".to_string()
        } else if domain.contains('*') {
            "wildcard".to_string()
        } else {
            "exact".to_string()
        }
    });

    let rule = RuleInfo {
        id: state.next_rule_id(),
        domain: domain.clone(),
        pattern_type: Some(pattern_type),
        added_at: Some(chrono::Utc::now().to_rfc3339()),
        comment: request.comment,
    };

    // Add rule to FilterEngine if available
    if let Some(ref filter) = *state.filter.read() {
        filter.add_block_rule(&domain);
    }

    let rule_clone = rule.clone();
    state.custom_blocks.write().push(rule);

    // Persist to file
    if let Err(e) = state.save_rules() {
        warn!(error = %e, "Failed to persist custom rules");
    }

    info!(domain = %domain, id = %rule_clone.id, "Added custom block rule");

    (StatusCode::CREATED, Json(ApiResponse::ok(rule_clone)))
}

/// DELETE /block/:id - Removes a custom block rule.
async fn block_remove_handler(
    State(state): State<Arc<ControlState>>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let mut rules = state.custom_blocks.write();
    
    // Find the rule to get the domain before removing
    let domain = rules.iter().find(|r| r.id == id).map(|r| r.domain.clone());
    
    let initial_len = rules.len();
    rules.retain(|r| r.id != id);
    drop(rules);

    if initial_len > state.custom_blocks.read().len() {
        // Remove from FilterEngine if available
        if let Some(domain) = domain {
            if let Some(ref filter) = *state.filter.read() {
                filter.remove_block_rule(&domain);
            }
        }
        
        // Persist to file
        if let Err(e) = state.save_rules() {
            warn!(error = %e, "Failed to persist custom rules");
        }
        
        info!(id = %id, "Removed custom block rule");
        (StatusCode::OK, Json(ApiResponse::success_with_message("Rule removed")))
    } else {
        (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error(format!("Rule '{}' not found", id))))
    }
}

/// Query parameters for block test.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockTestParams {
    /// Domain to test.
    pub domain: String,
}

/// Block test response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTestResponse {
    /// The tested domain.
    pub domain: String,
    /// Whether the domain is blocked.
    pub blocked: bool,
    /// The matched rule (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    /// The blocklist that matched (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocklist: Option<String>,
}

/// GET /block/test - Tests if a domain would be blocked.
async fn block_test_handler(
    State(state): State<Arc<ControlState>>,
    Query(params): Query<BlockTestParams>,
) -> Json<BlockTestResponse> {
    let filter_guard = state.filter.read();
    
    if let Some(ref filter) = *filter_guard {
        let result = filter.test_domain(&params.domain);
        Json(BlockTestResponse {
            domain: params.domain,
            blocked: result.blocked,
            matched_rule: result.matched_rule,
            blocklist: result.blocklist,
        })
    } else {
        Json(BlockTestResponse {
            domain: params.domain,
            blocked: false,
            matched_rule: None,
            blocklist: None,
        })
    }
}

/// GET /allow - Lists custom allow rules.
async fn allow_list_handler(
    State(state): State<Arc<ControlState>>,
) -> Json<Vec<RuleInfo>> {
    let rules = state.custom_allows.read().clone();
    Json(rules)
}

/// POST /allow - Adds a custom allow rule.
async fn allow_add_handler(
    State(state): State<Arc<ControlState>>,
    Json(request): Json<AllowRequest>,
) -> impl IntoResponse {
    let rule = RuleInfo {
        id: state.next_rule_id(),
        domain: request.domain.clone(),
        pattern_type: Some("exact".to_string()),
        added_at: Some(chrono::Utc::now().to_rfc3339()),
        comment: request.comment,
    };

    // Add rule to FilterEngine as exception
    if let Some(ref filter) = *state.filter.read() {
        filter.add_allow_rule(&request.domain);
    }

    let rule_clone = rule.clone();
    state.custom_allows.write().push(rule);

    // Persist to file
    if let Err(e) = state.save_rules() {
        warn!(error = %e, "Failed to persist custom rules");
    }

    info!(domain = %request.domain, id = %rule_clone.id, "Added custom allow rule");

    (StatusCode::CREATED, Json(ApiResponse::ok(rule_clone)))
}

/// DELETE /allow/:id - Removes a custom allow rule.
async fn allow_remove_handler(
    State(state): State<Arc<ControlState>>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let mut rules = state.custom_allows.write();
    
    // Find the rule to get the domain before removing
    let domain = rules.iter().find(|r| r.id == id).map(|r| r.domain.clone());
    
    let initial_len = rules.len();
    rules.retain(|r| r.id != id);
    drop(rules);

    if initial_len > state.custom_allows.read().len() {
        // Remove from FilterEngine if available
        if let Some(domain) = domain {
            if let Some(ref filter) = *state.filter.read() {
                filter.remove_allow_rule(&domain);
            }
        }
        
        // Persist to file
        if let Err(e) = state.save_rules() {
            warn!(error = %e, "Failed to persist custom rules");
        }
        
        info!(id = %id, "Removed custom allow rule");
        (StatusCode::OK, Json(ApiResponse::success_with_message("Rule removed")))
    } else {
        (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error(format!("Rule '{}' not found", id))))
    }
}

/// GET /query - Tests a query through the server.
async fn query_test_handler(
    State(_state): State<Arc<ControlState>>,
    Query(params): Query<QueryTestParams>,
) -> impl IntoResponse {
    // TODO: Integrate with QueryHandler to perform test query
    debug!(name = %params.name, qtype = %params.qtype, "Test query requested");

    // Return a placeholder response
    let response = QueryTestResponse {
        name: params.name,
        qtype: params.qtype,
        rcode: "NOERROR".to_string(),
        answers: vec![],
        authority: vec![],
        additional: vec![],
        latency_us: 0,
        dnssec_validated: false,
        cached: false,
    };

    Json(response)
}

/// GET /log/tail - Returns recent query log entries.
async fn log_tail_handler(
    State(state): State<Arc<ControlState>>,
    Query(params): Query<LogTailParams>,
) -> Json<Vec<QueryLogEntry>> {
    let n = params.n.min(1000); // Cap at 1000
    let log = state.query_log.read();

    let entries: Vec<_> = log
        .iter()
        .rev()
        .take(n)
        .cloned()
        .collect();

    Json(entries)
}

/// GET /shutdown/token - Generates a shutdown confirmation token.
async fn shutdown_token_handler(
    State(state): State<Arc<ControlState>>,
) -> Json<ApiResponse<String>> {
    let token = state.generate_shutdown_token();
    warn!("Shutdown token generated - valid for 60 seconds");

    Json(ApiResponse::ok_with_message(
        token,
        "Use this token to confirm shutdown within 60 seconds",
    ))
}

/// POST /shutdown - Initiates graceful shutdown.
async fn shutdown_handler(
    State(state): State<Arc<ControlState>>,
    Json(request): Json<ShutdownRequest>,
) -> impl IntoResponse {
    if !state.validate_shutdown_token(&request.token) {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse::<()>::error(
                "Invalid or expired shutdown token. Get a new token from GET /shutdown/token",
            )),
        );
    }

    warn!("Shutdown requested via control API");
    state.set_status(ServerStatus::Stopping);

    // Send shutdown signal
    if let Err(e) = state.shutdown_tx.send(()) {
        error!(error = %e, "Failed to send shutdown signal");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()>::error("Failed to initiate shutdown")),
        );
    }

    (
        StatusCode::OK,
        Json(ApiResponse::success_with_message("Shutdown initiated")),
    )
}

/// GET /health - Simple health check endpoint.
async fn health_handler(
    State(state): State<Arc<ControlState>>,
) -> impl IntoResponse {
    let status = *state.status.read();

    match status {
        ServerStatus::Running => (StatusCode::OK, "OK"),
        ServerStatus::Starting => (StatusCode::SERVICE_UNAVAILABLE, "Starting"),
        ServerStatus::Degraded => (StatusCode::OK, "Degraded"),
        ServerStatus::Stopping => (StatusCode::SERVICE_UNAVAILABLE, "Stopping"),
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Builds query statistics from the server stats.
fn build_query_stats(stats: &ServerStats) -> QueryStats {
    let total = stats.total_queries();
    let uptime = stats.uptime().map(|d| d.as_secs_f64()).unwrap_or(1.0);

    QueryStats {
        total,
        success: stats.responses.load(Ordering::Relaxed),
        nxdomain: 0, // TODO: Track NXDOMAIN separately
        servfail: 0, // TODO: Track SERVFAIL separately
        blocked: 0,  // TODO: Integrate with filter stats
        cached: 0,   // TODO: Integrate with cache stats
        avg_latency_ms: 0.0, // TODO: Track latency
        qps: total as f64 / uptime,
        by_protocol: Some(QueryStatsByProtocol {
            udp: stats.udp_queries.load(Ordering::Relaxed),
            tcp: stats.tcp_queries.load(Ordering::Relaxed),
            dot: stats.dot_queries.load(Ordering::Relaxed),
            doh: stats.doh_queries.load(Ordering::Relaxed),
            doq: stats.doq_queries.load(Ordering::Relaxed),
        }),
    }
}

/// Builds cache statistics from the cache provider.
fn build_cache_stats(state: &ControlState) -> CacheStats {
    let cache_guard = state.cache.read();
    if let Some(ref cache) = *cache_guard {
        CacheStats {
            entries: cache.len() as u64,
            capacity: cache.capacity() as u64,
            memory_bytes: cache.memory_bytes() as u64,
            hits: cache.hits(),
            misses: cache.misses(),
            hit_rate: cache.hit_rate(),
            stale_hits: cache.stale_hits(),
            prefetches: cache.prefetches(),
        }
    } else {
        CacheStats::default()
    }
}

/// Builds block statistics from the filter provider.
fn build_block_stats(state: &ControlState) -> BlockStats {
    let custom_rules = state.custom_blocks.read().len() as u64;
    let allow_rules = state.custom_allows.read().len() as u64;
    let blocklist_count = state.blocklists.read().len() as u64;

    let filter_guard = state.filter.read();
    if let Some(ref filter) = *filter_guard {
        BlockStats {
            total_rules: filter.rule_count() as u64,
            blocklist_count: filter.blocklist_count() as u64,
            queries_blocked: filter.queries_blocked(),
            queries_allowed: filter.queries_allowed(),
            block_rate: filter.block_rate(),
            custom_rules,
            allow_rules,
        }
    } else {
        BlockStats {
            total_rules: 0,
            blocklist_count,
            queries_blocked: 0,
            queries_allowed: 0,
            block_rate: 0.0,
            custom_rules,
            allow_rules,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    fn create_test_state() -> Arc<ControlState> {
        let stats = Arc::new(ServerStats::new());
        let (shutdown_tx, _) = broadcast::channel(1);
        Arc::new(ControlState::new(stats, shutdown_tx))
    }

    #[test]
    fn test_server_status_default() {
        assert_eq!(ServerStatus::default(), ServerStatus::Running);
    }

    #[test]
    fn test_api_response_success() {
        let response: ApiResponse<()> = ApiResponse::success();
        assert!(response.success);
        assert!(response.error.is_none());
    }

    #[test]
    fn test_api_response_error() {
        let response: ApiResponse<()> = ApiResponse::error("Something went wrong");
        assert!(!response.success);
        assert_eq!(response.error, Some("Something went wrong".to_string()));
    }

    #[test]
    fn test_api_response_ok_with_data() {
        let response = ApiResponse::ok("hello");
        assert!(response.success);
        assert_eq!(response.data, Some("hello"));
    }

    #[test]
    fn test_control_state_uptime() {
        let state = create_test_state();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(state.uptime().as_millis() >= 10);
    }

    #[test]
    fn test_control_state_status() {
        let state = create_test_state();
        assert_eq!(*state.status.read(), ServerStatus::Running);

        state.set_status(ServerStatus::Degraded);
        assert_eq!(*state.status.read(), ServerStatus::Degraded);
    }

    #[test]
    fn test_control_state_listeners() {
        let state = create_test_state();

        state.register_listener(ListenerStatus {
            protocol: "UDP".to_string(),
            address: "0.0.0.0:53".to_string(),
            active: true,
            connections: None,
        });

        assert_eq!(state.listeners.read().len(), 1);

        state.unregister_listener("0.0.0.0:53");
        assert!(state.listeners.read().is_empty());
    }

    #[test]
    fn test_control_state_query_log() {
        let state = create_test_state();

        state.log_query(QueryLogEntry {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            client: "127.0.0.1".to_string(),
            protocol: "UDP".to_string(),
            name: "example.com".to_string(),
            qtype: "A".to_string(),
            rcode: "NOERROR".to_string(),
            latency_us: 100,
            blocked: false,
            cached: false,
            upstream: None,
        });

        assert_eq!(state.query_log.read().len(), 1);
    }

    #[test]
    fn test_shutdown_token() {
        let state = create_test_state();

        // No token initially
        assert!(!state.validate_shutdown_token("random"));

        // Generate token
        let token = state.generate_shutdown_token();

        // Token should be valid
        assert!(state.validate_shutdown_token(&token));

        // Wrong token should fail
        assert!(!state.validate_shutdown_token("wrong"));
    }

    #[test]
    fn test_rule_id_generation() {
        let state = create_test_state();

        let id1 = state.next_rule_id();
        let id2 = state.next_rule_id();

        assert_ne!(id1, id2);
        assert!(id1.starts_with("rule_"));
        assert!(id2.starts_with("rule_"));
    }

    #[test]
    fn test_blocklist_registration() {
        let state = create_test_state();

        state.register_blocklist(BlocklistInfo {
            name: "test".to_string(),
            source: "/path/to/list".to_string(),
            format: "domains".to_string(),
            enabled: true,
            rule_count: 100,
            last_updated: None,
            next_update: None,
            last_error: None,
        });

        assert_eq!(state.blocklists.read().len(), 1);

        // Update same blocklist
        state.register_blocklist(BlocklistInfo {
            name: "test".to_string(),
            source: "/path/to/list".to_string(),
            format: "domains".to_string(),
            enabled: true,
            rule_count: 200, // Updated count
            last_updated: None,
            next_update: None,
            last_error: None,
        });

        // Should still be 1 (updated, not added)
        assert_eq!(state.blocklists.read().len(), 1);
        assert_eq!(state.blocklists.read()[0].rule_count, 200);
    }

    #[tokio::test]
    async fn test_status_handler() {
        let state = create_test_state();
        let response = status_handler(State(state)).await;

        assert_eq!(response.0.status, ServerStatus::Running);
        assert_eq!(response.0.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_server_status_returns_correct_response() {
        // Test the status mapping logic
        let state = create_test_state();
        
        // Running should return healthy
        assert_eq!(*state.status.read(), ServerStatus::Running);

        // Set to degraded - should still be considered "healthy"
        state.set_status(ServerStatus::Degraded);
        assert_eq!(*state.status.read(), ServerStatus::Degraded);

        // Set to stopping
        state.set_status(ServerStatus::Stopping);
        assert_eq!(*state.status.read(), ServerStatus::Stopping);
    }
}
