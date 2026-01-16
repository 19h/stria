//! Stria DNS Control Utility
//!
//! Command-line tool for managing and monitoring the Stria DNS server.
//!
//! # Examples
//!
//! ```bash
//! # Check server status
//! stria-ctl status
//!
//! # View statistics
//! stria-ctl stats
//! stria-ctl stats queries
//! stria-ctl stats cache
//!
//! # Manage cache
//! stria-ctl cache flush
//! stria-ctl cache lookup example.com
//!
//! # Block management
//! stria-ctl block add ads.example.com
//! stria-ctl block test suspicious.com
//!
//! # Configuration reload
//! stria-ctl reload
//! stria-ctl reload blocklists
//! ```

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use console::{style, Term};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{Read, Write, BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// CLI Structure
// ============================================================================

/// Stria DNS Control Utility
///
/// Communicates with the Stria DNS daemon to perform administrative tasks,
/// view statistics, and manage configuration.
#[derive(Parser, Debug)]
#[command(name = "stria-ctl")]
#[command(author, version, about = "Control utility for Stria DNS server")]
#[command(propagate_version = true)]
#[command(after_help = "EXAMPLES:
    stria-ctl status                    Show server status
    stria-ctl stats                     Show all statistics
    stria-ctl cache flush               Flush the cache
    stria-ctl block add ads.example.com Block a domain
    stria-ctl query example.com A       Test DNS resolution

For more information, visit https://github.com/19h/stria")]
struct Cli {
    /// Control socket path
    #[arg(short, long, global = true, default_value = "/var/run/stria/control.sock")]
    socket: PathBuf,

    /// HTTP control endpoint (overrides socket)
    #[arg(long, global = true, env = "AXIOM_CTL_HTTP")]
    http: Option<String>,

    /// Output as JSON for scripting
    #[arg(long, global = true)]
    json: bool,

    /// Quiet mode (minimal output)
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Connection timeout in seconds
    #[arg(long, global = true, default_value = "5")]
    timeout: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show server status and health
    ///
    /// Displays the current status of the Stria DNS server including
    /// version, uptime, and listener status.
    Status,

    /// Show server statistics
    ///
    /// Displays detailed statistics about queries, cache, and blocking.
    ///
    /// Examples:
    ///   stria-ctl stats           # All statistics
    ///   stria-ctl stats queries   # Query stats only
    ///   stria-ctl stats cache     # Cache stats only
    ///   stria-ctl stats blocks    # Block stats only
    Stats {
        #[command(subcommand)]
        category: Option<StatsCategory>,

        /// Watch mode - refresh every N seconds
        #[arg(short, long)]
        watch: Option<u64>,
    },

    /// Reload configuration
    ///
    /// Reloads the server configuration from disk. Can reload
    /// all configuration or just specific components.
    ///
    /// Examples:
    ///   stria-ctl reload             # Reload all configuration
    ///   stria-ctl reload blocklists  # Reload blocklists only
    Reload {
        #[command(subcommand)]
        what: Option<ReloadTarget>,
    },

    /// Cache management
    ///
    /// Manage the DNS cache including flushing entries and viewing statistics.
    ///
    /// Examples:
    ///   stria-ctl cache flush              # Flush entire cache
    ///   stria-ctl cache flush "*.ads.*"    # Flush matching entries
    ///   stria-ctl cache lookup example.com # Look up cached entry
    ///   stria-ctl cache stats              # Cache statistics
    Cache {
        #[command(subcommand)]
        action: CacheCommands,
    },

    /// Block rules management
    ///
    /// Manage custom block rules. These rules take precedence over
    /// blocklists and persist across restarts.
    ///
    /// Examples:
    ///   stria-ctl block list                      # List custom blocks
    ///   stria-ctl block add ads.example.com       # Block a domain
    ///   stria-ctl block add --pattern "*.ads.*"   # Block pattern
    ///   stria-ctl block remove ads.example.com    # Unblock
    ///   stria-ctl block test suspicious.com       # Test if blocked
    Block {
        #[command(subcommand)]
        action: BlockCommands,
    },

    /// Allowlist management
    ///
    /// Manage domains that should never be blocked, regardless of blocklist rules.
    ///
    /// Examples:
    ///   stria-ctl allow list                    # List allowed domains
    ///   stria-ctl allow add analytics.google.com # Allow a domain
    ///   stria-ctl allow remove analytics.google.com
    Allow {
        #[command(subcommand)]
        action: AllowCommands,
    },

    /// Blocklist management
    ///
    /// Manage blocklist subscriptions, updates, and status.
    ///
    /// Examples:
    ///   stria-ctl blocklist list          # List all blocklists
    ///   stria-ctl blocklist update        # Update all blocklists
    ///   stria-ctl blocklist update oisd   # Update specific blocklist
    ///   stria-ctl blocklist info oisd     # Show blocklist details
    Blocklist {
        #[command(subcommand)]
        action: BlocklistCommands,
    },

    /// Test DNS query (like dig)
    ///
    /// Performs a DNS query through the Stria server and displays the result,
    /// including whether the query was blocked or cached.
    ///
    /// Examples:
    ///   stria-ctl query example.com       # Query A record
    ///   stria-ctl query example.com AAAA  # Query AAAA record
    ///   stria-ctl query example.com MX    # Query MX record
    Query {
        /// Domain name to query
        domain: String,

        /// Record type (A, AAAA, MX, TXT, CNAME, NS, SOA, etc.)
        #[arg(default_value = "A")]
        record_type: String,

        /// Query class (IN, CH, HS)
        #[arg(short, long, default_value = "IN")]
        class: String,

        /// Show timing information
        #[arg(short, long)]
        timing: bool,
    },

    /// View query log
    ///
    /// View or tail the DNS query log. Useful for debugging and monitoring.
    ///
    /// Examples:
    ///   stria-ctl log                # Show recent queries
    ///   stria-ctl log --follow       # Follow log in real-time
    ///   stria-ctl log -n 100         # Show last 100 entries
    ///   stria-ctl log --blocked      # Show only blocked queries
    Log {
        /// Follow log in real-time (like tail -f)
        #[arg(short, long)]
        follow: bool,

        /// Number of lines to show
        #[arg(short = 'n', long, default_value = "20")]
        lines: usize,

        /// Show only blocked queries
        #[arg(long)]
        blocked: bool,

        /// Show only queries matching domain pattern
        #[arg(long)]
        domain: Option<String>,
    },

    /// Graceful server shutdown
    ///
    /// Initiates a graceful shutdown of the Stria DNS server.
    /// Requires confirmation unless --force is specified.
    Shutdown {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,

        /// Shutdown timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
}

// ============================================================================
// Stats Subcommands
// ============================================================================

#[derive(Subcommand, Debug, Clone)]
enum StatsCategory {
    /// Query statistics
    Queries,
    /// Cache statistics
    Cache,
    /// Block/filter statistics
    Blocks,
    /// Upstream resolver statistics
    Upstream,
    /// Protocol-specific statistics (UDP/TCP/DoT/DoH/DoQ)
    Protocol,
}

// ============================================================================
// Reload Subcommands
// ============================================================================

#[derive(Subcommand, Debug, Clone)]
enum ReloadTarget {
    /// Reload blocklists only
    Blocklists,
    /// Reload zone files only
    Zones,
    /// Reload TLS certificates
    Tls,
}

// ============================================================================
// Cache Subcommands
// ============================================================================

#[derive(Subcommand, Debug)]
enum CacheCommands {
    /// Flush cache entries
    ///
    /// Removes entries from the DNS cache. With no pattern,
    /// flushes the entire cache.
    Flush {
        /// Pattern to match (e.g., "*.ads.*", "example.com")
        pattern: Option<String>,

        /// Skip confirmation for full flush
        #[arg(long)]
        force: bool,
    },

    /// Look up a specific cache entry
    Lookup {
        /// Domain name to look up
        domain: String,

        /// Record type
        #[arg(short = 't', long, default_value = "A")]
        record_type: String,
    },

    /// Show cache statistics
    Stats,
}

// ============================================================================
// Block Subcommands
// ============================================================================

#[derive(Subcommand, Debug)]
enum BlockCommands {
    /// List custom block rules
    List {
        /// Filter by pattern
        #[arg(long)]
        filter: Option<String>,
    },

    /// Add a domain to the block list
    Add {
        /// Domain or pattern to block
        domain: String,

        /// Use pattern matching (supports wildcards)
        #[arg(long)]
        pattern: bool,

        /// Comment/reason for blocking
        #[arg(long)]
        comment: Option<String>,
    },

    /// Remove a domain from the block list
    Remove {
        /// Domain or pattern to unblock
        domain: String,
    },

    /// Test if a domain would be blocked
    Test {
        /// Domain to test
        domain: String,
    },
}

// ============================================================================
// Allow Subcommands
// ============================================================================

#[derive(Subcommand, Debug)]
enum AllowCommands {
    /// List allowed domains
    List {
        /// Filter by pattern
        #[arg(long)]
        filter: Option<String>,
    },

    /// Add a domain to the allowlist
    Add {
        /// Domain to allow
        domain: String,

        /// Comment/reason
        #[arg(long)]
        comment: Option<String>,
    },

    /// Remove a domain from the allowlist
    Remove {
        /// Domain to remove
        domain: String,
    },
}

// ============================================================================
// Blocklist Subcommands
// ============================================================================

#[derive(Subcommand, Debug)]
enum BlocklistCommands {
    /// List all blocklists with status
    List,

    /// Update blocklists
    Update {
        /// Specific blocklist name (updates all if not specified)
        name: Option<String>,
    },

    /// Show detailed information about a blocklist
    Info {
        /// Blocklist name
        name: String,
    },

    /// Enable a blocklist
    Enable {
        /// Blocklist name
        name: String,
    },

    /// Disable a blocklist
    Disable {
        /// Blocklist name
        name: String,
    },
}

// ============================================================================
// API Response Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StatusResponse {
    status: String,
    version: String,
    uptime_secs: u64,
    pid: u32,
    workers: usize,
    listeners: Vec<ListenerInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListenerInfo {
    protocol: String,
    address: String,
    port: u16,
    active: bool,
    connections: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StatsResponse {
    queries: QueryStats,
    cache: CacheStatsResponse,
    blocks: BlockStats,
    upstream: UpstreamStats,
    protocol: ProtocolStats,
}

#[derive(Debug, Serialize, Deserialize)]
struct QueryStats {
    total: u64,
    success: u64,
    failed: u64,
    blocked: u64,
    cached: u64,
    avg_latency_ms: f64,
    qps: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheStatsResponse {
    entries: usize,
    capacity: usize,
    memory_bytes: usize,
    hits: u64,
    misses: u64,
    hit_rate: f64,
    stale_serves: u64,
    prefetches: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockStats {
    total_rules: usize,
    exact_rules: usize,
    pattern_rules: usize,
    blocklist_count: usize,
    blocked_queries: u64,
    allowed_by_whitelist: u64,
    last_update: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UpstreamStats {
    servers: Vec<UpstreamServerStats>,
    total_queries: u64,
    total_failures: u64,
    avg_latency_ms: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct UpstreamServerStats {
    address: String,
    queries: u64,
    failures: u64,
    avg_latency_ms: f64,
    healthy: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProtocolStats {
    udp_queries: u64,
    tcp_queries: u64,
    dot_queries: u64,
    doh_queries: u64,
    doq_queries: u64,
    tcp_connections: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheLookupResponse {
    found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry: Option<CacheEntryInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntryInfo {
    name: String,
    record_type: String,
    records: Vec<RecordInfo>,
    ttl_remaining: u64,
    created_at: String,
    stale: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecordInfo {
    rdata: String,
    ttl: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockRuleInfo {
    domain: String,
    rule_type: String,
    action: String,
    source: Option<String>,
    comment: Option<String>,
    created_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockTestResponse {
    domain: String,
    blocked: bool,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocklist: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlocklistInfo {
    name: String,
    source: String,
    format: String,
    enabled: bool,
    rule_count: usize,
    last_updated: Option<String>,
    next_update: Option<String>,
    status: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct QueryResponse {
    domain: String,
    record_type: String,
    status: String,
    answers: Vec<QueryAnswer>,
    blocked: bool,
    cached: bool,
    latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_by: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct QueryAnswer {
    name: String,
    record_type: String,
    ttl: u32,
    rdata: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogEntry {
    timestamp: String,
    client: String,
    domain: String,
    record_type: String,
    status: String,
    latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_by: Option<String>,
}

// ============================================================================
// Control Client
// ============================================================================

struct ControlClient {
    socket_path: Option<PathBuf>,
    http_endpoint: Option<String>,
    timeout: Duration,
}

impl ControlClient {
    fn new(socket_path: Option<PathBuf>, http_endpoint: Option<String>, timeout: Duration) -> Self {
        Self {
            socket_path,
            http_endpoint,
            timeout,
        }
    }

    /// Send a GET request to the control API
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request("GET", path, None::<()>).await
    }

    /// Send a POST request to the control API
    async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: Option<B>) -> Result<T> {
        self.request("POST", path, body).await
    }

    /// Send a DELETE request to the control API
    async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request("DELETE", path, None::<()>).await
    }

    async fn request<T: DeserializeOwned, B: Serialize>(
        &self,
        method: &str,
        path: &str,
        body: Option<B>,
    ) -> Result<T> {
        if let Some(ref endpoint) = self.http_endpoint {
            self.http_request(method, &format!("{}{}", endpoint, path), body).await
        } else if let Some(ref socket) = self.socket_path {
            self.socket_request(method, path, body).await
        } else {
            bail!("No control socket or HTTP endpoint available");
        }
    }

    async fn http_request<T: DeserializeOwned, B: Serialize>(
        &self,
        method: &str,
        url: &str,
        body: Option<B>,
    ) -> Result<T> {
        // Build HTTP/1.1 request manually for simplicity
        // In production, would use reqwest or similar
        
        let url = url::Url::parse(url).context("Invalid URL")?;
        let host = url.host_str().context("Missing host")?;
        let port = url.port().unwrap_or(80);
        
        let addr = format!("{}:{}", host, port);
        let mut stream = std::net::TcpStream::connect_timeout(
            &addr.parse().context("Invalid address")?,
            self.timeout,
        ).context("Failed to connect to HTTP endpoint")?;
        
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        
        let body_str = body.map(|b| serde_json::to_string(&b)).transpose()?;
        let content_len = body_str.as_ref().map(|s| s.len()).unwrap_or(0);
        
        let request = if let Some(ref body) = body_str {
            format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                method, url.path(), host, content_len, body
            )
        } else {
            format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                method, url.path(), host
            )
        };
        
        stream.write_all(request.as_bytes())?;
        
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        
        // Parse HTTP response
        let body_start = response.find("\r\n\r\n")
            .context("Invalid HTTP response")?;
        let body = &response[body_start + 4..];
        
        serde_json::from_str(body).context("Failed to parse response")
    }

    async fn socket_request<T: DeserializeOwned, B: Serialize>(
        &self,
        method: &str,
        path: &str,
        body: Option<B>,
    ) -> Result<T> {
        let socket_path = self.socket_path.as_ref()
            .context("Socket path not set")?;
        
        let mut stream = UnixStream::connect(socket_path)
            .with_context(|| format!("Failed to connect to {}", socket_path.display()))?;
        
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        
        // Send request in simple line-based protocol:
        // METHOD PATH
        // [JSON body if present]
        // 
        let body_str = body.map(|b| serde_json::to_string(&b)).transpose()?;
        
        let request = if let Some(ref body) = body_str {
            format!("{} {}\n{}\n", method, path, body)
        } else {
            format!("{} {}\n\n", method, path)
        };
        
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        
        // Read response
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;
        
        // Response format:
        // STATUS (OK or ERROR)
        // JSON body
        let status_line = response.trim();
        
        let mut json_body = String::new();
        reader.read_to_string(&mut json_body)?;
        
        if status_line.starts_with("ERROR") {
            let error_msg = status_line.strip_prefix("ERROR ").unwrap_or("Unknown error");
            bail!("Server error: {}", error_msg);
        }
        
        serde_json::from_str(&json_body)
            .with_context(|| format!("Failed to parse response: {}", json_body))
    }

    /// Check if the control socket is available
    fn is_available(&self) -> bool {
        if let Some(ref socket) = self.socket_path {
            socket.exists()
        } else if self.http_endpoint.is_some() {
            true // Assume HTTP endpoint might be available
        } else {
            false
        }
    }
}

// ============================================================================
// Output Formatting
// ============================================================================

fn print_status(status: &StatusResponse, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(status).unwrap());
        return;
    }

    let status_indicator = match status.status.as_str() {
        "running" => style("●").green(),
        "degraded" => style("●").yellow(),
        _ => style("●").red(),
    };

    println!("{} {}", status_indicator, style("Stria DNS Server").bold());
    println!();
    println!("  {}  {}", style("Version:").dim(), status.version);
    println!("  {}  {}", style("PID:").dim(), status.pid);
    println!("  {}  {}", style("Workers:").dim(), status.workers);
    println!("  {}  {}", style("Uptime:").dim(), format_duration(status.uptime_secs));
    
    if let Some(ref path) = status.config_path {
        println!("  {}  {}", style("Config:").dim(), path);
    }
    
    println!();
    println!("{}", style("Listeners").cyan().bold());
    
    for listener in &status.listeners {
        let status_icon = if listener.active {
            style("✓").green()
        } else {
            style("✗").red()
        };
        
        let conn_info = listener.connections
            .map(|c| format!(" ({} connections)", c))
            .unwrap_or_default();
        
        println!("  {} {} :{} {}{}",
            status_icon,
            style(&listener.protocol).cyan(),
            listener.port,
            listener.address,
            style(conn_info).dim()
        );
    }
}

fn print_stats(stats: &StatsResponse, json: bool, category: Option<StatsCategory>) {
    if json {
        let output = match category {
            Some(StatsCategory::Queries) => serde_json::to_string_pretty(&stats.queries),
            Some(StatsCategory::Cache) => serde_json::to_string_pretty(&stats.cache),
            Some(StatsCategory::Blocks) => serde_json::to_string_pretty(&stats.blocks),
            Some(StatsCategory::Upstream) => serde_json::to_string_pretty(&stats.upstream),
            Some(StatsCategory::Protocol) => serde_json::to_string_pretty(&stats.protocol),
            None => serde_json::to_string_pretty(stats),
        };
        println!("{}", output.unwrap());
        return;
    }

    match category {
        Some(StatsCategory::Queries) => print_query_stats(&stats.queries),
        Some(StatsCategory::Cache) => print_cache_stats(&stats.cache),
        Some(StatsCategory::Blocks) => print_block_stats(&stats.blocks),
        Some(StatsCategory::Upstream) => print_upstream_stats(&stats.upstream),
        Some(StatsCategory::Protocol) => print_protocol_stats(&stats.protocol),
        None => {
            print_query_stats(&stats.queries);
            println!();
            print_cache_stats(&stats.cache);
            println!();
            print_block_stats(&stats.blocks);
        }
    }
}

fn print_query_stats(stats: &QueryStats) {
    println!("{}", style("Query Statistics").cyan().bold());
    println!("  {}    {:>12}", style("Total:").dim(), format_number(stats.total));
    println!("  {}  {:>12} ({}%)", 
        style("Success:").dim(),
        format_number(stats.success),
        format_percentage(stats.success, stats.total));
    println!("  {}   {:>12} ({}%)", 
        style("Failed:").dim(),
        format_number(stats.failed),
        format_percentage(stats.failed, stats.total));
    println!("  {}  {:>12} ({}%)", 
        style("Blocked:").dim(),
        format_number(stats.blocked),
        format_percentage(stats.blocked, stats.total));
    println!("  {}   {:>12} ({}%)", 
        style("Cached:").dim(),
        format_number(stats.cached),
        format_percentage(stats.cached, stats.total));
    println!("  {} {:>12.2}ms", style("Avg Latency:").dim(), stats.avg_latency_ms);
    println!("  {}      {:>12.1}", style("QPS:").dim(), stats.qps);
}

fn print_cache_stats(stats: &CacheStatsResponse) {
    println!("{}", style("Cache Statistics").cyan().bold());
    println!("  {}  {:>12}", style("Entries:").dim(), format_number(stats.entries as u64));
    println!("  {} {:>12}", style("Capacity:").dim(), format_number(stats.capacity as u64));
    println!("  {}   {:>12}", style("Memory:").dim(), format_bytes(stats.memory_bytes));
    println!("  {}     {:>12}", style("Hits:").dim(), format_number(stats.hits));
    println!("  {}   {:>12}", style("Misses:").dim(), format_number(stats.misses));
    println!("  {} {:>12.1}%", style("Hit Rate:").dim(), stats.hit_rate * 100.0);
    if stats.stale_serves > 0 {
        println!("  {}    {:>12}", style("Stale:").dim(), format_number(stats.stale_serves));
    }
    if stats.prefetches > 0 {
        println!("  {} {:>12}", style("Prefetches:").dim(), format_number(stats.prefetches));
    }
}

fn print_block_stats(stats: &BlockStats) {
    println!("{}", style("Blocking Statistics").cyan().bold());
    println!("  {}   {:>12}", style("Total Rules:").dim(), format_number(stats.total_rules as u64));
    println!("  {}   {:>12}", style("Exact Match:").dim(), format_number(stats.exact_rules as u64));
    println!("  {}     {:>12}", style("Patterns:").dim(), format_number(stats.pattern_rules as u64));
    println!("  {}   {:>12}", style("Blocklists:").dim(), stats.blocklist_count);
    println!("  {}      {:>12}", style("Blocked:").dim(), format_number(stats.blocked_queries));
    println!("  {}    {:>12}", style("Allowlisted:").dim(), format_number(stats.allowed_by_whitelist));
    if let Some(ref last_update) = stats.last_update {
        println!("  {}  {}", style("Last Update:").dim(), last_update);
    }
}

fn print_upstream_stats(stats: &UpstreamStats) {
    println!("{}", style("Upstream Statistics").cyan().bold());
    println!("  {}  {:>12}", style("Total Queries:").dim(), format_number(stats.total_queries));
    println!("  {}    {:>12}", style("Failures:").dim(), format_number(stats.total_failures));
    println!("  {} {:>12.2}ms", style("Avg Latency:").dim(), stats.avg_latency_ms);
    
    println!();
    println!("  {}", style("Servers:").dim());
    for server in &stats.servers {
        let health_icon = if server.healthy {
            style("●").green()
        } else {
            style("●").red()
        };
        println!("    {} {} - {} queries, {:.1}ms avg",
            health_icon,
            server.address,
            format_number(server.queries),
            server.avg_latency_ms
        );
    }
}

fn print_protocol_stats(stats: &ProtocolStats) {
    println!("{}", style("Protocol Statistics").cyan().bold());
    println!("  {}   {:>12}", style("UDP:").dim(), format_number(stats.udp_queries));
    println!("  {}   {:>12}", style("TCP:").dim(), format_number(stats.tcp_queries));
    println!("  {}   {:>12}", style("DoT:").dim(), format_number(stats.dot_queries));
    println!("  {}   {:>12}", style("DoH:").dim(), format_number(stats.doh_queries));
    println!("  {}   {:>12}", style("DoQ:").dim(), format_number(stats.doq_queries));
    println!();
    println!("  {} {:>12}", style("TCP Conns:").dim(), format_number(stats.tcp_connections));
}

fn print_cache_lookup(lookup: &CacheLookupResponse, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(lookup).unwrap());
        return;
    }

    if !lookup.found {
        println!("{}", style("Not found in cache").yellow());
        return;
    }

    if let Some(ref entry) = lookup.entry {
        let stale_marker = if entry.stale {
            format!(" {}", style("(stale)").yellow())
        } else {
            String::new()
        };
        
        println!("{} {} {}{}", 
            style("Cache entry:").green().bold(),
            entry.name,
            entry.record_type,
            stale_marker
        );
        println!("  {}  {}", style("Created:").dim(), entry.created_at);
        println!("  {}  {}s remaining", style("TTL:").dim(), entry.ttl_remaining);
        println!();
        
        for record in &entry.records {
            println!("  {} {} IN {} {}", 
                entry.name,
                record.ttl,
                entry.record_type,
                record.rdata
            );
        }
    }
}

fn print_block_rules(rules: &[BlockRuleInfo], json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(rules).unwrap());
        return;
    }

    if rules.is_empty() {
        println!("{}", style("No custom block rules").dim());
        return;
    }

    println!("{}", style("Custom Block Rules").cyan().bold());
    println!();
    
    for rule in rules {
        let type_indicator = match rule.rule_type.as_str() {
            "exact" => "",
            "suffix" => "*.",
            "pattern" => "~",
            _ => "?",
        };
        
        println!("  {} {}{}",
            style("●").red(),
            type_indicator,
            rule.domain
        );
        
        if let Some(ref comment) = rule.comment {
            println!("    {}", style(comment).dim());
        }
        
        if let Some(ref source) = rule.source {
            println!("    {} {}", style("from:").dim(), source);
        }
    }
}

fn print_block_test(result: &BlockTestResponse, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(result).unwrap());
        return;
    }

    if result.blocked {
        println!("{} is {}", result.domain, style("BLOCKED").red().bold());
        if let Some(ref rule) = result.matched_rule {
            println!("  {} {}", style("Matched:").dim(), rule);
        }
        if let Some(ref blocklist) = result.blocklist {
            println!("  {} {}", style("From:").dim(), blocklist);
        }
    } else {
        println!("{} is {}", result.domain, style("ALLOWED").green().bold());
    }
}

fn print_blocklists(lists: &[BlocklistInfo], json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(lists).unwrap());
        return;
    }

    println!("{}", style("Blocklists").cyan().bold());
    println!();
    
    for list in lists {
        let status_icon = match (list.enabled, list.status.as_str()) {
            (false, _) => style("○").dim(),
            (true, "ok") => style("●").green(),
            (true, "updating") => style("●").yellow(),
            (true, _) => style("●").red(),
        };
        
        let enabled_text = if list.enabled { "" } else { " (disabled)" };
        
        println!("  {} {}{}",
            status_icon,
            style(&list.name).bold(),
            style(enabled_text).dim()
        );
        println!("    {} {}", style("Rules:").dim(), format_number(list.rule_count as u64));
        println!("    {} {}", style("Format:").dim(), list.format);
        
        if let Some(ref updated) = list.last_updated {
            println!("    {} {}", style("Updated:").dim(), updated);
        }
    }
}

fn print_query_result(result: &QueryResponse, json: bool, timing: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(result).unwrap());
        return;
    }

    // Header
    println!();
    
    if result.blocked {
        println!("{} Query blocked", style(";;").red());
        if let Some(ref by) = result.blocked_by {
            println!("{} Blocked by: {}", style(";;").dim(), by);
        }
    } else {
        println!("{} {} query for {}", 
            style(";;").dim(),
            result.record_type,
            result.domain
        );
    }
    
    if result.cached {
        println!("{} Served from cache", style(";;").dim());
    }
    
    println!();
    
    // Answer section
    if result.answers.is_empty() {
        println!("{} No answer", style(";;").yellow());
    } else {
        println!("{}", style(";; ANSWER SECTION:").dim());
        for answer in &result.answers {
            println!("{}\t{}\tIN\t{}\t{}",
                answer.name,
                answer.ttl,
                answer.record_type,
                answer.rdata
            );
        }
    }
    
    // Timing
    if timing {
        println!();
        println!("{} Query time: {:.2}ms", style(";;").dim(), result.latency_ms);
    }
}

fn print_log_entries(entries: &[LogEntry], json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(entries).unwrap());
        return;
    }

    for entry in entries {
        let status_style = match entry.status.as_str() {
            "blocked" => style(&entry.status).red(),
            "cached" => style(&entry.status).green(),
            "success" => style(&entry.status).green(),
            "error" | "servfail" => style(&entry.status).red(),
            _ => style(&entry.status).dim(),
        };
        
        let blocked_info = entry.blocked_by.as_ref()
            .map(|b| format!(" [{}]", b))
            .unwrap_or_default();
        
        println!("{} {} {} {} {} {:.1}ms{}",
            style(&entry.timestamp).dim(),
            entry.client,
            entry.domain,
            entry.record_type,
            status_style,
            entry.latency_ms,
            style(blocked_info).dim()
        );
    }
}

// ============================================================================
// Formatting Helpers
// ============================================================================

fn format_duration(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 10_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else if n >= 1_000 {
        // Use thousands separator for readability
        let s = n.to_string();
        let bytes: Vec<_> = s.bytes().rev().collect();
        let chunks: Vec<_> = bytes.chunks(3)
            .map(|chunk| chunk.iter().rev().map(|&b| b as char).collect::<String>())
            .collect();
        chunks.into_iter().rev().collect::<Vec<_>>().join(",")
    } else {
        n.to_string()
    }
}

fn format_percentage(part: u64, total: u64) -> String {
    if total == 0 {
        "0.0".to_string()
    } else {
        format!("{:.1}", (part as f64 / total as f64) * 100.0)
    }
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

// ============================================================================
// Command Handlers
// ============================================================================

async fn handle_status(client: &ControlClient, json: bool) -> Result<()> {
    let status: StatusResponse = client.get("/v1/status").await?;
    print_status(&status, json);
    Ok(())
}

async fn handle_stats(
    client: &ControlClient,
    json: bool,
    category: Option<StatsCategory>,
    watch: Option<u64>,
) -> Result<()> {
    if let Some(interval) = watch {
        let term = Term::stdout();
        loop {
            term.clear_screen()?;
            let stats: StatsResponse = client.get("/v1/stats").await?;
            print_stats(&stats, json, category.clone());
            println!();
            println!("{}", style(format!("Refreshing every {}s (Ctrl+C to stop)", interval)).dim());
            tokio::time::sleep(Duration::from_secs(interval)).await;
        }
    } else {
        let stats: StatsResponse = client.get("/v1/stats").await?;
        print_stats(&stats, json, category);
    }
    Ok(())
}

async fn handle_reload(
    client: &ControlClient,
    json: bool,
    quiet: bool,
    target: Option<ReloadTarget>,
) -> Result<()> {
    let path = match target {
        Some(ReloadTarget::Blocklists) => "/v1/reload/blocklists",
        Some(ReloadTarget::Zones) => "/v1/reload/zones",
        Some(ReloadTarget::Tls) => "/v1/reload/tls",
        None => "/v1/reload",
    };

    let pb = if !quiet && !json {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap()
        );
        let msg = match target {
            Some(ReloadTarget::Blocklists) => "Reloading blocklists...",
            Some(ReloadTarget::Zones) => "Reloading zones...",
            Some(ReloadTarget::Tls) => "Reloading TLS certificates...",
            None => "Reloading configuration...",
        };
        pb.set_message(msg);
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    let response: ApiResponse<()> = client.post(path, None::<()>).await?;

    if let Some(pb) = pb {
        if response.success {
            pb.finish_with_message("Reload complete");
        } else {
            pb.finish_with_message("Reload failed");
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    } else if !quiet && !response.success {
        if let Some(error) = response.error {
            eprintln!("{} {}", style("Error:").red().bold(), error);
        }
    }

    if !response.success {
        std::process::exit(1);
    }

    Ok(())
}

async fn handle_cache(
    client: &ControlClient,
    json: bool,
    quiet: bool,
    action: CacheCommands,
) -> Result<()> {
    match action {
        CacheCommands::Flush { pattern, force } => {
            // Confirm full cache flush
            if pattern.is_none() && !force && !quiet {
                let confirm = dialoguer::Confirm::new()
                    .with_prompt("Flush entire cache?")
                    .default(false)
                    .interact()?;

                if !confirm {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            let path = match pattern {
                Some(ref p) => format!("/v1/cache/flush?pattern={}", urlencoding::encode(p)),
                None => "/v1/cache/flush".to_string(),
            };

            let pb = if !quiet && !json {
                let pb = ProgressBar::new_spinner();
                pb.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.green} {msg}")
                        .unwrap()
                );
                pb.set_message("Flushing cache...");
                pb.enable_steady_tick(Duration::from_millis(100));
                Some(pb)
            } else {
                None
            };

            #[derive(Deserialize, Serialize)]
            struct FlushResponse {
                flushed: u64,
            }

            let response: FlushResponse = client.post(&path, None::<()>).await?;

            if let Some(pb) = pb {
                pb.finish_with_message(format!("Flushed {} entries", format_number(response.flushed)));
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&response).unwrap());
            }
        }

        CacheCommands::Lookup { domain, record_type } => {
            let path = format!(
                "/v1/cache/lookup?domain={}&type={}",
                urlencoding::encode(&domain),
                urlencoding::encode(&record_type)
            );
            let response: CacheLookupResponse = client.get(&path).await?;
            print_cache_lookup(&response, json);
        }

        CacheCommands::Stats => {
            let stats: CacheStatsResponse = client.get("/v1/cache/stats").await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&stats).unwrap());
            } else {
                print_cache_stats(&stats);
            }
        }
    }
    Ok(())
}

async fn handle_block(
    client: &ControlClient,
    json: bool,
    action: BlockCommands,
) -> Result<()> {
    match action {
        BlockCommands::List { filter } => {
            let path = match filter {
                Some(ref f) => format!("/v1/block/rules?filter={}", urlencoding::encode(f)),
                None => "/v1/block/rules".to_string(),
            };
            let rules: Vec<BlockRuleInfo> = client.get(&path).await?;
            print_block_rules(&rules, json);
        }

        BlockCommands::Add { domain, pattern, comment } => {
            #[derive(Serialize)]
            struct AddBlockRequest {
                domain: String,
                pattern: bool,
                comment: Option<String>,
            }

            let body = AddBlockRequest { domain: domain.clone(), pattern, comment };
            let response: ApiResponse<()> = client.post("/v1/block/rules", Some(body)).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&response).unwrap());
            } else if response.success {
                println!("{} {} added to block list", style("✓").green(), domain);
            } else if let Some(error) = response.error {
                eprintln!("{} {}", style("Error:").red(), error);
                std::process::exit(1);
            }
        }

        BlockCommands::Remove { domain } => {
            let path = format!("/v1/block/rules/{}", urlencoding::encode(&domain));
            let response: ApiResponse<()> = client.delete(&path).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&response).unwrap());
            } else if response.success {
                println!("{} {} removed from block list", style("✓").green(), domain);
            } else if let Some(error) = response.error {
                eprintln!("{} {}", style("Error:").red(), error);
                std::process::exit(1);
            }
        }

        BlockCommands::Test { domain } => {
            let path = format!("/v1/block/test?domain={}", urlencoding::encode(&domain));
            let result: BlockTestResponse = client.get(&path).await?;
            print_block_test(&result, json);
        }
    }
    Ok(())
}

async fn handle_allow(
    client: &ControlClient,
    json: bool,
    action: AllowCommands,
) -> Result<()> {
    match action {
        AllowCommands::List { filter } => {
            let path = match filter {
                Some(ref f) => format!("/v1/allow/rules?filter={}", urlencoding::encode(f)),
                None => "/v1/allow/rules".to_string(),
            };
            let rules: Vec<BlockRuleInfo> = client.get(&path).await?;
            
            if json {
                println!("{}", serde_json::to_string_pretty(&rules).unwrap());
            } else if rules.is_empty() {
                println!("{}", style("No allowlist entries").dim());
            } else {
                println!("{}", style("Allowlist").cyan().bold());
                for rule in &rules {
                    println!("  {} {}", style("●").green(), rule.domain);
                    if let Some(ref comment) = rule.comment {
                        println!("    {}", style(comment).dim());
                    }
                }
            }
        }

        AllowCommands::Add { domain, comment } => {
            #[derive(Serialize)]
            struct AddAllowRequest {
                domain: String,
                comment: Option<String>,
            }

            let body = AddAllowRequest { domain: domain.clone(), comment };
            let response: ApiResponse<()> = client.post("/v1/allow/rules", Some(body)).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&response).unwrap());
            } else if response.success {
                println!("{} {} added to allowlist", style("✓").green(), domain);
            } else if let Some(error) = response.error {
                eprintln!("{} {}", style("Error:").red(), error);
                std::process::exit(1);
            }
        }

        AllowCommands::Remove { domain } => {
            let path = format!("/v1/allow/rules/{}", urlencoding::encode(&domain));
            let response: ApiResponse<()> = client.delete(&path).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&response).unwrap());
            } else if response.success {
                println!("{} {} removed from allowlist", style("✓").green(), domain);
            } else if let Some(error) = response.error {
                eprintln!("{} {}", style("Error:").red(), error);
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

async fn handle_blocklist(
    client: &ControlClient,
    json: bool,
    quiet: bool,
    action: BlocklistCommands,
) -> Result<()> {
    match action {
        BlocklistCommands::List => {
            let lists: Vec<BlocklistInfo> = client.get("/v1/blocklists").await?;
            print_blocklists(&lists, json);
        }

        BlocklistCommands::Update { name } => {
            let path = match name {
                Some(ref n) => format!("/v1/blocklists/{}/update", urlencoding::encode(n)),
                None => "/v1/blocklists/update".to_string(),
            };

            let pb = if !quiet && !json {
                let pb = ProgressBar::new_spinner();
                pb.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.green} {msg}")
                        .unwrap()
                );
                let msg = match &name {
                    Some(n) => format!("Updating {}...", n),
                    None => "Updating all blocklists...".to_string(),
                };
                pb.set_message(msg);
                pb.enable_steady_tick(Duration::from_millis(100));
                Some(pb)
            } else {
                None
            };

            #[derive(Deserialize, Serialize)]
            struct UpdateResponse {
                updated: usize,
                total_rules: usize,
            }

            let response: UpdateResponse = client.post(&path, None::<()>).await?;

            if let Some(pb) = pb {
                pb.finish_with_message(format!(
                    "Updated {} blocklist(s), {} total rules",
                    response.updated,
                    format_number(response.total_rules as u64)
                ));
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&response).unwrap());
            }
        }

        BlocklistCommands::Info { name } => {
            let path = format!("/v1/blocklists/{}", urlencoding::encode(&name));
            let info: BlocklistInfo = client.get(&path).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&info).unwrap());
            } else {
                println!("{}", style(&info.name).cyan().bold());
                println!();
                println!("  {} {}", style("Source:").dim(), info.source);
                println!("  {} {}", style("Format:").dim(), info.format);
                println!("  {} {}", style("Enabled:").dim(), 
                    if info.enabled { style("yes").green() } else { style("no").red() });
                println!("  {} {}", style("Rules:").dim(), format_number(info.rule_count as u64));
                println!("  {} {}", style("Status:").dim(), info.status);
                if let Some(ref updated) = info.last_updated {
                    println!("  {} {}", style("Last Updated:").dim(), updated);
                }
                if let Some(ref next) = info.next_update {
                    println!("  {} {}", style("Next Update:").dim(), next);
                }
            }
        }

        BlocklistCommands::Enable { name } => {
            let path = format!("/v1/blocklists/{}/enable", urlencoding::encode(&name));
            let response: ApiResponse<()> = client.post(&path, None::<()>).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&response).unwrap());
            } else if response.success {
                println!("{} {} enabled", style("✓").green(), name);
            } else if let Some(error) = response.error {
                eprintln!("{} {}", style("Error:").red(), error);
                std::process::exit(1);
            }
        }

        BlocklistCommands::Disable { name } => {
            let path = format!("/v1/blocklists/{}/disable", urlencoding::encode(&name));
            let response: ApiResponse<()> = client.post(&path, None::<()>).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&response).unwrap());
            } else if response.success {
                println!("{} {} disabled", style("✓").green(), name);
            } else if let Some(error) = response.error {
                eprintln!("{} {}", style("Error:").red(), error);
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

async fn handle_query(
    client: &ControlClient,
    json: bool,
    domain: String,
    record_type: String,
    _class: String,
    timing: bool,
) -> Result<()> {
    let path = format!(
        "/v1/query?domain={}&type={}",
        urlencoding::encode(&domain),
        urlencoding::encode(&record_type)
    );

    let result: QueryResponse = client.get(&path).await?;
    print_query_result(&result, json, timing);
    Ok(())
}

async fn handle_log(
    client: &ControlClient,
    json: bool,
    follow: bool,
    lines: usize,
    blocked: bool,
    domain: Option<String>,
) -> Result<()> {
    let mut path = format!("/v1/logs?lines={}", lines);
    if blocked {
        path.push_str("&blocked=true");
    }
    if let Some(ref d) = domain {
        path.push_str(&format!("&domain={}", urlencoding::encode(d)));
    }

    if follow {
        // For follow mode, we'd want to use SSE or websockets
        // For now, poll periodically
        let mut last_timestamp = String::new();
        
        loop {
            let entries: Vec<LogEntry> = client.get(&path).await?;
            
            for entry in &entries {
                if entry.timestamp > last_timestamp {
                    if json {
                        println!("{}", serde_json::to_string(&entry).unwrap());
                    } else {
                        print_log_entries(&[entry.clone()], false);
                    }
                    last_timestamp = entry.timestamp.clone();
                }
            }
            
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    } else {
        let entries: Vec<LogEntry> = client.get(&path).await?;
        print_log_entries(&entries, json);
    }

    Ok(())
}

async fn handle_shutdown(
    client: &ControlClient,
    json: bool,
    force: bool,
    timeout: u64,
) -> Result<()> {
    if !force {
        let confirm = dialoguer::Confirm::new()
            .with_prompt("Are you sure you want to shutdown the server?")
            .default(false)
            .interact()?;

        if !confirm {
            println!("Aborted.");
            return Ok(());
        }
    }

    #[derive(Serialize)]
    struct ShutdownRequest {
        timeout_secs: u64,
    }

    let body = ShutdownRequest { timeout_secs: timeout };
    let response: ApiResponse<()> = client.post("/v1/shutdown", Some(body)).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    } else if response.success {
        println!("{} Shutdown initiated", style("✓").green());
    } else if let Some(error) = response.error {
        eprintln!("{} {}", style("Error:").red(), error);
        std::process::exit(1);
    }

    Ok(())
}

// ============================================================================
// Main Entry Point
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Determine socket path - check multiple locations
    let socket_path = if cli.socket.exists() {
        Some(cli.socket.clone())
    } else {
        // Try common locations
        let candidates = [
            PathBuf::from("/var/run/stria/control.sock"),
            PathBuf::from("/run/stria/control.sock"),
            dirs::runtime_dir().map(|p| p.join("stria/control.sock")).unwrap_or_default(),
            PathBuf::from("/tmp/stria.sock"),
        ];
        
        candidates.into_iter().find(|p| p.exists())
    };

    let client = ControlClient::new(
        socket_path.clone(),
        cli.http.clone(),
        Duration::from_secs(cli.timeout),
    );

    // Check connectivity
    if !client.is_available() && cli.http.is_none() {
        if cli.json {
            let error = serde_json::json!({
                "error": "Cannot connect to Stria daemon",
                "socket": cli.socket.display().to_string(),
                "hint": "Is the server running? Check with 'systemctl status stria'"
            });
            eprintln!("{}", error);
        } else {
            eprintln!("{} Cannot connect to Stria daemon", style("Error:").red().bold());
            eprintln!();
            eprintln!("  Socket: {}", cli.socket.display());
            eprintln!();
            eprintln!("  Possible solutions:");
            eprintln!("    - Check if stria is running: systemctl status stria");
            eprintln!("    - Specify socket path: stria-ctl -s /path/to/socket status");
            eprintln!("    - Use HTTP endpoint: stria-ctl --http http://localhost:8080 status");
        }
        std::process::exit(1);
    }

    let result = match cli.command {
        Commands::Status => handle_status(&client, cli.json).await,
        
        Commands::Stats { category, watch } => {
            handle_stats(&client, cli.json, category, watch).await
        }
        
        Commands::Reload { what } => {
            handle_reload(&client, cli.json, cli.quiet, what).await
        }
        
        Commands::Cache { action } => {
            handle_cache(&client, cli.json, cli.quiet, action).await
        }
        
        Commands::Block { action } => {
            handle_block(&client, cli.json, action).await
        }
        
        Commands::Allow { action } => {
            handle_allow(&client, cli.json, action).await
        }
        
        Commands::Blocklist { action } => {
            handle_blocklist(&client, cli.json, cli.quiet, action).await
        }
        
        Commands::Query { domain, record_type, class, timing } => {
            handle_query(&client, cli.json, domain, record_type, class, timing).await
        }
        
        Commands::Log { follow, lines, blocked, domain } => {
            handle_log(&client, cli.json, follow, lines, blocked, domain).await
        }
        
        Commands::Shutdown { force, timeout } => {
            handle_shutdown(&client, cli.json, force, timeout).await
        }
    };

    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            if cli.json {
                let error = serde_json::json!({
                    "success": false,
                    "error": e.to_string()
                });
                eprintln!("{}", error);
            } else {
                eprintln!("{} {}", style("Error:").red().bold(), e);
            }
            std::process::exit(1);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3661), "1h 1m 1s");
        assert_eq!(format_duration(90061), "1d 1h 1m 1s");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(500), "500");
        assert_eq!(format_number(1500), "1,500");
        assert_eq!(format_number(15000), "15.0K");
        assert_eq!(format_number(1_500_000), "1.50M");
        assert_eq!(format_number(1_500_000_000), "1.50B");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1_572_864), "1.50 MB");
        assert_eq!(format_bytes(1_610_612_736), "1.50 GB");
    }

    #[test]
    fn test_format_percentage() {
        assert_eq!(format_percentage(50, 100), "50.0");
        assert_eq!(format_percentage(1, 3), "33.3");
        assert_eq!(format_percentage(0, 100), "0.0");
        assert_eq!(format_percentage(100, 0), "0.0");
    }

    #[test]
    fn test_cli_parsing() {
        // Basic commands
        Cli::try_parse_from(["stria-ctl", "status"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "stats"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "stats", "queries"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "stats", "cache"]).unwrap();
        
        // With global flags
        let cli = Cli::try_parse_from(["stria-ctl", "--json", "status"]).unwrap();
        assert!(cli.json);
        
        let cli = Cli::try_parse_from(["stria-ctl", "-q", "reload"]).unwrap();
        assert!(cli.quiet);
        
        // Socket override
        let cli = Cli::try_parse_from(["stria-ctl", "-s", "/tmp/test.sock", "status"]).unwrap();
        assert_eq!(cli.socket, PathBuf::from("/tmp/test.sock"));
        
        // Cache commands
        Cli::try_parse_from(["stria-ctl", "cache", "flush"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "cache", "flush", "*.ads.*"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "cache", "flush", "--force"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "cache", "lookup", "example.com"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "cache", "stats"]).unwrap();
        
        // Block commands
        Cli::try_parse_from(["stria-ctl", "block", "list"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "block", "add", "ads.example.com"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "block", "add", "--pattern", "*.ads.*"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "block", "remove", "ads.example.com"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "block", "test", "suspicious.com"]).unwrap();
        
        // Allow commands
        Cli::try_parse_from(["stria-ctl", "allow", "list"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "allow", "add", "example.com"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "allow", "remove", "example.com"]).unwrap();
        
        // Blocklist commands
        Cli::try_parse_from(["stria-ctl", "blocklist", "list"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "blocklist", "update"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "blocklist", "update", "oisd"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "blocklist", "info", "oisd"]).unwrap();
        
        // Query command
        Cli::try_parse_from(["stria-ctl", "query", "example.com"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "query", "example.com", "AAAA"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "query", "--timing", "example.com"]).unwrap();
        
        // Log command
        Cli::try_parse_from(["stria-ctl", "log"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "log", "--follow"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "log", "-n", "100"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "log", "--blocked"]).unwrap();
        
        // Reload commands
        Cli::try_parse_from(["stria-ctl", "reload"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "reload", "blocklists"]).unwrap();
        
        // Shutdown
        Cli::try_parse_from(["stria-ctl", "shutdown"]).unwrap();
        Cli::try_parse_from(["stria-ctl", "shutdown", "--force"]).unwrap();
    }

    #[test]
    fn test_cli_help() {
        // Verify help text renders without panicking
        Cli::command().debug_assert();
    }
}
