//! Stria DNS Server
//!
//! A modern, production-grade DNS server with DNSSEC, DoT/DoH/DoQ,
//! filtering, and comprehensive observability.

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use chrono::Utc;
use clap::{Parser, Subcommand};
use console::style;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use stria_cache::{CacheConfig, DnsCache};
use stria_config::Config;
use stria_filter::{
    Blocklist, BlocklistFormat, BlocklistSource, FilterAction, FilterEngine, FilterEngineConfig,
};
use stria_metrics::tracing_setup::{LogConfig, LogFormat, init_tracing};
use stria_proto::{Message, Question, RecordType, ResourceRecord, ResponseCode};
use stria_resolver::{
    Forwarder, RecursiveConfig, RecursiveResolver, Resolver, ResolverConfig as ResolverCrateConfig,
    Upstream, UpstreamConfig, UpstreamProtocol,
};
use stria_server::control::{
    BlocklistInfo, ControlServer, ControlState, ListenerStatus, QueryLogEntry,
};
use stria_server::stats::ServerStats;
use stria_server::{DnsServer, QueryContext, QueryHandler, ServerConfig, TcpConfig, UdpConfig};
use tokio::signal;
use tokio::sync::{broadcast, watch};
use tracing::{Level, debug, error, info, warn};

/// Stria DNS Server - Modern, fast, and secure DNS resolution
#[derive(Parser, Debug)]
#[command(name = "stria")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'l', long, global = true, value_name = "LEVEL")]
    log_level: Option<String>,

    /// Quiet mode (minimal output)
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the DNS server (default)
    Run {
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Validate configuration file
    Validate {
        /// Show detailed validation output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show version information
    Version {
        /// Show detailed version info
        #[arg(short, long)]
        verbose: bool,
    },
}

/// Find the configuration file in standard locations
fn find_config_file(explicit_path: Option<PathBuf>) -> Option<PathBuf> {
    // If explicit path provided, use it
    if let Some(path) = explicit_path {
        return Some(path);
    }

    // Search in standard locations
    let search_paths = [
        PathBuf::from("./stria.yaml"),
        PathBuf::from("./stria.yml"),
        PathBuf::from("./config.yaml"),
        PathBuf::from("/etc/stria/config.yaml"),
        PathBuf::from("/etc/stria/stria.yaml"),
        dirs::config_dir()
            .map(|p| p.join("stria/config.yaml"))
            .unwrap_or_default(),
    ];

    for path in search_paths {
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Parse log level from string
fn parse_log_level(level: &str) -> Level {
    match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" | "warning" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    }
}

/// Initialize logging/tracing subsystem
fn init_logging(config: &Config, cli_level: Option<&str>, quiet: bool) {
    let level = if quiet {
        Level::ERROR
    } else if let Some(lvl) = cli_level {
        parse_log_level(lvl)
    } else {
        parse_log_level(&config.logging.level)
    };

    let format = match config.logging.format.as_str() {
        "json" => LogFormat::Json,
        _ => LogFormat::Text,
    };

    let log_config = LogConfig {
        level,
        format,
        span_events: false,
    };

    init_tracing(&log_config);
}

/// Print the startup banner
fn print_banner(config: &Config, quiet: bool) {
    if quiet {
        return;
    }

    let version = env!("CARGO_PKG_VERSION");

    println!();
    println!(
        "  {} {}",
        style("Stria DNS Server").cyan().bold(),
        style(format!("v{}", version)).dim()
    );
    println!(
        "  {}",
        style("Modern, fast, and secure DNS resolution").dim()
    );
    println!();

    // Server info
    println!("  {} {}", style("Server:").green(), config.server.name);

    // Listeners
    let mut listeners = Vec::new();
    if !config.listeners.udp.is_empty() {
        listeners.push(format!("UDP({})", config.listeners.udp.len()));
    }
    if !config.listeners.tcp.is_empty() {
        listeners.push(format!("TCP({})", config.listeners.tcp.len()));
    }
    if !config.listeners.dot.is_empty() {
        listeners.push(format!("DoT({})", config.listeners.dot.len()));
    }
    if !config.listeners.doh.is_empty() {
        listeners.push(format!("DoH({})", config.listeners.doh.len()));
    }
    if !config.listeners.doq.is_empty() {
        listeners.push(format!("DoQ({})", config.listeners.doq.len()));
    }
    println!("  {} {}", style("Listeners:").green(), listeners.join(", "));

    // Resolver mode
    let mode = match config.resolver.mode {
        stria_config::resolver::ResolverMode::Recursive => "Recursive",
        stria_config::resolver::ResolverMode::Forward => "Forward",
        stria_config::resolver::ResolverMode::Authoritative => "Authoritative",
    };
    println!("  {} {}", style("Resolver:").green(), mode);

    // Features
    let mut features = Vec::new();
    if config.cache.enabled {
        features.push("Cache");
    }
    if config.dnssec.validation {
        features.push("DNSSEC");
    }
    if config.filter.enabled {
        features.push("Filtering");
    }
    if config.metrics.enabled {
        features.push("Metrics");
    }
    println!("  {} {}", style("Features:").green(), features.join(", "));

    println!();
}

// ============================================================================
// Provider Trait Implementations
// ============================================================================

use stria_server::control::{CacheProvider, FilterProvider, FilterTestResult};

/// Wrapper to implement CacheProvider for DnsCache
struct DnsCacheProvider(Arc<DnsCache>);

impl CacheProvider for DnsCacheProvider {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn clear(&self) {
        self.0.clear()
    }

    fn hits(&self) -> u64 {
        self.0.stats().hits()
    }

    fn misses(&self) -> u64 {
        self.0.stats().misses()
    }

    fn hit_rate(&self) -> f64 {
        self.0.stats().hit_rate()
    }

    fn stale_hits(&self) -> u64 {
        self.0.stats().stale_hits()
    }

    fn prefetches(&self) -> u64 {
        self.0.stats().prefetches()
    }

    fn capacity(&self) -> usize {
        100_000 // TODO: Get from config
    }

    fn memory_bytes(&self) -> usize {
        // Estimate: ~200 bytes per entry
        self.0.len() * 200
    }
}

/// Wrapper to implement FilterProvider for FilterEngine
struct FilterEngineProvider(Arc<FilterEngine>);

impl FilterProvider for FilterEngineProvider {
    fn rule_count(&self) -> usize {
        self.0.rule_count()
    }

    fn blocklist_count(&self) -> usize {
        self.0.blocklist_count()
    }

    fn queries_blocked(&self) -> u64 {
        self.0.stats().queries_blocked
    }

    fn queries_allowed(&self) -> u64 {
        self.0.stats().queries_allowed
    }

    fn block_rate(&self) -> f64 {
        self.0.stats().block_rate()
    }

    fn test_domain(&self, domain: &str) -> FilterTestResult {
        use std::str::FromStr;
        if let Ok(name) = stria_proto::Name::from_str(domain) {
            let result = self.0.check(&name);
            FilterTestResult {
                blocked: result.is_blocked(),
                matched_rule: result.matched_rule.as_ref().map(|r| r.pattern.to_string()),
                blocklist: result.blocklist_name.as_ref().map(|s| s.to_string()),
            }
        } else {
            FilterTestResult {
                blocked: false,
                matched_rule: None,
                blocklist: None,
            }
        }
    }

    fn clear_cache(&self) {
        self.0.clear_cache()
    }

    fn add_block_rule(&self, domain: &str) {
        use stria_filter::{FilterAction, Rule, RuleType};
        let rule = Rule::new(domain, RuleType::Exact, FilterAction::Block).with_source("custom");
        if let Err(e) = self.0.add_rule(rule) {
            warn!(domain = %domain, error = %e, "Failed to add block rule");
        }
    }

    fn remove_block_rule(&self, domain: &str) {
        // Note: FilterEngine doesn't have a direct remove method, so we clear cache
        // to ensure the removed rule isn't matched from cache. In a production system,
        // we'd implement proper rule removal in FilterEngine.
        self.0.clear_cache();
        debug!(domain = %domain, "Requested block rule removal (requires engine rebuild)");
    }

    fn add_allow_rule(&self, domain: &str) {
        use stria_filter::{FilterAction, Rule, RuleType};
        let rule = Rule::new(domain, RuleType::Exact, FilterAction::Allow).with_source("custom");
        if let Err(e) = self.0.add_rule(rule) {
            warn!(domain = %domain, error = %e, "Failed to add allow rule");
        }
    }

    fn remove_allow_rule(&self, domain: &str) {
        // Same as remove_block_rule - clear cache for now
        self.0.clear_cache();
        debug!(domain = %domain, "Requested allow rule removal (requires engine rebuild)");
    }
}

// ============================================================================
// Query Handler
// ============================================================================

/// Main query handler that orchestrates resolution
struct StriaHandler {
    config: Arc<ArcSwap<Config>>,
    cache: Arc<DnsCache>,
    resolver: Arc<dyn Resolver>,
    filter: Option<Arc<FilterEngine>>,
    control_state: Option<Arc<ControlState>>,
    // dnssec: Option<Arc<DnssecValidator>>,  // TODO: Add when stria-dnssec is available
}

impl StriaHandler {
    fn new(
        config: Arc<ArcSwap<Config>>,
        cache: Arc<DnsCache>,
        resolver: Arc<dyn Resolver>,
        filter: Option<Arc<FilterEngine>>,
        control_state: Option<Arc<ControlState>>,
    ) -> Self {
        Self {
            config,
            cache,
            resolver,
            filter,
            control_state,
        }
    }
}

#[async_trait::async_trait]
impl QueryHandler for StriaHandler {
    async fn handle(&self, query: Message, context: QueryContext) -> Message {
        let config = self.config.load();
        let start_time = std::time::Instant::now();

        // Get the question
        let question = match query.questions().first() {
            Some(q) => q.clone(),
            None => {
                let mut response = Message::response_from(&query);
                response.set_rcode(ResponseCode::FormErr);
                return response;
            }
        };

        // Record query metrics
        let qtype = question
            .record_type()
            .map(|t| t.to_string())
            .unwrap_or_else(|| question.qtype.to_string());
        stria_metrics::metrics().record_query(context.protocol.name(), &qtype);

        // Check filter before resolution (if filtering enabled)
        let mut _blocked = false;
        let mut _blocked_by: Option<String> = None;
        if let Some(ref filter) = self.filter {
            let name = &question.qname;
            let result = filter.check(name);

            if result.is_blocked() {
                _blocked = true;
                _blocked_by = result.blocklist_name.as_ref().map(|s| s.to_string());
                stria_metrics::metrics().record_blocked("filter");

                // Log to query log
                if let Some(ref ctl_state) = self.control_state {
                    ctl_state.log_query(QueryLogEntry {
                        timestamp: Utc::now().to_rfc3339(),
                        client: context.client.to_string(),
                        protocol: context.protocol.name().to_string(),
                        name: name.to_string(),
                        qtype: qtype.clone(),
                        rcode: "NXDOMAIN".to_string(),
                        latency_us: start_time.elapsed().as_micros() as u64,
                        blocked: true,
                        cached: false,
                        upstream: None,
                    });
                }

                // Return blocked response (NXDOMAIN or custom IP based on action)
                let mut response = Message::response_from(&query);
                match result.action {
                    FilterAction::Block => {
                        response.set_rcode(ResponseCode::NXDomain);
                    }
                    FilterAction::Redirect(ip) => {
                        response.set_rcode(ResponseCode::NoError);
                        // Add synthetic A/AAAA record pointing to the configured IP
                        if let Some(rtype) = question.record_type() {
                            match (rtype, ip) {
                                (RecordType::A, std::net::IpAddr::V4(v4)) => {
                                    let rr = ResourceRecord::a(name.clone(), 60, v4);
                                    response.add_answer(rr);
                                }
                                (RecordType::AAAA, std::net::IpAddr::V6(v6)) => {
                                    let rr = ResourceRecord::aaaa(name.clone(), 60, v6);
                                    response.add_answer(rr);
                                }
                                _ => {
                                    // Return empty for mismatched IP version
                                    response.set_rcode(ResponseCode::NoError);
                                }
                            }
                        }
                    }
                    FilterAction::Cname(_) => {
                        // CNAME rewriting - return NXDOMAIN for now
                        response.set_rcode(ResponseCode::NXDomain);
                    }
                    FilterAction::Allow => {
                        // Should not reach here since is_blocked() would be false
                    }
                }

                stria_metrics::metrics().record_latency(context.protocol.name(), context.elapsed());
                return response;
            }
        }

        // Check cache first
        let cache_key = stria_cache::CacheKey::from_question(&question);
        if let Some(result) = self.cache.lookup(&cache_key).await {
            stria_metrics::metrics().record_cache_hit();

            // Build response from cache
            let mut response = Message::response_from(&query);
            response.set_rcode(result.entry.rcode());
            for record in result.entry.records() {
                response.add_answer(record.clone());
            }

            // Log to query log
            if let Some(ref ctl_state) = self.control_state {
                ctl_state.log_query(QueryLogEntry {
                    timestamp: Utc::now().to_rfc3339(),
                    client: context.client.to_string(),
                    protocol: context.protocol.name().to_string(),
                    name: question.qname.to_string(),
                    qtype: qtype.clone(),
                    rcode: result.entry.rcode().to_string(),
                    latency_us: start_time.elapsed().as_micros() as u64,
                    blocked: false,
                    cached: true,
                    upstream: None,
                });
            }

            // Trigger prefetch if needed
            if result.should_prefetch {
                let resolver = self.resolver.clone();
                let cache = self.cache.clone();
                let q = question.clone();
                tokio::spawn(async move {
                    if let Ok(resp) = resolver.resolve(&q).await {
                        cache.cache_response(&q, &resp).await;
                        stria_metrics::metrics().record_prefetch();
                    }
                });
            }

            // Record latency
            stria_metrics::metrics().record_latency(context.protocol.name(), context.elapsed());

            return response;
        }

        stria_metrics::metrics().record_cache_miss();

        // Resolve the query
        let response = match self.resolver.resolve(&question).await {
            Ok(mut resp) => {
                // Update response ID to match query
                resp.set_id(query.id());

                // Cache the response
                if resp.is_success() {
                    self.cache.cache_response(&question, &resp).await;
                } else if resp.is_nxdomain() || resp.is_nodata() {
                    self.cache.cache_negative(&question, &resp).await;
                }

                // Log to query log
                if let Some(ref ctl_state) = self.control_state {
                    ctl_state.log_query(QueryLogEntry {
                        timestamp: Utc::now().to_rfc3339(),
                        client: context.client.to_string(),
                        protocol: context.protocol.name().to_string(),
                        name: question.qname.to_string(),
                        qtype: qtype.clone(),
                        rcode: resp.rcode().to_string(),
                        latency_us: start_time.elapsed().as_micros() as u64,
                        blocked: false,
                        cached: false,
                        upstream: Some("upstream".to_string()), // TODO: track actual upstream
                    });
                }

                // TODO: DNSSEC validation
                // if let Some(ref dnssec) = self.dnssec {
                //     if let Err(e) = dnssec.validate(&resp) {
                //         // Return SERVFAIL with EDE
                //     }
                // }

                resp
            }
            Err(e) => {
                warn!(error = %e, question = %question, "Resolution failed");
                stria_metrics::metrics().record_error("resolution_failed");

                let mut response = Message::response_from(&query);
                response.set_rcode(ResponseCode::ServFail);
                response
            }
        };

        // Record response metrics
        let rcode = response.rcode().to_string();
        stria_metrics::metrics().record_response(context.protocol.name(), &rcode);
        stria_metrics::metrics().record_latency(context.protocol.name(), context.elapsed());

        response
    }
}

/// Build the resolver based on configuration
fn build_resolver(config: &Config, cache: Arc<DnsCache>) -> Arc<dyn Resolver> {
    let resolver_config = ResolverCrateConfig {
        timeout: Duration::from_millis(config.resolver.timeout_ms),
        retries: config.resolver.retries,
        qname_minimization: config.resolver.qname_minimization,
        enable_0x20: config.resolver.enable_0x20,
        max_recursion_depth: config.resolver.max_recursion_depth,
        dnssec: config.dnssec.validation,
    };

    match config.resolver.mode {
        stria_config::resolver::ResolverMode::Forward => {
            let upstreams: Vec<Arc<Upstream>> = config
                .resolver
                .upstreams
                .iter()
                .map(|u| {
                    let protocol = match u.protocol {
                        stria_config::resolver::UpstreamProtocol::Udp => UpstreamProtocol::Udp,
                        stria_config::resolver::UpstreamProtocol::Tcp => UpstreamProtocol::Tcp,
                        stria_config::resolver::UpstreamProtocol::Dot => UpstreamProtocol::Dot,
                        stria_config::resolver::UpstreamProtocol::Doh => UpstreamProtocol::Doh,
                        stria_config::resolver::UpstreamProtocol::Doq => UpstreamProtocol::Doq,
                    };

                    Arc::new(Upstream::new(UpstreamConfig {
                        address: u.address,
                        protocol,
                        tls_name: u.tls_name.clone(),
                        path: u.path.clone(),
                        weight: u.weight,
                        timeout: Duration::from_millis(config.resolver.timeout_ms),
                    }))
                })
                .collect();

            Arc::new(Forwarder::new(resolver_config, upstreams))
        }
        stria_config::resolver::ResolverMode::Recursive => {
            // Use the shared cache for the recursive resolver
            let recursive_config = RecursiveConfig {
                max_depth: config.resolver.max_recursion_depth as u8,
                max_cname_chain: 8,
                query_timeout: Duration::from_millis(config.resolver.timeout_ms),
                total_timeout: Duration::from_secs(30),
                enable_dnssec: config.dnssec.validation,
                enable_qname_minimization: config.resolver.qname_minimization,
                prefer_ipv6: false,
                max_concurrent_ns_queries: 3,
                negative_cache_ttl: Duration::from_secs(config.cache.negative_ttl as u64),
                enable_0x20: config.resolver.enable_0x20,
            };

            info!(
                "Initializing recursive resolver with QNAME minimization={}, DNSSEC={}",
                recursive_config.enable_qname_minimization, recursive_config.enable_dnssec
            );

            Arc::new(RecursiveResolver::with_config(recursive_config, cache))
        }
        stria_config::resolver::ResolverMode::Authoritative => {
            // TODO: Implement authoritative-only mode
            warn!("Authoritative mode not yet implemented, using stub resolver");
            Arc::new(StubResolver)
        }
    }
}

/// Stub resolver for unimplemented modes
struct StubResolver;

#[async_trait::async_trait]
impl Resolver for StubResolver {
    async fn resolve(&self, _question: &Question) -> stria_resolver::Result<Message> {
        Err(stria_resolver::ResolverError::Protocol(
            "Resolver mode not implemented".to_string(),
        ))
    }
}

/// Build cache from configuration
fn build_cache(config: &Config) -> Arc<DnsCache> {
    let cache_config = CacheConfig {
        l1_max_entries: 10_000, // Per-thread cache
        l2_max_entries: config.cache.max_entries,
        min_ttl: Duration::from_secs(config.cache.min_ttl as u64),
        max_ttl: Duration::from_secs(config.cache.max_ttl as u64),
        negative_ttl: Duration::from_secs(config.cache.negative_ttl as u64),
        serve_stale: config.cache.serve_stale,
        stale_ttl: Duration::from_secs(config.cache.stale_ttl as u64),
        prefetch: config.cache.prefetch,
        prefetch_threshold: config.cache.prefetch_threshold,
    };

    Arc::new(DnsCache::new(cache_config))
}

/// Build filter engine from configuration
async fn build_filter(config: &Config) -> Option<Arc<FilterEngine>> {
    if !config.filter.enabled {
        return None;
    }

    let filter_config = FilterEngineConfig {
        cache_enabled: true,
        cache_max_entries: 100_000,
        cache_ttl_secs: 300,
        cname_protection: config.filter.cname_protection,
    };

    let engine = FilterEngine::with_config(filter_config);

    // Load blocklists from configuration
    for blocklist_config in &config.filter.blocklists {
        if !blocklist_config.enabled {
            continue;
        }

        let format = match blocklist_config.format.as_deref() {
            Some("hosts") => BlocklistFormat::Hosts,
            Some("domains") => BlocklistFormat::Domains,
            Some("adblock") => BlocklistFormat::AdblockPlus,
            Some("rpz") => BlocklistFormat::Rpz,
            Some("dnsmasq") => BlocklistFormat::DnsmasqDomains,
            _ => BlocklistFormat::Domains, // Default to domains format
        };

        let source = if blocklist_config.url.starts_with("http://")
            || blocklist_config.url.starts_with("https://")
        {
            BlocklistSource::Url(blocklist_config.url.clone())
        } else {
            BlocklistSource::File(PathBuf::from(&blocklist_config.url))
        };

        let blocklist = Blocklist::new(&blocklist_config.name, source, format);

        if let Err(e) = engine.add_blocklist(blocklist) {
            warn!(
                blocklist = %blocklist_config.name,
                error = %e,
                "Failed to add blocklist"
            );
        }
    }

    // Add custom block rules
    for domain in &config.filter.custom_block {
        use stria_filter::{Rule, RuleType};
        let rule = Rule::new(domain, RuleType::Exact, FilterAction::Block);
        if let Err(e) = engine.add_rule(rule) {
            warn!(domain = %domain, error = %e, "Failed to add custom block rule");
        }
    }

    // Add custom allow rules
    for domain in &config.filter.custom_allow {
        use stria_filter::{Rule, RuleType};
        let rule = Rule::new(domain, RuleType::Exact, FilterAction::Allow);
        if let Err(e) = engine.add_rule(rule) {
            warn!(domain = %domain, error = %e, "Failed to add custom allow rule");
        }
    }

    // Reload blocklists from their sources
    if let Err(e) = engine.reload().await {
        warn!(error = %e, "Failed to reload blocklists");
    }

    let stats = engine.stats();
    info!(
        total_rules = stats.total_rules,
        blocklists = stats.blocklist_count,
        "Filter engine initialized"
    );

    Some(Arc::new(engine))
}

/// Build server configuration from Config
fn build_server_config(config: &Config) -> ServerConfig {
    let udp = if config.listeners.udp.is_empty() {
        None
    } else {
        Some(UdpConfig {
            listen: config.listeners.udp.iter().map(|l| l.address).collect(),
            reuseport: config
                .listeners
                .udp
                .first()
                .map(|l| l.reuseport)
                .unwrap_or(true),
            recv_buffer: config
                .listeners
                .udp
                .first()
                .and_then(|l| l.recv_buffer)
                .unwrap_or(4 * 1024 * 1024),
            send_buffer: config
                .listeners
                .udp
                .first()
                .and_then(|l| l.send_buffer)
                .unwrap_or(4 * 1024 * 1024),
        })
    };

    let tcp = if config.listeners.tcp.is_empty() {
        None
    } else {
        Some(TcpConfig {
            listen: config.listeners.tcp.iter().map(|l| l.address).collect(),
            backlog: config
                .listeners
                .tcp
                .first()
                .map(|l| l.backlog)
                .unwrap_or(1024),
            idle_timeout: Duration::from_secs(
                config
                    .listeners
                    .tcp
                    .first()
                    .map(|l| l.idle_timeout)
                    .unwrap_or(10),
            ),
            max_connections: config.security.limits.max_tcp_connections,
            tcp_fastopen: config
                .listeners
                .tcp
                .first()
                .map(|l| l.tcp_fastopen)
                .unwrap_or(true),
        })
    };

    // Build DoT configuration
    #[cfg(feature = "dot")]
    let dot = if config.listeners.dot.is_empty() {
        None
    } else {
        let first = config.listeners.dot.first().unwrap();
        Some(stria_server::DotConfig {
            listen: config.listeners.dot.iter().map(|l| l.address).collect(),
            cert_path: first.tls.cert.clone(),
            key_path: first.tls.key.clone(),
            backlog: first.backlog,
            idle_timeout: Duration::from_secs(first.idle_timeout),
        })
    };

    // Build DoH configuration
    #[cfg(feature = "doh")]
    let doh = if config.listeners.doh.is_empty() {
        None
    } else {
        let first = config.listeners.doh.first().unwrap();
        Some(stria_server::DohConfig {
            listen: config.listeners.doh.iter().map(|l| l.address).collect(),
            cert_path: first.tls.cert.clone(),
            key_path: first.tls.key.clone(),
            path: first.path.clone(),
            http2: first.http2,
        })
    };

    // Build DoQ configuration
    #[cfg(feature = "doq")]
    let doq = if config.listeners.doq.is_empty() {
        None
    } else {
        let first = config.listeners.doq.first().unwrap();
        Some(stria_server::DoqConfig {
            listen: config.listeners.doq.iter().map(|l| l.address).collect(),
            cert_path: first.tls.cert.clone(),
            key_path: first.tls.key.clone(),
            idle_timeout: Duration::from_secs(first.idle_timeout),
        })
    };

    ServerConfig {
        udp,
        tcp,
        #[cfg(feature = "dot")]
        dot,
        #[cfg(feature = "doh")]
        doh,
        #[cfg(feature = "doq")]
        doq,
        rrl: if config.security.rrl.enabled {
            Some(stria_server::RrlConfig {
                enabled: true,
                responses_per_second: config.security.rrl.responses_per_second,
                window: Duration::from_secs(config.security.rrl.window as u64),
                slip: config.security.rrl.slip,
                ipv4_prefix: config.security.rrl.ipv4_prefix,
                ipv6_prefix: config.security.rrl.ipv6_prefix,
            })
        } else {
            None
        },
        shutdown_timeout: Duration::from_secs(30),
    }
}

/// Run the DNS server
async fn run_server(config: Config, quiet: bool) -> Result<()> {
    print_banner(&config, quiet);

    // Wrap config in ArcSwap for hot-reload support
    let config_holder = Arc::new(ArcSwap::new(Arc::new(config.clone())));

    // Initialize metrics
    if config.metrics.enabled {
        if let Some(ref prom) = config.metrics.prometheus {
            if prom.enabled {
                let prom_config = stria_metrics::prometheus::PrometheusConfig {
                    listen: prom.listen,
                    path: prom.path.clone(),
                };
                if let Err(e) = stria_metrics::prometheus::init_prometheus(&prom_config) {
                    warn!(error = %e, "Failed to initialize Prometheus metrics");
                }
            }
        }
    }

    // Create shutdown channel
    let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);

    // Create reload channel
    let (reload_tx, mut reload_rx) = watch::channel(());

    // Build server stats
    let stats = Arc::new(ServerStats::new());

    // Create control state with optional rules file for persistence
    let control_state = if let Some(ref rules_path) = config.control.rules_file {
        Arc::new(ControlState::with_rules_file(
            stats.clone(),
            shutdown_tx.clone(),
            rules_path.clone(),
        ))
    } else {
        Arc::new(ControlState::new(stats.clone(), shutdown_tx.clone()))
    };

    // Build components
    let cache = build_cache(&config);
    let resolver = build_resolver(&config, cache.clone());
    let filter = build_filter(&config).await;

    // Wire up cache provider to control state
    control_state.set_cache(Arc::new(DnsCacheProvider(cache.clone())));

    // Wire up filter provider to control state
    if let Some(ref filter_engine) = filter {
        control_state.set_filter(Arc::new(FilterEngineProvider(filter_engine.clone())));

        // Apply custom rules loaded from the rules file
        control_state.apply_loaded_rules();

        // Register blocklists in control state
        let filter_stats = filter_engine.stats();
        for blocklist_config in &config.filter.blocklists {
            control_state.register_blocklist(BlocklistInfo {
                name: blocklist_config.name.clone(),
                source: blocklist_config.url.clone(),
                format: blocklist_config
                    .format
                    .clone()
                    .unwrap_or_else(|| "auto".to_string()),
                enabled: blocklist_config.enabled,
                rule_count: filter_stats.total_rules as u64
                    / config.filter.blocklists.len().max(1) as u64,
                last_updated: None,
                next_update: None,
                last_error: None,
            });
        }
    }

    let handler = Arc::new(StriaHandler::new(
        config_holder.clone(),
        cache.clone(),
        resolver,
        filter.clone(),
        Some(control_state.clone()),
    ));

    // Build and start server
    let server_config = build_server_config(&config);
    let server = DnsServer::new(server_config, handler);

    // Register listeners in control state
    for listener in &config.listeners.udp {
        control_state.register_listener(ListenerStatus {
            protocol: "UDP".to_string(),
            address: listener.address.to_string(),
            active: true,
            connections: None,
        });
    }
    for listener in &config.listeners.tcp {
        control_state.register_listener(ListenerStatus {
            protocol: "TCP".to_string(),
            address: listener.address.to_string(),
            active: true,
            connections: Some(0),
        });
    }
    for listener in &config.listeners.dot {
        control_state.register_listener(ListenerStatus {
            protocol: "DoT".to_string(),
            address: listener.address.to_string(),
            active: true,
            connections: Some(0),
        });
    }
    for listener in &config.listeners.doh {
        control_state.register_listener(ListenerStatus {
            protocol: "DoH".to_string(),
            address: listener.address.to_string(),
            active: true,
            connections: Some(0),
        });
    }
    for listener in &config.listeners.doq {
        control_state.register_listener(ListenerStatus {
            protocol: "DoQ".to_string(),
            address: listener.address.to_string(),
            active: true,
            connections: Some(0),
        });
    }

    // Start control server
    let control_socket_path = config
        .control
        .socket_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("/var/run/stria/control.sock"));

    let control_server = ControlServer::new(control_state.clone());
    let control_socket = control_socket_path.clone();
    tokio::spawn(async move {
        if let Err(e) = control_server.run(&control_socket).await {
            warn!(error = %e, "Control server error");
        }
    });
    info!(path = %control_socket_path.display(), "Control server started");

    // Spawn signal handlers
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .expect("Failed to register SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown...");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, initiating graceful shutdown...");
            }
        }

        let _ = shutdown_tx_clone.send(());
    });

    // SIGHUP handler for config reload
    let config_holder_clone = config_holder.clone();
    let filter_clone = filter.clone();
    tokio::spawn(async move {
        let mut sighup = signal::unix::signal(signal::unix::SignalKind::hangup())
            .expect("Failed to register SIGHUP handler");

        loop {
            sighup.recv().await;
            info!("Received SIGHUP, reloading configuration...");

            // Reload blocklists if filter is enabled
            if let Some(ref filter_engine) = filter_clone {
                info!("Reloading blocklists...");
                if let Err(e) = filter_engine.reload().await {
                    error!(error = %e, "Failed to reload blocklists");
                } else {
                    let stats = filter_engine.stats();
                    info!(
                        total_rules = stats.total_rules,
                        blocklists = stats.blocklist_count,
                        "Blocklists reloaded"
                    );
                }
            }

            let _ = reload_tx.send(());
        }
    });

    // Print listening addresses
    for listener in &config.listeners.udp {
        info!(address = %listener.address, protocol = "UDP", "Listening");
    }
    for listener in &config.listeners.tcp {
        info!(address = %listener.address, protocol = "TCP", "Listening");
    }
    for listener in &config.listeners.dot {
        info!(address = %listener.address, protocol = "DoT", "Listening");
    }
    for listener in &config.listeners.doh {
        info!(address = %listener.address, protocol = "DoH", "Listening");
    }
    for listener in &config.listeners.doq {
        info!(address = %listener.address, protocol = "DoQ", "Listening");
    }

    info!("Stria DNS server started");

    // Run the server until shutdown
    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                error!(error = %e, "Server error");
                return Err(e.into());
            }
        }
        _ = shutdown_rx.recv() => {
            info!("Shutdown signal received");
        }
    }

    // Graceful shutdown
    info!("Initiating graceful shutdown...");
    server.shutdown();

    // Cleanup control socket
    if control_socket_path.exists() {
        let _ = std::fs::remove_file(&control_socket_path);
    }

    // Wait for shutdown timeout
    let shutdown_timeout = Duration::from_secs(30);
    tokio::time::sleep(shutdown_timeout).await;

    info!("Stria DNS server stopped");
    Ok(())
}

/// Validate configuration file
fn validate_config(path: Option<PathBuf>, verbose: bool) -> Result<()> {
    let config_path = find_config_file(path).context("No configuration file found")?;

    println!("Validating configuration: {}", config_path.display());

    let config = Config::from_file(&config_path).with_context(|| {
        format!(
            "Failed to load configuration from {}",
            config_path.display()
        )
    })?;

    if verbose {
        println!("\n{}", style("Configuration loaded:").green().bold());
        println!("  Server name: {}", config.server.name);
        println!(
            "  Workers: {}",
            if config.server.workers == 0 {
                "auto".to_string()
            } else {
                config.server.workers.to_string()
            }
        );
        println!("  UDP listeners: {}", config.listeners.udp.len());
        println!("  TCP listeners: {}", config.listeners.tcp.len());
        println!("  DoT listeners: {}", config.listeners.dot.len());
        println!("  DoH listeners: {}", config.listeners.doh.len());
        println!("  DoQ listeners: {}", config.listeners.doq.len());
        println!("  Resolver mode: {:?}", config.resolver.mode);
        println!("  Cache enabled: {}", config.cache.enabled);
        println!("  DNSSEC validation: {}", config.dnssec.validation);
        println!("  Filtering enabled: {}", config.filter.enabled);
        println!("  Metrics enabled: {}", config.metrics.enabled);
    }

    config
        .validate()
        .with_context(|| "Configuration validation failed")?;

    println!("{}", style("Configuration is valid!").green().bold());
    Ok(())
}

/// Print version information
fn print_version(verbose: bool) {
    let version = env!("CARGO_PKG_VERSION");
    let name = env!("CARGO_PKG_NAME");

    if verbose {
        println!(
            "{} {}",
            style(name).cyan().bold(),
            style(format!("v{}", version)).dim()
        );
        println!();
        println!(
            "  {}: {}",
            style("Build target").dim(),
            std::env::consts::ARCH
        );
        println!("  {}: {}", style("OS").dim(), std::env::consts::OS);

        // Feature flags
        let mut features = Vec::new();
        #[cfg(feature = "doh")]
        features.push("doh");
        #[cfg(feature = "dot")]
        features.push("dot");
        #[cfg(feature = "doq")]
        features.push("doq");
        #[cfg(feature = "dnssec")]
        features.push("dnssec");
        #[cfg(feature = "filtering")]
        features.push("filtering");
        #[cfg(feature = "metrics")]
        features.push("metrics");
        #[cfg(feature = "zones")]
        features.push("zones");
        #[cfg(feature = "io-uring")]
        features.push("io-uring");

        println!("  {}: {}", style("Features").dim(), features.join(", "));
        println!();
    } else {
        println!("{} {}", name, version);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle version command early (before config loading)
    if let Some(Commands::Version { verbose }) = &cli.command {
        print_version(*verbose);
        return Ok(());
    }

    // Handle validate command
    if let Some(Commands::Validate { verbose }) = &cli.command {
        return validate_config(cli.config, *verbose);
    }

    // Load configuration
    let config_path = find_config_file(cli.config.clone());
    let config = if let Some(path) = config_path {
        Config::from_file(&path)
            .with_context(|| format!("Failed to load configuration from {}", path.display()))?
    } else {
        // Use default configuration
        if !cli.quiet {
            eprintln!(
                "{}",
                style("No configuration file found, using defaults").yellow()
            );
        }
        Config::default()
    };

    // Validate configuration
    config.validate().context("Invalid configuration")?;

    // Initialize logging
    init_logging(&config, cli.log_level.as_deref(), cli.quiet);

    // Run the server (default command)
    match cli.command {
        Some(Commands::Run { foreground: _ }) | None => {
            run_server(config, cli.quiet).await?;
        }
        _ => unreachable!(),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_log_level() {
        assert_eq!(parse_log_level("trace"), Level::TRACE);
        assert_eq!(parse_log_level("DEBUG"), Level::DEBUG);
        assert_eq!(parse_log_level("Info"), Level::INFO);
        assert_eq!(parse_log_level("warn"), Level::WARN);
        assert_eq!(parse_log_level("warning"), Level::WARN);
        assert_eq!(parse_log_level("error"), Level::ERROR);
        assert_eq!(parse_log_level("unknown"), Level::INFO);
    }

    #[test]
    fn test_cli_parsing() {
        // Test basic parsing
        let cli = Cli::try_parse_from(["stria"]).unwrap();
        assert!(cli.config.is_none());
        assert!(!cli.quiet);
        assert!(cli.command.is_none());

        // Test with config
        let cli = Cli::try_parse_from(["stria", "-c", "/etc/stria/config.yaml"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/etc/stria/config.yaml")));

        // Test validate command
        let cli = Cli::try_parse_from(["stria", "validate", "--verbose"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Validate { verbose: true })
        ));

        // Test version command
        let cli = Cli::try_parse_from(["stria", "version"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Version { verbose: false })
        ));
    }
}
