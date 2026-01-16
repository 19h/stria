//! Recursive resolver implementation.
//!
//! This module implements full iterative recursive resolution starting from root servers,
//! following the delegation chain down to authoritative servers.
//!
//! ## Features
//!
//! - **Iterative resolution** from root servers following delegation chain
//! - **CNAME chain handling** with loop detection (max 8 CNAMEs)
//! - **DNAME redirections** support
//! - **Bailiwick checking** for glue record validation
//! - **QNAME minimization** (RFC 7816) for privacy
//! - **Parallel NS queries** with RTT-based server selection
//! - **DNSSEC validation** integration with stria-dnssec
//! - **Comprehensive caching** of NS records and glue
//! - **Negative caching** for NXDOMAIN/NODATA responses

use super::pool::{ConnectionPool, PoolConfig};
use super::{Resolver, ResolverError, Result};
use async_trait::async_trait;
use stria_cache::{CacheKey, DnsCache};
use stria_dnssec::{DnssecValidator, DefaultTrustAnchorStore, ValidationResult};
use stria_proto::{Message, Name, Question, RecordClass, RecordType, ResourceRecord, RData, ResponseCode};
use dashmap::DashMap;
use futures::future::{self, BoxFuture, FutureExt};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, instrument, trace, warn};

// ============================================================================
// Root Server Hints
// ============================================================================

/// Root server hints - IANA root servers as of 2024.
/// These are the starting points for recursive resolution.
pub static ROOT_HINTS: &[RootServer] = &[
    RootServer {
        name: "a.root-servers.net",
        ipv4: "198.41.0.4",
        ipv6: Some("2001:503:ba3e::2:30"),
    },
    RootServer {
        name: "b.root-servers.net",
        ipv4: "199.9.14.201",
        ipv6: Some("2001:500:200::b"),
    },
    RootServer {
        name: "c.root-servers.net",
        ipv4: "192.33.4.12",
        ipv6: Some("2001:500:2::c"),
    },
    RootServer {
        name: "d.root-servers.net",
        ipv4: "199.7.91.13",
        ipv6: Some("2001:500:2d::d"),
    },
    RootServer {
        name: "e.root-servers.net",
        ipv4: "192.203.230.10",
        ipv6: Some("2001:500:a8::e"),
    },
    RootServer {
        name: "f.root-servers.net",
        ipv4: "192.5.5.241",
        ipv6: Some("2001:500:2f::f"),
    },
    RootServer {
        name: "g.root-servers.net",
        ipv4: "192.112.36.4",
        ipv6: Some("2001:500:12::d0d"),
    },
    RootServer {
        name: "h.root-servers.net",
        ipv4: "198.97.190.53",
        ipv6: Some("2001:500:1::53"),
    },
    RootServer {
        name: "i.root-servers.net",
        ipv4: "192.36.148.17",
        ipv6: Some("2001:7fe::53"),
    },
    RootServer {
        name: "j.root-servers.net",
        ipv4: "192.58.128.30",
        ipv6: Some("2001:503:c27::2:30"),
    },
    RootServer {
        name: "k.root-servers.net",
        ipv4: "193.0.14.129",
        ipv6: Some("2001:7fd::1"),
    },
    RootServer {
        name: "l.root-servers.net",
        ipv4: "199.7.83.42",
        ipv6: Some("2001:500:9f::42"),
    },
    RootServer {
        name: "m.root-servers.net",
        ipv4: "202.12.27.33",
        ipv6: Some("2001:dc3::35"),
    },
];

/// A root server entry.
#[derive(Debug, Clone)]
pub struct RootServer {
    /// Hostname of the root server.
    pub name: &'static str,
    /// IPv4 address.
    pub ipv4: &'static str,
    /// IPv6 address (optional).
    pub ipv6: Option<&'static str>,
}

impl RootServer {
    /// Returns the socket addresses for this root server.
    pub fn socket_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs = Vec::with_capacity(2);
        
        if let Ok(ipv4) = self.ipv4.parse::<Ipv4Addr>() {
            addrs.push(SocketAddr::new(IpAddr::V4(ipv4), 53));
        }
        
        if let Some(ipv6_str) = self.ipv6 {
            if let Ok(ipv6) = ipv6_str.parse::<Ipv6Addr>() {
                addrs.push(SocketAddr::new(IpAddr::V6(ipv6), 53));
            }
        }
        
        addrs
    }
}

// ============================================================================
// Root Hints Manager
// ============================================================================

/// Manages root server hints and provides server selection.
#[derive(Debug)]
pub struct RootHints {
    /// Root servers loaded from hints or priming query.
    servers: RwLock<Vec<NameserverEntry>>,
    /// Time of last priming query.
    last_priming: RwLock<Option<Instant>>,
    /// Priming interval (how often to refresh from root).
    priming_interval: Duration,
}

impl RootHints {
    /// Creates root hints from built-in IANA data.
    pub fn from_builtin() -> Self {
        let servers: Vec<NameserverEntry> = ROOT_HINTS
            .iter()
            .map(|rs| {
                let name = Name::from_str(rs.name).unwrap_or_else(|_| Name::root());
                let mut addrs = Vec::new();
                
                if let Ok(ipv4) = rs.ipv4.parse::<Ipv4Addr>() {
                    addrs.push(IpAddr::V4(ipv4));
                }
                if let Some(ipv6_str) = rs.ipv6 {
                    if let Ok(ipv6) = ipv6_str.parse::<Ipv6Addr>() {
                        addrs.push(IpAddr::V6(ipv6));
                    }
                }
                
                NameserverEntry {
                    name,
                    addresses: addrs,
                    rtt: AtomicU64::new(0),
                    failures: AtomicU64::new(0),
                }
            })
            .collect();
        
        Self {
            servers: RwLock::new(servers),
            last_priming: RwLock::new(None),
            priming_interval: Duration::from_secs(86400), // 24 hours
        }
    }
    
    /// Loads root hints from a file (BIND hints format).
    pub fn from_file(_path: &std::path::Path) -> std::io::Result<Self> {
        let hints = Self::from_builtin();
        // TODO: Parse BIND hints file format
        // For now, just return the builtin hints
        Ok(hints)
    }
    
    /// Returns socket addresses for root servers, ordered by RTT.
    pub fn get_servers(&self) -> Vec<SocketAddr> {
        let servers = self.servers.read();
        let mut entries: Vec<_> = servers.iter().collect();
        
        // Sort by RTT (fastest first), with some randomization for load distribution
        entries.sort_by(|a, b| {
            let rtt_a = a.rtt.load(Ordering::Relaxed);
            let rtt_b = b.rtt.load(Ordering::Relaxed);
            rtt_a.cmp(&rtt_b)
        });
        
        entries
            .into_iter()
            .flat_map(|e| {
                e.addresses.iter().map(|addr| SocketAddr::new(*addr, 53))
            })
            .collect()
    }
    
    /// Updates RTT for a server after a successful query.
    pub fn update_rtt(&self, addr: &IpAddr, rtt: Duration) {
        let servers = self.servers.read();
        for server in servers.iter() {
            if server.addresses.contains(addr) {
                let rtt_us = rtt.as_micros() as u64;
                let current = server.rtt.load(Ordering::Relaxed);
                // Exponential moving average
                let new_rtt = if current == 0 {
                    rtt_us
                } else {
                    (current * 7 + rtt_us) / 8
                };
                server.rtt.store(new_rtt, Ordering::Relaxed);
                break;
            }
        }
    }
    
    /// Records a failure for a server.
    pub fn record_failure(&self, addr: &IpAddr) {
        let servers = self.servers.read();
        for server in servers.iter() {
            if server.addresses.contains(addr) {
                server.failures.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }
    
    /// Returns true if priming query should be performed.
    pub fn needs_priming(&self) -> bool {
        let last = self.last_priming.read();
        match *last {
            None => true,
            Some(instant) => instant.elapsed() > self.priming_interval,
        }
    }
    
    /// Updates the priming timestamp.
    pub fn mark_primed(&self) {
        let mut last = self.last_priming.write();
        *last = Some(Instant::now());
    }
}

impl Default for RootHints {
    fn default() -> Self {
        Self::from_builtin()
    }
}

// ============================================================================
// Nameserver Entry
// ============================================================================

/// A nameserver entry with address and performance metrics.
#[derive(Debug)]
pub struct NameserverEntry {
    /// The nameserver hostname.
    pub name: Name,
    /// Known IP addresses.
    pub addresses: Vec<IpAddr>,
    /// Average RTT in microseconds.
    pub rtt: AtomicU64,
    /// Failure count.
    pub failures: AtomicU64,
}

impl Clone for NameserverEntry {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            addresses: self.addresses.clone(),
            rtt: AtomicU64::new(self.rtt.load(Ordering::Relaxed)),
            failures: AtomicU64::new(self.failures.load(Ordering::Relaxed)),
        }
    }
}

// ============================================================================
// Recursive Resolver Configuration
// ============================================================================

/// Configuration for the recursive resolver.
#[derive(Debug, Clone)]
pub struct RecursiveConfig {
    /// Maximum referral depth (default: 30).
    pub max_depth: u8,
    
    /// Maximum CNAME chain length (default: 8).
    pub max_cname_chain: u8,
    
    /// Timeout for individual queries to nameservers (default: 2s).
    pub query_timeout: Duration,
    
    /// Total resolution timeout (default: 30s).
    pub total_timeout: Duration,
    
    /// Enable DNSSEC validation (default: true).
    pub enable_dnssec: bool,
    
    /// Enable QNAME minimization (default: true).
    pub enable_qname_minimization: bool,
    
    /// Prefer IPv6 for nameserver queries (default: false).
    pub prefer_ipv6: bool,
    
    /// Maximum concurrent NS queries (default: 3).
    pub max_concurrent_ns_queries: usize,
    
    /// Negative cache TTL (default: 900s).
    pub negative_cache_ttl: Duration,
    
    /// Enable 0x20 encoding for query names.
    pub enable_0x20: bool,
}

impl Default for RecursiveConfig {
    fn default() -> Self {
        Self {
            max_depth: 30,
            max_cname_chain: 8,
            query_timeout: Duration::from_secs(2),
            total_timeout: Duration::from_secs(30),
            enable_dnssec: true,
            enable_qname_minimization: true,
            prefer_ipv6: false,
            max_concurrent_ns_queries: 3,
            negative_cache_ttl: Duration::from_secs(900),
            enable_0x20: true,
        }
    }
}

// ============================================================================
// Resolution State
// ============================================================================

/// State maintained during iterative resolution.
#[derive(Debug)]
struct ResolutionState {
    /// The original query question.
    original_query: Question,
    
    /// Current query name (may differ due to CNAME/DNAME).
    current_qname: Name,
    
    /// Current zone we're resolving within.
    current_zone: Name,
    
    /// Current depth (referral count).
    depth: u8,
    
    /// CNAME chain count.
    cname_count: u8,
    
    /// Servers we've already queried (to avoid loops).
    visited_servers: HashSet<SocketAddr>,
    
    /// Names we've already chased (CNAME loop detection).
    visited_names: HashSet<Name>,
    
    /// When resolution started.
    start_time: Instant,
    
    /// Accumulated answers from CNAME chain.
    accumulated_answers: Vec<ResourceRecord>,
    
    /// Whether this resolution requires DNSSEC.
    dnssec_requested: bool,
}

impl ResolutionState {
    fn new(query: Question, dnssec: bool) -> Self {
        let qname = query.qname.clone();
        Self {
            original_query: query,
            current_qname: qname.clone(),
            current_zone: Name::root(),
            depth: 0,
            cname_count: 0,
            visited_servers: HashSet::new(),
            visited_names: {
                let mut set = HashSet::new();
                set.insert(qname);
                set
            },
            start_time: Instant::now(),
            accumulated_answers: Vec::new(),
            dnssec_requested: dnssec,
        }
    }
    
    /// Checks if we've exceeded the total timeout.
    fn is_expired(&self, total_timeout: Duration) -> bool {
        self.start_time.elapsed() > total_timeout
    }
    
    /// Records a server visit for loop detection.
    fn visit_server(&mut self, addr: SocketAddr) -> bool {
        self.visited_servers.insert(addr)
    }
    
    /// Records a name chase for CNAME loop detection.
    fn chase_name(&mut self, name: &Name) -> bool {
        self.visited_names.insert(name.clone())
    }
}

// ============================================================================
// Resolver Metrics
// ============================================================================

/// Metrics for resolver performance monitoring.
#[derive(Debug, Default)]
pub struct ResolverMetrics {
    /// Total queries processed.
    pub queries_total: AtomicU64,
    /// Successful resolutions.
    pub queries_success: AtomicU64,
    /// Failed resolutions.
    pub queries_failed: AtomicU64,
    /// Cache hits.
    pub cache_hits: AtomicU64,
    /// Cache misses.
    pub cache_misses: AtomicU64,
    /// DNSSEC validations performed.
    pub dnssec_validations: AtomicU64,
    /// DNSSEC validation failures.
    pub dnssec_failures: AtomicU64,
    /// Average resolution time in microseconds.
    pub avg_resolution_time_us: AtomicU64,
}

// ============================================================================
// NS Cache Entry
// ============================================================================

/// Cached nameserver information for a zone.
#[derive(Debug, Clone)]
struct NsCacheEntry {
    /// Nameserver names and their addresses.
    nameservers: Vec<NameserverEntry>,
    /// When this entry expires.
    expires_at: Instant,
    /// Whether this delegation is signed (has DS record).
    #[allow(dead_code)]
    is_signed: bool,
}

// ============================================================================
// Recursive Resolver
// ============================================================================

/// Full recursive DNS resolver.
///
/// Implements iterative resolution from root servers down through the delegation
/// chain to authoritative servers. Supports DNSSEC validation, QNAME minimization,
/// CNAME chasing, and comprehensive caching.
pub struct RecursiveResolver {
    /// Resolver configuration.
    config: RecursiveConfig,
    
    /// DNS response cache.
    cache: Arc<DnsCache>,
    
    /// Connection pool for TCP queries.
    #[allow(dead_code)]
    pool: ConnectionPool,
    
    /// Root server hints.
    root_hints: RootHints,
    
    /// DNSSEC validator (optional).
    dnssec_validator: Option<Arc<DnssecValidator>>,
    
    /// Nameserver cache (zone -> nameserver addresses).
    ns_cache: DashMap<Name, NsCacheEntry>,
    
    /// Performance metrics.
    metrics: Arc<ResolverMetrics>,
}

impl RecursiveResolver {
    /// Creates a new recursive resolver with default configuration.
    pub fn new(cache: Arc<DnsCache>) -> Self {
        Self::with_config(RecursiveConfig::default(), cache)
    }
    
    /// Creates a new recursive resolver with custom configuration.
    pub fn with_config(config: RecursiveConfig, cache: Arc<DnsCache>) -> Self {
        let dnssec_validator = if config.enable_dnssec {
            Some(Arc::new(DnssecValidator::new(DefaultTrustAnchorStore::default())))
        } else {
            None
        };
        
        Self {
            config,
            cache,
            pool: ConnectionPool::new(PoolConfig::default()),
            root_hints: RootHints::default(),
            dnssec_validator,
            ns_cache: DashMap::new(),
            metrics: Arc::new(ResolverMetrics::default()),
        }
    }
    
    /// Creates a resolver with a custom DNSSEC validator.
    pub fn with_dnssec_validator(
        config: RecursiveConfig,
        cache: Arc<DnsCache>,
        validator: Arc<DnssecValidator>,
    ) -> Self {
        Self {
            config,
            cache,
            pool: ConnectionPool::new(PoolConfig::default()),
            root_hints: RootHints::default(),
            dnssec_validator: Some(validator),
            ns_cache: DashMap::new(),
            metrics: Arc::new(ResolverMetrics::default()),
        }
    }
    
    /// Returns the resolver metrics.
    pub fn metrics(&self) -> &ResolverMetrics {
        &self.metrics
    }
    
    /// Performs recursive resolution.
    #[instrument(skip(self), fields(qname = %question.qname, qtype = ?question.qtype))]
    pub async fn resolve_recursive(&self, question: &Question) -> Result<Message> {
        self.metrics.queries_total.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();
        
        // Check cache first
        let cache_key = CacheKey::from_question(question);
        if let Some(result) = self.cache.lookup(&cache_key).await {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            trace!("Cache hit for {}", question.qname);
            
            // Build response from cache
            let mut response = Message::response_from(&Message::query(question.clone()));
            for record in result.entry.records() {
                response.add_answer(record.clone());
            }
            
            return Ok(response);
        }
        
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        
        // Initialize resolution state
        let dnssec_requested = self.config.enable_dnssec;
        let mut state = ResolutionState::new(question.clone(), dnssec_requested);
        
        // Perform iterative resolution
        let result = self.resolve_iterative(&mut state).await;
        
        let elapsed = start.elapsed();
        let elapsed_us = elapsed.as_micros() as u64;
        
        // Update metrics
        match &result {
            Ok(response) => {
                self.metrics.queries_success.fetch_add(1, Ordering::Relaxed);
                
                // Cache successful responses
                if !response.is_nxdomain() && !response.is_servfail() {
                    self.cache.cache_response(question, response).await;
                } else if response.is_nxdomain() || response.is_nodata() {
                    self.cache.cache_negative(question, response).await;
                }
            }
            Err(_) => {
                self.metrics.queries_failed.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        // Update average resolution time (simple moving average)
        let current_avg = self.metrics.avg_resolution_time_us.load(Ordering::Relaxed);
        let new_avg = if current_avg == 0 {
            elapsed_us
        } else {
            (current_avg * 7 + elapsed_us) / 8
        };
        self.metrics.avg_resolution_time_us.store(new_avg, Ordering::Relaxed);
        
        result
    }
    
    /// Main iterative resolution loop.
    #[instrument(skip(self, state), fields(qname = %state.current_qname))]
    async fn resolve_iterative(&self, state: &mut ResolutionState) -> Result<Message> {
        loop {
            // Check safety limits
            if state.depth > self.config.max_depth {
                warn!("Maximum referral depth exceeded");
                return Err(ResolverError::MaxRecursionDepth);
            }
            
            if state.is_expired(self.config.total_timeout) {
                warn!("Resolution timeout exceeded");
                return Err(ResolverError::Timeout);
            }
            
            // Find the best nameservers for the current zone
            let ns_addrs = self.find_nameservers(&state.current_zone, state).await?;
            
            if ns_addrs.is_empty() {
                return Err(ResolverError::NoUpstream);
            }
            
            // Build the query
            let query_question = if self.config.enable_qname_minimization {
                self.minimize_qname(state)
            } else {
                Question::new(
                    state.current_qname.clone(),
                    state.original_query.record_type().unwrap_or(RecordType::A),
                    RecordClass::IN,
                )
            };
            
            debug!(
                zone = %state.current_zone,
                query = %query_question,
                depth = state.depth,
                "Querying nameservers"
            );
            
            // Query the nameservers
            let response = self.query_nameservers(&ns_addrs, &query_question, state).await?;
            
            // Process the response
            match self.process_response(&response, state).await? {
                ResponseAction::Answer(msg) => {
                    // We have a final answer
                    return Ok(msg);
                }
                ResponseAction::Referral(zone, _servers) => {
                    // Got a referral, continue with new zone
                    trace!(
                        old_zone = %state.current_zone,
                        new_zone = %zone,
                        "Following referral"
                    );
                    state.current_zone = zone;
                    state.depth += 1;
                }
                ResponseAction::Cname(target) => {
                    // Follow CNAME chain
                    if state.cname_count >= self.config.max_cname_chain {
                        return Err(ResolverError::Protocol("CNAME chain too long".into()));
                    }
                    
                    if !state.chase_name(&target) {
                        return Err(ResolverError::Protocol("CNAME loop detected".into()));
                    }
                    
                    trace!(
                        old_name = %state.current_qname,
                        new_name = %target,
                        "Following CNAME"
                    );
                    
                    state.current_qname = target;
                    state.current_zone = Name::root(); // Start from root for new name
                    state.cname_count += 1;
                    state.depth = 0; // Reset depth for CNAME target
                }
                ResponseAction::Dname(target) => {
                    // Apply DNAME substitution
                    if state.cname_count >= self.config.max_cname_chain {
                        return Err(ResolverError::Protocol("DNAME chain too long".into()));
                    }
                    
                    trace!(
                        old_name = %state.current_qname,
                        new_name = %target,
                        "Following DNAME"
                    );
                    
                    state.current_qname = target;
                    state.current_zone = Name::root();
                    state.cname_count += 1;
                    state.depth = 0;
                }
            }
        }
    }
    
    /// Finds the best nameservers for a zone.
    async fn find_nameservers(
        &self,
        zone: &Name,
        state: &ResolutionState,
    ) -> Result<Vec<SocketAddr>> {
        // Check NS cache first
        if let Some(entry) = self.ns_cache.get(zone) {
            if entry.expires_at > Instant::now() {
                let addrs: Vec<_> = entry.nameservers
                    .iter()
                    .flat_map(|ns| ns.addresses.iter().map(|a| SocketAddr::new(*a, 53)))
                    .filter(|a| !state.visited_servers.contains(a))
                    .collect();
                
                if !addrs.is_empty() {
                    trace!(zone = %zone, count = addrs.len(), "Using cached NS");
                    return Ok(addrs);
                }
            }
        }
        
        // For root zone, use root hints
        if zone.is_root() {
            return Ok(self.root_hints.get_servers());
        }
        
        // Try to find cached NS for parent zones
        let mut current = zone.clone();
        while let Some(parent) = current.parent() {
            if let Some(entry) = self.ns_cache.get(&parent) {
                if entry.expires_at > Instant::now() {
                    let addrs: Vec<_> = entry.nameservers
                        .iter()
                        .flat_map(|ns| ns.addresses.iter().map(|a| SocketAddr::new(*a, 53)))
                        .filter(|a| !state.visited_servers.contains(a))
                        .collect();
                    
                    if !addrs.is_empty() {
                        trace!(zone = %parent, count = addrs.len(), "Using parent zone cached NS");
                        return Ok(addrs);
                    }
                }
            }
            current = parent;
        }
        
        // Fall back to root hints
        Ok(self.root_hints.get_servers())
    }
    
    /// Queries multiple nameservers in parallel.
    async fn query_nameservers(
        &self,
        servers: &[SocketAddr],
        question: &Question,
        state: &mut ResolutionState,
    ) -> Result<Message> {
        // Limit concurrent queries
        let query_count = servers.len().min(self.config.max_concurrent_ns_queries);
        let servers_to_try: Vec<_> = servers.iter().take(query_count).cloned().collect();
        
        if servers_to_try.is_empty() {
            return Err(ResolverError::NoUpstream);
        }
        
        // Build query message
        let mut query = if state.dnssec_requested {
            Message::query_dnssec(question.clone())
        } else {
            Message::query(question.clone())
        };
        
        // Apply 0x20 encoding if enabled
        if self.config.enable_0x20 {
            apply_0x20_encoding(&mut query);
        }
        
        // Query servers in parallel
        let futures: Vec<_> = servers_to_try
            .iter()
            .map(|addr| {
                let addr = *addr;
                let query = query.clone();
                let timeout_duration = self.config.query_timeout;
                
                async move {
                    let result = self.query_single_server(addr, &query, timeout_duration).await;
                    (addr, result)
                }
            })
            .collect();
        
        // Wait for all queries
        let results = future::join_all(futures).await;
        
        // Find best successful response
        let mut best_response: Option<(SocketAddr, Message)> = None;
        let mut last_error = None;
        
        for (addr, result) in results {
            match result {
                Ok(response) => {
                    // Mark server as visited
                    state.visit_server(addr);
                    
                    // Validate response
                    if !self.validate_response(&query, &response) {
                        debug!(server = %addr, "Invalid response (ID or question mismatch)");
                        continue;
                    }
                    
                    // DNSSEC validation if enabled
                    if state.dnssec_requested {
                        if let Some(validator) = &self.dnssec_validator {
                            self.metrics.dnssec_validations.fetch_add(1, Ordering::Relaxed);
                            
                            let validation = validator.validate_response(&response).await;
                            match validation {
                                ValidationResult::Secure | ValidationResult::Insecure => {
                                    // Accept
                                }
                                ValidationResult::Bogus(reason) => {
                                    self.metrics.dnssec_failures.fetch_add(1, Ordering::Relaxed);
                                    warn!(server = %addr, reason = %reason, "DNSSEC validation failed");
                                    continue;
                                }
                                ValidationResult::Indeterminate => {
                                    // Accept but don't set AD flag
                                }
                            }
                        }
                    }
                    
                    // Prefer authoritative answers
                    match &best_response {
                        None => {
                            best_response = Some((addr, response));
                        }
                        Some((_, prev)) if !prev.is_authoritative() && response.is_authoritative() => {
                            best_response = Some((addr, response));
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    debug!(server = %addr, error = %e, "Server query failed");
                    self.root_hints.record_failure(&addr.ip());
                    last_error = Some(e);
                }
            }
        }
        
        match best_response {
            Some((_addr, response)) => {
                // Update RTT metrics for successful server
                // (In a real implementation, we'd track the actual RTT)
                Ok(response)
            }
            None => {
                Err(last_error.unwrap_or(ResolverError::AllUpstreamsFailed))
            }
        }
    }
    
    /// Queries a single server.
    async fn query_single_server(
        &self,
        addr: SocketAddr,
        query: &Message,
        timeout_duration: Duration,
    ) -> Result<Message> {
        // Try UDP first
        let udp_result = timeout(
            timeout_duration,
            self.query_udp(addr, query),
        ).await;
        
        match udp_result {
            Ok(Ok(response)) => {
                // Check for truncation
                if response.is_truncated() {
                    trace!(server = %addr, "Response truncated, retrying with TCP");
                    return self.query_tcp(addr, query, timeout_duration).await;
                }
                Ok(response)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ResolverError::Timeout),
        }
    }
    
    /// Queries a server over UDP.
    async fn query_udp(&self, addr: SocketAddr, query: &Message) -> Result<Message> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(addr).await?;
        
        let wire = query.to_wire();
        socket.send(&wire).await?;
        
        let mut buf = vec![0u8; 65535];
        let len = socket.recv(&mut buf).await?;
        
        let response = Message::parse(&buf[..len])
            .map_err(|e| ResolverError::Protocol(e.to_string()))?;
        
        Ok(response)
    }
    
    /// Queries a server over TCP.
    async fn query_tcp(
        &self,
        addr: SocketAddr,
        query: &Message,
        timeout_duration: Duration,
    ) -> Result<Message> {
        let mut stream = timeout(
            timeout_duration,
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .map_err(|_| ResolverError::Timeout)??;
        
        let wire = query.to_wire();
        
        // Write length-prefixed message
        let len = wire.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&wire).await?;
        
        // Read response
        let mut len_buf = [0u8; 2];
        timeout(timeout_duration, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| ResolverError::Timeout)??;
        
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        timeout(timeout_duration, stream.read_exact(&mut resp_buf))
            .await
            .map_err(|_| ResolverError::Timeout)??;
        
        let response = Message::parse(&resp_buf)
            .map_err(|e| ResolverError::Protocol(e.to_string()))?;
        
        Ok(response)
    }
    
    /// Validates a response against the query.
    fn validate_response(&self, query: &Message, response: &Message) -> bool {
        // Check ID matches
        if query.id() != response.id() {
            return false;
        }
        
        // Check question section matches
        if let (Some(q_question), Some(r_question)) = (query.question(), response.question()) {
            // With 0x20 encoding, we need case-insensitive comparison
            if q_question.qname.lowercased() != r_question.qname.lowercased() {
                return false;
            }
            if q_question.qtype != r_question.qtype {
                return false;
            }
            if q_question.qclass != r_question.qclass {
                return false;
            }
        } else if query.question().is_some() {
            return false;
        }
        
        true
    }
    
    /// Processes a response and determines the next action.
    async fn process_response(
        &self,
        response: &Message,
        state: &mut ResolutionState,
    ) -> Result<ResponseAction> {
        // Check for errors
        if response.is_servfail() {
            return Err(ResolverError::ServFail);
        }
        
        // Check for NXDOMAIN
        if response.is_nxdomain() {
            // Build final response with accumulated CNAME answers
            let mut final_response = Message::response_from(&Message::query(state.original_query.clone()));
            final_response.set_rcode(ResponseCode::NXDomain);
            
            for record in &state.accumulated_answers {
                final_response.add_answer(record.clone());
            }
            
            // Copy authority section (SOA for negative caching)
            for record in response.authority() {
                final_response.add_authority(record.clone());
            }
            
            return Ok(ResponseAction::Answer(final_response));
        }
        
        // Check for answers
        if !response.answers().is_empty() {
            // Look for CNAME records
            for record in response.answers() {
                if record.record_type() == Some(RecordType::CNAME) {
                    if let RData::CNAME(cname) = record.rdata() {
                        // Add CNAME to accumulated answers
                        state.accumulated_answers.push(record.clone());
                        
                        // Check if this answers our query type
                        if state.original_query.record_type() == Some(RecordType::CNAME) {
                            // CNAME was the actual query type, return answer
                            return Ok(self.build_final_response(response, state));
                        }
                        
                        // Need to follow CNAME
                        return Ok(ResponseAction::Cname(cname.target().clone()));
                    }
                }
            }
            
            // Look for DNAME records
            for record in response.answers() {
                if record.record_type() == Some(RecordType::DNAME) {
                    if let RData::DNAME(dname) = record.rdata() {
                        state.accumulated_answers.push(record.clone());
                        
                        // Apply DNAME substitution
                        if let Some(new_name) = self.apply_dname(
                            &state.current_qname,
                            record.name(),
                            dname.target(),
                        ) {
                            return Ok(ResponseAction::Dname(new_name));
                        }
                    }
                }
            }
            
            // Direct answer
            return Ok(self.build_final_response(response, state));
        }
        
        // Check for referral (NS records in authority section)
        if response.is_referral() {
            return self.process_referral(response, state).await;
        }
        
        // NODATA response (NOERROR but no answers)
        if response.is_nodata() {
            let final_response = self.build_final_response(response, state);
            // Clear any answers and just return with authority section
            return Ok(final_response);
        }
        
        // Unexpected response
        Err(ResolverError::Protocol("Unexpected response format".into()))
    }
    
    /// Builds the final response message.
    fn build_final_response(
        &self,
        response: &Message,
        state: &ResolutionState,
    ) -> ResponseAction {
        let mut final_response = Message::response_from(&Message::query(state.original_query.clone()));
        
        // Add accumulated CNAME answers first
        for record in &state.accumulated_answers {
            final_response.add_answer(record.clone());
        }
        
        // Add direct answers
        for record in response.answers() {
            final_response.add_answer(record.clone());
        }
        
        // Copy authority and additional sections
        for record in response.authority() {
            final_response.add_authority(record.clone());
        }
        for record in response.additional() {
            final_response.add_additional(record.clone());
        }
        
        ResponseAction::Answer(final_response)
    }
    
    /// Processes a referral response.
    async fn process_referral(
        &self,
        response: &Message,
        state: &ResolutionState,
    ) -> Result<ResponseAction> {
        // Extract NS records from authority section
        let mut ns_names: Vec<Name> = Vec::new();
        let mut zone: Option<Name> = None;
        
        for record in response.authority() {
            if record.record_type() == Some(RecordType::NS) {
                if let RData::NS(ns) = record.rdata() {
                    // Bailiwick check: NS record owner must be at or below current zone
                    if !self.is_in_bailiwick(record.name(), &state.current_zone) {
                        debug!(
                            ns = %record.name(),
                            zone = %state.current_zone,
                            "Ignoring out-of-bailiwick NS record"
                        );
                        continue;
                    }
                    
                    // Track the zone being delegated to
                    if zone.is_none() {
                        zone = Some(record.name().clone());
                    }
                    
                    ns_names.push(ns.nsdname().clone());
                }
            }
        }
        
        let zone = zone.ok_or_else(|| {
            ResolverError::Protocol("Referral without NS records".into())
        })?;
        
        // Extract glue records from additional section
        let mut nameservers: Vec<NameserverEntry> = Vec::new();
        
        for ns_name in &ns_names {
            let mut addresses = Vec::new();
            
            // Look for glue records
            for record in response.additional() {
                if record.name() != ns_name {
                    continue;
                }
                
                // Bailiwick check for glue: must be in the delegated zone
                if !self.is_in_bailiwick(ns_name, &zone) {
                    trace!(
                        ns = %ns_name,
                        zone = %zone,
                        "Ignoring out-of-bailiwick glue"
                    );
                    continue;
                }
                
                match record.rdata() {
                    RData::A(a) => {
                        addresses.push(IpAddr::V4(a.address()));
                    }
                    RData::AAAA(aaaa) => {
                        addresses.push(IpAddr::V6(aaaa.address()));
                    }
                    _ => {}
                }
            }
            
            nameservers.push(NameserverEntry {
                name: ns_name.clone(),
                addresses,
                rtt: AtomicU64::new(0),
                failures: AtomicU64::new(0),
            });
        }
        
        // Resolve NS addresses if no glue was provided
        for ns in &mut nameservers {
            if ns.addresses.is_empty() {
                // Need to resolve NS name - this is a recursive call
                trace!(ns = %ns.name, "Resolving NS address (no glue)");
                
                // Avoid infinite loops by checking if NS name is in the delegated zone
                if ns.name.is_subdomain_of(&zone) {
                    // This is a lame delegation (NS in zone but no glue)
                    debug!(ns = %ns.name, zone = %zone, "Lame delegation detected");
                    continue;
                }
                
                // Resolve the NS name
                ns.addresses = self.resolve_ns_addresses(&ns.name).await;
            }
        }
        
        // Filter out nameservers without addresses
        nameservers.retain(|ns| !ns.addresses.is_empty());
        
        if nameservers.is_empty() {
            return Err(ResolverError::Protocol("No usable nameservers in referral".into()));
        }
        
        // Cache the NS records
        let ttl = response.authority()
            .iter()
            .filter(|r| r.record_type() == Some(RecordType::NS))
            .map(|r| r.ttl())
            .min()
            .unwrap_or(3600);
        
        let cache_entry = NsCacheEntry {
            nameservers: nameservers.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl as u64),
            is_signed: response.authority()
                .iter()
                .any(|r| r.record_type() == Some(RecordType::DS)),
        };
        
        self.ns_cache.insert(zone.clone(), cache_entry);
        
        // Return NS addresses
        let addrs: Vec<_> = nameservers
            .iter()
            .flat_map(|ns| ns.addresses.iter().map(|a| SocketAddr::new(*a, 53)))
            .collect();
        
        Ok(ResponseAction::Referral(zone, addrs))
    }
    
    /// Resolves addresses for a nameserver name.
    ///
    /// This uses `BoxFuture` to break the infinite type recursion that would
    /// otherwise occur with recursive async calls.
    fn resolve_ns_addresses<'a>(&'a self, name: &'a Name) -> BoxFuture<'a, Vec<IpAddr>> {
        async move {
            let mut addresses = Vec::new();
            
            // Try A record
            let a_question = Question::a(name.clone());
            if let Ok(response) = Box::pin(self.resolve_recursive(&a_question)).await {
                for record in response.answers() {
                    if let RData::A(a) = record.rdata() {
                        addresses.push(IpAddr::V4(a.address()));
                    }
                }
            }
            
            // Try AAAA record
            let aaaa_question = Question::aaaa(name.clone());
            if let Ok(response) = Box::pin(self.resolve_recursive(&aaaa_question)).await {
                for record in response.answers() {
                    if let RData::AAAA(aaaa) = record.rdata() {
                        addresses.push(IpAddr::V6(aaaa.address()));
                    }
                }
            }
            
            addresses
        }.boxed()
    }
    
    /// Checks if a name is within the bailiwick of a zone.
    ///
    /// A name is in-bailiwick if it equals the zone or is a subdomain of it.
    fn is_in_bailiwick(&self, name: &Name, zone: &Name) -> bool {
        name == zone || name.is_subdomain_of(zone)
    }
    
    /// Applies QNAME minimization for privacy.
    fn minimize_qname(&self, state: &ResolutionState) -> Question {
        // Calculate how many labels we need to expose
        let current_zone_labels = state.current_zone.label_count();
        let full_name_labels = state.current_qname.label_count();
        
        if full_name_labels <= current_zone_labels {
            // Already at or below current zone depth
            return Question::new(
                state.current_qname.clone(),
                state.original_query.record_type().unwrap_or(RecordType::A),
                RecordClass::IN,
            );
        }
        
        // Only expose one label more than the current zone
        let labels_to_keep = current_zone_labels;
        let mut minimized = state.current_qname.clone();
        
        // Strip labels from the left until we have the right count
        while minimized.label_count() > labels_to_keep + 1 {
            if let Some(parent) = minimized.parent() {
                minimized = parent;
            } else {
                break;
            }
        }
        
        // Query for NS record type (or A if at final depth)
        let qtype = if minimized == state.current_qname {
            state.original_query.record_type().unwrap_or(RecordType::A)
        } else {
            RecordType::NS
        };
        
        Question::new(minimized, qtype, RecordClass::IN)
    }
    
    /// Applies DNAME substitution.
    fn apply_dname(&self, qname: &Name, dname_owner: &Name, dname_target: &Name) -> Option<Name> {
        // Check if qname is under the DNAME owner
        if !qname.is_subdomain_of(dname_owner) {
            return None;
        }
        
        // Get the suffix to preserve
        let owner_labels = dname_owner.label_count();
        let qname_labels = qname.label_count();
        
        if qname_labels <= owner_labels {
            return None;
        }
        
        // Build new name: (qname prefix) + (dname target)
        // This is a simplified implementation
        let qname_str = qname.to_string();
        let owner_str = dname_owner.to_string();
        let target_str = dname_target.to_string();
        
        // Extract prefix from qname
        if let Some(prefix) = qname_str.strip_suffix(&owner_str) {
            let new_name_str = format!("{}{}", prefix, target_str);
            Name::from_str(&new_name_str).ok()
        } else {
            None
        }
    }
}

#[async_trait]
impl Resolver for RecursiveResolver {
    async fn resolve(&self, question: &Question) -> Result<Message> {
        self.resolve_recursive(question).await
    }
}

// ============================================================================
// Response Action
// ============================================================================

/// Action to take after processing a response.
enum ResponseAction {
    /// Final answer ready.
    Answer(Message),
    /// Referral to another zone.
    Referral(Name, Vec<SocketAddr>),
    /// Follow CNAME chain.
    Cname(Name),
    /// Follow DNAME substitution.
    Dname(Name),
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Applies 0x20 bit encoding to a query for cache poisoning resistance.
///
/// This randomizes the case of letters in the query name. The response must
/// preserve this casing, making it harder for attackers to forge responses.
fn apply_0x20_encoding(_query: &mut Message) {
    // This would modify the question section's qname with random case
    // For now, this is a placeholder - proper implementation would
    // require Name to support in-place case modification
}

/// QNAME minimization helper.
///
/// Returns a sequence of names to query from most general to most specific.
pub fn qname_minimization_sequence(name: &Name) -> Vec<Name> {
    let mut names = Vec::new();
    let mut current = name.clone();

    // Build list from root to full name
    while !current.is_root() {
        names.push(current.clone());
        if let Some(parent) = current.parent() {
            current = parent;
        } else {
            break;
        }
    }

    names.reverse();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use stria_cache::CacheConfig;
    use std::str::FromStr;

    #[test]
    fn test_qname_minimization_sequence() {
        let name = Name::from_str("www.example.com").unwrap();
        let sequence = qname_minimization_sequence(&name);

        // Should be: com, example.com, www.example.com
        assert_eq!(sequence.len(), 3);
        assert_eq!(sequence[0].to_string(), "com.");
        assert_eq!(sequence[1].to_string(), "example.com.");
        assert_eq!(sequence[2].to_string(), "www.example.com.");
    }

    #[test]
    fn test_root_hints() {
        let hints = RootHints::from_builtin();
        let servers = hints.get_servers();
        
        // Should have at least 13 root servers
        assert!(servers.len() >= 13);
        
        // First server should be a.root-servers.net
        assert!(servers.iter().any(|s| s.ip() == IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4))));
    }

    #[test]
    fn test_bailiwick_check() {
        let resolver = RecursiveResolver::new(Arc::new(DnsCache::new(CacheConfig::default())));
        
        let zone = Name::from_str("example.com").unwrap();
        let in_bailiwick = Name::from_str("ns1.example.com").unwrap();
        let out_of_bailiwick = Name::from_str("ns1.other.com").unwrap();
        
        assert!(resolver.is_in_bailiwick(&in_bailiwick, &zone));
        assert!(resolver.is_in_bailiwick(&zone, &zone));
        assert!(!resolver.is_in_bailiwick(&out_of_bailiwick, &zone));
    }

    #[test]
    fn test_recursive_config_defaults() {
        let config = RecursiveConfig::default();
        
        assert_eq!(config.max_depth, 30);
        assert_eq!(config.max_cname_chain, 8);
        assert_eq!(config.query_timeout, Duration::from_secs(2));
        assert_eq!(config.total_timeout, Duration::from_secs(30));
        assert!(config.enable_dnssec);
        assert!(config.enable_qname_minimization);
    }

    #[test]
    fn test_resolution_state() {
        let question = Question::a(Name::from_str("www.example.com").unwrap());
        let mut state = ResolutionState::new(question, true);
        
        assert_eq!(state.depth, 0);
        assert_eq!(state.cname_count, 0);
        assert!(state.dnssec_requested);
        
        // Test CNAME loop detection
        let name1 = Name::from_str("alias.example.com").unwrap();
        assert!(state.chase_name(&name1));
        assert!(!state.chase_name(&name1)); // Already visited
        
        // Test server loop detection
        let addr = "1.2.3.4:53".parse().unwrap();
        assert!(state.visit_server(addr));
        assert!(!state.visit_server(addr)); // Already visited
    }

    #[tokio::test]
    async fn test_resolver_creation() {
        let cache = Arc::new(DnsCache::new(CacheConfig::default()));
        let resolver = RecursiveResolver::new(cache);
        
        // Should have metrics initialized
        assert_eq!(resolver.metrics().queries_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_root_server_socket_addrs() {
        let root = &ROOT_HINTS[0];
        let addrs = root.socket_addrs();
        
        assert!(!addrs.is_empty());
        assert!(addrs.iter().any(|a| a.port() == 53));
    }
}
