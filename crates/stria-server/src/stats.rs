//! Server statistics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Server statistics.
#[derive(Debug, Default)]
pub struct ServerStats {
    /// Server start time.
    start_time: Option<Instant>,

    /// UDP queries received.
    pub udp_queries: AtomicU64,

    /// TCP queries received.
    pub tcp_queries: AtomicU64,

    /// DoT queries received.
    pub dot_queries: AtomicU64,

    /// DoH queries received.
    pub doh_queries: AtomicU64,

    /// DoQ queries received.
    pub doq_queries: AtomicU64,

    /// Responses sent.
    pub responses: AtomicU64,

    /// Rate-limited queries.
    pub rate_limited: AtomicU64,

    /// Dropped queries.
    pub dropped: AtomicU64,

    /// Parse errors.
    pub parse_errors: AtomicU64,

    /// Active TCP connections.
    pub tcp_connections: AtomicU64,
}

impl ServerStats {
    /// Creates new server statistics.
    pub fn new() -> Self {
        Self {
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    /// Returns the server uptime.
    pub fn uptime(&self) -> Option<std::time::Duration> {
        self.start_time.map(|t| t.elapsed())
    }

    /// Returns total queries received.
    pub fn total_queries(&self) -> u64 {
        self.udp_queries.load(Ordering::Relaxed)
            + self.tcp_queries.load(Ordering::Relaxed)
            + self.dot_queries.load(Ordering::Relaxed)
            + self.doh_queries.load(Ordering::Relaxed)
            + self.doq_queries.load(Ordering::Relaxed)
    }

    /// Increments UDP query counter.
    pub fn inc_udp(&self) {
        self.udp_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments TCP query counter.
    pub fn inc_tcp(&self) {
        self.tcp_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments response counter.
    pub fn inc_response(&self) {
        self.responses.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments rate-limited counter.
    pub fn inc_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments parse error counter.
    pub fn inc_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments TCP connection counter.
    pub fn inc_tcp_connection(&self) {
        self.tcp_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements TCP connection counter.
    pub fn dec_tcp_connection(&self) {
        self.tcp_connections.fetch_sub(1, Ordering::Relaxed);
    }
}
