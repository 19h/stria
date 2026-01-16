//! # Stria DNS Metrics
//!
//! Comprehensive observability with Prometheus metrics, OpenTelemetry tracing,
//! and structured logging.
//!
//! ## Features
//!
//! - **Prometheus metrics**: QPS, latency histograms, cache stats, error rates
//! - **OpenTelemetry tracing**: Distributed tracing support
//! - **Structured logging**: JSON and text log formats
//! - **Health checks**: Liveness and readiness probes

use metrics::{counter, gauge, histogram};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub mod prometheus;
pub mod tracing_setup;

/// Global metrics instance.
static METRICS: OnceCell<DnsMetrics> = OnceCell::new();

/// Gets or initializes the global metrics instance.
pub fn metrics() -> &'static DnsMetrics {
    METRICS.get_or_init(DnsMetrics::new)
}

/// DNS server metrics.
pub struct DnsMetrics {
    /// Server start time.
    start_time: Instant,

    /// Total queries received.
    queries_total: AtomicU64,

    /// Total responses sent.
    responses_total: AtomicU64,
}

impl DnsMetrics {
    /// Creates a new metrics instance.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            queries_total: AtomicU64::new(0),
            responses_total: AtomicU64::new(0),
        }
    }

    /// Returns the server uptime.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    // =========================================================================
    // Query metrics
    // =========================================================================

    /// Records a received query.
    pub fn record_query(&self, protocol: &str, qtype: &str) {
        self.queries_total.fetch_add(1, Ordering::Relaxed);
        counter!("dns_queries_total", "protocol" => protocol.to_string(), "type" => qtype.to_string()).increment(1);
    }

    /// Records a sent response.
    pub fn record_response(&self, protocol: &str, rcode: &str) {
        self.responses_total.fetch_add(1, Ordering::Relaxed);
        counter!("dns_responses_total", "protocol" => protocol.to_string(), "rcode" => rcode.to_string()).increment(1);
    }

    /// Records query latency.
    pub fn record_latency(&self, protocol: &str, duration: Duration) {
        histogram!("dns_query_duration_seconds", "protocol" => protocol.to_string()).record(duration.as_secs_f64());
    }

    /// Records a query error.
    pub fn record_error(&self, error_type: &str) {
        counter!("dns_errors_total", "type" => error_type.to_string()).increment(1);
    }

    // =========================================================================
    // Cache metrics
    // =========================================================================

    /// Records a cache hit.
    pub fn record_cache_hit(&self) {
        counter!("dns_cache_hits_total").increment(1);
    }

    /// Records a cache miss.
    pub fn record_cache_miss(&self) {
        counter!("dns_cache_misses_total").increment(1);
    }

    /// Updates cache size gauge.
    pub fn set_cache_size(&self, size: usize) {
        gauge!("dns_cache_entries").set(size as f64);
    }

    /// Updates cache memory usage gauge.
    pub fn set_cache_memory(&self, bytes: usize) {
        gauge!("dns_cache_memory_bytes").set(bytes as f64);
    }

    /// Records a stale cache serve.
    pub fn record_stale_serve(&self) {
        counter!("dns_cache_stale_serves_total").increment(1);
    }

    /// Records a cache prefetch.
    pub fn record_prefetch(&self) {
        counter!("dns_cache_prefetches_total").increment(1);
    }

    // =========================================================================
    // Upstream metrics
    // =========================================================================

    /// Records an upstream query.
    pub fn record_upstream_query(&self, upstream: &str) {
        counter!("dns_upstream_queries_total", "upstream" => upstream.to_string()).increment(1);
    }

    /// Records upstream latency.
    pub fn record_upstream_latency(&self, upstream: &str, duration: Duration) {
        histogram!("dns_upstream_duration_seconds", "upstream" => upstream.to_string())
            .record(duration.as_secs_f64());
    }

    /// Records an upstream failure.
    pub fn record_upstream_failure(&self, upstream: &str, error: &str) {
        counter!("dns_upstream_failures_total", "upstream" => upstream.to_string(), "error" => error.to_string())
            .increment(1);
    }

    // =========================================================================
    // DNSSEC metrics
    // =========================================================================

    /// Records a DNSSEC validation.
    pub fn record_dnssec_validation(&self, result: &str) {
        counter!("dns_dnssec_validations_total", "result" => result.to_string()).increment(1);
    }

    // =========================================================================
    // Filtering metrics
    // =========================================================================

    /// Records a blocked query.
    pub fn record_blocked(&self, reason: &str) {
        counter!("dns_blocked_total", "reason" => reason.to_string()).increment(1);
    }

    // =========================================================================
    // Rate limiting metrics
    // =========================================================================

    /// Records a rate-limited query.
    pub fn record_rate_limited(&self) {
        counter!("dns_rate_limited_total").increment(1);
    }

    /// Records a slipped response.
    pub fn record_rrl_slip(&self) {
        counter!("dns_rrl_slips_total").increment(1);
    }

    // =========================================================================
    // Connection metrics
    // =========================================================================

    /// Updates the active connections gauge.
    pub fn set_active_connections(&self, protocol: &str, count: usize) {
        gauge!("dns_connections_active", "protocol" => protocol.to_string()).set(count as f64);
    }

    /// Records a new connection.
    pub fn record_connection(&self, protocol: &str) {
        counter!("dns_connections_total", "protocol" => protocol.to_string()).increment(1);
    }

    // =========================================================================
    // Zone metrics
    // =========================================================================

    /// Updates the zone record count.
    pub fn set_zone_records(&self, zone: &str, count: usize) {
        gauge!("dns_zone_records", "zone" => zone.to_string()).set(count as f64);
    }

    /// Records a zone transfer.
    pub fn record_zone_transfer(&self, zone: &str, transfer_type: &str) {
        counter!("dns_zone_transfers_total", "zone" => zone.to_string(), "type" => transfer_type.to_string())
            .increment(1);
    }
}

impl Default for DnsMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Query timing helper.
pub struct QueryTimer {
    start: Instant,
    protocol: String,
}

impl QueryTimer {
    /// Starts a new query timer.
    pub fn start(protocol: impl Into<String>) -> Self {
        Self {
            start: Instant::now(),
            protocol: protocol.into(),
        }
    }

    /// Returns the elapsed duration.
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Finishes timing and records the latency.
    pub fn finish(self) {
        metrics().record_latency(&self.protocol, self.elapsed());
    }
}

/// Health check status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Service is healthy.
    Healthy,

    /// Service is degraded but operational.
    Degraded,

    /// Service is unhealthy.
    Unhealthy,
}

impl HealthStatus {
    /// Returns true if the service is healthy or degraded.
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }
}

/// Health check result.
#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// Overall status.
    pub status: HealthStatus,

    /// Individual component statuses.
    pub components: Vec<ComponentHealth>,
}

/// Component health status.
#[derive(Debug, Clone)]
pub struct ComponentHealth {
    /// Component name.
    pub name: String,

    /// Component status.
    pub status: HealthStatus,

    /// Optional message.
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = DnsMetrics::new();
        assert!(metrics.uptime() >= Duration::ZERO);
    }

    #[test]
    fn test_query_timer() {
        let timer = QueryTimer::start("udp");
        std::thread::sleep(Duration::from_millis(10));
        let elapsed = timer.elapsed();
        assert!(elapsed >= Duration::from_millis(10));
    }

    #[test]
    fn test_health_status() {
        assert!(HealthStatus::Healthy.is_ok());
        assert!(HealthStatus::Degraded.is_ok());
        assert!(!HealthStatus::Unhealthy.is_ok());
    }
}
