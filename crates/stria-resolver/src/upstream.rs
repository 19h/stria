//! Upstream server management.

use super::Result;
use stria_proto::Message;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Upstream protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocol {
    /// Plain UDP.
    Udp,
    /// Plain TCP.
    Tcp,
    /// DNS over TLS.
    Dot,
    /// DNS over HTTPS.
    Doh,
    /// DNS over QUIC.
    Doq,
}

impl UpstreamProtocol {
    /// Returns the default port for this protocol.
    pub const fn default_port(&self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 53,
            Self::Dot | Self::Doq => 853,
            Self::Doh => 443,
        }
    }
}

/// Upstream server configuration.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Server address.
    pub address: SocketAddr,

    /// Protocol to use.
    pub protocol: UpstreamProtocol,

    /// TLS server name (for encrypted protocols).
    pub tls_name: Option<String>,

    /// HTTP path (for DoH).
    pub path: Option<String>,

    /// Weight for load balancing (higher = more traffic).
    pub weight: u32,

    /// Query timeout.
    pub timeout: Duration,
}

/// Upstream server state.
pub struct Upstream {
    config: UpstreamConfig,
    /// Number of successful queries.
    successes: AtomicU64,
    /// Number of failed queries.
    failures: AtomicU64,
    /// Current average latency (microseconds).
    latency_us: AtomicU64,
    /// Whether the upstream is currently healthy.
    healthy: std::sync::atomic::AtomicBool,
    /// Last health check time.
    last_check: RwLock<Instant>,
}

impl Upstream {
    /// Creates a new upstream.
    pub fn new(config: UpstreamConfig) -> Self {
        Self {
            config,
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            latency_us: AtomicU64::new(0),
            healthy: std::sync::atomic::AtomicBool::new(true),
            last_check: RwLock::new(Instant::now()),
        }
    }

    /// Returns the upstream configuration.
    pub fn config(&self) -> &UpstreamConfig {
        &self.config
    }

    /// Returns the server address.
    pub fn address(&self) -> SocketAddr {
        self.config.address
    }

    /// Returns the protocol.
    pub fn protocol(&self) -> UpstreamProtocol {
        self.config.protocol
    }

    /// Returns true if the upstream is healthy.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Marks the upstream as healthy.
    pub fn mark_healthy(&self) {
        self.healthy.store(true, Ordering::Relaxed);
    }

    /// Marks the upstream as unhealthy.
    pub fn mark_unhealthy(&self) {
        self.healthy.store(false, Ordering::Relaxed);
    }

    /// Records a successful query.
    pub fn record_success(&self, latency: Duration) {
        self.successes.fetch_add(1, Ordering::Relaxed);

        // Update average latency (exponential moving average)
        let new_latency = latency.as_micros() as u64;
        let current = self.latency_us.load(Ordering::Relaxed);
        let updated = if current == 0 {
            new_latency
        } else {
            (current * 7 + new_latency) / 8 // EMA with alpha = 0.125
        };
        self.latency_us.store(updated, Ordering::Relaxed);

        self.mark_healthy();
    }

    /// Records a failed query.
    pub fn record_failure(&self) {
        let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;

        // Mark unhealthy after 3 consecutive failures
        // (simplified - real implementation would be more sophisticated)
        if failures > 3 {
            self.mark_unhealthy();
        }
    }

    /// Returns the success rate.
    pub fn success_rate(&self) -> f64 {
        let successes = self.successes.load(Ordering::Relaxed);
        let failures = self.failures.load(Ordering::Relaxed);
        let total = successes + failures;

        if total == 0 {
            1.0
        } else {
            successes as f64 / total as f64
        }
    }

    /// Returns the average latency.
    pub fn average_latency(&self) -> Duration {
        Duration::from_micros(self.latency_us.load(Ordering::Relaxed))
    }

    /// Returns the effective weight for load balancing.
    ///
    /// This combines the configured weight with health metrics.
    pub fn effective_weight(&self) -> u32 {
        if !self.is_healthy() {
            return 0;
        }

        let base = self.config.weight;
        let success_rate = self.success_rate();

        (base as f64 * success_rate) as u32
    }
}

/// Upstream group for load balancing.
pub struct UpstreamGroup {
    upstreams: Vec<Arc<Upstream>>,
    next_index: AtomicUsize,
}

impl UpstreamGroup {
    /// Creates a new upstream group.
    pub fn new(upstreams: Vec<Arc<Upstream>>) -> Self {
        Self {
            upstreams,
            next_index: AtomicUsize::new(0),
        }
    }

    /// Returns the next available upstream (round-robin with health check).
    pub fn next(&self) -> Option<Arc<Upstream>> {
        if self.upstreams.is_empty() {
            return None;
        }

        let len = self.upstreams.len();
        let start = self.next_index.fetch_add(1, Ordering::Relaxed) % len;

        // Try each upstream starting from the current index
        for i in 0..len {
            let idx = (start + i) % len;
            let upstream = &self.upstreams[idx];
            if upstream.is_healthy() {
                return Some(upstream.clone());
            }
        }

        // All unhealthy - return the first one anyway
        Some(self.upstreams[0].clone())
    }

    /// Returns the best upstream based on weighted selection.
    pub fn select_weighted(&self) -> Option<Arc<Upstream>> {
        if self.upstreams.is_empty() {
            return None;
        }

        let total_weight: u32 = self.upstreams.iter().map(|u| u.effective_weight()).sum();

        if total_weight == 0 {
            // All have zero weight, use round-robin
            return self.next();
        }

        let target = rand::random::<u32>() % total_weight;
        let mut cumulative = 0;

        for upstream in &self.upstreams {
            cumulative += upstream.effective_weight();
            if cumulative > target {
                return Some(upstream.clone());
            }
        }

        self.upstreams.last().cloned()
    }

    /// Returns all upstreams.
    pub fn all(&self) -> &[Arc<Upstream>] {
        &self.upstreams
    }

    /// Returns healthy upstreams.
    pub fn healthy(&self) -> Vec<Arc<Upstream>> {
        self.upstreams
            .iter()
            .filter(|u| u.is_healthy())
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_upstream() -> Upstream {
        Upstream::new(UpstreamConfig {
            address: "8.8.8.8:53".parse().unwrap(),
            protocol: UpstreamProtocol::Udp,
            tls_name: None,
            path: None,
            weight: 100,
            timeout: Duration::from_secs(5),
        })
    }

    #[test]
    fn test_upstream_health() {
        let upstream = test_upstream();
        assert!(upstream.is_healthy());

        upstream.mark_unhealthy();
        assert!(!upstream.is_healthy());

        upstream.mark_healthy();
        assert!(upstream.is_healthy());
    }

    #[test]
    fn test_upstream_metrics() {
        let upstream = test_upstream();

        upstream.record_success(Duration::from_millis(10));
        upstream.record_success(Duration::from_millis(20));

        assert_eq!(upstream.successes.load(Ordering::Relaxed), 2);
        assert!(upstream.average_latency() > Duration::ZERO);
        assert_eq!(upstream.success_rate(), 1.0);
    }
}
