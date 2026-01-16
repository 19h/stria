//! # Stria DNS Cache
//!
//! Multi-tier DNS caching with L1/L2/L3 support, serve-stale, prefetch,
//! and cache poisoning resistance.
//!
//! ## Architecture
//!
//! - **L1 (Per-CPU)**: Thread-local caches for hot records, lock-free access
//! - **L2 (Shared)**: Process-wide shared cache with fine-grained locking
//! - **L3 (Distributed)**: Optional Redis/memcached for multi-instance deployments
//!
//! ## Features
//!
//! - Serve-stale (RFC 8767)
//! - Aggressive NSEC caching (RFC 8198)
//! - Prefetch for expiring records
//! - Cache poisoning countermeasures
//! - Negative caching with proper TTL handling

use stria_proto::{Message, Name, Question, RecordType, ResourceRecord};
use dashmap::DashMap;
use moka::future::Cache as MokaCache;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod entry;
pub mod key;
pub mod l1;
pub mod l2;
pub mod negative;
pub mod prefetch;

pub use entry::CacheEntry;
pub use key::CacheKey;

/// DNS cache configuration.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum entries in L1 cache.
    pub l1_max_entries: usize,

    /// Maximum entries in L2 cache.
    pub l2_max_entries: usize,

    /// Minimum TTL (floor).
    pub min_ttl: Duration,

    /// Maximum TTL (ceiling).
    pub max_ttl: Duration,

    /// Negative cache TTL.
    pub negative_ttl: Duration,

    /// Enable serve-stale.
    pub serve_stale: bool,

    /// Stale serving TTL (how long after expiry to serve stale).
    pub stale_ttl: Duration,

    /// Enable prefetch.
    pub prefetch: bool,

    /// Prefetch threshold (percentage of TTL remaining).
    pub prefetch_threshold: u8,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            l1_max_entries: 10_000,
            l2_max_entries: 100_000,
            min_ttl: Duration::from_secs(30),
            max_ttl: Duration::from_secs(86400 * 7),
            negative_ttl: Duration::from_secs(900),
            serve_stale: true,
            stale_ttl: Duration::from_secs(86400),
            prefetch: true,
            prefetch_threshold: 10,
        }
    }
}

/// DNS cache.
pub struct DnsCache {
    config: CacheConfig,
    cache: MokaCache<CacheKey, CacheEntry>,
    stats: CacheStats,
}

impl DnsCache {
    /// Creates a new DNS cache.
    pub fn new(config: CacheConfig) -> Self {
        let cache = MokaCache::builder()
            .max_capacity(config.l2_max_entries as u64)
            .time_to_live(config.max_ttl)
            .build();

        Self {
            config,
            cache,
            stats: CacheStats::default(),
        }
    }

    /// Looks up a cache entry.
    pub async fn lookup(&self, key: &CacheKey) -> Option<CacheLookupResult> {
        let entry = self.cache.get(key).await?;

        let now = Instant::now();
        let is_expired = entry.is_expired(now);
        let is_stale = is_expired && entry.is_within_stale_period(now, self.config.stale_ttl);

        if !is_expired {
            self.stats.record_hit();

            // Check if prefetch is needed
            let should_prefetch = self.config.prefetch
                && entry.should_prefetch(now, self.config.prefetch_threshold);

            Some(CacheLookupResult {
                entry,
                stale: false,
                should_prefetch,
            })
        } else if self.config.serve_stale && is_stale {
            self.stats.record_stale_hit();
            Some(CacheLookupResult {
                entry,
                stale: true,
                should_prefetch: true,
            })
        } else {
            self.stats.record_miss();
            None
        }
    }

    /// Inserts a cache entry.
    pub async fn insert(&self, key: CacheKey, entry: CacheEntry) {
        self.cache.insert(key, entry).await;
    }

    /// Caches a successful response.
    pub async fn cache_response(&self, question: &Question, response: &Message) {
        let key = CacheKey::from_question(question);

        // Determine TTL
        let ttl = response
            .answers()
            .iter()
            .map(|r| r.ttl())
            .min()
            .unwrap_or(0);

        let ttl = Duration::from_secs(ttl as u64)
            .max(self.config.min_ttl)
            .min(self.config.max_ttl);

        let entry = CacheEntry::from_response(response, ttl);
        self.insert(key, entry).await;
    }

    /// Caches a negative response (NXDOMAIN or NODATA).
    pub async fn cache_negative(&self, question: &Question, response: &Message) {
        let key = CacheKey::from_question(question);

        // Use SOA minimum TTL if available, otherwise config default
        let ttl = response
            .authority()
            .iter()
            .filter(|r| r.record_type() == Some(RecordType::SOA))
            .filter_map(|r| {
                if let stria_proto::RData::SOA(soa) = r.rdata() {
                    Some(Duration::from_secs(soa.minimum() as u64))
                } else {
                    None
                }
            })
            .next()
            .unwrap_or(self.config.negative_ttl)
            .min(self.config.negative_ttl);

        let entry = CacheEntry::negative(response.rcode(), ttl);
        self.insert(key, entry).await;
    }

    /// Invalidates a cache entry.
    pub async fn invalidate(&self, key: &CacheKey) {
        self.cache.invalidate(key).await;
    }

    /// Clears the entire cache.
    pub fn clear(&self) {
        self.cache.invalidate_all();
    }

    /// Returns cache statistics.
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Returns the number of entries in the cache.
    pub fn len(&self) -> usize {
        self.cache.entry_count() as usize
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.entry_count() == 0
    }
}

/// Cache lookup result.
#[derive(Debug)]
pub struct CacheLookupResult {
    /// The cache entry.
    pub entry: CacheEntry,

    /// Whether this is stale data.
    pub stale: bool,

    /// Whether prefetch should be triggered.
    pub should_prefetch: bool,
}

/// Cache statistics.
#[derive(Debug, Default)]
pub struct CacheStats {
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    stale_hits: std::sync::atomic::AtomicU64,
    prefetches: std::sync::atomic::AtomicU64,
}

impl CacheStats {
    fn record_hit(&self) {
        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_miss(&self) {
        self.misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_stale_hit(&self) {
        self.stale_hits
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_prefetch(&self) {
        self.prefetches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn stale_hits(&self) -> u64 {
        self.stale_hits.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn prefetches(&self) -> u64 {
        self.prefetches.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits();
        let total = hits + self.misses();
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_cache_basic() {
        let cache = DnsCache::new(CacheConfig::default());

        let key = CacheKey::new(
            Name::from_str("example.com").unwrap(),
            stria_proto::rtype::Type::Known(RecordType::A),
            stria_proto::class::Class::Known(stria_proto::RecordClass::IN),
        );

        let entry = CacheEntry::empty(Duration::from_secs(300));
        cache.insert(key.clone(), entry).await;

        let result = cache.lookup(&key).await;
        assert!(result.is_some());
    }
}
