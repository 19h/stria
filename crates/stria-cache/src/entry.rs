//! Cache entry implementation.

use stria_proto::{Message, ResourceRecord, ResponseCode};
use std::time::{Duration, Instant};

/// A cached DNS response.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The cached records.
    records: Vec<ResourceRecord>,

    /// Response code (for negative caching).
    rcode: ResponseCode,

    /// When this entry was created.
    created_at: Instant,

    /// Time to live.
    ttl: Duration,

    /// Whether this is a negative cache entry.
    negative: bool,
}

impl CacheEntry {
    /// Creates a new cache entry from records.
    pub fn new(records: Vec<ResourceRecord>, ttl: Duration) -> Self {
        Self {
            records,
            rcode: ResponseCode::NoError,
            created_at: Instant::now(),
            ttl,
            negative: false,
        }
    }

    /// Creates an empty cache entry (for testing).
    pub fn empty(ttl: Duration) -> Self {
        Self::new(Vec::new(), ttl)
    }

    /// Creates a cache entry from a DNS response.
    pub fn from_response(response: &Message, ttl: Duration) -> Self {
        Self {
            records: response.answers().to_vec(),
            rcode: response.rcode(),
            created_at: Instant::now(),
            ttl,
            negative: response.answers().is_empty(),
        }
    }

    /// Creates a negative cache entry.
    pub fn negative(rcode: ResponseCode, ttl: Duration) -> Self {
        Self {
            records: Vec::new(),
            rcode,
            created_at: Instant::now(),
            ttl,
            negative: true,
        }
    }

    /// Returns the cached records.
    pub fn records(&self) -> &[ResourceRecord] {
        &self.records
    }

    /// Returns the response code.
    pub fn rcode(&self) -> ResponseCode {
        self.rcode
    }

    /// Returns when this entry was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns the original TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns true if this is a negative cache entry.
    pub fn is_negative(&self) -> bool {
        self.negative
    }

    /// Returns true if this entry has expired.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.created_at) >= self.ttl
    }

    /// Returns true if this entry is within the stale serving period.
    pub fn is_within_stale_period(&self, now: Instant, stale_ttl: Duration) -> bool {
        let age = now.duration_since(self.created_at);
        age < self.ttl + stale_ttl
    }

    /// Returns the remaining TTL.
    pub fn remaining_ttl(&self, now: Instant) -> Duration {
        let age = now.duration_since(self.created_at);
        if age >= self.ttl {
            Duration::ZERO
        } else {
            self.ttl - age
        }
    }

    /// Returns true if this entry should be prefetched.
    pub fn should_prefetch(&self, now: Instant, threshold_percent: u8) -> bool {
        let remaining = self.remaining_ttl(now);
        let threshold = self.ttl * u32::from(threshold_percent) / 100;
        remaining <= threshold
    }

    /// Returns the records with adjusted TTLs.
    pub fn records_with_adjusted_ttl(&self, now: Instant) -> Vec<ResourceRecord> {
        let remaining = self.remaining_ttl(now).as_secs() as u32;
        self.records
            .iter()
            .map(|r| r.with_ttl(remaining.max(1)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_entry_expiry() {
        let entry = CacheEntry::empty(Duration::from_secs(10));
        let now = Instant::now();

        assert!(!entry.is_expired(now));
        assert!(entry.remaining_ttl(now) <= Duration::from_secs(10));
    }

    #[test]
    fn test_prefetch_threshold() {
        let entry = CacheEntry::empty(Duration::from_secs(100));
        let now = Instant::now();

        // At creation, should not need prefetch (10% threshold = 10s remaining)
        assert!(!entry.should_prefetch(now, 10));
    }
}
