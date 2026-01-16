//! Negative caching implementation.

use stria_proto::ResponseCode;
use std::time::Duration;

/// Configuration for negative caching.
#[derive(Debug, Clone)]
pub struct NegativeCacheConfig {
    /// Maximum TTL for NXDOMAIN responses.
    pub nxdomain_ttl: Duration,

    /// Maximum TTL for NODATA responses.
    pub nodata_ttl: Duration,

    /// Enable aggressive NSEC caching (RFC 8198).
    pub aggressive_nsec: bool,
}

impl Default for NegativeCacheConfig {
    fn default() -> Self {
        Self {
            nxdomain_ttl: Duration::from_secs(900),
            nodata_ttl: Duration::from_secs(900),
            aggressive_nsec: true,
        }
    }
}

/// Determines the negative cache TTL for a response.
pub fn negative_ttl_for_rcode(rcode: ResponseCode, config: &NegativeCacheConfig) -> Duration {
    match rcode {
        ResponseCode::NXDomain => config.nxdomain_ttl,
        ResponseCode::NoError => config.nodata_ttl, // NODATA
        _ => Duration::ZERO, // Don't cache other error types
    }
}

/// Returns true if this response code should be negative cached.
pub fn should_negative_cache(rcode: ResponseCode) -> bool {
    matches!(rcode, ResponseCode::NXDomain | ResponseCode::NoError)
}
