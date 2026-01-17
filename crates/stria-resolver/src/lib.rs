//! # Stria DNS Resolver
//!
//! Recursive DNS resolver with connection pooling, upstream management,
//! and QNAME minimization.
//!
//! ## Features
//!
//! - Full recursive resolution from root servers
//! - Forward mode to upstream resolvers
//! - Connection pooling for TCP/DoT/DoH/DoQ
//! - QNAME minimization (RFC 7816)
//! - 0x20 bit encoding for cache poisoning resistance
//! - Automatic failover and load balancing

use async_trait::async_trait;
use std::time::Duration;
use stria_proto::{Message, Name, Question};
use thiserror::Error;

pub mod forward;
pub mod pool;
pub mod recursive;
pub mod upstream;

pub use forward::Forwarder;
pub use pool::ConnectionPool;
pub use recursive::{ROOT_HINTS, RecursiveConfig, RecursiveResolver, ResolverMetrics, RootHints};
pub use upstream::{Upstream, UpstreamConfig, UpstreamProtocol};

/// Resolver error.
#[derive(Error, Debug)]
pub enum ResolverError {
    #[error("Timeout")]
    Timeout,

    #[error("No upstream available")]
    NoUpstream,

    #[error("All upstreams failed")]
    AllUpstreamsFailed,

    #[error("Maximum recursion depth exceeded")]
    MaxRecursionDepth,

    #[error("SERVFAIL from upstream")]
    ServFail,

    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("DNSSEC validation failed: {0}")]
    DnssecFailed(String),
}

/// Result type for resolver operations.
pub type Result<T> = std::result::Result<T, ResolverError>;

/// Resolver configuration.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Query timeout.
    pub timeout: Duration,

    /// Maximum retries per upstream.
    pub retries: u32,

    /// Enable QNAME minimization.
    pub qname_minimization: bool,

    /// Enable 0x20 bit encoding.
    pub enable_0x20: bool,

    /// Maximum recursion depth.
    pub max_recursion_depth: u8,

    /// Enable DNSSEC validation.
    pub dnssec: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            retries: 3,
            qname_minimization: true,
            enable_0x20: true,
            max_recursion_depth: 16,
            dnssec: true,
        }
    }
}

/// Resolver trait.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolves a DNS query.
    async fn resolve(&self, question: &Question) -> Result<Message>;
}

/// Resolution context tracking recursion state.
#[derive(Debug, Clone)]
pub struct ResolutionContext {
    /// Current recursion depth.
    pub depth: u8,

    /// Maximum depth.
    pub max_depth: u8,

    /// Names already queried (for loop detection).
    pub queried_names: Vec<Name>,

    /// Enable QNAME minimization.
    pub qname_minimization: bool,

    /// Enable DNSSEC validation.
    pub dnssec: bool,
}

impl ResolutionContext {
    /// Creates a new resolution context.
    pub fn new(config: &ResolverConfig) -> Self {
        Self {
            depth: 0,
            max_depth: config.max_recursion_depth,
            queried_names: Vec::new(),
            qname_minimization: config.qname_minimization,
            dnssec: config.dnssec,
        }
    }

    /// Creates a child context for recursion.
    pub fn child(&self) -> Result<Self> {
        if self.depth >= self.max_depth {
            return Err(ResolverError::MaxRecursionDepth);
        }

        Ok(Self {
            depth: self.depth + 1,
            max_depth: self.max_depth,
            queried_names: self.queried_names.clone(),
            qname_minimization: self.qname_minimization,
            dnssec: self.dnssec,
        })
    }

    /// Records a queried name for loop detection.
    pub fn record_query(&mut self, name: &Name) -> bool {
        if self.queried_names.contains(name) {
            return false; // Loop detected
        }
        self.queried_names.push(name.clone());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolution_context() {
        let config = ResolverConfig::default();
        let mut ctx = ResolutionContext::new(&config);

        assert_eq!(ctx.depth, 0);

        let child = ctx.child().unwrap();
        assert_eq!(child.depth, 1);
    }

    #[test]
    fn test_max_recursion_depth() {
        let config = ResolverConfig {
            max_recursion_depth: 2,
            ..Default::default()
        };

        let ctx = ResolutionContext::new(&config);
        let ctx = ctx.child().unwrap();
        let ctx = ctx.child().unwrap();
        assert!(ctx.child().is_err());
    }
}
