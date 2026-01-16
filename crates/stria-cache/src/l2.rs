//! L2 (shared) cache implementation.
//!
//! This module provides the shared, process-wide cache that sits behind
//! the per-thread L1 caches.

// This is re-exported from the main lib.rs using moka
// Additional L2-specific utilities can go here

/// Placeholder for L2-specific configuration and utilities.
pub struct L2Config {
    /// Maximum number of entries.
    pub max_entries: usize,

    /// Maximum memory usage.
    pub max_memory: usize,
}

impl Default for L2Config {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_memory: 256 * 1024 * 1024, // 256 MB
        }
    }
}
