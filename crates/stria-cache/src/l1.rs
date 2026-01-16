//! L1 (per-CPU/thread) cache implementation.

use super::{CacheEntry, CacheKey};
use std::collections::HashMap;
use std::time::Instant;

/// Per-thread L1 cache.
///
/// This is a small, fast cache that sits in front of the shared L2 cache.
/// It's designed to be accessed without any locking.
pub struct L1Cache {
    /// Cache entries.
    entries: HashMap<CacheKey, CacheEntry>,

    /// Maximum entries.
    max_entries: usize,

    /// LRU order tracking (simple approximation).
    access_count: u64,
}

impl L1Cache {
    /// Creates a new L1 cache.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries),
            max_entries,
            access_count: 0,
        }
    }

    /// Looks up an entry.
    pub fn get(&mut self, key: &CacheKey) -> Option<&CacheEntry> {
        self.access_count += 1;
        self.entries.get(key)
    }

    /// Inserts an entry.
    pub fn insert(&mut self, key: CacheKey, entry: CacheEntry) {
        // Simple eviction: if at capacity, remove a random entry
        if self.entries.len() >= self.max_entries {
            // Remove first entry (not true LRU, but simple and fast)
            if let Some(k) = self.entries.keys().next().cloned() {
                self.entries.remove(&k);
            }
        }

        self.entries.insert(key, entry);
    }

    /// Removes an entry.
    pub fn remove(&mut self, key: &CacheKey) -> Option<CacheEntry> {
        self.entries.remove(key)
    }

    /// Clears expired entries.
    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, v| !v.is_expired(now));
    }

    /// Clears the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

thread_local! {
    static THREAD_CACHE: std::cell::RefCell<Option<L1Cache>> = const { std::cell::RefCell::new(None) };
}

/// Initializes the thread-local L1 cache.
pub fn init_thread_cache(max_entries: usize) {
    THREAD_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(L1Cache::new(max_entries));
    });
}

/// Accesses the thread-local L1 cache.
pub fn with_thread_cache<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut L1Cache) -> R,
{
    THREAD_CACHE.with(|cache| {
        let mut borrow = cache.borrow_mut();
        borrow.as_mut().map(f)
    })
}
