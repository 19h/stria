//! Cache prefetch implementation.

use super::CacheKey;
use std::collections::HashSet;
use std::sync::Arc;
use parking_lot::Mutex;
use tokio::sync::mpsc;

/// Prefetch request.
#[derive(Debug, Clone)]
pub struct PrefetchRequest {
    /// Cache key to prefetch.
    pub key: CacheKey,

    /// Priority (higher = more urgent).
    pub priority: u8,
}

/// Prefetch queue for managing background cache refreshes.
pub struct PrefetchQueue {
    /// Sender for prefetch requests.
    sender: mpsc::Sender<PrefetchRequest>,

    /// Set of keys currently being prefetched (to avoid duplicates).
    in_flight: Arc<Mutex<HashSet<CacheKey>>>,
}

impl PrefetchQueue {
    /// Creates a new prefetch queue.
    pub fn new(buffer_size: usize) -> (Self, mpsc::Receiver<PrefetchRequest>) {
        let (sender, receiver) = mpsc::channel(buffer_size);
        let queue = Self {
            sender,
            in_flight: Arc::new(Mutex::new(HashSet::new())),
        };
        (queue, receiver)
    }

    /// Submits a prefetch request.
    pub async fn submit(&self, key: CacheKey, priority: u8) -> bool {
        // Check if already in flight
        {
            let mut in_flight = self.in_flight.lock();
            if in_flight.contains(&key) {
                return false;
            }
            in_flight.insert(key.clone());
        }

        let request = PrefetchRequest { key: key.clone(), priority };

        if self.sender.send(request).await.is_err() {
            // Channel closed, remove from in_flight
            let mut in_flight = self.in_flight.lock();
            in_flight.remove(&key);
            return false;
        }

        true
    }

    /// Marks a prefetch as complete.
    pub fn complete(&self, key: &CacheKey) {
        let mut in_flight = self.in_flight.lock();
        in_flight.remove(key);
    }

    /// Returns the number of in-flight prefetches.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.lock().len()
    }
}

/// Prefetch worker that processes prefetch requests.
pub async fn prefetch_worker(
    mut receiver: mpsc::Receiver<PrefetchRequest>,
    queue: Arc<PrefetchQueue>,
    resolver: impl Fn(CacheKey) + Send + 'static,
) {
    while let Some(request) = receiver.recv().await {
        // Perform the resolution
        resolver(request.key.clone());

        // Mark as complete
        queue.complete(&request.key);
    }
}
