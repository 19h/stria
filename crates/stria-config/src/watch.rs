//! Configuration file watching for hot-reload.

use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

/// Configuration file watcher.
pub struct ConfigWatcher {
    watcher: RecommendedWatcher,
    receiver: Receiver<notify::Result<Event>>,
}

impl ConfigWatcher {
    /// Creates a new configuration watcher.
    pub fn new() -> notify::Result<Self> {
        let (tx, rx) = channel();

        let watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_secs(2)),
        )?;

        Ok(Self {
            watcher,
            receiver: rx,
        })
    }

    /// Starts watching a file.
    pub fn watch(&mut self, path: impl AsRef<Path>) -> notify::Result<()> {
        self.watcher
            .watch(path.as_ref(), RecursiveMode::NonRecursive)
    }

    /// Stops watching a file.
    pub fn unwatch(&mut self, path: impl AsRef<Path>) -> notify::Result<()> {
        self.watcher.unwatch(path.as_ref())
    }

    /// Checks for file changes (non-blocking).
    pub fn poll(&self) -> Option<bool> {
        match self.receiver.try_recv() {
            Ok(Ok(event)) => {
                if event.kind.is_modify() || event.kind.is_create() {
                    Some(true)
                } else {
                    Some(false)
                }
            }
            Ok(Err(_)) => None,
            Err(_) => None,
        }
    }

    /// Waits for a file change (blocking).
    pub fn wait(&self) -> Option<bool> {
        match self.receiver.recv() {
            Ok(Ok(event)) => {
                if event.kind.is_modify() || event.kind.is_create() {
                    Some(true)
                } else {
                    Some(false)
                }
            }
            _ => None,
        }
    }
}
