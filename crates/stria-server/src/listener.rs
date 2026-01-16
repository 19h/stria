//! Listener management.

use super::{Protocol, Result};
use std::net::SocketAddr;

/// Listener state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerState {
    /// Listener is starting.
    Starting,
    /// Listener is running.
    Running,
    /// Listener is stopping.
    Stopping,
    /// Listener is stopped.
    Stopped,
    /// Listener has failed.
    Failed,
}

/// Listener information.
#[derive(Debug, Clone)]
pub struct ListenerInfo {
    /// Protocol.
    pub protocol: Protocol,
    /// Listen address.
    pub address: SocketAddr,
    /// Current state.
    pub state: ListenerState,
    /// Active connections (for TCP-based).
    pub connections: usize,
    /// Queries handled.
    pub queries: u64,
}

/// Trait for listener management.
pub trait Listener: Send + Sync {
    /// Returns listener information.
    fn info(&self) -> ListenerInfo;

    /// Returns the protocol.
    fn protocol(&self) -> Protocol;

    /// Returns the listen address.
    fn address(&self) -> SocketAddr;
}
