//! Query handler interface.

use async_trait::async_trait;
use stria_proto::Message;
use bytes::Bytes;
use std::net::SocketAddr;
use std::time::Instant;

use super::Protocol;

/// Context for a DNS query.
#[derive(Debug, Clone)]
pub struct QueryContext {
    /// Client address.
    pub client: SocketAddr,

    /// Protocol used.
    pub protocol: Protocol,

    /// When the query was received.
    pub received_at: Instant,

    /// EDNS UDP payload size (if applicable).
    pub udp_size: Option<u16>,

    /// Connection ID (for TCP-based protocols).
    pub connection_id: Option<u64>,

    /// Whether this is a TCP keepalive query.
    pub tcp_keepalive: bool,
}

impl QueryContext {
    /// Creates a new query context.
    pub fn new(client: SocketAddr, protocol: Protocol) -> Self {
        Self {
            client,
            protocol,
            received_at: Instant::now(),
            udp_size: None,
            connection_id: None,
            tcp_keepalive: false,
        }
    }

    /// Sets the EDNS UDP size.
    pub fn with_udp_size(mut self, size: u16) -> Self {
        self.udp_size = Some(size);
        self
    }

    /// Sets the connection ID.
    pub fn with_connection_id(mut self, id: u64) -> Self {
        self.connection_id = Some(id);
        self
    }

    /// Returns the maximum response size.
    pub fn max_response_size(&self) -> usize {
        match self.protocol {
            Protocol::Udp => self.udp_size.map(|s| s as usize).unwrap_or(512),
            _ => 65535,
        }
    }

    /// Returns the elapsed time since the query was received.
    pub fn elapsed(&self) -> std::time::Duration {
        self.received_at.elapsed()
    }
}

/// Query handler trait.
///
/// Implement this trait to handle DNS queries.
#[async_trait]
pub trait QueryHandler: Send + Sync {
    /// Handles a DNS query.
    ///
    /// # Arguments
    ///
    /// * `query` - The parsed DNS query message
    /// * `context` - Query context with client info and protocol
    ///
    /// # Returns
    ///
    /// The response message to send back.
    async fn handle(&self, query: Message, context: QueryContext) -> Message;
}

/// A simple query handler that returns REFUSED for all queries.
/// Useful for testing.
pub struct RefusedHandler;

#[async_trait]
impl QueryHandler for RefusedHandler {
    async fn handle(&self, query: Message, _context: QueryContext) -> Message {
        let mut response = Message::response_from(&query);
        response.set_rcode(stria_proto::ResponseCode::Refused);
        response
    }
}

/// A query handler that returns SERVFAIL for all queries.
/// Useful as a fallback.
pub struct ServfailHandler;

#[async_trait]
impl QueryHandler for ServfailHandler {
    async fn handle(&self, query: Message, _context: QueryContext) -> Message {
        let mut response = Message::response_from(&query);
        response.set_rcode(stria_proto::ResponseCode::ServFail);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_context() {
        let ctx = QueryContext::new("127.0.0.1:12345".parse().unwrap(), Protocol::Udp);
        assert_eq!(ctx.max_response_size(), 512);

        let ctx = ctx.with_udp_size(4096);
        assert_eq!(ctx.max_response_size(), 4096);

        let tcp_ctx = QueryContext::new("127.0.0.1:12345".parse().unwrap(), Protocol::Tcp);
        assert_eq!(tcp_ctx.max_response_size(), 65535);
    }
}
