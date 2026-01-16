//! Forward resolver implementation.

use super::upstream::{Upstream, UpstreamGroup};
use super::{Resolver, ResolverConfig, ResolverError, Result};
use async_trait::async_trait;
use stria_proto::{Message, Question};
use bytes::BytesMut;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, trace};

/// Forward resolver that sends queries to upstream servers.
pub struct Forwarder {
    config: ResolverConfig,
    upstreams: UpstreamGroup,
}

impl Forwarder {
    /// Creates a new forwarder.
    pub fn new(config: ResolverConfig, upstreams: Vec<Arc<Upstream>>) -> Self {
        Self {
            config,
            upstreams: UpstreamGroup::new(upstreams),
        }
    }

    /// Sends a query to an upstream and returns the response.
    async fn query_upstream(&self, upstream: &Upstream, query: &Message) -> Result<Message> {
        let start = Instant::now();

        let result = match upstream.protocol() {
            super::upstream::UpstreamProtocol::Udp => {
                self.query_udp(upstream, query).await
            }
            super::upstream::UpstreamProtocol::Tcp => {
                self.query_tcp(upstream, query).await
            }
            _ => {
                // DoT/DoH/DoQ would require connection pools
                Err(ResolverError::Protocol("Protocol not implemented".into()))
            }
        };

        match &result {
            Ok(_) => upstream.record_success(start.elapsed()),
            Err(_) => upstream.record_failure(),
        }

        result
    }

    async fn query_udp(&self, upstream: &Upstream, query: &Message) -> Result<Message> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(upstream.address()).await?;

        let wire = query.to_wire();
        socket.send(&wire).await?;

        let mut buf = vec![0u8; 65535];
        let len = timeout(self.config.timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| ResolverError::Timeout)??;

        let response = Message::parse(&buf[..len])
            .map_err(|e| ResolverError::Protocol(e.to_string()))?;

        // Verify response matches query
        if response.id() != query.id() {
            return Err(ResolverError::Protocol("Response ID mismatch".into()));
        }

        // Check for truncation and retry with TCP
        if response.is_truncated() {
            trace!(upstream = %upstream.address(), "Response truncated, retrying with TCP");
            return self.query_tcp(upstream, query).await;
        }

        Ok(response)
    }

    async fn query_tcp(&self, upstream: &Upstream, query: &Message) -> Result<Message> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = timeout(
            self.config.timeout,
            tokio::net::TcpStream::connect(upstream.address()),
        )
        .await
        .map_err(|_| ResolverError::Timeout)??;

        let wire = query.to_wire();

        // Write length-prefixed message
        let len = wire.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&wire).await?;

        // Read response
        let mut len_buf = [0u8; 2];
        timeout(self.config.timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| ResolverError::Timeout)??;

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        timeout(self.config.timeout, stream.read_exact(&mut resp_buf))
            .await
            .map_err(|_| ResolverError::Timeout)??;

        let response = Message::parse(&resp_buf)
            .map_err(|e| ResolverError::Protocol(e.to_string()))?;

        if response.id() != query.id() {
            return Err(ResolverError::Protocol("Response ID mismatch".into()));
        }

        Ok(response)
    }
}

#[async_trait]
impl Resolver for Forwarder {
    async fn resolve(&self, question: &Question) -> Result<Message> {
        let mut query = Message::query(question.clone());

        // Try upstreams
        let mut last_error = None;

        for attempt in 0..self.config.retries {
            let upstream = self.upstreams.next().ok_or(ResolverError::NoUpstream)?;

            debug!(
                attempt,
                upstream = %upstream.address(),
                question = %question,
                "Forwarding query"
            );

            match self.query_upstream(&upstream, &query).await {
                Ok(response) => {
                    // Check for SERVFAIL
                    if response.is_servfail() {
                        last_error = Some(ResolverError::ServFail);
                        continue;
                    }
                    return Ok(response);
                }
                Err(e) => {
                    debug!(error = %e, "Upstream query failed");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(ResolverError::AllUpstreamsFailed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::{UpstreamConfig, UpstreamProtocol};
    use std::time::Duration;

    #[test]
    fn test_forwarder_creation() {
        let config = ResolverConfig::default();
        let upstream = Arc::new(Upstream::new(UpstreamConfig {
            address: "8.8.8.8:53".parse().unwrap(),
            protocol: UpstreamProtocol::Udp,
            tls_name: None,
            path: None,
            weight: 100,
            timeout: Duration::from_secs(5),
        }));

        let forwarder = Forwarder::new(config, vec![upstream]);
        assert!(forwarder.upstreams.all().len() == 1);
    }
}
