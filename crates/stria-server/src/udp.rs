//! UDP server implementation.

use super::handler::{QueryContext, QueryHandler};
use super::{Protocol, Result, ServerError};
use stria_proto::Message;
use bytes::{Bytes, BytesMut};
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, trace, warn};

/// UDP DNS server.
pub struct UdpServer {
    socket: Arc<UdpSocket>,
    handler: Arc<dyn QueryHandler>,
    local_addr: SocketAddr,
}

impl UdpServer {
    /// Binds a new UDP server to the given address.
    pub async fn bind(addr: SocketAddr, handler: Arc<dyn QueryHandler>) -> Result<Self> {
        // Create socket with socket2 for more control
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, None)?;

        // Set socket options
        socket.set_reuse_address(true)?;

        #[cfg(unix)]
        socket.set_reuse_port(true)?;

        socket.set_nonblocking(true)?;

        // Bind
        socket.bind(&addr.into())?;

        // Convert to tokio socket
        let std_socket: std::net::UdpSocket = socket.into();
        let socket = UdpSocket::from_std(std_socket)?;
        let local_addr = socket.local_addr()?;

        info!(addr = %local_addr, "UDP server listening");

        Ok(Self {
            socket: Arc::new(socket),
            handler,
            local_addr,
        })
    }

    /// Returns the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Runs the UDP server.
    pub async fn run(&self) -> Result<()> {
        let mut buf = vec![0u8; 65535];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let data = Bytes::copy_from_slice(&buf[..len]);
                    let socket = self.socket.clone();
                    let handler = self.handler.clone();

                    // Process query in a separate task
                    tokio::spawn(async move {
                        if let Err(e) = process_query(socket, handler, data, src).await {
                            debug!(error = %e, client = %src, "Error processing UDP query");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Error receiving UDP packet");
                }
            }
        }
    }
}

async fn process_query(
    socket: Arc<UdpSocket>,
    handler: Arc<dyn QueryHandler>,
    data: Bytes,
    src: SocketAddr,
) -> Result<()> {
    // Parse query
    let query = match Message::parse(&data) {
        Ok(msg) => msg,
        Err(e) => {
            trace!(error = %e, client = %src, "Failed to parse DNS query");
            return Ok(()); // Drop malformed queries
        }
    };

    // Create context
    let ctx = QueryContext::new(src, Protocol::Udp)
        .with_udp_size(query.edns().map(|e| e.udp_size()).unwrap_or(512));

    // Handle query
    let mut response = handler.handle(query, ctx.clone()).await;

    // Serialize response
    let wire = response.to_wire();

    // Check size and truncate if necessary
    let max_size = ctx.max_response_size();
    let response_bytes = if wire.len() > max_size {
        response.truncate_to(max_size);
        response.to_wire()
    } else {
        wire
    };

    // Send response
    socket.send_to(&response_bytes, src).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::RefusedHandler;

    #[tokio::test]
    async fn test_udp_server_bind() {
        let handler = Arc::new(RefusedHandler);
        let server = UdpServer::bind("127.0.0.1:0".parse().unwrap(), handler)
            .await
            .unwrap();

        assert!(server.local_addr().port() > 0);
    }
}
