//! TCP server implementation.

use super::handler::{QueryContext, QueryHandler};
use super::{Protocol, Result, ServerError};
use stria_proto::Message;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

/// Connection ID counter.
static CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

/// TCP DNS server.
pub struct TcpServer {
    listener: TcpListener,
    handler: Arc<dyn QueryHandler>,
    local_addr: SocketAddr,
    idle_timeout: Duration,
    max_connections: usize,
}

impl TcpServer {
    /// Binds a new TCP server to the given address.
    pub async fn bind(addr: SocketAddr, handler: Arc<dyn QueryHandler>) -> Result<Self> {
        // Create socket with socket2 for more control
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::STREAM, None)?;

        // Set socket options
        socket.set_reuse_address(true)?;

        #[cfg(unix)]
        socket.set_reuse_port(true)?;

        socket.set_nonblocking(true)?;

        // Bind and listen
        socket.bind(&addr.into())?;
        socket.listen(1024)?;

        // Convert to tokio listener
        let std_listener: std::net::TcpListener = socket.into();
        let listener = TcpListener::from_std(std_listener)?;
        let local_addr = listener.local_addr()?;

        info!(addr = %local_addr, "TCP server listening");

        Ok(Self {
            listener,
            handler,
            local_addr,
            idle_timeout: Duration::from_secs(10),
            max_connections: 10_000,
        })
    }

    /// Returns the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Sets the idle timeout.
    pub fn set_idle_timeout(&mut self, timeout: Duration) {
        self.idle_timeout = timeout;
    }

    /// Runs the TCP server.
    pub async fn run(&self) -> Result<()> {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let handler = self.handler.clone();
                    let idle_timeout = self.idle_timeout;
                    let conn_id = CONNECTION_ID.fetch_add(1, Ordering::Relaxed);

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer, handler, idle_timeout, conn_id).await {
                            debug!(error = %e, client = %peer, "TCP connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Error accepting TCP connection");
                }
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    handler: Arc<dyn QueryHandler>,
    idle_timeout: Duration,
    conn_id: u64,
) -> Result<()> {
    trace!(client = %peer, conn_id, "New TCP connection");

    let mut buf = BytesMut::with_capacity(4096);

    loop {
        // Read with timeout
        match timeout(idle_timeout, read_message(&mut stream, &mut buf)).await {
            Ok(Ok(query_bytes)) => {
                // Parse query
                let query = match Message::parse(&query_bytes) {
                    Ok(msg) => msg,
                    Err(e) => {
                        debug!(error = %e, client = %peer, "Failed to parse TCP query");
                        continue;
                    }
                };

                // Create context
                let ctx = QueryContext::new(peer, Protocol::Tcp).with_connection_id(conn_id);

                // Handle query
                let response = handler.handle(query, ctx).await;

                // Serialize and send response
                let wire = response.to_wire();
                write_message(&mut stream, &wire).await?;
            }
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    trace!(client = %peer, conn_id, "TCP connection closed by client");
                } else {
                    debug!(error = %e, client = %peer, "TCP read error");
                }
                break;
            }
            Err(_) => {
                trace!(client = %peer, conn_id, "TCP connection idle timeout");
                break;
            }
        }
    }

    Ok(())
}

/// Reads a DNS message from a TCP stream.
async fn read_message(stream: &mut TcpStream, buf: &mut BytesMut) -> std::io::Result<Bytes> {
    // Read 2-byte length prefix
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    if len == 0 || len > 65535 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid TCP message length",
        ));
    }

    // Read message body
    buf.clear();
    buf.resize(len, 0);
    stream.read_exact(buf).await?;

    Ok(buf.clone().freeze())
}

/// Writes a DNS message to a TCP stream.
async fn write_message(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    // Write 2-byte length prefix
    let len = data.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;

    // Write message body
    stream.write_all(data).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::RefusedHandler;

    #[tokio::test]
    async fn test_tcp_server_bind() {
        let handler = Arc::new(RefusedHandler);
        let server = TcpServer::bind("127.0.0.1:0".parse().unwrap(), handler)
            .await
            .unwrap();

        assert!(server.local_addr().port() > 0);
    }
}
