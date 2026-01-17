//! DNS over TLS (DoT) server implementation.
//!
//! This module provides DoT support per RFC 7858.
//!
//! DNS over TLS wraps traditional DNS messages in a TLS connection on port 853.
//! Like TCP DNS, messages are prefixed with a 2-byte length field.
//!
//! # Features
//!
//! - TLS 1.2 and TLS 1.3 support via rustls
//! - Certificate and key loading from PEM files
//! - Connection keepalive with configurable idle timeout
//! - ALPN protocol negotiation (optional)
//! - Multiple concurrent connections
//!
//! # Example
//!
//! ```ignore
//! use stria_server::dot::DotServer;
//! use std::sync::Arc;
//!
//! let tls_config = DotServer::load_tls_config("cert.pem", "key.pem")?;
//! let server = DotServer::bind(
//!     "0.0.0.0:853".parse()?,
//!     tls_config,
//!     handler,
//! ).await?;
//! server.run().await?;
//! ```

use crate::handler::{QueryContext, QueryHandler};
use crate::{Protocol, Result, ServerError};
use bytes::{Bytes, BytesMut};
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use socket2::{Domain, Socket, Type};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use stria_proto::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, trace};

/// Connection ID counter for DoT connections.
static CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

/// ALPN protocol identifier for DNS over TLS.
const ALPN_DOT: &[u8] = b"dot";

/// DNS over TLS server.
///
/// Provides encrypted DNS transport using TLS on port 853 (by default).
/// Each connection can handle multiple pipelined queries.
pub struct DotServer {
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    handler: Arc<dyn QueryHandler>,
    local_addr: SocketAddr,
    idle_timeout: Duration,
    max_connections: usize,
}

impl DotServer {
    /// Loads TLS configuration from PEM certificate and key files.
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path to the PEM-encoded certificate chain
    /// * `key_path` - Path to the PEM-encoded private key
    ///
    /// # Returns
    ///
    /// A configured `ServerConfig` suitable for DoT.
    ///
    /// # Errors
    ///
    /// Returns an error if the files cannot be read or parsed.
    pub fn load_tls_config<P: AsRef<Path>>(cert_path: P, key_path: P) -> Result<Arc<ServerConfig>> {
        Self::load_tls_config_with_alpn(cert_path, key_path, false)
    }

    /// Loads TLS configuration with optional ALPN support.
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path to the PEM-encoded certificate chain
    /// * `key_path` - Path to the PEM-encoded private key  
    /// * `enable_alpn` - Whether to enable ALPN protocol negotiation
    ///
    /// # Returns
    ///
    /// A configured `ServerConfig` suitable for DoT.
    pub fn load_tls_config_with_alpn<P: AsRef<Path>>(
        cert_path: P,
        key_path: P,
        enable_alpn: bool,
    ) -> Result<Arc<ServerConfig>> {
        // Load certificate chain
        let cert_file = File::open(cert_path.as_ref())
            .map_err(|e| ServerError::Tls(format!("Failed to open certificate file: {}", e)))?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| ServerError::Tls(format!("Failed to parse certificates: {}", e)))?;

        if certs.is_empty() {
            return Err(ServerError::Tls("No certificates found in file".into()));
        }

        // Load private key
        let key_file = File::open(key_path.as_ref())
            .map_err(|e| ServerError::Tls(format!("Failed to open key file: {}", e)))?;
        let mut key_reader = BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| ServerError::Tls(format!("Failed to parse private key: {}", e)))?
            .ok_or_else(|| ServerError::Tls("No private key found in file".into()))?;

        // Build server config
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Tls(format!("Failed to build TLS config: {}", e)))?;

        // Enable ALPN if requested
        if enable_alpn {
            config.alpn_protocols = vec![ALPN_DOT.to_vec()];
        }

        Ok(Arc::new(config))
    }

    /// Binds a new DoT server to the given address.
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address to bind to (typically port 853)
    /// * `tls_config` - TLS server configuration with certificates
    /// * `handler` - The query handler for processing DNS queries
    ///
    /// # Returns
    ///
    /// A new `DotServer` ready to accept connections.
    pub async fn bind(
        addr: SocketAddr,
        tls_config: Arc<ServerConfig>,
        handler: Arc<dyn QueryHandler>,
    ) -> Result<Self> {
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

        let tls_acceptor = TlsAcceptor::from(tls_config);

        info!(addr = %local_addr, "DoT server listening");

        Ok(Self {
            listener,
            tls_acceptor,
            handler,
            local_addr,
            idle_timeout: Duration::from_secs(30),
            max_connections: 10_000,
        })
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Sets the idle connection timeout.
    ///
    /// Connections that don't receive any queries within this duration
    /// will be closed. Default is 30 seconds.
    pub fn set_idle_timeout(&mut self, timeout: Duration) {
        self.idle_timeout = timeout;
    }

    /// Sets the maximum number of concurrent connections.
    ///
    /// Default is 10,000 connections.
    pub fn set_max_connections(&mut self, max: usize) {
        self.max_connections = max;
    }

    /// Runs the DoT server, accepting and handling connections.
    ///
    /// This method runs indefinitely, accepting TLS connections and
    /// spawning tasks to handle them.
    pub async fn run(&self) -> Result<()> {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let tls_acceptor = self.tls_acceptor.clone();
                    let handler = self.handler.clone();
                    let idle_timeout = self.idle_timeout;
                    let conn_id = CONNECTION_ID.fetch_add(1, Ordering::Relaxed);

                    tokio::spawn(async move {
                        // Perform TLS handshake
                        match tls_acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                if let Err(e) = handle_connection(
                                    tls_stream,
                                    peer,
                                    handler,
                                    idle_timeout,
                                    conn_id,
                                )
                                .await
                                {
                                    debug!(error = %e, client = %peer, conn_id, "DoT connection error");
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, client = %peer, "TLS handshake failed");
                            }
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Error accepting DoT connection");
                }
            }
        }
    }
}

/// Handles a single DoT connection.
///
/// Processes DNS queries over the TLS stream until the connection is closed
/// or times out.
async fn handle_connection(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    peer: SocketAddr,
    handler: Arc<dyn QueryHandler>,
    idle_timeout: Duration,
    conn_id: u64,
) -> Result<()> {
    trace!(client = %peer, conn_id, "New DoT connection");

    let mut buf = BytesMut::with_capacity(4096);

    loop {
        // Read with timeout
        match timeout(idle_timeout, read_message(&mut stream, &mut buf)).await {
            Ok(Ok(query_bytes)) => {
                // Parse query
                let query = match Message::parse(&query_bytes) {
                    Ok(msg) => msg,
                    Err(e) => {
                        debug!(error = %e, client = %peer, "Failed to parse DoT query");
                        continue;
                    }
                };

                trace!(
                    client = %peer,
                    conn_id,
                    id = query.id(),
                    "Processing DoT query"
                );

                // Create context
                let ctx = QueryContext::new(peer, Protocol::Dot).with_connection_id(conn_id);

                // Handle query
                let response = handler.handle(query, ctx).await;

                // Serialize and send response
                let wire = response.to_wire();
                write_message(&mut stream, &wire).await?;
            }
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    trace!(client = %peer, conn_id, "DoT connection closed by client");
                } else {
                    debug!(error = %e, client = %peer, "DoT read error");
                }
                break;
            }
            Err(_) => {
                trace!(client = %peer, conn_id, "DoT connection idle timeout");
                break;
            }
        }
    }

    Ok(())
}

/// Reads a DNS message from a TLS stream.
///
/// DNS over TLS uses the same framing as TCP: a 2-byte big-endian length
/// prefix followed by the message data.
async fn read_message<S>(stream: &mut S, buf: &mut BytesMut) -> std::io::Result<Bytes>
where
    S: AsyncReadExt + Unpin,
{
    // Read 2-byte length prefix
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    if len == 0 || len > 65535 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid DoT message length",
        ));
    }

    // Read message body
    buf.clear();
    buf.resize(len, 0);
    stream.read_exact(buf).await?;

    Ok(buf.clone().freeze())
}

/// Writes a DNS message to a TLS stream.
///
/// Prefixes the message with a 2-byte big-endian length.
async fn write_message<S>(stream: &mut S, data: &[u8]) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    // Write 2-byte length prefix
    let len = data.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;

    // Write message body
    stream.write_all(data).await?;

    // Flush to ensure data is sent
    stream.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::RefusedHandler;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Install the ring crypto provider for tests
    fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    // Generate a self-signed certificate for testing
    fn generate_test_cert() -> (NamedTempFile, NamedTempFile) {
        use rcgen::{CertifiedKey, generate_simple_self_signed};

        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(subject_alt_names).unwrap();

        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(cert.pem().as_bytes()).unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file
            .write_all(key_pair.serialize_pem().as_bytes())
            .unwrap();

        (cert_file, key_file)
    }

    #[tokio::test]
    async fn test_dot_server_bind() {
        install_crypto_provider();
        let (cert_file, key_file) = generate_test_cert();
        let tls_config = DotServer::load_tls_config(cert_file.path(), key_file.path()).unwrap();
        let handler = Arc::new(RefusedHandler);

        let server = DotServer::bind("127.0.0.1:0".parse().unwrap(), tls_config, handler)
            .await
            .unwrap();

        assert!(server.local_addr().port() > 0);
    }

    #[tokio::test]
    async fn test_tls_config_with_alpn() {
        install_crypto_provider();
        let (cert_file, key_file) = generate_test_cert();
        let tls_config =
            DotServer::load_tls_config_with_alpn(cert_file.path(), key_file.path(), true).unwrap();

        assert_eq!(tls_config.alpn_protocols, vec![ALPN_DOT.to_vec()]);
    }

    #[test]
    fn test_load_tls_config_missing_cert() {
        let result = DotServer::load_tls_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
    }
}
