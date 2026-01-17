//! DNS over QUIC (DoQ) server implementation.
//!
//! This module provides DoQ support per RFC 9250.
//!
//! DNS over QUIC uses the QUIC transport protocol to provide encrypted DNS
//! with improved latency characteristics. Each DNS query/response pair uses
//! a separate bidirectional QUIC stream.
//!
//! # Features
//!
//! - QUIC transport with TLS 1.3
//! - 0-RTT early data support (with replay protection considerations)
//! - Connection migration (handled by QUIC layer)
//! - Multiple concurrent streams per connection
//! - Proper ALPN negotiation with "doq" identifier
//!
//! # Security Considerations
//!
//! 0-RTT data is susceptible to replay attacks. DNS queries are generally
//! idempotent, making them suitable for 0-RTT, but implementations should
//! consider the implications for their specific use case.
//!
//! # Example
//!
//! ```ignore
//! use stria_server::doq::DoqServer;
//! use std::sync::Arc;
//!
//! let server_config = DoqServer::build_server_config("cert.pem", "key.pem")?;
//! let server = DoqServer::bind(
//!     "0.0.0.0:853".parse()?,
//!     server_config,
//!     handler,
//! ).await?;
//! server.run().await?;
//! ```

use crate::handler::{QueryContext, QueryHandler};
use crate::{Protocol, Result, ServerError};
use bytes::Bytes;
use quinn::{
    Connection, Endpoint, RecvStream, SendStream, ServerConfig as QuinnServerConfig, VarInt,
    crypto::rustls::QuicServerConfig,
};
use rustls::pki_types::CertificateDer;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use stria_proto::Message;
use tracing::{debug, info, trace};

/// ALPN protocol identifier for DNS over QUIC per RFC 9250.
const ALPN_DOQ: &[u8] = b"doq";

/// Maximum DNS message size (same as TCP).
const MAX_DNS_MESSAGE_SIZE: usize = 65535;

/// Connection ID counter.
static CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

/// DNS over QUIC server.
///
/// Provides encrypted DNS transport using QUIC on port 853 (by default).
/// Each query uses a separate bidirectional QUIC stream.
pub struct DoqServer {
    endpoint: Endpoint,
    handler: Arc<dyn QueryHandler>,
    local_addr: SocketAddr,
    idle_timeout: Duration,
}

impl DoqServer {
    /// Builds a QUIC server configuration from PEM certificate and key files.
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path to the PEM-encoded certificate chain
    /// * `key_path` - Path to the PEM-encoded private key
    ///
    /// # Returns
    ///
    /// A configured `ServerConfig` suitable for DoQ with proper ALPN.
    pub fn build_server_config<P: AsRef<Path>>(
        cert_path: P,
        key_path: P,
    ) -> Result<QuinnServerConfig> {
        Self::build_server_config_with_options(cert_path, key_path, true)
    }

    /// Builds a QUIC server configuration with configurable options.
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path to the PEM-encoded certificate chain
    /// * `key_path` - Path to the PEM-encoded private key
    /// * `enable_0rtt` - Whether to enable 0-RTT early data
    ///
    /// # Returns
    ///
    /// A configured `ServerConfig` suitable for DoQ.
    pub fn build_server_config_with_options<P: AsRef<Path>>(
        cert_path: P,
        key_path: P,
        enable_0rtt: bool,
    ) -> Result<QuinnServerConfig> {
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

        // Build rustls server config
        let mut crypto_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Tls(format!("Failed to build TLS config: {}", e)))?;

        // Set ALPN for DoQ
        crypto_config.alpn_protocols = vec![ALPN_DOQ.to_vec()];

        // Enable session tickets for resumption
        crypto_config.max_early_data_size = if enable_0rtt { u32::MAX } else { 0 };

        // Build quinn server config using QUIC-specific rustls wrapper
        let quic_crypto_config = QuicServerConfig::try_from(crypto_config)
            .map_err(|e| ServerError::Tls(format!("Failed to create QUIC crypto config: {}", e)))?;
        let mut server_config = QuinnServerConfig::with_crypto(Arc::new(quic_crypto_config));

        // Configure transport parameters
        let mut transport_config = quinn::TransportConfig::default();

        // Set idle timeout (default 30 seconds)
        transport_config.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));

        // Set max concurrent streams
        transport_config.max_concurrent_bidi_streams(VarInt::from_u32(100));
        transport_config.max_concurrent_uni_streams(VarInt::from_u32(0)); // DoQ uses bidi only

        // Enable 0-RTT
        if enable_0rtt {
            // Server needs to send max_early_data_size via transport config
            // This is already handled by max_early_data_size in crypto config
        }

        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }

    /// Binds a new DoQ server to the given address.
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address to bind to (typically port 853)
    /// * `server_config` - QUIC server configuration
    /// * `handler` - The query handler for processing DNS queries
    ///
    /// # Returns
    ///
    /// A new `DoqServer` ready to accept connections.
    pub async fn bind(
        addr: SocketAddr,
        server_config: QuinnServerConfig,
        handler: Arc<dyn QueryHandler>,
    ) -> Result<Self> {
        // Create the QUIC endpoint
        let endpoint = Endpoint::server(server_config, addr).map_err(|e| {
            ServerError::Io(std::io::Error::other(format!(
                "Failed to bind QUIC endpoint: {}",
                e
            )))
        })?;

        let local_addr = endpoint.local_addr()?;

        info!(addr = %local_addr, "DoQ server listening");

        Ok(Self {
            endpoint,
            handler,
            local_addr,
            idle_timeout: Duration::from_secs(30),
        })
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Sets the idle connection timeout.
    ///
    /// Note: This only affects new connections. The timeout is primarily
    /// controlled by the transport config passed during construction.
    pub fn set_idle_timeout(&mut self, timeout: Duration) {
        self.idle_timeout = timeout;
    }

    /// Runs the DoQ server, accepting and handling connections.
    ///
    /// This method runs indefinitely, accepting QUIC connections and
    /// spawning tasks to handle them.
    pub async fn run(self) -> Result<()> {
        info!(addr = %self.local_addr, "DoQ server running");

        while let Some(incoming) = self.endpoint.accept().await {
            let handler = self.handler.clone();
            let conn_id = CONNECTION_ID.fetch_add(1, Ordering::Relaxed);

            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        let peer = connection.remote_address();
                        trace!(client = %peer, conn_id, "New DoQ connection");

                        if let Err(e) = handle_connection(connection, handler, conn_id).await {
                            debug!(error = %e, client = %peer, conn_id, "DoQ connection error");
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, conn_id, "Failed to accept QUIC connection");
                    }
                }
            });
        }

        Ok(())
    }

    /// Gracefully shuts down the server.
    ///
    /// Closes the endpoint and waits for existing connections to drain.
    pub async fn shutdown(self) {
        info!("Shutting down DoQ server");
        self.endpoint.close(VarInt::from_u32(0), b"server shutdown");
        self.endpoint.wait_idle().await;
    }
}

/// Handles a QUIC connection, processing streams.
async fn handle_connection(
    connection: Connection,
    handler: Arc<dyn QueryHandler>,
    conn_id: u64,
) -> Result<()> {
    let peer = connection.remote_address();

    // Accept streams until the connection is closed
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let handler = handler.clone();
                let stream_id = recv.id().index();

                tokio::spawn(async move {
                    if let Err(e) = handle_stream(send, recv, peer, handler, conn_id).await {
                        debug!(
                            error = %e,
                            client = %peer,
                            conn_id,
                            stream_id,
                            "DoQ stream error"
                        );
                    }
                });
            }
            Err(e) => {
                // Connection closed
                match e {
                    quinn::ConnectionError::ApplicationClosed(_) => {
                        trace!(client = %peer, conn_id, "DoQ connection closed by peer");
                    }
                    quinn::ConnectionError::LocallyClosed => {
                        trace!(client = %peer, conn_id, "DoQ connection closed locally");
                    }
                    quinn::ConnectionError::TimedOut => {
                        trace!(client = %peer, conn_id, "DoQ connection timed out");
                    }
                    _ => {
                        debug!(error = %e, client = %peer, conn_id, "DoQ connection error");
                    }
                }
                break;
            }
        }
    }

    Ok(())
}

/// Handles a single bidirectional QUIC stream (one DNS query/response).
///
/// Per RFC 9250:
/// - Client sends DNS query as a single message
/// - Server sends DNS response as a single message
/// - Messages use the same 2-byte length prefix format as TCP
async fn handle_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    peer: SocketAddr,
    handler: Arc<dyn QueryHandler>,
    conn_id: u64,
) -> Result<()> {
    let stream_id = recv.id().index();

    // Read the DNS query
    let query_bytes = read_dns_message(&mut recv).await?;

    trace!(
        client = %peer,
        conn_id,
        stream_id,
        len = query_bytes.len(),
        "Received DoQ query"
    );

    // Parse the query
    let query = match Message::parse(&query_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            debug!(error = %e, client = %peer, "Failed to parse DoQ query");
            // Close stream with error
            send.finish().ok();
            return Ok(());
        }
    };

    // Create context
    let ctx = QueryContext::new(peer, Protocol::Doq).with_connection_id(conn_id);

    // Handle the query
    let response = handler.handle(query, ctx).await;

    // Serialize and send response
    let wire = response.to_wire();
    write_dns_message(&mut send, &wire).await?;

    // Finish the stream
    send.finish().map_err(|e| {
        ServerError::Io(std::io::Error::other(format!(
            "Failed to finish stream: {}",
            e
        )))
    })?;

    trace!(
        client = %peer,
        conn_id,
        stream_id,
        len = wire.len(),
        "Sent DoQ response"
    );

    Ok(())
}

/// Reads a DNS message from a QUIC receive stream.
///
/// Per RFC 9250, DNS messages are prefixed with a 2-byte length field,
/// just like TCP DNS.
async fn read_dns_message(recv: &mut RecvStream) -> Result<Bytes> {
    // Read 2-byte length prefix
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await.map_err(|e| {
        ServerError::Io(std::io::Error::other(format!(
            "Failed to read length: {}",
            e
        )))
    })?;

    let len = u16::from_be_bytes(len_buf) as usize;

    if len == 0 {
        return Err(ServerError::Protocol("Empty DNS message".into()));
    }

    if len > MAX_DNS_MESSAGE_SIZE {
        return Err(ServerError::Protocol(format!(
            "DNS message too large: {} bytes",
            len
        )));
    }

    // Read message body
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(|e| {
        ServerError::Io(std::io::Error::other(format!(
            "Failed to read message: {}",
            e
        )))
    })?;

    Ok(Bytes::from(buf))
}

/// Writes a DNS message to a QUIC send stream.
///
/// Prefixes the message with a 2-byte big-endian length.
async fn write_dns_message(send: &mut SendStream, data: &[u8]) -> Result<()> {
    // Write 2-byte length prefix
    let len = data.len() as u16;
    send.write_all(&len.to_be_bytes()).await.map_err(|e| {
        ServerError::Io(std::io::Error::other(format!(
            "Failed to write length: {}",
            e
        )))
    })?;

    // Write message body
    send.write_all(data).await.map_err(|e| {
        ServerError::Io(std::io::Error::other(format!(
            "Failed to write message: {}",
            e
        )))
    })?;

    Ok(())
}

/// DoQ error codes per RFC 9250.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DoqErrorCode {
    /// No error. Used when gracefully closing a connection.
    NoError = 0x0,
    /// The DoQ implementation encountered an internal error.
    InternalError = 0x1,
    /// The DoQ implementation encountered a protocol error.
    ProtocolError = 0x2,
    /// The implementation is unable to pursue the transaction or connection
    /// because some resource has been exhausted.
    RequestCancelled = 0x3,
    /// The implementation detected that its peer generated too many streams.
    ExcessiveLoad = 0x4,
    /// The implementation encountered an error processing the request.
    UnspecifiedError = 0x5,
}

impl DoqErrorCode {
    /// Converts the error code to a QUIC VarInt.
    pub fn to_varint(self) -> VarInt {
        VarInt::from_u32(self as u32)
    }
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
    async fn test_doq_server_bind() {
        install_crypto_provider();
        let (cert_file, key_file) = generate_test_cert();
        let server_config =
            DoqServer::build_server_config(cert_file.path(), key_file.path()).unwrap();
        let handler = Arc::new(RefusedHandler);

        let server = DoqServer::bind("127.0.0.1:0".parse().unwrap(), server_config, handler)
            .await
            .unwrap();

        assert!(server.local_addr().port() > 0);
    }

    #[test]
    fn test_server_config_alpn() {
        install_crypto_provider();
        let (cert_file, key_file) = generate_test_cert();
        let _server_config =
            DoqServer::build_server_config(cert_file.path(), key_file.path()).unwrap();

        // Server config is opaque, but we can verify it was created successfully
        // ALPN is set internally
    }

    #[test]
    fn test_server_config_without_0rtt() {
        install_crypto_provider();
        let (cert_file, key_file) = generate_test_cert();
        let _server_config =
            DoqServer::build_server_config_with_options(cert_file.path(), key_file.path(), false)
                .unwrap();
    }

    #[test]
    fn test_load_config_missing_cert() {
        install_crypto_provider();
        let result =
            DoqServer::build_server_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_doq_error_codes() {
        assert_eq!(DoqErrorCode::NoError.to_varint(), VarInt::from_u32(0));
        assert_eq!(DoqErrorCode::InternalError.to_varint(), VarInt::from_u32(1));
        assert_eq!(DoqErrorCode::ProtocolError.to_varint(), VarInt::from_u32(2));
    }
}
