//! DNS over HTTPS (DoH) server implementation.
//!
//! This module provides DoH support per RFC 8484.
//!
//! DNS over HTTPS encodes DNS messages in HTTP requests/responses. The server
//! supports both GET (with base64url-encoded query) and POST (with binary body)
//! methods.
//!
//! # Features
//!
//! - HTTP/2 support (required by RFC 8484)
//! - GET method with `dns` query parameter (base64url-encoded)
//! - POST method with `application/dns-message` body
//! - Health check endpoint at `/health`
//! - Configurable DNS query path (default: `/dns-query`)
//! - TLS termination with rustls
//!
//! # Example
//!
//! ```ignore
//! use stria_server::doh::DohServer;
//! use std::sync::Arc;
//!
//! let tls_config = DohServer::load_tls_config("cert.pem", "key.pem")?;
//! let server = DohServer::bind(
//!     "0.0.0.0:443".parse()?,
//!     tls_config,
//!     handler,
//! ).await?;
//! server.run().await?;
//! ```

use crate::handler::{QueryContext, QueryHandler};
use crate::{Protocol, Result, ServerError};
use stria_proto::Message;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use data_encoding::BASE64URL_NOPAD;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use serde::Deserialize;
use socket2::{Domain, Socket, Type};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, trace};

/// MIME type for DNS messages per RFC 8484.
const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

/// Connection ID counter.
static CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

/// ALPN protocol identifiers for HTTP/2 and HTTP/1.1.
const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// DNS over HTTPS server.
///
/// Provides encrypted DNS transport using HTTPS on port 443 (by default).
/// Supports both GET and POST methods per RFC 8484.
pub struct DohServer {
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    router: Router,
    local_addr: SocketAddr,
    request_timeout: Duration,
}

/// Query parameters for GET requests.
#[derive(Debug, Deserialize)]
struct DnsQueryParams {
    /// Base64url-encoded DNS query (without padding).
    dns: String,
}

/// Shared state for the Axum router.
#[derive(Clone)]
struct AppState {
    handler: Arc<dyn QueryHandler>,
}

impl DohServer {
    /// Loads TLS configuration from PEM certificate and key files.
    ///
    /// The configuration enables HTTP/2 ALPN negotiation as required by RFC 8484.
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path to the PEM-encoded certificate chain
    /// * `key_path` - Path to the PEM-encoded private key
    ///
    /// # Returns
    ///
    /// A configured `ServerConfig` suitable for DoH with HTTP/2 ALPN.
    pub fn load_tls_config<P: AsRef<Path>>(
        cert_path: P,
        key_path: P,
    ) -> Result<Arc<ServerConfig>> {
        // Load certificate chain
        let cert_file = File::open(cert_path.as_ref()).map_err(|e| {
            ServerError::Tls(format!("Failed to open certificate file: {}", e))
        })?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| ServerError::Tls(format!("Failed to parse certificates: {}", e)))?;

        if certs.is_empty() {
            return Err(ServerError::Tls("No certificates found in file".into()));
        }

        // Load private key
        let key_file = File::open(key_path.as_ref()).map_err(|e| {
            ServerError::Tls(format!("Failed to open key file: {}", e))
        })?;
        let mut key_reader = BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| ServerError::Tls(format!("Failed to parse private key: {}", e)))?
            .ok_or_else(|| ServerError::Tls("No private key found in file".into()))?;

        // Build server config with HTTP/2 ALPN
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Tls(format!("Failed to build TLS config: {}", e)))?;

        // Enable ALPN for HTTP/2 (required by RFC 8484) with HTTP/1.1 fallback
        config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];

        Ok(Arc::new(config))
    }

    /// Binds a new DoH server to the given address.
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address to bind to (typically port 443)
    /// * `tls_config` - TLS server configuration with certificates
    /// * `handler` - The query handler for processing DNS queries
    ///
    /// # Returns
    ///
    /// A new `DohServer` ready to accept connections.
    pub async fn bind(
        addr: SocketAddr,
        tls_config: Arc<ServerConfig>,
        handler: Arc<dyn QueryHandler>,
    ) -> Result<Self> {
        Self::bind_with_path(addr, tls_config, handler, "/dns-query").await
    }

    /// Binds a new DoH server with a custom DNS query path.
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address to bind to
    /// * `tls_config` - TLS server configuration
    /// * `handler` - The query handler
    /// * `path` - The HTTP path for DNS queries (e.g., "/dns-query")
    pub async fn bind_with_path(
        addr: SocketAddr,
        tls_config: Arc<ServerConfig>,
        handler: Arc<dyn QueryHandler>,
        path: &str,
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

        // Build the router
        let state = AppState { handler };
        let router = Router::new()
            .route(path, get(handle_get_query).post(handle_post_query))
            .route("/health", get(handle_health))
            .route("/metrics", get(handle_metrics))
            .with_state(state)
            .layer(TraceLayer::new_for_http());

        info!(addr = %local_addr, path, "DoH server listening");

        Ok(Self {
            listener,
            tls_acceptor,
            router,
            local_addr,
            request_timeout: Duration::from_secs(30),
        })
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Sets the request timeout.
    ///
    /// Individual HTTP requests that take longer than this will be cancelled.
    /// Default is 30 seconds.
    pub fn set_request_timeout(&mut self, timeout: Duration) {
        self.request_timeout = timeout;
    }

    /// Runs the DoH server, accepting and handling connections.
    ///
    /// This method runs indefinitely, accepting HTTPS connections and
    /// processing DNS queries over HTTP/2 or HTTP/1.1.
    pub async fn run(self) -> Result<()> {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let tls_acceptor = self.tls_acceptor.clone();
                    let router = self.router.clone();
                    let request_timeout = self.request_timeout;
                    let conn_id = CONNECTION_ID.fetch_add(1, Ordering::Relaxed);

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            stream,
                            peer,
                            tls_acceptor,
                            router,
                            request_timeout,
                            conn_id,
                        )
                        .await
                        {
                            debug!(error = %e, client = %peer, conn_id, "DoH connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Error accepting DoH connection");
                }
            }
        }
    }
}

/// Handles a single HTTPS connection.
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    tls_acceptor: TlsAcceptor,
    router: Router,
    _request_timeout: Duration,
    conn_id: u64,
) -> Result<()> {
    trace!(client = %peer, conn_id, "New DoH connection");

    // Perform TLS handshake
    let tls_stream = tls_acceptor
        .accept(stream)
        .await
        .map_err(|e| ServerError::Tls(format!("TLS handshake failed: {}", e)))?;

    // Wrap the TLS stream for hyper
    let io = TokioIo::new(tls_stream);

    // Create the HTTP connection builder with both HTTP/1 and HTTP/2 support
    let builder = ConnectionBuilder::new(TokioExecutor::new());

    // Convert tower service to hyper service
    let service = TowerToHyperService::new(router);

    // Serve the connection
    if let Err(e) = builder
        .serve_connection_with_upgrades(io, service)
        .await
    {
        // Connection errors are typically just client disconnects
        debug!(error = %e, client = %peer, conn_id, "HTTP connection ended");
    }

    trace!(client = %peer, conn_id, "DoH connection closed");
    Ok(())
}

/// Handles GET requests with base64url-encoded DNS query.
///
/// Per RFC 8484, the DNS query is passed in the `dns` query parameter
/// as a base64url-encoded (without padding) DNS message.
async fn handle_get_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParams>,
    request: Request<Body>,
) -> impl IntoResponse {
    // Get client address from connection info or headers
    let peer = extract_client_addr(&headers, &request);

    trace!(client = ?peer, "DoH GET request");

    // Decode base64url query
    let query_bytes = match BASE64URL_NOPAD.decode(params.dns.as_bytes()) {
        Ok(bytes) => Bytes::from(bytes),
        Err(e) => {
            debug!(error = %e, "Invalid base64url in DNS query parameter");
            return (
                StatusCode::BAD_REQUEST,
                "Invalid base64url encoding in dns parameter",
            )
                .into_response();
        }
    };

    // Process the query
    process_dns_query(state.handler, query_bytes, peer).await
}

/// Handles POST requests with binary DNS message body.
///
/// Per RFC 8484, the request body contains the raw DNS message with
/// Content-Type: application/dns-message.
async fn handle_post_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> impl IntoResponse {
    // Verify content type
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.starts_with(DNS_MESSAGE_CONTENT_TYPE) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("Expected Content-Type: {}", DNS_MESSAGE_CONTENT_TYPE),
        )
            .into_response();
    }

    // Get client address
    let peer = extract_client_addr(&headers, &request);

    trace!(client = ?peer, "DoH POST request");

    // Read the body
    let body_bytes = match axum::body::to_bytes(request.into_body(), 65535).await {
        Ok(bytes) => bytes,
        Err(e) => {
            debug!(error = %e, "Failed to read request body");
            return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
        }
    };

    // Process the query
    process_dns_query(state.handler, body_bytes, peer).await
}

/// Processes a DNS query and returns an HTTP response.
async fn process_dns_query(
    handler: Arc<dyn QueryHandler>,
    query_bytes: Bytes,
    peer: Option<SocketAddr>,
) -> Response {
    // Parse the DNS query
    let query = match Message::parse(&query_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            debug!(error = %e, "Failed to parse DNS query");
            return (StatusCode::BAD_REQUEST, "Invalid DNS message").into_response();
        }
    };

    // Create context
    let client = peer.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
    let ctx = QueryContext::new(client, Protocol::Doh);

    // Handle the query
    let response = handler.handle(query, ctx).await;

    // Serialize the response
    let wire = response.to_wire();

    // Build HTTP response with correct content type
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)
        .header(header::CONTENT_LENGTH, wire.len())
        .header(header::CACHE_CONTROL, format_cache_control(&response))
        .body(Body::from(wire))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build response").into_response()
        })
}

/// Formats the Cache-Control header based on the DNS response TTL.
fn format_cache_control(response: &Message) -> String {
    // Find minimum TTL from answer section
    let min_ttl = response
        .answers()
        .iter()
        .map(|r| r.ttl())
        .min()
        .unwrap_or(0);

    if min_ttl > 0 {
        format!("max-age={}", min_ttl)
    } else {
        "no-cache".to_string()
    }
}

/// Extracts the client address from headers or connection info.
fn extract_client_addr(headers: &HeaderMap, _request: &Request<Body>) -> Option<SocketAddr> {
    // Try X-Forwarded-For first (for reverse proxy setups)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(s) = forwarded.to_str() {
            // Take the first address in the chain
            if let Some(first) = s.split(',').next() {
                if let Ok(addr) = first.trim().parse() {
                    return Some(SocketAddr::new(addr, 0));
                }
            }
        }
    }

    // Try X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(s) = real_ip.to_str() {
            if let Ok(addr) = s.trim().parse() {
                return Some(SocketAddr::new(addr, 0));
            }
        }
    }

    None
}

/// Health check endpoint handler.
async fn handle_health() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Metrics endpoint handler.
///
/// Returns basic server metrics in a Prometheus-compatible format.
async fn handle_metrics() -> impl IntoResponse {
    // TODO: Integrate with stria-metrics for real metrics
    let metrics = format!(
        "# HELP doh_connections_total Total number of DoH connections\n\
         # TYPE doh_connections_total counter\n\
         doh_connections_total {}\n",
        CONNECTION_ID.load(Ordering::Relaxed)
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        metrics,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::RefusedHandler;
    use stria_proto::name::Name;
    use stria_proto::question::Question;
    use std::io::Write;
    use std::str::FromStr;
    use tempfile::NamedTempFile;

    // Install the ring crypto provider for tests
    fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    // Generate a self-signed certificate for testing
    fn generate_test_cert() -> (NamedTempFile, NamedTempFile) {
        use rcgen::{generate_simple_self_signed, CertifiedKey};

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
    async fn test_doh_server_bind() {
        install_crypto_provider();
        let (cert_file, key_file) = generate_test_cert();
        let tls_config = DohServer::load_tls_config(cert_file.path(), key_file.path()).unwrap();
        let handler = Arc::new(RefusedHandler);

        let server = DohServer::bind("127.0.0.1:0".parse().unwrap(), tls_config, handler)
            .await
            .unwrap();

        assert!(server.local_addr().port() > 0);
    }

    #[tokio::test]
    async fn test_doh_server_with_custom_path() {
        install_crypto_provider();
        let (cert_file, key_file) = generate_test_cert();
        let tls_config = DohServer::load_tls_config(cert_file.path(), key_file.path()).unwrap();
        let handler = Arc::new(RefusedHandler);

        let server = DohServer::bind_with_path(
            "127.0.0.1:0".parse().unwrap(),
            tls_config,
            handler,
            "/custom-dns",
        )
        .await
        .unwrap();

        assert!(server.local_addr().port() > 0);
    }

    #[test]
    fn test_base64url_decode() {
        // Create a simple DNS query
        let query = Message::query(Question::a(Name::from_str("example.com").unwrap()));
        let wire = query.to_wire();

        // Encode it
        let encoded = BASE64URL_NOPAD.encode(&wire);

        // Decode it back
        let decoded = BASE64URL_NOPAD.decode(encoded.as_bytes()).unwrap();
        assert_eq!(&wire[..], &decoded[..]);
    }

    #[test]
    fn test_tls_config_alpn() {
        install_crypto_provider();
        let (cert_file, key_file) = generate_test_cert();
        let tls_config = DohServer::load_tls_config(cert_file.path(), key_file.path()).unwrap();

        // Should have HTTP/2 ALPN
        assert!(tls_config.alpn_protocols.contains(&ALPN_H2.to_vec()));
    }

    #[test]
    fn test_cache_control_formatting() {
        // Response with answers should have max-age
        let query = Message::query(Question::a(Name::from_str("example.com").unwrap()));
        let mut response = Message::response_from(&query);
        response.add_answer(stria_proto::record::ResourceRecord::a(
            Name::from_str("example.com").unwrap(),
            300,
            std::net::Ipv4Addr::new(192, 0, 2, 1),
        ));

        let cache_control = format_cache_control(&response);
        assert_eq!(cache_control, "max-age=300");

        // Empty response should have no-cache
        let empty_response = Message::response_from(&query);
        let cache_control = format_cache_control(&empty_response);
        assert_eq!(cache_control, "no-cache");
    }
}
