//! Prometheus metrics exporter.

use std::net::SocketAddr;

#[cfg(feature = "prometheus")]
use metrics_exporter_prometheus::PrometheusBuilder;

/// Prometheus metrics server configuration.
#[derive(Debug, Clone)]
pub struct PrometheusConfig {
    /// Listen address.
    pub listen: SocketAddr,

    /// Endpoint path.
    pub path: String,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            listen: ([127, 0, 0, 1], 9153).into(),
            path: "/metrics".to_string(),
        }
    }
}

/// Initializes the Prometheus metrics exporter.
#[cfg(feature = "prometheus")]
pub fn init_prometheus(config: &PrometheusConfig) -> Result<(), Box<dyn std::error::Error>> {
    PrometheusBuilder::new()
        .with_http_listener(config.listen)
        .install()?;

    tracing::info!("Prometheus metrics server listening on {}", config.listen);
    Ok(())
}

#[cfg(not(feature = "prometheus"))]
pub fn init_prometheus(_config: &PrometheusConfig) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
