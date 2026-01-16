//! Tracing and logging setup.

use tracing::Level;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Logging configuration.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Log level.
    pub level: Level,

    /// Log format ("text" or "json").
    pub format: LogFormat,

    /// Include span events.
    pub span_events: bool,
}

/// Log format options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable text format.
    Text,

    /// JSON format.
    Json,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            format: LogFormat::Text,
            span_events: false,
        }
    }
}

/// Initializes the tracing subscriber.
pub fn init_tracing(config: &LogConfig) {
    let filter = EnvFilter::builder()
        .with_default_directive(config.level.into())
        .from_env_lossy();

    let span_events = if config.span_events {
        FmtSpan::NEW | FmtSpan::CLOSE
    } else {
        FmtSpan::NONE
    };

    match config.format {
        LogFormat::Text => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_span_events(span_events),
                )
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_span_events(span_events),
                )
                .init();
        }
    }
}

/// Initializes tracing with environment-based configuration.
pub fn init_tracing_from_env() {
    let filter = EnvFilter::from_default_env();

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true).with_thread_ids(true))
        .init();
}
