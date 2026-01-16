# Stria DNS Server
# Multi-stage build for minimal final image

# Build stage
FROM rust:1.83-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build release binaries
RUN cargo build --release --bin stria --bin stria-ctl

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false stria

# Copy binaries from builder
COPY --from=builder /build/target/release/stria /usr/local/bin/
COPY --from=builder /build/target/release/stria-ctl /usr/local/bin/

# Copy example configuration
COPY examples/minimal.yaml /etc/stria/config.yaml

# Create data directories
RUN mkdir -p /var/lib/stria /var/run/stria \
    && chown -R stria:stria /var/lib/stria /var/run/stria /etc/stria

# Switch to non-root user
USER stria

# Expose DNS ports
EXPOSE 53/udp 53/tcp
# DoT
EXPOSE 853/tcp
# DoH
EXPOSE 443/tcp
# DoQ
EXPOSE 853/udp
# Control API
EXPOSE 8080/tcp
# Metrics
EXPOSE 9153/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD stria-ctl stats || exit 1

# Default command
ENTRYPOINT ["stria"]
CMD ["--config", "/etc/stria/config.yaml"]
