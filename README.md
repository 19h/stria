<p align="center">
  <br>
  <strong>stria</strong>
  <br><br>
  <strong>Modern, Production-Grade DNS Server</strong>
  <br>
  <em>Built with Rust for uncompromising performance, security, and reliability.</em>
  <br><br>
</p>

---

<p align="center">
  <a href="#key-features">Features</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#installation">Installation</a> &bull;
  <a href="#configuration">Configuration</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#performance">Performance</a>
</p>

---

## Overview

**Stria** is a next-generation DNS server engineered from the ground up in Rust to deliver exceptional performance, comprehensive security, and operational excellence. Designed for environments ranging from home networks to enterprise deployments, Stria combines the reliability of battle-tested DNS implementations with modern innovations in protocol support, caching strategies, and observability.

### Why Stria?

- **Blazing Fast**: Sub-millisecond cached response latency, 1M+ QPS capability on commodity hardware
- **Secure by Default**: Full DNSSEC validation, encrypted transport (DoT/DoH/DoQ), response rate limiting
- **Privacy-First**: QNAME minimization, no client subnet leakage, encrypted upstream queries
- **Zero-Copy Architecture**: Lock-free concurrent query handling with optional io_uring support
- **Intuitive Configuration**: YAML-based config that feels natural and deliberate
- **Observable**: Prometheus metrics, OpenTelemetry tracing, structured logging

---

## Key Features

<table>
<tr>
<td width="50%" valign="top">

### Protocol Support

| Protocol | Status | Port |
|----------|--------|------|
| DNS over UDP | Stable | 53 |
| DNS over TCP | Stable | 53 |
| DNS over TLS (DoT) | Stable | 853 |
| DNS over HTTPS (DoH) | Stable | 443 |
| DNS over QUIC (DoQ) | Stable | 853 |

### Security Features

- **DNSSEC Validation** - Full chain validation with configurable trust anchors
- **Response Rate Limiting (RRL)** - Mitigate amplification attacks with slip responses
- **Cache Poisoning Resistance** - 0x20 bit encoding, source port randomization, TXID entropy
- **Access Control Lists** - Fine-grained query/recursion/transfer permissions

</td>
<td width="50%" valign="top">

### Performance Features

- **Multi-Tier Caching** - L1 (per-thread), L2 (shared), L3 (Redis)
- **Serve-Stale** - Return expired records during upstream failures (RFC 8767)
- **Prefetch** - Proactively refresh hot records before TTL expiry
- **Connection Pooling** - Persistent connections to upstreams

### Operational Features

- **Hot Configuration Reload** - SIGHUP-triggered config refresh
- **Graceful Shutdown** - Complete in-flight queries before stopping
- **Prometheus Metrics** - 50+ metrics with histograms and counters
- **OpenTelemetry** - Distributed tracing support

</td>
</tr>
</table>

### DNS Filtering Engine

High-performance filtering with support for multiple blocklist formats:

```yaml
block:
  - stevenblack/unified          # Built-in shorthand
  - hagezi/pro                   # Popular blocklists
  - https://example.com/list.txt # Direct URLs

allow:
  - s.youtube.com                # Allowlist overrides
  - www.googleadservices.com
```

**Supported Formats**: Hosts files, domain lists, AdBlock Plus syntax, dnsmasq, Response Policy Zones (RPZ)

---

## Quick Start

### One-Line Install

```bash
cargo install stria
```

### Or Run with Docker

```bash
docker run -d -p 53:53/udp -p 53:53/tcp ghcr.io/19h/stria
```

### Minimal Configuration

Create `stria.yaml`:

```yaml
# Forward all queries to Cloudflare
upstream: 1.1.1.1
```

### Start the Server

```bash
stria run
```

That's it. Stria is now running on port 53, forwarding queries to Cloudflare.

### Test It

```bash
dig @127.0.0.1 example.com
```

---

## Installation

### From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/19h/stria.git
cd stria

# Build release binaries (optimized)
cargo build --release

# Binaries are in target/release/
ls target/release/stria target/release/stria-ctl

# Install to ~/.cargo/bin
cargo install --path crates/stria
```

This builds two binaries:
- `stria` - The main DNS server
- `stria-ctl` - Runtime control utility

### Feature Flags

Stria supports modular compilation via feature flags:

| Feature | Description | Default |
|---------|-------------|---------|
| `full` | All features enabled | Yes |
| `minimal` | Bare-bones forwarding server | No |
| `doh` | DNS over HTTPS support | Yes |
| `dot` | DNS over TLS support | Yes |
| `doq` | DNS over QUIC support | Yes |
| `dnssec` | DNSSEC validation | Yes |
| `filtering` | Blocklist filtering engine | Yes |
| `metrics` | Prometheus/OpenTelemetry | Yes |
| `zones` | Authoritative zone hosting | Yes |
| `io-uring` | Linux io_uring support | No |

**Minimal build** (forwarding only):
```bash
cargo build --release --no-default-features --features minimal
```

**With io_uring** (Linux only):
```bash
cargo build --release --features io-uring
```

### System Requirements

- **Rust**: 1.85+ (Edition 2024)
- **OS**: Linux, macOS, Windows, FreeBSD
- **Architecture**: x86_64, aarch64, arm

---

## Configuration

Stria uses intuitive YAML configuration. Config files are searched in order:

1. Explicit path via `-c`/`--config`
2. `./stria.yaml` or `./stria.yml`
3. `/etc/stria/config.yaml`
4. `~/.config/stria/config.yaml`

### Configuration Examples

<details>
<summary><strong>Home Network</strong> - Ad-blocking with local DNS</summary>

```yaml
# Stria DNS - Home Network
# Ad-blocking DNS server with caching

listen: 53

upstream:
  - 1.1.1.1
  - 9.9.9.9

# Block ads, trackers, malware
block:
  - stevenblack/unified        # Ads + malware
  - energized/spark            # Lightweight tracker blocking
  
# Never block these (even if on blocklists)
allow:
  - s.youtube.com              # YouTube history
  - www.googleadservices.com   # Google Shopping

cache:
  size: 50000
  
# Local DNS for your home devices
local:
  router.home: 192.168.1.1
  nas.home: 192.168.1.10
  printer.home: 192.168.1.20
```

</details>

<details>
<summary><strong>Privacy-Focused</strong> - Maximum privacy with encrypted upstream</summary>

```yaml
# Stria DNS - Privacy Focused
# Maximum privacy with encrypted upstream and aggressive blocking

listen:
  - 53
  - 853/tls
  - 443/https

# Only use encrypted upstream (no plaintext DNS)
upstream:
  - tls://1.1.1.1:853                    # Cloudflare DoT
  - tls://dns.quad9.net:853              # Quad9 DoT  
  - https://cloudflare-dns.com/dns-query # Cloudflare DoH

# Aggressive blocking
block:
  - stevenblack/unified
  - energized/ultimate
  - oisd/full
  - hagezi/pro

# DNSSEC validation
dnssec: true

# Minimize data exposure
privacy:
  ecs: false                   # Don't send client subnet info
  qname-minimization: true     # Minimize query name in requests

# TLS certificates
tls:
  cert: /etc/stria/cert.pem
  key: /etc/stria/key.pem
```

</details>

<details>
<summary><strong>Pi-hole Replacement</strong> - Drop-in replacement with better performance</summary>

```yaml
# Stria DNS - Pi-hole Replacement
# Drop-in replacement for Pi-hole with better performance

listen: 53

upstream:
  - 1.1.1.1
  - 1.0.0.1

# Comprehensive ad/tracker blocking
block:
  - stevenblack/unified
  - energized/blu
  - oisd/small
  - https://v.firebog.net/hosts/AdguardDNS.txt

# Whitelist for common false positives
allow:
  - cdn.optimizely.com
  - s.youtube.com
  - video-stats.l.google.com

# Local DNS entries (like Pi-hole's "Local DNS Records")
local:
  pihole.local: 192.168.1.2
  homeassistant.local: 192.168.1.3
  plex.local: 192.168.1.4

# CNAME records (like Pi-hole's "Local CNAME Records")  
cname:
  ha.home: homeassistant.local
  media.home: plex.local

cache:
  size: 100000

# API for stats (Pi-hole admin replacement)
api:
  listen: :8080
```

</details>

<details>
<summary><strong>Enterprise</strong> - High-availability with split-horizon and zones</summary>

```yaml
# Stria DNS - Enterprise
# High-availability DNS with split-horizon, metrics, and zone hosting

listen:
  - 53
  - 853/tls
  - 443/https

upstream:
  - 10.0.0.53          # Primary internal
  - 10.0.0.54          # Secondary internal
  - 1.1.1.1            # Fallback

# Split-horizon DNS
views:
  internal:
    match: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    zones:
      - file: /etc/stria/zones/corp.example.com.zone
      - file: /etc/stria/zones/10.in-addr.arpa.zone
      
  external:
    match: any
    upstream:
      - 1.1.1.1
      - 8.8.8.8

# Authoritative zones
zones:
  - name: example.com
    type: primary
    file: /etc/stria/zones/example.com.zone
    dnssec:
      algorithm: ECDSAP256SHA256
      
  - name: example.com
    type: secondary  
    primary: 10.0.0.60
    tsig: xfer-key

# Access control
acl:
  allow-query: any
  allow-recursion: 10.0.0.0/8, 172.16.0.0/12
  allow-transfer: 10.0.0.53, 10.0.0.54

# Rate limiting
ratelimit:
  qps: 1000
  slip: 2

# Caching
cache:
  size: 500000
  serve-stale: true
  prefetch: true

# Metrics & observability  
metrics:
  prometheus: :9153
  otlp: http://otel-collector:4317

# Logging
log:
  level: info
  format: json
  queries: /var/log/stria/queries.log

# TLS
tls:
  cert: /etc/stria/tls/server.crt
  key: /etc/stria/tls/server.key
  ca: /etc/stria/tls/ca.crt
```

</details>

### Configuration Syntax

> **Note**: The examples above use a planned simplified syntax for readability. The full configuration schema below shows the complete structure currently implemented.

### Configuration Reference

<details>
<summary><strong>Full Configuration Schema</strong></summary>

```yaml
# Server identity and metadata
server:
  name: "stria"                    # Server name (for NSID, logs)
  version: "0.1.0"                 # Version string
  hostname: null                   # Hostname for version.bind queries
  workers: 0                       # Worker threads (0 = auto-detect)
  user: nobody                     # Drop privileges to user
  group: nogroup                   # Drop privileges to group
  directory: /var/lib/stria        # Working directory
  pid_file: /var/run/stria.pid     # PID file location

# Network listeners
listeners:
  udp:
    - address: 0.0.0.0:53
      reuseport: true              # SO_REUSEPORT for load balancing
      recv_buffer: 4194304         # 4MB receive buffer
      send_buffer: 4194304
  tcp:
    - address: 0.0.0.0:53
      reuseport: true
      backlog: 1024
      idle_timeout: 10             # Seconds
      tcp_fastopen: true
      tcp_fastopen_queue: 256
  dot:
    - address: 0.0.0.0:853
      reuseport: true
      backlog: 1024
      idle_timeout: 30
      tls:
        cert: /etc/stria/cert.pem
        key: /etc/stria/key.pem
        ca: null                   # CA for client auth (optional)
        client_auth: false
        min_version: "1.2"
        alpn: ["dot"]
  doh:
    - address: 0.0.0.0:443
      path: /dns-query
      http2: true
      reuseport: true
      backlog: 1024
      idle_timeout: 30
      tls:
        cert: /etc/stria/cert.pem
        key: /etc/stria/key.pem
        min_version: "1.2"
        alpn: ["h2", "http/1.1"]
  doq:
    - address: 0.0.0.0:853
      reuseport: true
      idle_timeout: 30
      max_streams: 100
      tls:
        cert: /etc/stria/cert.pem
        key: /etc/stria/key.pem

# Resolution
resolver:
  mode: forward                    # forward | recursive | authoritative
  upstreams:
    - address: 1.1.1.1:53
      protocol: udp                # udp | tcp | dot | doh | doq
      tls_name: null               # TLS server name (for DoT/DoH/DoQ)
      path: null                   # HTTP path (for DoH)
      bootstrap: []                # Bootstrap addresses for hostnames
      weight: 100                  # Load balancing weight
      health_check_interval: 30    # Seconds
    - address: 1.1.1.1:853
      protocol: dot
      tls_name: cloudflare-dns.com
      weight: 100
  root_hints: null                 # Root hints file (for recursive mode)
  timeout_ms: 5000
  retries: 3
  qname_minimization: true         # RFC 7816
  enable_0x20: true                # Case randomization
  max_recursion_depth: 16
  pool:
    max_connections: 100           # Per upstream
    min_idle: 10
    connect_timeout_ms: 5000
    idle_timeout_secs: 60
    max_lifetime_secs: 3600

# Caching
cache:
  enabled: true
  max_entries: 100000
  max_memory: 268435456            # 256MB
  min_ttl: 30
  max_ttl: 604800                  # 7 days
  negative_ttl: 900                # 15 minutes
  serve_stale: true                # RFC 8767
  stale_ttl: 86400                 # 1 day
  prefetch: true
  prefetch_threshold: 10           # % of TTL remaining
  l2:                              # Shared memory cache (optional)
    size: 134217728                # 128MB
  l3:                              # Redis cache (optional)
    url: redis://localhost:6379
    pool_size: 10
    prefix: "stria:"

# DNSSEC
dnssec:
  validation: true
  trust_anchors: /etc/stria/root.key  # RFC 5011 trust anchors
  negative_trust_anchors: []       # Domains to skip validation
  algorithms:                      # Supported algorithms
    - ECDSAP256SHA256
    - ECDSAP384SHA384
    - ED25519
    - RSASHA256
  digest_types:
    - SHA-256
    - SHA-384
  aggressive_nsec: true            # RFC 8198

# Security
security:
  rrl:
    enabled: true
    responses_per_second: 5
    window: 15                     # Seconds
    slip: 2                        # TC bit every N responses
    ipv4_prefix: 24
    ipv6_prefix: 56
    max_table_size: 100000
    exempt: []                     # IP networks exempt from RRL
  acl:
    default_action: allow          # allow | deny
    allow_recursion:               # Networks allowed recursion
      - 127.0.0.0/8
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - ::1/128
      - fc00::/7
    allow_query: []                # Empty = allow all
    deny_query: []
    allow_transfer:
      - 127.0.0.1/32
      - ::1/128
    allow_update: []
  cookies:
    enabled: true
    secret: null                   # Auto-generated if null
    require: false
  limits:
    max_udp_size: 4096
    max_tcp_size: 65535
    max_tcp_connections: 10000
    max_tcp_per_client: 100
    max_queries_per_tcp: 100
    max_outstanding_per_client: 100
    tcp_idle_timeout: 10

# Filtering
filter:
  enabled: false
  blocklists:
    - name: stevenblack
      url: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
      format: hosts                # hosts | domains | adblock | dnsmasq | rpz
      enabled: true
  rules: []                        # Local filter rules
  exceptions: []                   # Allowlist exceptions
  exclusions: []                   # Additional blocks
  custom_block: []                 # Domains to always block
  custom_allow: []                 # Domains to never block
  blocked_response: nxdomain       # nxdomain | nodata | refused | ip | null
  blocked_ip: null                 # Custom IP when blocked_response is 'ip'
  cname_protection: true           # Block CNAME cloaking
  safe_search:
    enabled: false
    google: true
    bing: true
    duckduckgo: true
    youtube: true
    pixabay: true
  parental:
    enabled: false
    level: 2                       # 0-4 sensitivity

# Metrics
metrics:
  enabled: true
  prometheus:
    enabled: true
    listen: 127.0.0.1:9153
    path: /metrics
  otlp:
    endpoint: http://localhost:4317
    service_name: stria
    headers: {}

# Logging
logging:
  level: info                      # trace | debug | info | warn | error
  format: text                     # text | json
  output: stdout                   # stdout | stderr | /path/to/file
  query_log: false
  query_log_file: null

# Zone hosting (authoritative mode)
zones:
  - name: example.com
    zone_type: primary             # primary | secondary | forward | stub
    file: /etc/stria/zones/example.com.zone
    primaries: []                  # For secondary zones
    forwarders: []                 # For forward zones
    tsig_key: null                 # TSIG key name
    allow_transfer: []
    allow_update: []
    dnssec:
      enabled: true
      ksk_algorithm: ECDSAP256SHA256
      zsk_algorithm: ECDSAP256SHA256
      key_directory: /etc/stria/keys
      nsec3:
        iterations: 10
        salt: "auto"
        opt_out: false

# Control server (for stria-ctl)
control:
  enabled: true
  socket_path: /var/run/stria/control.sock
  http_listen: 127.0.0.1:8080      # HTTP control API endpoint
  rules_file: /var/lib/stria/custom_rules.json  # Persistent custom block/allow rules
```

</details>

---

## Architecture

Stria is designed as a modular system of specialized crates, enabling both flexibility and optimal compilation.

```
                                     ┌─────────────────────────────────────────────────┐
                                     │                   stria                         │
                                     │         Main Binary & CLI Interface             │
                                     └────────────────────┬────────────────────────────┘
                                                          │
              ┌───────────────────────────────────────────┼───────────────────────────────────────────┐
              │                                           │                                           │
              ▼                                           ▼                                           ▼
┌─────────────────────────┐             ┌─────────────────────────────┐             ┌─────────────────────────┐
│     stria-server        │             │      stria-resolver         │             │      stria-cache        │
│  Protocol Listeners     │             │   Forward & Recursive       │             │   Multi-Tier Cache      │
│  UDP/TCP/DoT/DoH/DoQ    │             │   Resolution Engine         │             │   L1/L2/L3 + Prefetch   │
└───────────┬─────────────┘             └──────────────┬──────────────┘             └───────────┬─────────────┘
            │                                          │                                        │
            │                           ┌──────────────┼──────────────┐                         │
            │                           │              │              │                         │
            ▼                           ▼              ▼              ▼                         ▼
┌─────────────────────────┐   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   ┌─────────────────────────┐
│     stria-filter        │   │stria-dnssec │ │ stria-zone  │ │  stria-ede  │   │     stria-metrics       │
│  Blocklist Filtering    │   │  Validation │ │Zone Hosting │ │Extended Err │   │ Prometheus/OpenTelemetry│
│  Hosts/AdBlock/RPZ      │   │  Trust Mgmt │ │ AXFR/IXFR   │ │  RFC 8914   │   │   Tracing & Logging     │
└─────────────────────────┘   └─────────────┘ └─────────────┘ └─────────────┘   └─────────────────────────┘
                                              │
              ┌───────────────────────────────┼───────────────────────────────┐
              │                               │                               │
              ▼                               ▼                               ▼
┌─────────────────────────┐   ┌─────────────────────────────┐   ┌─────────────────────────┐
│     stria-proto         │   │       stria-config          │   │      (External)         │
│   DNS Wire Protocol     │   │    YAML Configuration       │   │   Upstream Resolvers    │
│   RFC 1035 + Extensions │   │    Hot Reload Support       │   │   1.1.1.1 / 8.8.8.8     │
└─────────────────────────┘   └─────────────────────────────┘   └─────────────────────────┘
```

### Crate Overview

| Crate | Description | Key Types |
|-------|-------------|-----------|
| **stria** | Main binary and CLI | `Cli`, `StriaHandler` |
| **stria-proto** | DNS wire protocol (RFC 1035+) | `Message`, `Name`, `Question`, `ResourceRecord` |
| **stria-server** | Multi-protocol server | `DnsServer`, `QueryHandler`, `Protocol` |
| **stria-resolver** | Forward/recursive resolution | `Resolver`, `Forwarder`, `Upstream` |
| **stria-cache** | Multi-tier DNS caching | `DnsCache`, `CacheKey`, `CacheEntry` |
| **stria-dnssec** | DNSSEC validation | `DnssecValidator`, `TrustAnchor`, `Algorithm` |
| **stria-filter** | Blocklist filtering engine | `FilterEngine`, `Rule`, `Blocklist` |
| **stria-zone** | Authoritative zone management | `Zone`, `ZoneStore`, `ZoneTransfer` |
| **stria-metrics** | Observability | `DnsMetrics`, `QueryTimer` |
| **stria-config** | Configuration management | `Config`, `ConfigHolder` |
| **stria-ede** | Extended DNS Errors (RFC 8914) | `EdeCode`, `ExtendedDnsError` |

### Query Flow

```
Client Query (UDP:53)
        │
        ▼
┌───────────────────┐
│   stria-server    │──── Protocol-specific listener (UDP/TCP/DoT/DoH/DoQ)
│   QueryHandler    │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│   stria-filter    │──── Check blocklists (if enabled)
│     check()       │     Returns NXDOMAIN/REDIRECT if blocked
└────────┬──────────┘
         │ (not blocked)
         ▼
┌───────────────────┐
│   stria-cache     │──── L1 (per-thread) → L2 (shared) → L3 (Redis)
│     lookup()      │     Returns cached response if fresh
└────────┬──────────┘
         │ (cache miss)
         ▼
┌───────────────────┐
│  stria-resolver   │──── Forward to upstream or recursive resolution
│     resolve()     │     Connection pooling, retries, failover
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│   stria-dnssec    │──── Validate RRSIG/DNSKEY chain (if enabled)
│    validate()     │     Returns SERVFAIL with EDE if bogus
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│   stria-cache     │──── Store response with appropriate TTL
│  cache_response() │     Trigger prefetch if threshold reached
└────────┬──────────┘
         │
         ▼
    Client Response
```

---

## Performance

### Design Principles

- **Lock-Free Query Handling**: Concurrent processing without mutex contention
- **Zero-Copy Parsing**: Minimize allocations in hot paths
- **SIMD Acceleration**: Optional vectorized domain name operations
- **io_uring Support**: Async I/O on modern Linux kernels
- **Connection Pooling**: Persistent upstream connections with keepalive

### Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Cached QPS | 1,000,000+ | Per server instance |
| Cache Latency (p50) | < 100 µs | In-memory L2 cache |
| Cache Latency (p99) | < 1 ms | Including L1 miss |
| Forwarded QPS | 100,000+ | With connection pooling |
| Memory (100K cache) | < 50 MB | Efficient entry storage |

### Benchmarking

Run the included benchmarks:

```bash
# Protocol parsing/serialization
cargo bench --package stria-proto

# Cache operations
cargo bench --package stria-cache

# Filter matching
cargo bench --package stria-filter

# End-to-end queries
cargo bench --package stria
```

---

## RFC Compliance

Stria implements comprehensive RFC support for modern DNS operations:

### Core Protocol

| RFC | Title | Status |
|-----|-------|--------|
| RFC 1035 | Domain Names - Implementation and Specification | Full |
| RFC 2181 | Clarifications to the DNS Specification | Full |
| RFC 6891 | Extension Mechanisms for DNS (EDNS0) | Full |
| RFC 6895 | DNS IANA Considerations | Full |
| RFC 8914 | Extended DNS Errors | Full |

### Encrypted Transport

| RFC | Title | Status |
|-----|-------|--------|
| RFC 7858 | DNS over TLS (DoT) | Full |
| RFC 8484 | DNS over HTTPS (DoH) | Full |
| RFC 9250 | DNS over QUIC (DoQ) | Full |

### DNSSEC

| RFC | Title | Status |
|-----|-------|--------|
| RFC 4033 | DNS Security Introduction | Full |
| RFC 4034 | Resource Records for DNSSEC | Full |
| RFC 4035 | Protocol Modifications for DNSSEC | Full |
| RFC 5155 | NSEC3 Hashed Authenticated Denial | Full |
| RFC 6840 | DNSSEC Clarifications | Full |
| RFC 8624 | Algorithm Implementation Requirements | Full |

### Performance & Privacy

| RFC | Title | Status |
|-----|-------|--------|
| RFC 7816 | DNS Query Name Minimisation | Full |
| RFC 8767 | Serving Stale Data | Full |
| RFC 8198 | Aggressive NSEC Caching | Partial |

### Zone Operations

| RFC | Title | Status |
|-----|-------|--------|
| RFC 1995 | Incremental Zone Transfer (IXFR) | Full |
| RFC 1996 | Zone Change Notification (NOTIFY) | Full |
| RFC 2136 | Dynamic Updates | Full |
| RFC 9432 | Catalog Zones | Planned |

---

## Command Line Interface

```
stria - Modern, fast, and secure DNS resolution

USAGE:
    stria [OPTIONS] [COMMAND]

OPTIONS:
    -c, --config <FILE>      Configuration file path
    -l, --log-level <LEVEL>  Log level (trace/debug/info/warn/error)
    -q, --quiet              Minimal output
    -h, --help               Print help
    -V, --version            Print version

COMMANDS:
    run         Start the DNS server (default)
    validate    Validate configuration file
    version     Show version information
```

### Examples

```bash
# Start with default config search
stria

# Start with specific config
stria -c /etc/stria/config.yaml run

# Validate configuration
stria validate --verbose

# Debug mode
stria -l debug run
```

### Control Utility (stria-ctl)

The `stria-ctl` utility provides runtime control and monitoring of the Stria server:

```bash
# Server Statistics
stria-ctl stats                    # Show server statistics
stria-ctl stats --json             # Output as JSON

# Cache Management
stria-ctl cache stats              # Show cache statistics
stria-ctl cache flush              # Flush entire cache
stria-ctl cache flush example.com  # Flush specific domain

# Custom Filtering Rules (persisted to disk)
stria-ctl block list               # List custom block rules
stria-ctl block add ads.example.com      # Block a domain
stria-ctl block add --suffix example.com # Block domain and subdomains
stria-ctl block remove <rule-id>   # Remove a block rule

stria-ctl allow list               # List custom allow rules  
stria-ctl allow add safe.example.com     # Allow a domain (override blocks)
stria-ctl allow remove <rule-id>   # Remove an allow rule

# Filter Statistics
stria-ctl filter stats             # Show filter statistics

# Configuration
stria-ctl reload                   # Hot-reload configuration (SIGHUP)
```

Custom block/allow rules are persisted to disk (configurable via `control.rules_file`) and automatically restored on server restart.

---

## Metrics & Observability

### Prometheus Metrics

Stria exposes comprehensive metrics at `/metrics` (default port 9153):

```
# Query metrics
stria_queries_total{protocol="udp",qtype="A"} 1234567
stria_responses_total{protocol="udp",rcode="NOERROR"} 1234000
stria_query_duration_seconds{protocol="udp",quantile="0.99"} 0.0001

# Cache metrics
stria_cache_hits_total 1000000
stria_cache_misses_total 234567
stria_cache_entries 98765
stria_cache_prefetches_total 5000

# Upstream metrics
stria_upstream_queries_total{upstream="1.1.1.1"} 234567
stria_upstream_failures_total{upstream="1.1.1.1"} 123
stria_upstream_latency_seconds{upstream="1.1.1.1",quantile="0.99"} 0.05

# DNSSEC metrics
stria_dnssec_validations_total{result="secure"} 100000
stria_dnssec_validations_total{result="bogus"} 5

# Filtering metrics
stria_blocked_queries_total{reason="blocklist"} 50000
stria_blocked_queries_total{reason="rate_limited"} 100
```

### Structured Logging

Configure JSON logging for log aggregation:

```yaml
logging:
  level: info
  format: json
```

Output:
```json
{"timestamp":"2026-01-16T12:00:00Z","level":"INFO","target":"stria","message":"Query processed","query":"example.com","qtype":"A","rcode":"NOERROR","latency_us":85}
```

---

## Security Considerations

### Running as Non-Root

Stria can bind to privileged ports and then drop privileges:

```yaml
server:
  user: nobody
  group: nogroup
```

Or use capabilities (Linux):
```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/stria
```

### TLS Configuration

For DoT/DoH, provide certificates:

```yaml
tls:
  cert: /etc/stria/tls/server.crt
  key: /etc/stria/tls/server.key
  ca: /etc/stria/tls/ca.crt        # For client verification (optional)
  min_version: "1.2"               # Minimum TLS version
  ciphers:                         # Allowed cipher suites
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
```

### Rate Limiting

Protect against amplification attacks:

```yaml
security:
  rrl:
    enabled: true
    responses_per_second: 100      # Per source prefix
    slip: 2                        # TC bit every N responses
    ipv4_prefix: 24                # /24 grouping
    ipv6_prefix: 56                # /56 grouping
```

---

## Development

### Building from Source

```bash
git clone https://github.com/19h/stria.git
cd stria

# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests (271 tests across all crates)
cargo test --workspace

# Run integration tests
cargo test --package stria --test integration
```

### Test Coverage

Stria has comprehensive test coverage across all crates:

| Crate | Tests | Description |
|-------|-------|-------------|
| stria-proto | 107 | Wire protocol parsing, serialization, DNS types |
| stria-server | 34 | UDP/TCP/DoT/DoH/DoQ servers, control API |
| stria-filter | 19 | Blocklist matching, rule types, formats |
| stria-zone | 14 | Zone file parsing, record management |
| stria-resolver | 13 | Forward/recursive resolution, upstreams |
| stria-config | 11 | Configuration parsing, validation |
| stria-dnssec | 10 | DNSSEC validation, algorithms |
| stria (integration) | 31 | End-to-end server tests |
| stria (unit) | 8 | CLI parsing, main binary |
| Other crates | 24 | Cache, metrics, EDE |
| **Total** | **271** | |

---

## Deployment

### Systemd (Linux)

Stria includes a production-ready systemd service with security hardening:

```bash
# Build release binaries
cargo build --release

# Install using the provided script
sudo ./deploy/install.sh

# Or manually:
sudo cp target/release/stria /usr/local/bin/
sudo cp target/release/stria-ctl /usr/local/bin/
sudo cp deploy/stria.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now stria
```

The systemd service includes:
- Non-root user execution (`stria` user)
- Security hardening (ProtectSystem, NoNewPrivileges, etc.)
- Capability binding for port 53 (CAP_NET_BIND_SERVICE)
- Automatic restart on failure

### Docker

Build and run with Docker:

```bash
# Build the image
docker build -t stria .

# Run with default config
docker run -d --name stria \
  -p 53:53/udp -p 53:53/tcp \
  -p 8080:8080 \
  stria

# Run with custom config
docker run -d --name stria \
  -p 53:53/udp -p 53:53/tcp \
  -v /path/to/config:/etc/stria:ro \
  -v stria-data:/var/lib/stria \
  stria
```

### Docker Compose

For easy deployment with persistent data:

```bash
# Create config directory with your configuration
mkdir -p config
cp examples/minimal.yaml config/config.yaml

# Start the server
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

The included `docker-compose.yml` provides:
- Volume mounts for configuration and persistent data
- Health checks using stria-ctl
- Security options (read-only filesystem, dropped capabilities)
- Exposed ports for DNS, control API, and metrics

---

## Comparison

| Feature | Stria | BIND | Unbound | CoreDNS | Pi-hole |
|---------|-------|------|---------|---------|---------|
| Language | Rust | C | C | Go | PHP/C |
| DoT Support | Yes | Yes | Yes | Plugin | No |
| DoH Support | Yes | No | Yes | Plugin | No |
| DoQ Support | Yes | No | No | No | No |
| DNSSEC | Full | Full | Full | Plugin | Via upstream |
| Filtering | Native | No | Limited | Plugin | Native |
| Hot Reload | Yes | Yes | Yes | Yes | No |
| Prometheus | Native | Contrib | Contrib | Native | No |
| Memory Safety | Yes | No | No | Yes | N/A |

---

## Acknowledgments

Stria builds upon the excellent work of the DNS community and RFC authors. Special thanks to:

- The Rust community for an exceptional systems programming language
- Authors of trust-dns, hickory-dns for DNS ecosystem foundations
- The IETF for comprehensive DNS standards
- StevenBlack, Energized, OISD, Hagezi for blocklist curation

---

## License

Stria is dual-licensed under:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT))
- **Apache License 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

Choose the license that best fits your use case.

---

<p align="center">
  <strong>an int product, lol.</strong>
</p>
