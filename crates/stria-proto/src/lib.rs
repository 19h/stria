//! # Stria DNS Protocol Library
//!
//! This crate provides comprehensive DNS protocol types, wire format parsing,
//! and serialization following RFC 1035 and its extensions.
//!
//! ## Features
//!
//! - **Complete RFC 1035 compliance** with clarifications from RFC 2181
//! - **EDNS0 support** (RFC 6891) with OPT pseudo-RR
//! - **All standard record types** including modern types like HTTPS/SVCB
//! - **DNSSEC record types** (DNSKEY, DS, RRSIG, NSEC, NSEC3)
//! - **Zero-copy parsing** where possible for maximum performance
//! - **SIMD-accelerated** domain name operations (optional)
//!
//! ## Example
//!
//! ```rust,ignore
//! use stria_proto::{Message, Question, Name, RecordType, RecordClass};
//!
//! // Parse a DNS message from wire format
//! let bytes: &[u8] = &[/* DNS message bytes */];
//! let message = Message::parse(bytes)?;
//!
//! // Build a DNS query
//! let query = Message::query(
//!     Question::new(Name::from_str("example.com.")?, RecordType::A, RecordClass::IN)
//! );
//!
//! // Serialize to wire format
//! let wire_bytes = query.to_wire()?;
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod class;
pub mod edns;
pub mod error;
pub mod header;
pub mod message;
pub mod name;
pub mod opcode;
pub mod question;
pub mod rcode;
pub mod rdata;
pub mod record;
pub mod rtype;
pub mod wire;

// Re-exports for convenience
pub use class::RecordClass;
pub use edns::{Edns, EdnsOption};
pub use error::{Error, Result};
pub use header::Header;
pub use message::Message;
pub use name::Name;
pub use opcode::OpCode;
pub use question::Question;
pub use rcode::ResponseCode;
pub use rdata::RData;
pub use record::ResourceRecord;
pub use rtype::RecordType;

/// Maximum length of a DNS label (63 bytes per RFC 1035)
pub const MAX_LABEL_LENGTH: usize = 63;

/// Maximum length of a domain name (255 bytes per RFC 1035)
pub const MAX_NAME_LENGTH: usize = 255;

/// Maximum size of a UDP DNS message without EDNS0 (512 bytes per RFC 1035)
pub const MAX_UDP_MESSAGE_SIZE: usize = 512;

/// Default EDNS0 UDP payload size (4096 bytes)
pub const DEFAULT_EDNS_UDP_SIZE: u16 = 4096;

/// Maximum EDNS0 UDP payload size (65535 bytes)
pub const MAX_EDNS_UDP_SIZE: u16 = 65535;

/// DNS port (53)
pub const DNS_PORT: u16 = 53;

/// DNS over TLS port (853)
pub const DOT_PORT: u16 = 853;

/// DNS over HTTPS default port (443)
pub const DOH_PORT: u16 = 443;

/// DNS over QUIC port (853)
pub const DOQ_PORT: u16 = 853;
