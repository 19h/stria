//! # Stria DNS Zone Management
//!
//! This crate provides comprehensive DNS zone management functionality including:
//!
//! - **Zone storage**: In-memory and persistent zone data stores
//! - **Zone file parsing**: RFC 1035 master file format with directives
//! - **Zone transfers**: AXFR and IXFR for zone replication
//! - **NOTIFY handling**: RFC 1996 zone change notifications
//! - **Dynamic updates**: RFC 2136 dynamic DNS updates
//! - **Hierarchical lookup**: Zone tree for efficient zone matching
//!
//! ## Features
//!
//! - `sql` - Enable SQL-backed zone storage (SQLite, PostgreSQL, MySQL)
//! - `ldap` - Enable LDAP-backed zone storage
//! - `etcd` - Enable etcd-backed zone storage
//! - `consul` - Enable Consul-backed zone storage
//!
//! ## Example
//!
//! ```rust,ignore
//! use stria_zone::{Zone, ZoneType, ZoneStore, InMemoryZoneStore};
//! use stria_proto::{Name, RecordType};
//! use std::str::FromStr;
//!
//! // Create an in-memory zone store
//! let store = InMemoryZoneStore::new();
//!
//! // Load a zone from a file
//! let zone = Zone::from_file("example.com.zone")?;
//! store.save_zone(&zone).await?;
//!
//! // Query records
//! let records = store.get_records(
//!     &Name::from_str("www.example.com.")?,
//!     RecordType::A
//! ).await?;
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

use std::fmt;
use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, instrument, warn};

use stria_proto::class::Class;
use stria_proto::rdata::SOA;
use stria_proto::rtype::Type;
use stria_proto::{
    Header, Message, Name, OpCode, Question, RData, RecordClass, RecordType, ResourceRecord,
    ResponseCode,
};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during zone operations.
#[derive(Debug, Error)]
pub enum ZoneError {
    /// Zone not found in store.
    #[error("zone not found: {name}")]
    ZoneNotFound {
        /// The zone name that was not found.
        name: String,
    },

    /// Record not found in zone.
    #[error("record not found: {name} {rtype}")]
    RecordNotFound {
        /// The record name.
        name: String,
        /// The record type.
        rtype: String,
    },

    /// Zone already exists.
    #[error("zone already exists: {name}")]
    ZoneExists {
        /// The zone name.
        name: String,
    },

    /// Invalid zone data.
    #[error("invalid zone data: {message}")]
    InvalidZone {
        /// Description of the problem.
        message: String,
    },

    /// Zone file parse error.
    #[error("zone file parse error at line {line}: {message}")]
    ParseError {
        /// Line number where the error occurred.
        line: usize,
        /// Description of the error.
        message: String,
    },

    /// Zone transfer error.
    #[error("zone transfer error: {message}")]
    TransferError {
        /// Description of the error.
        message: String,
    },

    /// Dynamic update error.
    #[error("dynamic update error: {code:?} - {message}")]
    UpdateError {
        /// The response code for the error.
        code: ResponseCode,
        /// Description of the error.
        message: String,
    },

    /// NOTIFY processing error.
    #[error("notify error: {message}")]
    NotifyError {
        /// Description of the error.
        message: String,
    },

    /// Serial number mismatch.
    #[error("serial mismatch: expected {expected}, got {actual}")]
    SerialMismatch {
        /// Expected serial number.
        expected: u32,
        /// Actual serial number.
        actual: u32,
    },

    /// DNSSEC error.
    #[error("DNSSEC error: {message}")]
    DnssecError {
        /// Description of the error.
        message: String,
    },

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol error.
    #[error("protocol error: {0}")]
    Protocol(#[from] stria_proto::Error),

    /// Storage backend error.
    #[error("storage error: {message}")]
    StorageError {
        /// Description of the error.
        message: String,
    },

    /// Operation timed out.
    #[error("operation timed out")]
    Timeout,

    /// Operation was cancelled.
    #[error("operation cancelled")]
    Cancelled,

    /// Not authorized for this operation.
    #[error("not authorized: {message}")]
    NotAuthorized {
        /// Description of the authorization failure.
        message: String,
    },
}

impl ZoneError {
    /// Creates a new parse error.
    pub fn parse(line: usize, message: impl Into<String>) -> Self {
        Self::ParseError {
            line,
            message: message.into(),
        }
    }

    /// Creates a new invalid zone error.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidZone {
            message: message.into(),
        }
    }

    /// Creates a new transfer error.
    pub fn transfer(message: impl Into<String>) -> Self {
        Self::TransferError {
            message: message.into(),
        }
    }

    /// Creates a new storage error.
    pub fn storage(message: impl Into<String>) -> Self {
        Self::StorageError {
            message: message.into(),
        }
    }

    /// Returns the appropriate DNS response code for this error.
    pub fn response_code(&self) -> ResponseCode {
        match self {
            Self::ZoneNotFound { .. } => ResponseCode::NXDomain,
            Self::RecordNotFound { .. } => ResponseCode::NXDomain,
            Self::ZoneExists { .. } => ResponseCode::YXDomain,
            Self::InvalidZone { .. } => ResponseCode::FormErr,
            Self::ParseError { .. } => ResponseCode::FormErr,
            Self::UpdateError { code, .. } => *code,
            Self::NotAuthorized { .. } => ResponseCode::Refused,
            Self::SerialMismatch { .. } => ResponseCode::ServFail,
            _ => ResponseCode::ServFail,
        }
    }
}

/// Result type for zone operations.
pub type Result<T> = std::result::Result<T, ZoneError>;

// ============================================================================
// Zone Types
// ============================================================================

/// The type of a DNS zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ZoneType {
    /// Primary (master) zone - authoritative source of zone data.
    ///
    /// A primary zone is the original source of zone data and accepts
    /// dynamic updates. Changes are propagated to secondary zones via
    /// zone transfers.
    Primary,

    /// Secondary (slave) zone - replicated from a primary.
    ///
    /// A secondary zone receives zone data from a primary (or another
    /// secondary) via zone transfers. It provides authoritative answers
    /// but does not accept direct updates.
    Secondary,

    /// Stub zone - contains only NS records and glue.
    ///
    /// A stub zone is a partial copy of a zone that contains only the
    /// NS records and necessary glue records. Used to improve delegation
    /// performance without full zone transfers.
    Stub,

    /// Forward zone - forwards queries to specified servers.
    ///
    /// A forward zone redirects all queries for the zone to a specified
    /// set of forwarders rather than performing iterative resolution.
    Forward,

    /// Hint zone - root hints for bootstrap resolution.
    ///
    /// The hint zone (typically the root zone ".") provides initial
    /// name server addresses for iterative resolution. Usually contains
    /// the root server addresses.
    Hint,
}

impl ZoneType {
    /// Returns true if this zone type is authoritative.
    #[inline]
    pub const fn is_authoritative(&self) -> bool {
        matches!(self, Self::Primary | Self::Secondary)
    }

    /// Returns true if this zone accepts dynamic updates.
    #[inline]
    pub const fn accepts_updates(&self) -> bool {
        matches!(self, Self::Primary)
    }

    /// Returns true if this zone participates in zone transfers.
    #[inline]
    pub const fn supports_transfer(&self) -> bool {
        matches!(self, Self::Primary | Self::Secondary)
    }

    /// Returns the string name of this zone type.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
            Self::Stub => "stub",
            Self::Forward => "forward",
            Self::Hint => "hint",
        }
    }
}

impl fmt::Display for ZoneType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Default for ZoneType {
    fn default() -> Self {
        Self::Primary
    }
}

// ============================================================================
// Zone Class
// ============================================================================

/// DNS class for a zone, wrapping `stria_proto::Class`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ZoneClass(pub Class);

impl ZoneClass {
    /// Internet class (IN) - the most common class.
    pub const IN: Self = Self(Class::Known(RecordClass::IN));

    /// Chaos class (CH) - used for server metadata queries.
    pub const CH: Self = Self(Class::Known(RecordClass::CH));

    /// Hesiod class (HS) - MIT Athena naming system.
    pub const HS: Self = Self(Class::Known(RecordClass::HS));

    /// Returns true if this is the Internet class.
    #[inline]
    pub fn is_internet(&self) -> bool {
        self.0.is_internet()
    }

    /// Returns the inner Class value.
    #[inline]
    pub const fn inner(&self) -> Class {
        self.0
    }

    /// Returns the numeric class value.
    #[inline]
    pub fn to_u16(&self) -> u16 {
        self.0.to_u16()
    }
}

impl Default for ZoneClass {
    fn default() -> Self {
        Self::IN
    }
}

impl From<Class> for ZoneClass {
    fn from(c: Class) -> Self {
        Self(c)
    }
}

impl From<RecordClass> for ZoneClass {
    fn from(c: RecordClass) -> Self {
        Self(Class::Known(c))
    }
}

impl fmt::Display for ZoneClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ============================================================================
// RRset - Resource Record Set
// ============================================================================

/// A set of resource records with the same name, type, and class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RRset {
    /// The owner name of all records in this set.
    name: Name,
    /// The record type.
    rtype: RecordType,
    /// The record class.
    rclass: RecordClass,
    /// TTL for the set (all records should have the same TTL per RFC 2181).
    ttl: u32,
    /// The resource records in this set.
    records: Vec<ResourceRecord>,
}

impl RRset {
    /// Creates a new empty RRset.
    pub fn new(name: Name, rtype: RecordType, rclass: RecordClass, ttl: u32) -> Self {
        Self {
            name,
            rtype,
            rclass,
            ttl,
            records: Vec::new(),
        }
    }

    /// Creates an RRset from a single record.
    pub fn from_record(record: ResourceRecord) -> Self {
        let rtype = record.record_type().unwrap_or(RecordType::A);
        let rclass = record.record_class().unwrap_or(RecordClass::IN);
        Self {
            name: record.name().clone(),
            rtype,
            rclass,
            ttl: record.ttl(),
            records: vec![record],
        }
    }

    /// Returns the owner name.
    #[inline]
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Returns the record type.
    #[inline]
    pub const fn rtype(&self) -> RecordType {
        self.rtype
    }

    /// Returns the record class.
    #[inline]
    pub const fn rclass(&self) -> RecordClass {
        self.rclass
    }

    /// Returns the TTL.
    #[inline]
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns the records in this set.
    #[inline]
    pub fn records(&self) -> &[ResourceRecord] {
        &self.records
    }

    /// Returns the number of records.
    #[inline]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns true if this set is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Adds a record to this set.
    ///
    /// Returns false if the record doesn't match the set's name/type/class.
    pub fn add(&mut self, record: ResourceRecord) -> bool {
        if record.name() != &self.name {
            return false;
        }
        if record.record_type() != Some(self.rtype) {
            return false;
        }
        if record.record_class() != Some(self.rclass) {
            return false;
        }
        self.records.push(record);
        true
    }

    /// Removes duplicate records from the set.
    pub fn deduplicate(&mut self) {
        let mut seen = HashSet::new();
        self.records.retain(|r| {
            let key = r.to_wire();
            seen.insert(key)
        });
    }
}

// ============================================================================
// Zone Node - Records at a single owner name
// ============================================================================

/// Records stored at a single owner name within a zone.
///
/// This represents all resource records sharing the same owner name,
/// organized by record type for efficient lookup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZoneNode {
    /// Records organized by type.
    rrsets: HashMap<RecordType, RRset>,
    /// RRSIG records covering each type.
    signatures: HashMap<RecordType, Vec<ResourceRecord>>,
}

impl ZoneNode {
    /// Creates a new empty zone node.
    pub fn new() -> Self {
        Self {
            rrsets: HashMap::new(),
            signatures: HashMap::new(),
        }
    }

    /// Adds a record to this node.
    pub fn add_record(&mut self, record: ResourceRecord) {
        let rtype = record.record_type().unwrap_or(RecordType::A);

        // RRSIG records are stored separately
        if rtype == RecordType::RRSIG {
            if let RData::RRSIG(rrsig) = record.rdata() {
                let covered = RecordType::try_from(rrsig.type_covered()).ok();
                if let Some(covered_type) = covered {
                    self.signatures
                        .entry(covered_type)
                        .or_default()
                        .push(record);
                }
            }
            return;
        }

        match self.rrsets.entry(rtype) {
            hashbrown::hash_map::Entry::Occupied(mut e) => {
                e.get_mut().add(record);
            }
            hashbrown::hash_map::Entry::Vacant(e) => {
                e.insert(RRset::from_record(record));
            }
        }
    }

    /// Gets records of a specific type.
    pub fn get_rrset(&self, rtype: RecordType) -> Option<&RRset> {
        self.rrsets.get(&rtype)
    }

    /// Gets all record types present at this node.
    pub fn types(&self) -> impl Iterator<Item = RecordType> + '_ {
        self.rrsets.keys().copied()
    }

    /// Gets all RRsets at this node.
    pub fn rrsets(&self) -> impl Iterator<Item = &RRset> {
        self.rrsets.values()
    }

    /// Gets RRSIG records covering a specific type.
    pub fn get_signatures(&self, rtype: RecordType) -> Option<&Vec<ResourceRecord>> {
        self.signatures.get(&rtype)
    }

    /// Returns true if this node has any records.
    pub fn is_empty(&self) -> bool {
        self.rrsets.is_empty()
    }

    /// Removes records of a specific type.
    pub fn remove_rrset(&mut self, rtype: RecordType) -> Option<RRset> {
        self.signatures.remove(&rtype);
        self.rrsets.remove(&rtype)
    }

    /// Removes a specific record.
    pub fn remove_record(&mut self, record: &ResourceRecord) -> bool {
        let rtype = record.record_type().unwrap_or(RecordType::A);

        if let Some(rrset) = self.rrsets.get_mut(&rtype) {
            let initial_len = rrset.records.len();
            rrset.records.retain(|r| r != record);
            let removed = rrset.records.len() < initial_len;

            if rrset.is_empty() {
                self.rrsets.remove(&rtype);
                self.signatures.remove(&rtype);
            }

            return removed;
        }

        false
    }
}

// ============================================================================
// Zone Structure
// ============================================================================

/// DNSSEC key information for a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecKeys {
    /// Key Signing Keys (KSK).
    pub ksks: Vec<ResourceRecord>,
    /// Zone Signing Keys (ZSK).
    pub zsks: Vec<ResourceRecord>,
    /// NSEC3 parameters if using NSEC3.
    pub nsec3param: Option<ResourceRecord>,
}

impl DnssecKeys {
    /// Creates empty DNSSEC key information.
    pub fn new() -> Self {
        Self {
            ksks: Vec::new(),
            zsks: Vec::new(),
            nsec3param: None,
        }
    }

    /// Returns true if any keys are present.
    pub fn has_keys(&self) -> bool {
        !self.ksks.is_empty() || !self.zsks.is_empty()
    }
}

impl Default for DnssecKeys {
    fn default() -> Self {
        Self::new()
    }
}

/// A DNS zone containing all records for a domain.
///
/// The zone is the fundamental unit of DNS data management. It represents
/// a contiguous portion of the domain name space for which a server is
/// authoritative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    /// The zone apex (origin name).
    name: Name,
    /// The type of zone.
    zone_type: ZoneType,
    /// The zone class.
    zone_class: ZoneClass,
    /// The SOA record for this zone.
    soa: SOA,
    /// The current serial number.
    serial: u32,
    /// Default TTL for records without explicit TTL.
    default_ttl: u32,
    /// Records organized by owner name.
    nodes: HashMap<Name, ZoneNode>,
    /// NS records at the apex.
    ns_set: Vec<ResourceRecord>,
    /// DNSSEC keys if the zone is signed.
    dnssec_keys: Option<DnssecKeys>,
    /// When the zone was last modified.
    last_modified: DateTime<Utc>,
    /// Zone metadata.
    metadata: ZoneMetadata,
}

/// Zone metadata for administrative purposes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZoneMetadata {
    /// Primary server addresses (for secondary zones).
    pub primaries: Vec<SocketAddr>,
    /// Allow transfer to these addresses.
    pub allow_transfer: Vec<String>,
    /// Allow updates from these addresses.
    pub allow_update: Vec<String>,
    /// Allow notify from these addresses.
    pub allow_notify: Vec<String>,
    /// TSIG key name for transfers.
    pub tsig_key: Option<String>,
    /// Zone file path if loaded from file.
    pub file_path: Option<String>,
    /// Whether automatic NOTIFY is enabled.
    pub notify_enabled: bool,
    /// Custom refresh interval override.
    pub refresh_override: Option<u32>,
}

impl Zone {
    /// Creates a new zone with the given apex name and SOA record.
    pub fn new(name: Name, zone_type: ZoneType, soa: SOA) -> Self {
        let serial = soa.serial();
        Self {
            name,
            zone_type,
            zone_class: ZoneClass::IN,
            soa,
            serial,
            default_ttl: 3600,
            nodes: HashMap::new(),
            ns_set: Vec::new(),
            dnssec_keys: None,
            last_modified: Utc::now(),
            metadata: ZoneMetadata::default(),
        }
    }

    /// Creates a new primary zone.
    pub fn primary(name: Name, soa: SOA) -> Self {
        Self::new(name, ZoneType::Primary, soa)
    }

    /// Creates a new secondary zone.
    pub fn secondary(name: Name, soa: SOA, primaries: Vec<SocketAddr>) -> Self {
        let mut zone = Self::new(name, ZoneType::Secondary, soa);
        zone.metadata.primaries = primaries;
        zone
    }

    /// Returns the zone apex name.
    #[inline]
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Returns the zone type.
    #[inline]
    pub const fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    /// Returns the zone class.
    #[inline]
    pub const fn zone_class(&self) -> ZoneClass {
        self.zone_class
    }

    /// Returns the SOA record.
    #[inline]
    pub fn soa(&self) -> &SOA {
        &self.soa
    }

    /// Returns the current serial number.
    #[inline]
    pub const fn serial(&self) -> u32 {
        self.serial
    }

    /// Returns the default TTL.
    #[inline]
    pub const fn default_ttl(&self) -> u32 {
        self.default_ttl
    }

    /// Sets the default TTL.
    pub fn set_default_ttl(&mut self, ttl: u32) {
        self.default_ttl = ttl;
    }

    /// Returns the NS records at the apex.
    #[inline]
    pub fn ns_set(&self) -> &[ResourceRecord] {
        &self.ns_set
    }

    /// Returns DNSSEC keys if present.
    #[inline]
    pub fn dnssec_keys(&self) -> Option<&DnssecKeys> {
        self.dnssec_keys.as_ref()
    }

    /// Returns zone metadata.
    #[inline]
    pub fn metadata(&self) -> &ZoneMetadata {
        &self.metadata
    }

    /// Returns mutable zone metadata.
    #[inline]
    pub fn metadata_mut(&mut self) -> &mut ZoneMetadata {
        &mut self.metadata
    }

    /// Returns when the zone was last modified.
    #[inline]
    pub fn last_modified(&self) -> DateTime<Utc> {
        self.last_modified
    }

    /// Returns true if this zone is authoritative.
    #[inline]
    pub fn is_authoritative(&self) -> bool {
        self.zone_type.is_authoritative()
    }

    /// Returns true if the zone is DNSSEC signed.
    pub fn is_signed(&self) -> bool {
        self.dnssec_keys
            .as_ref()
            .map(|k| k.has_keys())
            .unwrap_or(false)
    }

    /// Returns true if the given name is within this zone.
    pub fn contains_name(&self, name: &Name) -> bool {
        name.is_subdomain_of(&self.name)
    }

    /// Adds a record to the zone.
    pub fn add_record(&mut self, record: ResourceRecord) {
        let owner = record.name().clone();
        let rtype = record.record_type();

        // Update NS set if this is an NS record at the apex
        if rtype == Some(RecordType::NS) && &owner == &self.name {
            self.ns_set.push(record.clone());
        }

        // Update DNSSEC keys if this is a DNSKEY
        if rtype == Some(RecordType::DNSKEY) && &owner == &self.name {
            let keys = self.dnssec_keys.get_or_insert_with(DnssecKeys::new);
            if let RData::DNSKEY(dnskey) = record.rdata() {
                if dnskey.is_sep() {
                    keys.ksks.push(record.clone());
                } else {
                    keys.zsks.push(record.clone());
                }
            }
        }

        // Update NSEC3PARAM if present
        if rtype == Some(RecordType::NSEC3PARAM) && &owner == &self.name {
            let keys = self.dnssec_keys.get_or_insert_with(DnssecKeys::new);
            keys.nsec3param = Some(record.clone());
        }

        // Add to the appropriate node
        let node = self.nodes.entry(owner).or_insert_with(ZoneNode::new);
        node.add_record(record);

        self.last_modified = Utc::now();
    }

    /// Gets records at a specific name and type.
    pub fn get_records(&self, name: &Name, rtype: RecordType) -> Option<&RRset> {
        self.nodes.get(name).and_then(|node| node.get_rrset(rtype))
    }

    /// Gets all records at a specific name.
    pub fn get_node(&self, name: &Name) -> Option<&ZoneNode> {
        self.nodes.get(name)
    }

    /// Removes records at a specific name and type.
    pub fn remove_records(&mut self, name: &Name, rtype: RecordType) -> Option<RRset> {
        self.last_modified = Utc::now();

        // Update NS set if removing apex NS
        if rtype == RecordType::NS && name == &self.name {
            self.ns_set.clear();
        }

        self.nodes
            .get_mut(name)
            .and_then(|node| node.remove_rrset(rtype))
    }

    /// Updates the serial number.
    ///
    /// The new serial should be greater than the current one per RFC 1982
    /// serial number arithmetic.
    pub fn update_serial(&mut self, new_serial: u32) {
        self.serial = new_serial;
        self.soa = SOA::new(
            self.soa.mname().clone(),
            self.soa.rname().clone(),
            new_serial,
            self.soa.refresh(),
            self.soa.retry(),
            self.soa.expire(),
            self.soa.minimum(),
        );
        self.last_modified = Utc::now();
    }

    /// Increments the serial number using YYYYMMDDNN format if possible.
    pub fn increment_serial(&mut self) {
        let now = Utc::now();
        let date_serial = (now.format("%Y%m%d").to_string().parse::<u32>().unwrap_or(0)) * 100;

        let new_serial = if self.serial < date_serial {
            date_serial + 1
        } else {
            self.serial.wrapping_add(1)
        };

        self.update_serial(new_serial);
    }

    /// Returns an iterator over all records in the zone.
    pub fn iter_records(&self) -> impl Iterator<Item = &ResourceRecord> {
        self.nodes
            .values()
            .flat_map(|node| node.rrsets())
            .flat_map(|rrset| rrset.records())
    }

    /// Returns the number of unique owner names in the zone.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the total number of resource records in the zone.
    pub fn record_count(&self) -> usize {
        self.nodes
            .values()
            .flat_map(|node| node.rrsets())
            .map(|rrset| rrset.len())
            .sum()
    }

    /// Validates the zone for consistency.
    pub fn validate(&self) -> Result<()> {
        // Must have SOA at apex
        if self.get_records(&self.name, RecordType::SOA).is_none() {
            return Err(ZoneError::invalid("zone missing SOA record at apex"));
        }

        // Must have at least one NS at apex
        if self.ns_set.is_empty() {
            return Err(ZoneError::invalid("zone missing NS records at apex"));
        }

        // CNAME must be alone (no other records at same name)
        for (name, node) in &self.nodes {
            if node.get_rrset(RecordType::CNAME).is_some() {
                let other_types: Vec<_> = node
                    .types()
                    .filter(|t| *t != RecordType::CNAME && *t != RecordType::RRSIG)
                    .collect();
                if !other_types.is_empty() {
                    return Err(ZoneError::invalid(format!(
                        "CNAME at {} has other records: {:?}",
                        name, other_types
                    )));
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Zone Tree - Hierarchical Zone Lookup
// ============================================================================

/// A hierarchical structure for efficient zone lookup.
///
/// The zone tree organizes zones by their domain name hierarchy,
/// allowing efficient lookup of the most specific zone for any query name.
#[derive(Debug)]
pub struct ZoneTree {
    /// Zones indexed by their apex name.
    zones: DashMap<Name, Arc<ArcSwap<Zone>>>,
}

impl ZoneTree {
    /// Creates a new empty zone tree.
    pub fn new() -> Self {
        Self {
            zones: DashMap::new(),
        }
    }

    /// Inserts a zone into the tree.
    pub fn insert(&self, zone: Zone) {
        let name = zone.name().clone();
        self.zones
            .insert(name, Arc::new(ArcSwap::from_pointee(zone)));
    }

    /// Removes a zone from the tree.
    pub fn remove(&self, name: &Name) -> Option<Zone> {
        self.zones.remove(name).map(|(_, arc)| {
            // Get the zone out of the ArcSwap
            // The ArcSwap contains Arc<Zone>, so we load and clone
            let guard = arc.load();
            (**guard).clone()
        })
    }

    /// Gets a zone by its exact name.
    pub fn get(&self, name: &Name) -> Option<arc_swap::Guard<Arc<Zone>>> {
        self.zones.get(name).map(|entry| entry.value().load())
    }

    /// Finds the zone that is authoritative for a given query name.
    ///
    /// Returns the most specific (longest matching) zone.
    pub fn find_zone(&self, name: &Name) -> Option<arc_swap::Guard<Arc<Zone>>> {
        // Try exact match first
        if let Some(entry) = self.zones.get(name) {
            return Some(entry.value().load());
        }

        // Walk up the tree to find the closest enclosing zone
        let mut current = name.clone();
        while let Some(parent) = current.parent() {
            if let Some(entry) = self.zones.get(&parent) {
                return Some(entry.value().load());
            }
            current = parent;
        }

        // Try root zone
        self.zones.get(&Name::root()).map(|e| e.value().load())
    }

    /// Finds the closest encloser for a name.
    ///
    /// The closest encloser is the longest existing ancestor of the query name
    /// within a zone. This is important for NSEC/NSEC3 denial of existence.
    pub fn find_closest_encloser(&self, name: &Name) -> Option<(arc_swap::Guard<Arc<Zone>>, Name)> {
        let zone = self.find_zone(name)?;
        let zone_apex = zone.name().clone();

        // Find the closest existing name within the zone
        let mut current = name.clone();
        while current.is_subdomain_of(&zone_apex) {
            if zone.get_node(&current).is_some() {
                return Some((zone, current));
            }
            if let Some(parent) = current.parent() {
                current = parent;
            } else {
                break;
            }
        }

        // Fall back to zone apex
        Some((zone, zone_apex))
    }

    /// Updates a zone in-place.
    pub fn update<F>(&self, name: &Name, f: F) -> bool
    where
        F: FnOnce(&mut Zone),
    {
        if let Some(entry) = self.zones.get(name) {
            let guard = entry.value().load();
            let mut zone: Zone = (**guard).clone();
            f(&mut zone);
            entry.value().store(Arc::new(zone));
            true
        } else {
            false
        }
    }

    /// Returns the number of zones in the tree.
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    /// Returns true if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// Returns an iterator over all zone names.
    pub fn zone_names(&self) -> Vec<Name> {
        self.zones.iter().map(|e| e.key().clone()).collect()
    }
}

impl Default for ZoneTree {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Zone Store Trait
// ============================================================================

/// A storage backend for DNS zones.
///
/// This trait defines the interface for zone storage backends,
/// allowing different implementations (in-memory, SQL, LDAP, etc.).
#[async_trait]
pub trait ZoneStore: Send + Sync {
    /// Loads a zone from storage.
    async fn load_zone(&self, name: &Name) -> Result<Zone>;

    /// Saves a zone to storage.
    async fn save_zone(&self, zone: &Zone) -> Result<()>;

    /// Deletes a zone from storage.
    async fn delete_zone(&self, name: &Name) -> Result<()>;

    /// Lists all zone names in storage.
    async fn list_zones(&self) -> Result<Vec<Name>>;

    /// Checks if a zone exists.
    async fn zone_exists(&self, name: &Name) -> Result<bool>;

    /// Gets records at a specific name and type.
    async fn get_records(
        &self,
        zone: &Name,
        name: &Name,
        rtype: RecordType,
    ) -> Result<Vec<ResourceRecord>>;

    /// Gets all records at a specific name.
    async fn get_all_records(&self, zone: &Name, name: &Name) -> Result<Vec<ResourceRecord>>;

    /// Adds a record to a zone.
    async fn add_record(&self, zone: &Name, record: ResourceRecord) -> Result<()>;

    /// Deletes a record from a zone.
    async fn delete_record(&self, zone: &Name, record: &ResourceRecord) -> Result<()>;

    /// Deletes all records at a name/type.
    async fn delete_rrset(&self, zone: &Name, name: &Name, rtype: RecordType) -> Result<()>;

    /// Gets the SOA record for a zone.
    async fn get_soa(&self, zone: &Name) -> Result<SOA>;

    /// Updates the zone serial number.
    async fn update_serial(&self, zone: &Name, new_serial: u32) -> Result<()>;

    /// Begins a transaction for atomic updates.
    async fn begin_transaction(&self, zone: &Name) -> Result<Box<dyn ZoneTransaction>>;
}

/// A transaction for atomic zone updates.
#[async_trait]
pub trait ZoneTransaction: Send {
    /// Adds a record within the transaction.
    async fn add_record(&mut self, record: ResourceRecord) -> Result<()>;

    /// Deletes a record within the transaction.
    async fn delete_record(&mut self, record: &ResourceRecord) -> Result<()>;

    /// Commits the transaction.
    async fn commit(self: Box<Self>) -> Result<()>;

    /// Rolls back the transaction.
    async fn rollback(self: Box<Self>) -> Result<()>;
}

// ============================================================================
// In-Memory Zone Store
// ============================================================================

/// An in-memory zone storage implementation using DashMap.
///
/// This provides a thread-safe, concurrent zone store suitable for
/// high-performance DNS servers. Zones are stored entirely in memory.
#[derive(Debug)]
pub struct InMemoryZoneStore {
    /// Zones indexed by their apex name.
    zones: DashMap<Name, Zone>,
}

impl InMemoryZoneStore {
    /// Creates a new empty in-memory zone store.
    pub fn new() -> Self {
        Self {
            zones: DashMap::new(),
        }
    }

    /// Creates a store with initial zones.
    pub fn with_zones(zones: impl IntoIterator<Item = Zone>) -> Self {
        let store = Self::new();
        for zone in zones {
            store.zones.insert(zone.name().clone(), zone);
        }
        store
    }

    /// Returns a reference to the internal zone map.
    pub fn inner(&self) -> &DashMap<Name, Zone> {
        &self.zones
    }
}

impl Default for InMemoryZoneStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ZoneStore for InMemoryZoneStore {
    async fn load_zone(&self, name: &Name) -> Result<Zone> {
        self.zones
            .get(name)
            .map(|z| z.clone())
            .ok_or_else(|| ZoneError::ZoneNotFound {
                name: name.to_string(),
            })
    }

    async fn save_zone(&self, zone: &Zone) -> Result<()> {
        self.zones.insert(zone.name().clone(), zone.clone());
        Ok(())
    }

    async fn delete_zone(&self, name: &Name) -> Result<()> {
        self.zones
            .remove(name)
            .ok_or_else(|| ZoneError::ZoneNotFound {
                name: name.to_string(),
            })?;
        Ok(())
    }

    async fn list_zones(&self) -> Result<Vec<Name>> {
        Ok(self.zones.iter().map(|e| e.key().clone()).collect())
    }

    async fn zone_exists(&self, name: &Name) -> Result<bool> {
        Ok(self.zones.contains_key(name))
    }

    async fn get_records(
        &self,
        zone: &Name,
        name: &Name,
        rtype: RecordType,
    ) -> Result<Vec<ResourceRecord>> {
        let zone = self
            .zones
            .get(zone)
            .ok_or_else(|| ZoneError::ZoneNotFound {
                name: zone.to_string(),
            })?;

        Ok(zone
            .get_records(name, rtype)
            .map(|rrset| rrset.records().to_vec())
            .unwrap_or_default())
    }

    async fn get_all_records(&self, zone_name: &Name, name: &Name) -> Result<Vec<ResourceRecord>> {
        let zone = self
            .zones
            .get(zone_name)
            .ok_or_else(|| ZoneError::ZoneNotFound {
                name: zone_name.to_string(),
            })?;

        let records = zone
            .get_node(name)
            .map(|node| {
                node.rrsets()
                    .flat_map(|rrset| rrset.records().iter().cloned())
                    .collect()
            })
            .unwrap_or_default();

        Ok(records)
    }

    async fn add_record(&self, zone_name: &Name, record: ResourceRecord) -> Result<()> {
        let mut zone = self
            .zones
            .get_mut(zone_name)
            .ok_or_else(|| ZoneError::ZoneNotFound {
                name: zone_name.to_string(),
            })?;

        zone.add_record(record);
        Ok(())
    }

    async fn delete_record(&self, zone_name: &Name, record: &ResourceRecord) -> Result<()> {
        let mut zone = self
            .zones
            .get_mut(zone_name)
            .ok_or_else(|| ZoneError::ZoneNotFound {
                name: zone_name.to_string(),
            })?;

        if let Some(node) = zone.nodes.get_mut(record.name()) {
            node.remove_record(record);
        }

        Ok(())
    }

    async fn delete_rrset(&self, zone_name: &Name, name: &Name, rtype: RecordType) -> Result<()> {
        let mut zone = self
            .zones
            .get_mut(zone_name)
            .ok_or_else(|| ZoneError::ZoneNotFound {
                name: zone_name.to_string(),
            })?;

        zone.remove_records(name, rtype);
        Ok(())
    }

    async fn get_soa(&self, zone_name: &Name) -> Result<SOA> {
        let zone = self
            .zones
            .get(zone_name)
            .ok_or_else(|| ZoneError::ZoneNotFound {
                name: zone_name.to_string(),
            })?;

        Ok(zone.soa().clone())
    }

    async fn update_serial(&self, zone_name: &Name, new_serial: u32) -> Result<()> {
        let mut zone = self
            .zones
            .get_mut(zone_name)
            .ok_or_else(|| ZoneError::ZoneNotFound {
                name: zone_name.to_string(),
            })?;

        zone.update_serial(new_serial);
        Ok(())
    }

    async fn begin_transaction(&self, zone: &Name) -> Result<Box<dyn ZoneTransaction>> {
        if !self.zones.contains_key(zone) {
            return Err(ZoneError::ZoneNotFound {
                name: zone.to_string(),
            });
        }

        Ok(Box::new(InMemoryTransaction {
            zone_name: zone.clone(),
            adds: Vec::new(),
            deletes: Vec::new(),
        }))
    }
}

/// Transaction for in-memory zone store.
struct InMemoryTransaction {
    #[allow(dead_code)]
    zone_name: Name,
    adds: Vec<ResourceRecord>,
    deletes: Vec<ResourceRecord>,
}

#[async_trait]
impl ZoneTransaction for InMemoryTransaction {
    async fn add_record(&mut self, record: ResourceRecord) -> Result<()> {
        self.adds.push(record);
        Ok(())
    }

    async fn delete_record(&mut self, record: &ResourceRecord) -> Result<()> {
        self.deletes.push(record.clone());
        Ok(())
    }

    async fn commit(self: Box<Self>) -> Result<()> {
        // In a real implementation, this would apply changes atomically
        // For now, this is a placeholder that doesn't actually modify the store
        // The actual store would need to be passed in somehow
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<()> {
        // Just drop the pending changes
        Ok(())
    }
}

// ============================================================================
// Zone File Parser
// ============================================================================

/// Parser state for zone file processing.
#[derive(Debug)]
struct ParserState {
    /// Current origin (from $ORIGIN directive).
    origin: Name,
    /// Current default TTL (from $TTL directive).
    default_ttl: u32,
    /// Last owner name seen (for continuation lines).
    last_owner: Option<Name>,
    /// Current line number for error reporting.
    line_number: usize,
    /// Include depth for nested $INCLUDE.
    include_depth: usize,
}

impl ParserState {
    fn new(origin: Name) -> Self {
        Self {
            origin,
            default_ttl: 3600,
            last_owner: None,
            line_number: 0,
            include_depth: 0,
        }
    }
}

/// Parser for RFC 1035 master file format zone files.
///
/// Supports the following directives:
/// - `$ORIGIN` - Sets the origin for relative names
/// - `$TTL` - Sets the default TTL
/// - `$INCLUDE` - Includes another zone file
///
/// Also handles:
/// - `@` as shorthand for the current origin
/// - Relative names (automatically appended to origin)
/// - Parentheses for multi-line records
/// - Comments starting with `;`
#[derive(Debug)]
pub struct ZoneFileParser {
    /// Maximum allowed include depth.
    max_include_depth: usize,
}

impl ZoneFileParser {
    /// Creates a new zone file parser.
    pub fn new() -> Self {
        Self {
            max_include_depth: 10,
        }
    }

    /// Sets the maximum include depth.
    pub fn max_include_depth(mut self, depth: usize) -> Self {
        self.max_include_depth = depth;
        self
    }

    /// Parses a zone file from a reader.
    pub fn parse<R: Read>(&self, reader: R, origin: Name) -> Result<Zone> {
        let mut state = ParserState::new(origin.clone());
        let mut records: Vec<ResourceRecord> = Vec::new();
        let mut soa: Option<SOA> = None;

        let reader = BufReader::new(reader);
        let mut lines = reader.lines();
        let mut in_parens = false;
        let mut accumulated = String::new();

        while let Some(line_result) = lines.next() {
            let line = line_result.map_err(ZoneError::Io)?;
            state.line_number += 1;

            // Handle multi-line with parentheses
            let line = line.trim();

            // Skip empty lines and pure comments
            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            // Remove inline comments
            let line = line.split(';').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            // Track parentheses for multi-line records
            let open_count = line.chars().filter(|&c| c == '(').count();
            let close_count = line.chars().filter(|&c| c == ')').count();

            if in_parens {
                accumulated.push(' ');
                accumulated.push_str(line);
                if close_count > open_count {
                    in_parens = false;
                    let full_line = accumulated.replace(['(', ')'], " ");
                    accumulated.clear();
                    self.parse_line(&full_line, &mut state, &mut records, &mut soa)?;
                }
            } else if open_count > close_count {
                in_parens = true;
                accumulated = line.to_string();
            } else {
                let line = line.replace(['(', ')'], " ");
                self.parse_line(&line, &mut state, &mut records, &mut soa)?;
            }
        }

        // Build the zone
        let soa = soa.ok_or_else(|| ZoneError::invalid("zone file missing SOA record"))?;
        let mut zone = Zone::new(origin, ZoneType::Primary, soa);
        zone.default_ttl = state.default_ttl;

        for record in records {
            zone.add_record(record);
        }

        zone.validate()?;
        Ok(zone)
    }

    /// Parses a single line from the zone file.
    fn parse_line(
        &self,
        line: &str,
        state: &mut ParserState,
        records: &mut Vec<ResourceRecord>,
        soa: &mut Option<SOA>,
    ) -> Result<()> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        }

        // Handle directives
        if line.starts_with('$') {
            return self.parse_directive(line, state);
        }

        // Parse resource record
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            return Ok(());
        }

        let (owner, tokens) = self.parse_owner(&tokens, state)?;
        let (ttl, tokens) = self.parse_ttl(&tokens, state.default_ttl)?;
        let (class, tokens) = self.parse_class(&tokens)?;
        let (rtype, tokens) = self.parse_rtype(&tokens, state)?;

        let rdata = self.parse_rdata(rtype, &tokens, &state.origin, state)?;

        let record = ResourceRecord::new(
            owner.clone(),
            Type::Known(rtype),
            Class::Known(class),
            ttl,
            rdata,
        );

        // Capture SOA record
        if rtype == RecordType::SOA && &owner == &state.origin {
            if let RData::SOA(soa_data) = record.rdata() {
                *soa = Some(soa_data.clone());
            }
        }

        state.last_owner = Some(owner);
        records.push(record);

        Ok(())
    }

    /// Parses a directive line.
    fn parse_directive(&self, line: &str, state: &mut ParserState) -> Result<()> {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let directive = tokens.first().unwrap_or(&"");

        match directive.to_uppercase().as_str() {
            "$ORIGIN" => {
                let name = tokens.get(1).ok_or_else(|| {
                    ZoneError::parse(state.line_number, "$ORIGIN requires a domain name")
                })?;
                state.origin = self.make_absolute(name, &state.origin, state)?;
            }
            "$TTL" => {
                let ttl_str = tokens
                    .get(1)
                    .ok_or_else(|| ZoneError::parse(state.line_number, "$TTL requires a value"))?;
                state.default_ttl = self.parse_ttl_value(ttl_str, state)?;
            }
            "$INCLUDE" => {
                if state.include_depth >= self.max_include_depth {
                    return Err(ZoneError::parse(
                        state.line_number,
                        "maximum $INCLUDE depth exceeded",
                    ));
                }
                // In a real implementation, we would read and parse the included file
                warn!(
                    line = state.line_number,
                    "$INCLUDE directive not fully implemented"
                );
            }
            _ => {
                return Err(ZoneError::parse(
                    state.line_number,
                    format!("unknown directive: {}", directive),
                ));
            }
        }

        Ok(())
    }

    /// Parses the owner name from the token list.
    fn parse_owner<'a>(
        &self,
        tokens: &'a [&'a str],
        state: &ParserState,
    ) -> Result<(Name, &'a [&'a str])> {
        if tokens.is_empty() {
            return Err(ZoneError::parse(state.line_number, "empty record line"));
        }

        let first = tokens[0];

        // Check if first token looks like a name or TTL/class/type
        if first
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
            || first.eq_ignore_ascii_case("IN")
            || first.eq_ignore_ascii_case("CH")
            || first.eq_ignore_ascii_case("HS")
            || RecordType::try_from(
                first.parse::<u16>().unwrap_or_else(|_| {
                    self.rtype_from_str(first).map(|t| t.to_u16()).unwrap_or(0)
                }),
            )
            .is_ok()
        {
            // No owner name - use last owner or origin
            let owner = state
                .last_owner
                .clone()
                .unwrap_or_else(|| state.origin.clone());
            return Ok((owner, tokens));
        }

        let owner = self.make_absolute(first, &state.origin, state)?;
        Ok((owner, &tokens[1..]))
    }

    /// Parses the TTL from the token list.
    fn parse_ttl<'a>(&self, tokens: &'a [&'a str], default: u32) -> Result<(u32, &'a [&'a str])> {
        if tokens.is_empty() {
            return Ok((default, tokens));
        }

        let first = tokens[0];

        // Check if this looks like a TTL (numeric or time format like 1h, 1d)
        if first
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            // Try to parse as TTL
            if let Ok(ttl) = self.parse_ttl_value_silent(first) {
                // Make sure it's not a record type number
                if RecordType::try_from(ttl as u16).is_err() || ttl > 65535 {
                    return Ok((ttl, &tokens[1..]));
                }
            }
        }

        Ok((default, tokens))
    }

    /// Parses TTL value supporting time suffixes (s, m, h, d, w).
    fn parse_ttl_value(&self, s: &str, state: &ParserState) -> Result<u32> {
        self.parse_ttl_value_silent(s)
            .map_err(|_| ZoneError::parse(state.line_number, format!("invalid TTL: {}", s)))
    }

    fn parse_ttl_value_silent(&self, s: &str) -> std::result::Result<u32, ()> {
        let s = s.to_lowercase();
        let mut total: u32 = 0;
        let mut current: u32 = 0;

        for c in s.chars() {
            match c {
                '0'..='9' => {
                    current = current
                        .checked_mul(10)
                        .and_then(|v| v.checked_add(c.to_digit(10).unwrap()))
                        .ok_or(())?;
                }
                's' => {
                    total = total.checked_add(current).ok_or(())?;
                    current = 0;
                }
                'm' => {
                    total = total
                        .checked_add(current.checked_mul(60).ok_or(())?)
                        .ok_or(())?;
                    current = 0;
                }
                'h' => {
                    total = total
                        .checked_add(current.checked_mul(3600).ok_or(())?)
                        .ok_or(())?;
                    current = 0;
                }
                'd' => {
                    total = total
                        .checked_add(current.checked_mul(86400).ok_or(())?)
                        .ok_or(())?;
                    current = 0;
                }
                'w' => {
                    total = total
                        .checked_add(current.checked_mul(604800).ok_or(())?)
                        .ok_or(())?;
                    current = 0;
                }
                _ => return Err(()),
            }
        }

        Ok(total.checked_add(current).ok_or(())?)
    }

    /// Parses the class from the token list.
    fn parse_class<'a>(&self, tokens: &'a [&'a str]) -> Result<(RecordClass, &'a [&'a str])> {
        if tokens.is_empty() {
            return Ok((RecordClass::IN, tokens));
        }

        let first = tokens[0].to_uppercase();
        match first.as_str() {
            "IN" => Ok((RecordClass::IN, &tokens[1..])),
            "CH" | "CHAOS" => Ok((RecordClass::CH, &tokens[1..])),
            "HS" | "HESIOD" => Ok((RecordClass::HS, &tokens[1..])),
            _ => Ok((RecordClass::IN, tokens)), // Default to IN
        }
    }

    /// Parses the record type from the token list.
    fn parse_rtype<'a>(
        &self,
        tokens: &'a [&'a str],
        state: &ParserState,
    ) -> Result<(RecordType, &'a [&'a str])> {
        if tokens.is_empty() {
            return Err(ZoneError::parse(state.line_number, "missing record type"));
        }

        let rtype = self.rtype_from_str(tokens[0]).ok_or_else(|| {
            ZoneError::parse(
                state.line_number,
                format!("unknown record type: {}", tokens[0]),
            )
        })?;

        Ok((rtype, &tokens[1..]))
    }

    /// Converts a string to a RecordType.
    fn rtype_from_str(&self, s: &str) -> Option<RecordType> {
        match s.to_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::AAAA),
            "NS" => Some(RecordType::NS),
            "CNAME" => Some(RecordType::CNAME),
            "SOA" => Some(RecordType::SOA),
            "PTR" => Some(RecordType::PTR),
            "MX" => Some(RecordType::MX),
            "TXT" => Some(RecordType::TXT),
            "SRV" => Some(RecordType::SRV),
            "CAA" => Some(RecordType::CAA),
            "DNSKEY" => Some(RecordType::DNSKEY),
            "DS" => Some(RecordType::DS),
            "RRSIG" => Some(RecordType::RRSIG),
            "NSEC" => Some(RecordType::NSEC),
            "NSEC3" => Some(RecordType::NSEC3),
            "NSEC3PARAM" => Some(RecordType::NSEC3PARAM),
            "TLSA" => Some(RecordType::TLSA),
            "SSHFP" => Some(RecordType::SSHFP),
            "HTTPS" => Some(RecordType::HTTPS),
            "SVCB" => Some(RecordType::SVCB),
            "DNAME" => Some(RecordType::DNAME),
            "HINFO" => Some(RecordType::HINFO),
            "RP" => Some(RecordType::RP),
            "NAPTR" => Some(RecordType::NAPTR),
            "LOC" => Some(RecordType::LOC),
            _ => {
                // Try TYPEnn format
                if s.to_uppercase().starts_with("TYPE") {
                    s[4..]
                        .parse::<u16>()
                        .ok()
                        .and_then(|n| RecordType::try_from(n).ok())
                } else {
                    None
                }
            }
        }
    }

    /// Parses the RDATA based on record type.
    fn parse_rdata(
        &self,
        rtype: RecordType,
        tokens: &[&str],
        origin: &Name,
        state: &ParserState,
    ) -> Result<RData> {
        match rtype {
            RecordType::A => self.parse_a(tokens, state),
            RecordType::AAAA => self.parse_aaaa(tokens, state),
            RecordType::NS => self.parse_ns(tokens, origin, state),
            RecordType::CNAME => self.parse_cname(tokens, origin, state),
            RecordType::SOA => self.parse_soa(tokens, origin, state),
            RecordType::PTR => self.parse_ptr(tokens, origin, state),
            RecordType::MX => self.parse_mx(tokens, origin, state),
            RecordType::TXT => self.parse_txt(tokens, state),
            RecordType::SRV => self.parse_srv(tokens, origin, state),
            _ => Err(ZoneError::parse(
                state.line_number,
                format!("unsupported record type for parsing: {:?}", rtype),
            )),
        }
    }

    fn parse_a(&self, tokens: &[&str], state: &ParserState) -> Result<RData> {
        let addr = tokens
            .first()
            .ok_or_else(|| ZoneError::parse(state.line_number, "A record missing address"))?
            .parse::<Ipv4Addr>()
            .map_err(|_| ZoneError::parse(state.line_number, "invalid IPv4 address"))?;
        Ok(RData::A(stria_proto::rdata::A::new(addr)))
    }

    fn parse_aaaa(&self, tokens: &[&str], state: &ParserState) -> Result<RData> {
        let addr = tokens
            .first()
            .ok_or_else(|| ZoneError::parse(state.line_number, "AAAA record missing address"))?
            .parse::<Ipv6Addr>()
            .map_err(|_| ZoneError::parse(state.line_number, "invalid IPv6 address"))?;
        Ok(RData::AAAA(stria_proto::rdata::AAAA::new(addr)))
    }

    fn parse_ns(&self, tokens: &[&str], origin: &Name, state: &ParserState) -> Result<RData> {
        let target = tokens
            .first()
            .ok_or_else(|| ZoneError::parse(state.line_number, "NS record missing target"))?;
        let name = self.make_absolute(target, origin, state)?;
        Ok(RData::NS(stria_proto::rdata::NS::new(name)))
    }

    fn parse_cname(&self, tokens: &[&str], origin: &Name, state: &ParserState) -> Result<RData> {
        let target = tokens
            .first()
            .ok_or_else(|| ZoneError::parse(state.line_number, "CNAME record missing target"))?;
        let name = self.make_absolute(target, origin, state)?;
        Ok(RData::CNAME(stria_proto::rdata::CNAME::new(name)))
    }

    fn parse_ptr(&self, tokens: &[&str], origin: &Name, state: &ParserState) -> Result<RData> {
        let target = tokens
            .first()
            .ok_or_else(|| ZoneError::parse(state.line_number, "PTR record missing target"))?;
        let name = self.make_absolute(target, origin, state)?;
        Ok(RData::PTR(stria_proto::rdata::PTR::new(name)))
    }

    fn parse_mx(&self, tokens: &[&str], origin: &Name, state: &ParserState) -> Result<RData> {
        if tokens.len() < 2 {
            return Err(ZoneError::parse(
                state.line_number,
                "MX record requires preference and exchange",
            ));
        }
        let preference = tokens[0]
            .parse::<u16>()
            .map_err(|_| ZoneError::parse(state.line_number, "invalid MX preference"))?;
        let exchange = self.make_absolute(tokens[1], origin, state)?;
        Ok(RData::MX(stria_proto::rdata::MX::new(preference, exchange)))
    }

    fn parse_txt(&self, tokens: &[&str], _state: &ParserState) -> Result<RData> {
        // Join all tokens and handle quoted strings
        let text = tokens.join(" ");
        let text = text.trim_matches('"').to_string();
        Ok(RData::TXT(stria_proto::rdata::TXT::from_string(text)))
    }

    fn parse_srv(&self, tokens: &[&str], origin: &Name, state: &ParserState) -> Result<RData> {
        if tokens.len() < 4 {
            return Err(ZoneError::parse(
                state.line_number,
                "SRV record requires priority, weight, port, and target",
            ));
        }
        let priority = tokens[0]
            .parse::<u16>()
            .map_err(|_| ZoneError::parse(state.line_number, "invalid SRV priority"))?;
        let weight = tokens[1]
            .parse::<u16>()
            .map_err(|_| ZoneError::parse(state.line_number, "invalid SRV weight"))?;
        let port = tokens[2]
            .parse::<u16>()
            .map_err(|_| ZoneError::parse(state.line_number, "invalid SRV port"))?;
        let target = self.make_absolute(tokens[3], origin, state)?;
        Ok(RData::SRV(stria_proto::rdata::SRV::new(
            priority, weight, port, target,
        )))
    }

    fn parse_soa(&self, tokens: &[&str], origin: &Name, state: &ParserState) -> Result<RData> {
        if tokens.len() < 7 {
            return Err(ZoneError::parse(
                state.line_number,
                "SOA record requires mname, rname, serial, refresh, retry, expire, minimum",
            ));
        }

        let mname = self.make_absolute(tokens[0], origin, state)?;
        let rname = self.make_absolute(tokens[1], origin, state)?;
        let serial = tokens[2]
            .parse::<u32>()
            .map_err(|_| ZoneError::parse(state.line_number, "invalid SOA serial"))?;
        let refresh = self
            .parse_ttl_value(tokens[3], state)
            .unwrap_or_else(|_| tokens[3].parse().unwrap_or(3600));
        let retry = self
            .parse_ttl_value(tokens[4], state)
            .unwrap_or_else(|_| tokens[4].parse().unwrap_or(600));
        let expire = self
            .parse_ttl_value(tokens[5], state)
            .unwrap_or_else(|_| tokens[5].parse().unwrap_or(604800));
        let minimum = self
            .parse_ttl_value(tokens[6], state)
            .unwrap_or_else(|_| tokens[6].parse().unwrap_or(3600));

        Ok(RData::SOA(SOA::new(
            mname, rname, serial, refresh, retry, expire, minimum,
        )))
    }

    /// Makes a name absolute by appending the origin if necessary.
    fn make_absolute(&self, name: &str, origin: &Name, state: &ParserState) -> Result<Name> {
        if name == "@" {
            return Ok(origin.clone());
        }

        if name.ends_with('.') {
            // Already absolute
            Name::from_str(name)
                .map_err(|_| ZoneError::parse(state.line_number, format!("invalid name: {}", name)))
        } else {
            // Relative - append origin
            let full_name = format!("{}.{}", name, origin);
            Name::from_str(&full_name)
                .map_err(|_| ZoneError::parse(state.line_number, format!("invalid name: {}", name)))
        }
    }
}

impl Default for ZoneFileParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses a zone file from a path.
pub fn parse_zone_file(path: impl AsRef<Path>, origin: Name) -> Result<Zone> {
    let file = std::fs::File::open(path).map_err(ZoneError::Io)?;
    ZoneFileParser::new().parse(file, origin)
}

/// Parses a zone from a string.
pub fn parse_zone_str(content: &str, origin: Name) -> Result<Zone> {
    ZoneFileParser::new().parse(content.as_bytes(), origin)
}

// ============================================================================
// Zone Transfer (AXFR/IXFR)
// ============================================================================

/// Configuration for zone transfers.
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Read/write timeout.
    pub io_timeout: Duration,
    /// Maximum message size.
    pub max_message_size: usize,
    /// TSIG key for authentication.
    pub tsig_key: Option<String>,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
            max_message_size: 65535,
            tsig_key: None,
        }
    }
}

/// Handler for zone transfer operations (AXFR/IXFR).
#[derive(Debug)]
pub struct ZoneTransfer {
    /// Configuration.
    config: TransferConfig,
}

impl ZoneTransfer {
    /// Creates a new zone transfer handler.
    pub fn new(config: TransferConfig) -> Self {
        Self { config }
    }

    /// Creates a handler with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(TransferConfig::default())
    }

    /// Performs an outbound AXFR (serving a full zone transfer).
    ///
    /// Returns an iterator of DNS messages to send.
    #[instrument(skip(self, zone))]
    pub fn axfr_out(&self, zone: &Zone, query: &Message) -> Result<Vec<Message>> {
        info!(zone = %zone.name(), serial = zone.serial(), "starting outbound AXFR");

        let mut messages = Vec::new();

        // First message with SOA
        let mut msg = self.create_transfer_response(query);
        let soa_record = self.create_soa_record(zone);
        msg.add_answer(soa_record.clone());

        // Add all zone records
        for record in zone.iter_records() {
            // Skip the SOA - we handle it specially
            if record.record_type() == Some(RecordType::SOA) && record.name() == zone.name() {
                continue;
            }

            // Check if adding this record would exceed message size
            if msg.wire_len() + record.wire_len() > self.config.max_message_size {
                messages.push(msg);
                msg = self.create_transfer_response(query);
            }

            msg.add_answer(record.clone());
        }

        // Final SOA to mark end of transfer
        msg.add_answer(soa_record);
        messages.push(msg);

        info!(
            zone = %zone.name(),
            message_count = messages.len(),
            "completed outbound AXFR"
        );

        Ok(messages)
    }

    /// Performs an inbound AXFR (receiving a full zone transfer).
    ///
    /// Connects to the primary and receives the complete zone.
    #[instrument(skip(self))]
    pub async fn axfr_in(&self, zone_name: &Name, primary: SocketAddr) -> Result<Zone> {
        info!(zone = %zone_name, primary = %primary, "starting inbound AXFR");

        let mut stream =
            tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(primary))
                .await
                .map_err(|_| ZoneError::Timeout)?
                .map_err(ZoneError::Io)?;

        // Send AXFR query
        let query = self.create_axfr_query(zone_name);
        self.send_message(&mut stream, &query).await?;

        // Receive responses
        let mut records = Vec::new();
        let mut first_soa: Option<SOA> = None;
        let mut saw_final_soa = false;

        while !saw_final_soa {
            let response = self.receive_message(&mut stream).await?;

            if response.rcode() != ResponseCode::NoError {
                return Err(ZoneError::transfer(format!(
                    "AXFR failed with rcode: {:?}",
                    response.rcode()
                )));
            }

            for record in response.answers() {
                if record.record_type() == Some(RecordType::SOA) {
                    if let RData::SOA(soa) = record.rdata() {
                        if first_soa.is_none() {
                            first_soa = Some(soa.clone());
                        } else {
                            // This is the final SOA
                            saw_final_soa = true;
                            break;
                        }
                    }
                }
                records.push(record.clone());
            }
        }

        let soa = first_soa.ok_or_else(|| ZoneError::transfer("no SOA in AXFR response"))?;
        let mut zone = Zone::new(zone_name.clone(), ZoneType::Secondary, soa);

        for record in records {
            zone.add_record(record);
        }

        info!(
            zone = %zone_name,
            serial = zone.serial(),
            records = zone.record_count(),
            "completed inbound AXFR"
        );

        Ok(zone)
    }

    /// Performs an outbound IXFR (serving an incremental zone transfer).
    #[instrument(skip(self, zone))]
    pub fn ixfr_out(
        &self,
        zone: &Zone,
        query: &Message,
        client_serial: u32,
    ) -> Result<Vec<Message>> {
        // If client is up to date, return just the current SOA
        if !SOA::serial_gt(zone.serial(), client_serial) {
            let mut msg = self.create_transfer_response(query);
            msg.add_answer(self.create_soa_record(zone));
            return Ok(vec![msg]);
        }

        // For now, fall back to AXFR
        // A full implementation would track zone changes and provide deltas
        warn!(
            zone = %zone.name(),
            client_serial,
            current_serial = zone.serial(),
            "IXFR falling back to AXFR (no diff available)"
        );
        self.axfr_out(zone, query)
    }

    /// Performs an inbound IXFR (receiving an incremental zone transfer).
    #[instrument(skip(self, current_zone))]
    pub async fn ixfr_in(&self, current_zone: &Zone, primary: SocketAddr) -> Result<Zone> {
        info!(
            zone = %current_zone.name(),
            current_serial = current_zone.serial(),
            primary = %primary,
            "starting inbound IXFR"
        );

        let mut stream =
            tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(primary))
                .await
                .map_err(|_| ZoneError::Timeout)?
                .map_err(ZoneError::Io)?;

        // Send IXFR query with current SOA in authority section
        let query = self.create_ixfr_query(current_zone);
        self.send_message(&mut stream, &query).await?;

        // Receive response
        let response = self.receive_message(&mut stream).await?;

        if response.rcode() != ResponseCode::NoError {
            return Err(ZoneError::transfer(format!(
                "IXFR failed with rcode: {:?}",
                response.rcode()
            )));
        }

        // Check if response is AXFR-style (starts with different serial)
        // or true IXFR (incremental changes)
        let answers = response.answers();

        if answers.is_empty() {
            return Err(ZoneError::transfer("empty IXFR response"));
        }

        // Check first record - should be SOA
        if answers[0].record_type() != Some(RecordType::SOA) {
            return Err(ZoneError::transfer("IXFR response doesn't start with SOA"));
        }

        // If only one answer and it's the current serial, we're up to date
        if answers.len() == 1 {
            if let RData::SOA(soa) = answers[0].rdata() {
                if soa.serial() == current_zone.serial() {
                    info!(zone = %current_zone.name(), "zone is up to date");
                    return Ok(current_zone.clone());
                }
            }
        }

        // For now, treat any multi-record response as AXFR
        // A full implementation would parse IXFR sequences
        self.axfr_in(current_zone.name(), primary).await
    }

    fn create_transfer_response(&self, query: &Message) -> Message {
        let mut response = Message::response_from(query);
        response.header_mut().set_authoritative(true);
        response
    }

    fn create_soa_record(&self, zone: &Zone) -> ResourceRecord {
        ResourceRecord::new(
            zone.name().clone(),
            Type::Known(RecordType::SOA),
            Class::Known(RecordClass::IN),
            zone.soa().minimum(),
            RData::SOA(zone.soa().clone()),
        )
    }

    fn create_axfr_query(&self, zone_name: &Name) -> Message {
        let question = Question::new(zone_name.clone(), RecordType::AXFR, RecordClass::IN);
        Message::query(question)
    }

    fn create_ixfr_query(&self, zone: &Zone) -> Message {
        let question = Question::new(zone.name().clone(), RecordType::IXFR, RecordClass::IN);
        let mut msg = Message::query(question);

        // Add current SOA to authority section
        msg.add_authority(self.create_soa_record(zone));
        msg
    }

    async fn send_message(&self, stream: &mut TcpStream, msg: &Message) -> Result<()> {
        let wire = msg.to_wire();
        let len = wire.len() as u16;

        // TCP DNS uses 2-byte length prefix
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(ZoneError::Io)?;
        stream.write_all(&wire).await.map_err(ZoneError::Io)?;
        stream.flush().await.map_err(ZoneError::Io)?;

        Ok(())
    }

    async fn receive_message(&self, stream: &mut TcpStream) -> Result<Message> {
        // Read length prefix
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(self.config.io_timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| ZoneError::Timeout)?
            .map_err(ZoneError::Io)?;

        let len = u16::from_be_bytes(len_buf) as usize;
        if len > self.config.max_message_size {
            return Err(ZoneError::transfer(format!(
                "message too large: {} bytes",
                len
            )));
        }

        // Read message
        let mut buf = vec![0u8; len];
        tokio::time::timeout(self.config.io_timeout, stream.read_exact(&mut buf))
            .await
            .map_err(|_| ZoneError::Timeout)?
            .map_err(ZoneError::Io)?;

        Message::parse(&buf).map_err(ZoneError::Protocol)
    }
}

// ============================================================================
// NOTIFY Handler
// ============================================================================

/// Handler for DNS NOTIFY messages (RFC 1996).
///
/// NOTIFY is used by primary servers to inform secondaries that zone
/// data has changed, prompting an immediate refresh rather than waiting
/// for the SOA refresh interval.
#[derive(Debug)]
pub struct NotifyHandler {
    /// Pending notifications (zone name -> list of servers to notify).
    pending: DashMap<Name, Vec<SocketAddr>>,
    /// Notification timeout.
    timeout: Duration,
}

impl NotifyHandler {
    /// Creates a new NOTIFY handler.
    pub fn new() -> Self {
        Self {
            pending: DashMap::new(),
            timeout: Duration::from_secs(5),
        }
    }

    /// Sets the notification timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Processes an incoming NOTIFY message.
    ///
    /// Returns a response message and indicates whether a zone refresh
    /// should be triggered.
    #[instrument(skip(self))]
    pub fn process_notify(&self, notify: &Message, source: SocketAddr) -> (Message, bool) {
        let mut response = Message::response_from(notify);
        response.header_mut().set_authoritative(true);

        // Validate the NOTIFY
        if notify.opcode() != OpCode::Notify {
            warn!("received non-NOTIFY message in notify handler");
            response.set_rcode(ResponseCode::FormErr);
            return (response, false);
        }

        let question = match notify.question() {
            Some(q) => q,
            None => {
                response.set_rcode(ResponseCode::FormErr);
                return (response, false);
            }
        };

        // Check if we're interested in this zone
        let zone_name = &question.qname;
        info!(
            zone = %zone_name,
            source = %source,
            "received NOTIFY"
        );

        // Return success and indicate refresh needed
        response.set_rcode(ResponseCode::NoError);
        (response, true)
    }

    /// Sends NOTIFY messages to a list of servers for a zone.
    #[instrument(skip(self))]
    pub async fn send_notify(&self, zone: &Zone, targets: &[SocketAddr]) -> Result<()> {
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(ZoneError::Io)?;

        let notify = self.create_notify_message(zone);
        let wire = notify.to_wire();

        for target in targets {
            debug!(zone = %zone.name(), target = %target, "sending NOTIFY");

            if let Err(e) = socket.send_to(&wire, target).await {
                warn!(target = %target, error = %e, "failed to send NOTIFY");
            }
        }

        Ok(())
    }

    fn create_notify_message(&self, zone: &Zone) -> Message {
        let question = Question::new(zone.name().clone(), RecordType::SOA, RecordClass::IN);

        // Use a simple random ID
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u16)
            .unwrap_or(0);

        let mut header = Header::new(id);
        header.opcode = OpCode::Notify;
        header.flags.insert(stria_proto::header::HeaderFlags::AA);
        header.qd_count = 1;
        header.an_count = 1;

        let mut msg = Message::new(header);
        msg.add_question(question);

        // Include current SOA in answer section
        let soa_record = ResourceRecord::new(
            zone.name().clone(),
            Type::Known(RecordType::SOA),
            Class::Known(RecordClass::IN),
            zone.soa().minimum(),
            RData::SOA(zone.soa().clone()),
        );
        msg.add_answer(soa_record);

        msg
    }
}

impl Default for NotifyHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Dynamic Update (RFC 2136)
// ============================================================================

/// A prerequisite condition for a dynamic update.
#[derive(Debug, Clone)]
pub enum UpdatePrerequisite {
    /// Name must exist (have at least one RR).
    NameInUse(Name),
    /// Name must not exist.
    NameNotInUse(Name),
    /// RRset must exist.
    RRsetExists(Name, RecordType),
    /// RRset must not exist.
    RRsetNotExists(Name, RecordType),
    /// RRset must exist with exact value.
    RRsetExistsValue(ResourceRecord),
}

/// An update operation in a dynamic update.
#[derive(Debug, Clone)]
pub enum UpdateOperation {
    /// Add records to an RRset.
    AddRRset(Vec<ResourceRecord>),
    /// Delete an RRset.
    DeleteRRset(Name, RecordType),
    /// Delete all RRsets at a name.
    DeleteName(Name),
    /// Delete specific RRs.
    DeleteRR(ResourceRecord),
}

/// Handler for RFC 2136 Dynamic DNS Updates.
#[derive(Debug)]
pub struct DynamicUpdate {
    /// Whether to allow updates to SOA records.
    allow_soa_update: bool,
    /// Whether to allow updates to NS records at apex.
    allow_apex_ns_update: bool,
}

impl DynamicUpdate {
    /// Creates a new dynamic update handler.
    pub fn new() -> Self {
        Self {
            allow_soa_update: false,
            allow_apex_ns_update: false,
        }
    }

    /// Allows SOA record updates.
    pub fn allow_soa_update(mut self, allow: bool) -> Self {
        self.allow_soa_update = allow;
        self
    }

    /// Allows NS record updates at the zone apex.
    pub fn allow_apex_ns_update(mut self, allow: bool) -> Self {
        self.allow_apex_ns_update = allow;
        self
    }

    /// Processes a dynamic update message.
    ///
    /// Returns the response message and whether the zone was modified.
    #[instrument(skip(self, zone))]
    pub fn process_update(&self, update: &Message, zone: &mut Zone) -> Result<Message> {
        let mut response = Message::response_from(update);

        // Validate opcode
        if update.opcode() != OpCode::Update {
            response.set_rcode(ResponseCode::FormErr);
            return Ok(response);
        }

        // Get zone name from question section
        let zone_name = match update.question() {
            Some(q) if q.record_type() == Some(RecordType::SOA) => q.qname.clone(),
            _ => {
                response.set_rcode(ResponseCode::FormErr);
                return Ok(response);
            }
        };

        // Verify we're updating the right zone
        if &zone_name != zone.name() {
            response.set_rcode(ResponseCode::NotZone);
            return Ok(response);
        }

        // Check zone type
        if !zone.zone_type().accepts_updates() {
            response.set_rcode(ResponseCode::Refused);
            return Ok(response);
        }

        // Parse and check prerequisites (answer section)
        let prerequisites = self.parse_prerequisites(update)?;
        if let Err(e) = self.check_prerequisites(&prerequisites, zone) {
            response.set_rcode(e.response_code());
            return Ok(response);
        }

        // Parse update operations (authority section)
        let operations = self.parse_operations(update, zone)?;

        // Apply updates
        if let Err(e) = self.apply_operations(&operations, zone) {
            response.set_rcode(e.response_code());
            return Ok(response);
        }

        // Increment serial
        zone.increment_serial();

        response.set_rcode(ResponseCode::NoError);
        info!(zone = %zone.name(), serial = zone.serial(), "dynamic update applied");

        Ok(response)
    }

    fn parse_prerequisites(&self, update: &Message) -> Result<Vec<UpdatePrerequisite>> {
        let mut prereqs = Vec::new();

        for record in update.answers() {
            let prereq = match (record.ttl(), record.rclass()) {
                (0, Class::Known(RecordClass::ANY)) => {
                    if record.rdata().wire_len() == 0 {
                        if record.record_type() == Some(RecordType::ANY) {
                            UpdatePrerequisite::NameInUse(record.name().clone())
                        } else {
                            UpdatePrerequisite::RRsetExists(
                                record.name().clone(),
                                record.record_type().unwrap_or(RecordType::A),
                            )
                        }
                    } else {
                        continue; // Invalid
                    }
                }
                (0, Class::Known(RecordClass::NONE)) => {
                    if record.rdata().wire_len() == 0 {
                        if record.record_type() == Some(RecordType::ANY) {
                            UpdatePrerequisite::NameNotInUse(record.name().clone())
                        } else {
                            UpdatePrerequisite::RRsetNotExists(
                                record.name().clone(),
                                record.record_type().unwrap_or(RecordType::A),
                            )
                        }
                    } else {
                        continue; // Invalid
                    }
                }
                (0, _) => {
                    // Value-dependent prerequisite
                    UpdatePrerequisite::RRsetExistsValue(record.clone())
                }
                _ => continue, // Invalid prerequisite
            };

            prereqs.push(prereq);
        }

        Ok(prereqs)
    }

    fn check_prerequisites(&self, prereqs: &[UpdatePrerequisite], zone: &Zone) -> Result<()> {
        for prereq in prereqs {
            match prereq {
                UpdatePrerequisite::NameInUse(name) => {
                    if !zone.contains_name(name)
                        || zone.get_node(name).map(|n| n.is_empty()).unwrap_or(true)
                    {
                        return Err(ZoneError::UpdateError {
                            code: ResponseCode::NXRRSet,
                            message: format!("name {} not in use", name),
                        });
                    }
                }
                UpdatePrerequisite::NameNotInUse(name) => {
                    if zone.get_node(name).map(|n| !n.is_empty()).unwrap_or(false) {
                        return Err(ZoneError::UpdateError {
                            code: ResponseCode::YXDomain,
                            message: format!("name {} exists", name),
                        });
                    }
                }
                UpdatePrerequisite::RRsetExists(name, rtype) => {
                    if zone.get_records(name, *rtype).is_none() {
                        return Err(ZoneError::UpdateError {
                            code: ResponseCode::NXRRSet,
                            message: format!("RRset {} {} not found", name, rtype),
                        });
                    }
                }
                UpdatePrerequisite::RRsetNotExists(name, rtype) => {
                    if zone.get_records(name, *rtype).is_some() {
                        return Err(ZoneError::UpdateError {
                            code: ResponseCode::YXRRSet,
                            message: format!("RRset {} {} exists", name, rtype),
                        });
                    }
                }
                UpdatePrerequisite::RRsetExistsValue(record) => {
                    let rtype = record.record_type().unwrap_or(RecordType::A);
                    let rrset = zone.get_records(record.name(), rtype);
                    let found = rrset
                        .map(|rs| rs.records().iter().any(|r| r.rdata() == record.rdata()))
                        .unwrap_or(false);
                    if !found {
                        return Err(ZoneError::UpdateError {
                            code: ResponseCode::NXRRSet,
                            message: "exact RRset value not found".to_string(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn parse_operations(&self, update: &Message, zone: &Zone) -> Result<Vec<UpdateOperation>> {
        let mut operations = Vec::new();

        for record in update.authority() {
            if !record.name().is_subdomain_of(zone.name()) {
                return Err(ZoneError::UpdateError {
                    code: ResponseCode::NotZone,
                    message: format!("{} not in zone", record.name()),
                });
            }

            let op = match record.rclass() {
                Class::Known(RecordClass::IN) => {
                    // Add record
                    self.validate_add(record, zone)?;
                    UpdateOperation::AddRRset(vec![record.clone()])
                }
                Class::Known(RecordClass::ANY) => {
                    if record.ttl() == 0 && record.rdata().wire_len() == 0 {
                        if record.record_type() == Some(RecordType::ANY) {
                            // Delete all RRsets at name
                            UpdateOperation::DeleteName(record.name().clone())
                        } else {
                            // Delete RRset
                            UpdateOperation::DeleteRRset(
                                record.name().clone(),
                                record.record_type().unwrap_or(RecordType::A),
                            )
                        }
                    } else {
                        continue; // Invalid
                    }
                }
                Class::Known(RecordClass::NONE) => {
                    if record.ttl() == 0 {
                        // Delete specific RR
                        UpdateOperation::DeleteRR(record.clone())
                    } else {
                        continue; // Invalid
                    }
                }
                _ => continue, // Ignore unknown class
            };

            operations.push(op);
        }

        Ok(operations)
    }

    fn validate_add(&self, record: &ResourceRecord, zone: &Zone) -> Result<()> {
        let rtype = record.record_type().unwrap_or(RecordType::A);

        // Check for SOA updates
        if rtype == RecordType::SOA {
            if !self.allow_soa_update {
                return Err(ZoneError::UpdateError {
                    code: ResponseCode::Refused,
                    message: "SOA updates not allowed".to_string(),
                });
            }
        }

        // Check for apex NS updates
        if rtype == RecordType::NS && record.name() == zone.name() {
            if !self.allow_apex_ns_update {
                return Err(ZoneError::UpdateError {
                    code: ResponseCode::Refused,
                    message: "apex NS updates not allowed".to_string(),
                });
            }
        }

        // Check CNAME rules
        if rtype == RecordType::CNAME {
            if let Some(node) = zone.get_node(record.name()) {
                let has_other = node
                    .types()
                    .any(|t| t != RecordType::CNAME && t != RecordType::RRSIG);
                if has_other {
                    return Err(ZoneError::UpdateError {
                        code: ResponseCode::FormErr,
                        message: "cannot add CNAME with other records".to_string(),
                    });
                }
            }
        } else if let Some(node) = zone.get_node(record.name()) {
            if node.get_rrset(RecordType::CNAME).is_some() {
                return Err(ZoneError::UpdateError {
                    code: ResponseCode::FormErr,
                    message: "cannot add records to CNAME".to_string(),
                });
            }
        }

        Ok(())
    }

    fn apply_operations(&self, operations: &[UpdateOperation], zone: &mut Zone) -> Result<()> {
        for op in operations {
            match op {
                UpdateOperation::AddRRset(records) => {
                    for record in records {
                        zone.add_record(record.clone());
                    }
                }
                UpdateOperation::DeleteRRset(name, rtype) => {
                    zone.remove_records(name, *rtype);
                }
                UpdateOperation::DeleteName(name) => {
                    zone.nodes.remove(name);
                }
                UpdateOperation::DeleteRR(record) => {
                    if let Some(node) = zone.nodes.get_mut(record.name()) {
                        node.remove_record(record);
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for DynamicUpdate {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_soa() -> SOA {
        SOA::new(
            Name::from_str("ns1.example.com.").unwrap(),
            Name::from_str("hostmaster.example.com.").unwrap(),
            2024010101,
            3600,
            900,
            604800,
            86400,
        )
    }

    fn create_test_zone() -> Zone {
        let origin = Name::from_str("example.com.").unwrap();
        let soa = create_test_soa();
        let mut zone = Zone::primary(origin.clone(), soa);

        // Add SOA as record
        zone.add_record(ResourceRecord::new(
            origin.clone(),
            Type::Known(RecordType::SOA),
            Class::Known(RecordClass::IN),
            86400,
            RData::SOA(create_test_soa()),
        ));

        // Add NS records
        zone.add_record(ResourceRecord::new(
            origin.clone(),
            Type::Known(RecordType::NS),
            Class::Known(RecordClass::IN),
            86400,
            RData::NS(stria_proto::rdata::NS::new(
                Name::from_str("ns1.example.com.").unwrap(),
            )),
        ));

        // Add A record
        zone.add_record(ResourceRecord::a(
            Name::from_str("www.example.com.").unwrap(),
            3600,
            Ipv4Addr::new(192, 0, 2, 1),
        ));

        zone
    }

    #[test]
    fn test_zone_type() {
        assert!(ZoneType::Primary.is_authoritative());
        assert!(ZoneType::Secondary.is_authoritative());
        assert!(!ZoneType::Forward.is_authoritative());

        assert!(ZoneType::Primary.accepts_updates());
        assert!(!ZoneType::Secondary.accepts_updates());
    }

    #[test]
    fn test_zone_class() {
        assert!(ZoneClass::IN.is_internet());
        assert!(!ZoneClass::CH.is_internet());
        assert_eq!(ZoneClass::IN.to_u16(), 1);
    }

    #[test]
    fn test_zone_creation() {
        let zone = create_test_zone();

        assert_eq!(zone.name().to_string(), "example.com.");
        assert_eq!(zone.zone_type(), ZoneType::Primary);
        assert!(zone.is_authoritative());
        assert_eq!(zone.serial(), 2024010101);
    }

    #[test]
    fn test_zone_records() {
        let zone = create_test_zone();

        // Check A record
        let www = Name::from_str("www.example.com.").unwrap();
        let a_records = zone.get_records(&www, RecordType::A);
        assert!(a_records.is_some());
        assert_eq!(a_records.unwrap().len(), 1);

        // Check NS records
        let ns_records = zone.get_records(zone.name(), RecordType::NS);
        assert!(ns_records.is_some());
    }

    #[test]
    fn test_zone_contains_name() {
        let zone = create_test_zone();

        assert!(zone.contains_name(&Name::from_str("www.example.com.").unwrap()));
        assert!(zone.contains_name(&Name::from_str("sub.www.example.com.").unwrap()));
        assert!(!zone.contains_name(&Name::from_str("other.com.").unwrap()));
    }

    #[test]
    fn test_zone_serial_update() {
        let mut zone = create_test_zone();
        let old_serial = zone.serial();

        zone.increment_serial();

        assert!(zone.serial() > old_serial);
    }

    #[test]
    fn test_zone_tree() {
        let tree = ZoneTree::new();

        let zone1 = create_test_zone();
        let mut zone2 = Zone::primary(
            Name::from_str("sub.example.com.").unwrap(),
            create_test_soa(),
        );
        zone2.add_record(ResourceRecord::new(
            Name::from_str("sub.example.com.").unwrap(),
            Type::Known(RecordType::SOA),
            Class::Known(RecordClass::IN),
            86400,
            RData::SOA(create_test_soa()),
        ));

        tree.insert(zone1);
        tree.insert(zone2);

        assert_eq!(tree.len(), 2);

        // Find zone for www.example.com
        let found = tree.find_zone(&Name::from_str("www.example.com.").unwrap());
        assert!(found.is_some());
        assert_eq!(found.unwrap().name().to_string(), "example.com.");

        // Find zone for www.sub.example.com (should be sub.example.com)
        let found = tree.find_zone(&Name::from_str("www.sub.example.com.").unwrap());
        assert!(found.is_some());
        assert_eq!(found.unwrap().name().to_string(), "sub.example.com.");
    }

    #[tokio::test]
    async fn test_in_memory_store() {
        let store = InMemoryZoneStore::new();
        let zone = create_test_zone();
        let zone_name = zone.name().clone();

        // Save zone
        store.save_zone(&zone).await.unwrap();

        // Check exists
        assert!(store.zone_exists(&zone_name).await.unwrap());

        // Load zone
        let loaded = store.load_zone(&zone_name).await.unwrap();
        assert_eq!(loaded.name(), zone.name());
        assert_eq!(loaded.serial(), zone.serial());

        // List zones
        let zones = store.list_zones().await.unwrap();
        assert_eq!(zones.len(), 1);

        // Get records
        let records = store
            .get_records(
                &zone_name,
                &Name::from_str("www.example.com.").unwrap(),
                RecordType::A,
            )
            .await
            .unwrap();
        assert_eq!(records.len(), 1);

        // Delete zone
        store.delete_zone(&zone_name).await.unwrap();
        assert!(!store.zone_exists(&zone_name).await.unwrap());
    }

    #[test]
    fn test_zone_file_parser_simple() {
        let content = r#"
$TTL 3600
$ORIGIN example.com.
@   IN  SOA ns1.example.com. hostmaster.example.com. (
            2024010101 ; serial
            3600       ; refresh
            900        ; retry
            604800     ; expire
            86400      ; minimum
        )
@       IN  NS  ns1.example.com.
@       IN  NS  ns2.example.com.
ns1     IN  A   192.0.2.1
ns2     IN  A   192.0.2.2
www     IN  A   192.0.2.10
mail    IN  A   192.0.2.20
@       IN  MX  10 mail.example.com.
"#;

        let origin = Name::from_str("example.com.").unwrap();
        let zone = parse_zone_str(content, origin).unwrap();

        assert_eq!(zone.name().to_string(), "example.com.");
        assert_eq!(zone.serial(), 2024010101);
        assert_eq!(zone.ns_set().len(), 2);

        // Check A records
        let www = zone
            .get_records(&Name::from_str("www.example.com.").unwrap(), RecordType::A)
            .unwrap();
        assert_eq!(www.len(), 1);

        // Check MX record
        let mx = zone
            .get_records(&Name::from_str("example.com.").unwrap(), RecordType::MX)
            .unwrap();
        assert_eq!(mx.len(), 1);
    }

    #[test]
    fn test_zone_validation() {
        let origin = Name::from_str("example.com.").unwrap();
        let soa = create_test_soa();
        let mut zone = Zone::primary(origin.clone(), soa);

        // Zone without SOA record should fail validation
        let result = zone.validate();
        assert!(result.is_err());

        // Add SOA record
        zone.add_record(ResourceRecord::new(
            origin.clone(),
            Type::Known(RecordType::SOA),
            Class::Known(RecordClass::IN),
            86400,
            RData::SOA(create_test_soa()),
        ));

        // Still should fail - no NS
        let result = zone.validate();
        assert!(result.is_err());

        // Add NS record
        zone.add_record(ResourceRecord::new(
            origin.clone(),
            Type::Known(RecordType::NS),
            Class::Known(RecordClass::IN),
            86400,
            RData::NS(stria_proto::rdata::NS::new(
                Name::from_str("ns1.example.com.").unwrap(),
            )),
        ));

        // Now should pass
        zone.validate().unwrap();
    }

    #[test]
    fn test_rrset() {
        let name = Name::from_str("www.example.com.").unwrap();
        let mut rrset = RRset::new(name.clone(), RecordType::A, RecordClass::IN, 3600);

        assert!(rrset.is_empty());

        let record = ResourceRecord::a(name.clone(), 3600, Ipv4Addr::new(192, 0, 2, 1));
        assert!(rrset.add(record));

        assert_eq!(rrset.len(), 1);
        assert!(!rrset.is_empty());
    }

    #[test]
    fn test_zone_node() {
        let mut node = ZoneNode::new();

        let name = Name::from_str("www.example.com.").unwrap();
        let record = ResourceRecord::a(name.clone(), 3600, Ipv4Addr::new(192, 0, 2, 1));

        node.add_record(record);

        assert!(node.get_rrset(RecordType::A).is_some());
        assert!(node.get_rrset(RecordType::AAAA).is_none());

        let types: Vec<_> = node.types().collect();
        assert_eq!(types, vec![RecordType::A]);
    }

    #[test]
    fn test_ttl_parsing() {
        let parser = ZoneFileParser::new();

        assert_eq!(parser.parse_ttl_value_silent("3600"), Ok(3600));
        assert_eq!(parser.parse_ttl_value_silent("1h"), Ok(3600));
        assert_eq!(parser.parse_ttl_value_silent("1d"), Ok(86400));
        assert_eq!(parser.parse_ttl_value_silent("1w"), Ok(604800));
        assert_eq!(parser.parse_ttl_value_silent("1h30m"), Ok(5400));
    }

    #[test]
    fn test_notify_handler() {
        let handler = NotifyHandler::new();
        let zone = create_test_zone();

        let notify_msg = handler.create_notify_message(&zone);

        assert_eq!(notify_msg.opcode(), OpCode::Notify);
        assert!(notify_msg.is_authoritative());
        assert_eq!(notify_msg.questions().len(), 1);
        assert_eq!(notify_msg.answers().len(), 1);
    }
}
