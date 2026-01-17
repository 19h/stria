//! DNS resource records.
//!
//! A resource record (RR) is the fundamental unit of DNS data,
//! containing a name, type, class, TTL, and record-specific data.

use crate::class::{Class, RecordClass};
use crate::error::{Error, Result};
use crate::name::{Name, NameParser};
use crate::rdata::RData;
use crate::rtype::{RecordType, Type};
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};

/// A DNS resource record.
///
/// # Wire Format
///
/// ```text
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /                      NAME                     /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     CLASS                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TTL                      |
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                   RDLENGTH                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /                     RDATA                     /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceRecord {
    /// The domain name this record is for.
    name: Name,
    /// The record type.
    rtype: Type,
    /// The record class.
    rclass: Class,
    /// Time to live in seconds.
    ttl: u32,
    /// The record data.
    rdata: RData,
}

impl ResourceRecord {
    /// Creates a new resource record.
    pub fn new(name: Name, rtype: Type, rclass: Class, ttl: u32, rdata: RData) -> Self {
        Self {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        }
    }

    /// Creates a new resource record with known type and class.
    pub fn new_known(
        name: Name,
        rtype: RecordType,
        rclass: RecordClass,
        ttl: u32,
        rdata: RData,
    ) -> Self {
        Self::new(name, Type::Known(rtype), Class::Known(rclass), ttl, rdata)
    }

    /// Creates an A record.
    pub fn a(name: Name, ttl: u32, addr: std::net::Ipv4Addr) -> Self {
        Self::new_known(
            name,
            RecordType::A,
            RecordClass::IN,
            ttl,
            RData::A(crate::rdata::A::new(addr)),
        )
    }

    /// Creates an AAAA record.
    pub fn aaaa(name: Name, ttl: u32, addr: std::net::Ipv6Addr) -> Self {
        Self::new_known(
            name,
            RecordType::AAAA,
            RecordClass::IN,
            ttl,
            RData::AAAA(crate::rdata::AAAA::new(addr)),
        )
    }

    /// Creates a CNAME record.
    pub fn cname(name: Name, ttl: u32, target: Name) -> Self {
        Self::new_known(
            name,
            RecordType::CNAME,
            RecordClass::IN,
            ttl,
            RData::CNAME(crate::rdata::CNAME::new(target)),
        )
    }

    /// Creates an MX record.
    pub fn mx(name: Name, ttl: u32, preference: u16, exchange: Name) -> Self {
        Self::new_known(
            name,
            RecordType::MX,
            RecordClass::IN,
            ttl,
            RData::MX(crate::rdata::MX::new(preference, exchange)),
        )
    }

    /// Creates a TXT record.
    pub fn txt(name: Name, ttl: u32, text: impl Into<Vec<u8>>) -> Self {
        Self::new_known(
            name,
            RecordType::TXT,
            RecordClass::IN,
            ttl,
            RData::TXT(crate::rdata::TXT::from_string(text)),
        )
    }

    /// Returns the record name.
    #[inline]
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Returns the record type.
    #[inline]
    pub fn rtype(&self) -> Type {
        self.rtype
    }

    /// Returns the record type if known.
    #[inline]
    pub fn record_type(&self) -> Option<RecordType> {
        self.rtype.as_known()
    }

    /// Returns the record class.
    #[inline]
    pub fn rclass(&self) -> Class {
        self.rclass
    }

    /// Returns the record class if known.
    #[inline]
    pub fn record_class(&self) -> Option<RecordClass> {
        self.rclass.as_known()
    }

    /// Returns the TTL in seconds.
    #[inline]
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns the TTL as a Duration.
    #[inline]
    pub fn ttl_duration(&self) -> Duration {
        Duration::from_secs(u64::from(self.ttl))
    }

    /// Returns the record data.
    #[inline]
    pub fn rdata(&self) -> &RData {
        &self.rdata
    }

    /// Returns true if this record has expired.
    ///
    /// # Arguments
    ///
    /// * `cached_at` - When the record was cached
    /// * `now` - Current time
    pub fn is_expired(&self, cached_at: Instant, now: Instant) -> bool {
        let elapsed = now.duration_since(cached_at);
        elapsed >= self.ttl_duration()
    }

    /// Returns the remaining TTL based on when it was cached.
    ///
    /// Returns 0 if the record has expired.
    pub fn remaining_ttl(&self, cached_at: Instant, now: Instant) -> u32 {
        let elapsed = now.duration_since(cached_at);
        let original = self.ttl_duration();
        if elapsed >= original {
            0
        } else {
            (original - elapsed).as_secs() as u32
        }
    }

    /// Returns a copy with the TTL adjusted for cache time.
    pub fn with_remaining_ttl(&self, cached_at: Instant, now: Instant) -> Self {
        let mut record = self.clone();
        record.ttl = self.remaining_ttl(cached_at, now);
        record
    }

    /// Returns a copy with a different TTL.
    pub fn with_ttl(&self, ttl: u32) -> Self {
        let mut record = self.clone();
        record.ttl = ttl;
        record
    }

    /// Returns true if this is an A record.
    #[inline]
    pub fn is_a(&self) -> bool {
        matches!(self.rtype, Type::Known(RecordType::A))
    }

    /// Returns true if this is an AAAA record.
    #[inline]
    pub fn is_aaaa(&self) -> bool {
        matches!(self.rtype, Type::Known(RecordType::AAAA))
    }

    /// Returns true if this is a CNAME record.
    #[inline]
    pub fn is_cname(&self) -> bool {
        matches!(self.rtype, Type::Known(RecordType::CNAME))
    }

    /// Returns true if this is a DNSSEC-related record.
    #[inline]
    pub fn is_dnssec(&self) -> bool {
        self.rtype
            .as_known()
            .map(|t| t.is_dnssec())
            .unwrap_or(false)
    }

    /// Returns true if this record should be cached.
    #[inline]
    pub fn is_cacheable(&self) -> bool {
        self.ttl > 0
            && self
                .rtype
                .as_known()
                .map(|t| t.is_cacheable())
                .unwrap_or(true)
    }

    /// Parses a resource record from wire format.
    ///
    /// Returns the record and the number of bytes consumed.
    pub fn parse(data: &[u8], offset: usize) -> Result<(Self, usize)> {
        let parser = NameParser::new(data);
        let (name, name_len) = parser.parse_name(offset)?;

        let fixed_start = offset + name_len;
        if fixed_start + 10 > data.len() {
            return Err(Error::buffer_too_short(fixed_start + 10, data.len()));
        }

        let rtype_value = u16::from_be_bytes([data[fixed_start], data[fixed_start + 1]]);
        let rclass_value = u16::from_be_bytes([data[fixed_start + 2], data[fixed_start + 3]]);
        let ttl = u32::from_be_bytes(data[fixed_start + 4..fixed_start + 8].try_into().unwrap());
        let rdlength = u16::from_be_bytes([data[fixed_start + 8], data[fixed_start + 9]]);

        let rdata_start = fixed_start + 10;
        if rdata_start + rdlength as usize > data.len() {
            return Err(Error::buffer_too_short(
                rdata_start + rdlength as usize,
                data.len(),
            ));
        }

        let rtype = Type::from_u16(rtype_value);
        let rclass = Class::from_u16(rclass_value);

        // Parse RDATA based on type
        let rdata = if let Type::Known(known_type) = rtype {
            RData::parse(known_type, data, rdata_start, rdlength)?
        } else {
            RData::Unknown(crate::rdata::Unknown::new(
                rtype_value,
                &data[rdata_start..rdata_start + rdlength as usize],
            ))
        };

        let total_len = name_len + 10 + rdlength as usize;

        Ok((
            Self {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            },
            total_len,
        ))
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        self.name.wire_len() + 10 + self.rdata.wire_len()
    }

    /// Writes the resource record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        self.name.write_wire(buf);
        buf.extend_from_slice(&self.rtype.to_u16().to_be_bytes());
        buf.extend_from_slice(&self.rclass.to_u16().to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());

        let rdlength = self.rdata.wire_len() as u16;
        buf.extend_from_slice(&rdlength.to_be_bytes());
        self.rdata.write_to(buf);
    }

    /// Converts the record to wire format bytes.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(self.wire_len());
        self.write_to(&mut buf);
        buf.to_vec()
    }
}

impl fmt::Display for ResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}",
            self.name, self.ttl, self.rclass, self.rtype, self.rdata
        )
    }
}

/// Parser for resource record sections.
#[derive(Debug)]
pub struct RecordParser<'a> {
    /// The message data.
    data: &'a [u8],
    /// Current offset in the message.
    offset: usize,
    /// Number of records remaining.
    remaining: u16,
}

impl<'a> RecordParser<'a> {
    /// Creates a new record parser.
    #[inline]
    pub const fn new(data: &'a [u8], offset: usize, count: u16) -> Self {
        Self {
            data,
            offset,
            remaining: count,
        }
    }

    /// Returns the current offset.
    #[inline]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the number of remaining records.
    #[inline]
    pub const fn remaining(&self) -> u16 {
        self.remaining
    }

    /// Parses the next record.
    pub fn next(&mut self) -> Result<Option<ResourceRecord>> {
        if self.remaining == 0 {
            return Ok(None);
        }

        let (record, consumed) = ResourceRecord::parse(self.data, self.offset)?;
        self.offset += consumed;
        self.remaining -= 1;

        Ok(Some(record))
    }

    /// Collects all remaining records into a vector.
    pub fn collect_all(&mut self) -> Result<Vec<ResourceRecord>> {
        let mut records = Vec::with_capacity(self.remaining as usize);
        while let Some(r) = self.next()? {
            records.push(r);
        }
        Ok(records)
    }
}

/// An RRset - a set of resource records with the same name, type, and class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RRset {
    /// The common name.
    name: Name,
    /// The common type.
    rtype: Type,
    /// The common class.
    rclass: Class,
    /// The records in this set.
    records: Vec<ResourceRecord>,
}

impl RRset {
    /// Creates a new RRset.
    pub fn new(name: Name, rtype: Type, rclass: Class) -> Self {
        Self {
            name,
            rtype,
            rclass,
            records: Vec::new(),
        }
    }

    /// Creates an RRset from a vector of records.
    ///
    /// Returns None if the records don't all have the same name/type/class.
    pub fn from_records(records: Vec<ResourceRecord>) -> Option<Self> {
        if records.is_empty() {
            return None;
        }

        let first = &records[0];
        let name = first.name().clone();
        let rtype = first.rtype();
        let rclass = first.rclass();

        for record in &records[1..] {
            if record.name() != &name || record.rtype() != rtype || record.rclass() != rclass {
                return None;
            }
        }

        Some(Self {
            name,
            rtype,
            rclass,
            records,
        })
    }

    /// Returns the common name.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Returns the common type.
    pub fn rtype(&self) -> Type {
        self.rtype
    }

    /// Returns the common class.
    pub fn rclass(&self) -> Class {
        self.rclass
    }

    /// Returns the records in this set.
    pub fn records(&self) -> &[ResourceRecord] {
        &self.records
    }

    /// Adds a record to the set.
    ///
    /// Returns false if the record doesn't match the set's name/type/class.
    pub fn add(&mut self, record: ResourceRecord) -> bool {
        if record.name() != &self.name
            || record.rtype() != self.rtype
            || record.rclass() != self.rclass
        {
            return false;
        }
        self.records.push(record);
        true
    }

    /// Returns the minimum TTL across all records.
    pub fn min_ttl(&self) -> u32 {
        self.records.iter().map(|r| r.ttl()).min().unwrap_or(0)
    }

    /// Returns true if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_resource_record_a() {
        let name = Name::from_str("example.com").unwrap();
        let rr = ResourceRecord::a(name.clone(), 300, Ipv4Addr::new(192, 0, 2, 1));

        assert_eq!(rr.name(), &name);
        assert!(rr.is_a());
        assert_eq!(rr.ttl(), 300);
        assert_eq!(rr.rdata().as_a(), Some(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn test_resource_record_roundtrip() {
        let name = Name::from_str("www.example.com").unwrap();
        let original = ResourceRecord::a(name, 3600, Ipv4Addr::new(10, 0, 0, 1));

        let wire = original.to_wire();
        let (parsed, consumed) = ResourceRecord::parse(&wire, 0).unwrap();

        assert_eq!(consumed, wire.len());
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_rrset() {
        let name = Name::from_str("example.com").unwrap();

        let rr1 = ResourceRecord::a(name.clone(), 300, Ipv4Addr::new(192, 0, 2, 1));
        let rr2 = ResourceRecord::a(name.clone(), 600, Ipv4Addr::new(192, 0, 2, 2));

        let rrset = RRset::from_records(vec![rr1, rr2]).unwrap();

        assert_eq!(rrset.name(), &name);
        assert_eq!(rrset.len(), 2);
        assert_eq!(rrset.min_ttl(), 300);
    }

    #[test]
    fn test_ttl_calculations() {
        let name = Name::from_str("example.com").unwrap();
        let rr = ResourceRecord::a(name, 300, Ipv4Addr::new(192, 0, 2, 1));

        let now = Instant::now();
        let cached_at = now - Duration::from_secs(100);

        assert!(!rr.is_expired(cached_at, now));
        assert_eq!(rr.remaining_ttl(cached_at, now), 200);

        let expired_at = now - Duration::from_secs(400);
        assert!(rr.is_expired(expired_at, now));
        assert_eq!(rr.remaining_ttl(expired_at, now), 0);
    }

    #[test]
    fn test_record_display() {
        let name = Name::from_str("example.com").unwrap();
        let rr = ResourceRecord::a(name, 300, Ipv4Addr::new(192, 0, 2, 1));

        let display = rr.to_string();
        assert!(display.contains("example.com"));
        assert!(display.contains("300"));
        assert!(display.contains("IN"));
        assert!(display.contains("A"));
        assert!(display.contains("192.0.2.1"));
    }
}
