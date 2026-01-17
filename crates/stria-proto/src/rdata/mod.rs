//! DNS record data (RDATA) types.
//!
//! This module contains implementations for all DNS record types,
//! organized by category:
//!
//! - **Address records**: A, AAAA
//! - **Name records**: NS, CNAME, PTR, DNAME, MX, SRV
//! - **Text records**: TXT, HINFO, RP
//! - **Authority records**: SOA
//! - **Security records**: DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM
//! - **Service records**: SRV, NAPTR, SVCB, HTTPS, CAA
//! - **Certificate records**: TLSA, SSHFP, CERT, SMIMEA, OPENPGPKEY
//! - **Location records**: LOC

pub mod address;
pub mod authority;
pub mod cert;
pub mod dnssec;
pub mod name;
pub mod service;
pub mod text;
pub mod unknown;

pub use address::{A, AAAA};
pub use authority::SOA;
pub use cert::{CERT, OPENPGPKEY, SMIMEA, SSHFP, TLSA};
pub use dnssec::{DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM, RRSIG};
pub use name::{CNAME, DNAME, MX, NS, PTR};
pub use service::{CAA, HTTPS, NAPTR, SRV, SVCB};
pub use text::{HINFO, RP, TXT};
pub use unknown::Unknown;

use crate::error::{Error, Result};
use crate::name::{Name, NameParser};
use crate::rtype::RecordType;
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// DNS record data.
///
/// This enum represents the parsed data for all supported DNS record types.
/// Unknown record types are preserved as opaque byte sequences.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RData {
    // =========================================================================
    // Address Records
    // =========================================================================
    /// IPv4 address (A record)
    A(A),

    /// IPv6 address (AAAA record)
    AAAA(AAAA),

    // =========================================================================
    // Name Records
    // =========================================================================
    /// Name server (NS record)
    NS(NS),

    /// Canonical name (CNAME record)
    CNAME(CNAME),

    /// Pointer (PTR record)
    PTR(PTR),

    /// Delegation name (DNAME record)
    DNAME(DNAME),

    /// Mail exchange (MX record)
    MX(MX),

    // =========================================================================
    // Authority Records
    // =========================================================================
    /// Start of authority (SOA record)
    SOA(SOA),

    // =========================================================================
    // Text Records
    // =========================================================================
    /// Text (TXT record)
    TXT(TXT),

    /// Host information (HINFO record)
    HINFO(HINFO),

    /// Responsible person (RP record)
    RP(RP),

    // =========================================================================
    // Service Records
    // =========================================================================
    /// Service location (SRV record)
    SRV(SRV),

    /// Naming authority pointer (NAPTR record)
    NAPTR(NAPTR),

    /// Service binding (SVCB record)
    SVCB(SVCB),

    /// HTTPS service binding (HTTPS record)
    HTTPS(HTTPS),

    /// Certification authority authorization (CAA record)
    CAA(CAA),

    // =========================================================================
    // Certificate Records
    // =========================================================================
    /// TLSA certificate association
    TLSA(TLSA),

    /// SSH key fingerprint (SSHFP record)
    SSHFP(SSHFP),

    /// Certificate (CERT record)
    CERT(CERT),

    /// S/MIME certificate association
    SMIMEA(SMIMEA),

    /// OpenPGP public key
    OPENPGPKEY(OPENPGPKEY),

    // =========================================================================
    // DNSSEC Records
    // =========================================================================
    /// DNS public key (DNSKEY record)
    DNSKEY(DNSKEY),

    /// Delegation signer (DS record)
    DS(DS),

    /// DNSSEC signature (RRSIG record)
    RRSIG(RRSIG),

    /// Next secure (NSEC record)
    NSEC(NSEC),

    /// Next secure v3 (NSEC3 record)
    NSEC3(NSEC3),

    /// NSEC3 parameters (NSEC3PARAM record)
    NSEC3PARAM(NSEC3PARAM),

    // =========================================================================
    // Other
    // =========================================================================
    /// Unknown or unsupported record type (preserved as raw bytes)
    Unknown(Unknown),
}

impl RData {
    /// Parses RDATA from wire format.
    ///
    /// # Arguments
    ///
    /// * `rtype` - The record type
    /// * `data` - The complete message data (for name compression)
    /// * `offset` - Offset to the start of the RDATA
    /// * `rdlength` - Length of the RDATA
    pub fn parse(rtype: RecordType, data: &[u8], offset: usize, rdlength: u16) -> Result<Self> {
        let rdata_slice = data
            .get(offset..offset + rdlength as usize)
            .ok_or_else(|| Error::buffer_too_short(offset + rdlength as usize, data.len()))?;

        match rtype {
            RecordType::A => Ok(RData::A(A::parse(rdata_slice)?)),
            RecordType::AAAA => Ok(RData::AAAA(AAAA::parse(rdata_slice)?)),
            RecordType::NS => Ok(RData::NS(NS::parse(data, offset)?)),
            RecordType::CNAME => Ok(RData::CNAME(CNAME::parse(data, offset)?)),
            RecordType::PTR => Ok(RData::PTR(PTR::parse(data, offset)?)),
            RecordType::DNAME => Ok(RData::DNAME(DNAME::parse(data, offset)?)),
            RecordType::MX => Ok(RData::MX(MX::parse(data, offset)?)),
            RecordType::SOA => Ok(RData::SOA(SOA::parse(data, offset)?)),
            RecordType::TXT => Ok(RData::TXT(TXT::parse(rdata_slice)?)),
            RecordType::HINFO => Ok(RData::HINFO(HINFO::parse(rdata_slice)?)),
            RecordType::RP => Ok(RData::RP(RP::parse(data, offset)?)),
            RecordType::SRV => Ok(RData::SRV(SRV::parse(data, offset)?)),
            RecordType::NAPTR => Ok(RData::NAPTR(NAPTR::parse(data, offset, rdlength)?)),
            RecordType::SVCB => Ok(RData::SVCB(SVCB::parse(data, offset, rdlength)?)),
            RecordType::HTTPS => Ok(RData::HTTPS(HTTPS::parse(data, offset, rdlength)?)),
            RecordType::CAA => Ok(RData::CAA(CAA::parse(rdata_slice)?)),
            RecordType::TLSA => Ok(RData::TLSA(TLSA::parse(rdata_slice)?)),
            RecordType::SSHFP => Ok(RData::SSHFP(SSHFP::parse(rdata_slice)?)),
            RecordType::CERT => Ok(RData::CERT(CERT::parse(rdata_slice)?)),
            RecordType::SMIMEA => Ok(RData::SMIMEA(SMIMEA::parse(rdata_slice)?)),
            RecordType::OPENPGPKEY => Ok(RData::OPENPGPKEY(OPENPGPKEY::parse(rdata_slice)?)),
            RecordType::DNSKEY => Ok(RData::DNSKEY(DNSKEY::parse(rdata_slice)?)),
            RecordType::DS => Ok(RData::DS(DS::parse(rdata_slice)?)),
            RecordType::RRSIG => Ok(RData::RRSIG(RRSIG::parse(data, offset, rdlength)?)),
            RecordType::NSEC => Ok(RData::NSEC(NSEC::parse(data, offset, rdlength)?)),
            RecordType::NSEC3 => Ok(RData::NSEC3(NSEC3::parse(rdata_slice)?)),
            RecordType::NSEC3PARAM => Ok(RData::NSEC3PARAM(NSEC3PARAM::parse(rdata_slice)?)),
            _ => Ok(RData::Unknown(Unknown::new(rtype.to_u16(), rdata_slice))),
        }
    }

    /// Returns the record type for this RDATA.
    pub fn record_type(&self) -> RecordType {
        match self {
            RData::A(_) => RecordType::A,
            RData::AAAA(_) => RecordType::AAAA,
            RData::NS(_) => RecordType::NS,
            RData::CNAME(_) => RecordType::CNAME,
            RData::PTR(_) => RecordType::PTR,
            RData::DNAME(_) => RecordType::DNAME,
            RData::MX(_) => RecordType::MX,
            RData::SOA(_) => RecordType::SOA,
            RData::TXT(_) => RecordType::TXT,
            RData::HINFO(_) => RecordType::HINFO,
            RData::RP(_) => RecordType::RP,
            RData::SRV(_) => RecordType::SRV,
            RData::NAPTR(_) => RecordType::NAPTR,
            RData::SVCB(_) => RecordType::SVCB,
            RData::HTTPS(_) => RecordType::HTTPS,
            RData::CAA(_) => RecordType::CAA,
            RData::TLSA(_) => RecordType::TLSA,
            RData::SSHFP(_) => RecordType::SSHFP,
            RData::CERT(_) => RecordType::CERT,
            RData::SMIMEA(_) => RecordType::SMIMEA,
            RData::OPENPGPKEY(_) => RecordType::OPENPGPKEY,
            RData::DNSKEY(_) => RecordType::DNSKEY,
            RData::DS(_) => RecordType::DS,
            RData::RRSIG(_) => RecordType::RRSIG,
            RData::NSEC(_) => RecordType::NSEC,
            RData::NSEC3(_) => RecordType::NSEC3,
            RData::NSEC3PARAM(_) => RecordType::NSEC3PARAM,
            RData::Unknown(u) => RecordType::try_from(u.type_code()).unwrap_or(RecordType::NULL),
        }
    }

    /// Returns the wire format length of this RDATA.
    pub fn wire_len(&self) -> usize {
        match self {
            RData::A(r) => r.wire_len(),
            RData::AAAA(r) => r.wire_len(),
            RData::NS(r) => r.wire_len(),
            RData::CNAME(r) => r.wire_len(),
            RData::PTR(r) => r.wire_len(),
            RData::DNAME(r) => r.wire_len(),
            RData::MX(r) => r.wire_len(),
            RData::SOA(r) => r.wire_len(),
            RData::TXT(r) => r.wire_len(),
            RData::HINFO(r) => r.wire_len(),
            RData::RP(r) => r.wire_len(),
            RData::SRV(r) => r.wire_len(),
            RData::NAPTR(r) => r.wire_len(),
            RData::SVCB(r) => r.wire_len(),
            RData::HTTPS(r) => r.wire_len(),
            RData::CAA(r) => r.wire_len(),
            RData::TLSA(r) => r.wire_len(),
            RData::SSHFP(r) => r.wire_len(),
            RData::CERT(r) => r.wire_len(),
            RData::SMIMEA(r) => r.wire_len(),
            RData::OPENPGPKEY(r) => r.wire_len(),
            RData::DNSKEY(r) => r.wire_len(),
            RData::DS(r) => r.wire_len(),
            RData::RRSIG(r) => r.wire_len(),
            RData::NSEC(r) => r.wire_len(),
            RData::NSEC3(r) => r.wire_len(),
            RData::NSEC3PARAM(r) => r.wire_len(),
            RData::Unknown(r) => r.wire_len(),
        }
    }

    /// Writes this RDATA to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        match self {
            RData::A(r) => r.write_to(buf),
            RData::AAAA(r) => r.write_to(buf),
            RData::NS(r) => r.write_to(buf),
            RData::CNAME(r) => r.write_to(buf),
            RData::PTR(r) => r.write_to(buf),
            RData::DNAME(r) => r.write_to(buf),
            RData::MX(r) => r.write_to(buf),
            RData::SOA(r) => r.write_to(buf),
            RData::TXT(r) => r.write_to(buf),
            RData::HINFO(r) => r.write_to(buf),
            RData::RP(r) => r.write_to(buf),
            RData::SRV(r) => r.write_to(buf),
            RData::NAPTR(r) => r.write_to(buf),
            RData::SVCB(r) => r.write_to(buf),
            RData::HTTPS(r) => r.write_to(buf),
            RData::CAA(r) => r.write_to(buf),
            RData::TLSA(r) => r.write_to(buf),
            RData::SSHFP(r) => r.write_to(buf),
            RData::CERT(r) => r.write_to(buf),
            RData::SMIMEA(r) => r.write_to(buf),
            RData::OPENPGPKEY(r) => r.write_to(buf),
            RData::DNSKEY(r) => r.write_to(buf),
            RData::DS(r) => r.write_to(buf),
            RData::RRSIG(r) => r.write_to(buf),
            RData::NSEC(r) => r.write_to(buf),
            RData::NSEC3(r) => r.write_to(buf),
            RData::NSEC3PARAM(r) => r.write_to(buf),
            RData::Unknown(r) => r.write_to(buf),
        }
    }

    /// Returns the IPv4 address if this is an A record.
    pub fn as_a(&self) -> Option<Ipv4Addr> {
        match self {
            RData::A(a) => Some(a.address()),
            _ => None,
        }
    }

    /// Returns the IPv6 address if this is an AAAA record.
    pub fn as_aaaa(&self) -> Option<Ipv6Addr> {
        match self {
            RData::AAAA(aaaa) => Some(aaaa.address()),
            _ => None,
        }
    }

    /// Returns the target name if this is a CNAME record.
    pub fn as_cname(&self) -> Option<&Name> {
        match self {
            RData::CNAME(cname) => Some(cname.target()),
            _ => None,
        }
    }

    /// Returns true if this RDATA contains a domain name that should be
    /// followed for resolution (CNAME, DNAME).
    pub fn is_alias(&self) -> bool {
        matches!(self, RData::CNAME(_) | RData::DNAME(_))
    }
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RData::A(r) => write!(f, "{r}"),
            RData::AAAA(r) => write!(f, "{r}"),
            RData::NS(r) => write!(f, "{r}"),
            RData::CNAME(r) => write!(f, "{r}"),
            RData::PTR(r) => write!(f, "{r}"),
            RData::DNAME(r) => write!(f, "{r}"),
            RData::MX(r) => write!(f, "{r}"),
            RData::SOA(r) => write!(f, "{r}"),
            RData::TXT(r) => write!(f, "{r}"),
            RData::HINFO(r) => write!(f, "{r}"),
            RData::RP(r) => write!(f, "{r}"),
            RData::SRV(r) => write!(f, "{r}"),
            RData::NAPTR(r) => write!(f, "{r}"),
            RData::SVCB(r) => write!(f, "{r}"),
            RData::HTTPS(r) => write!(f, "{r}"),
            RData::CAA(r) => write!(f, "{r}"),
            RData::TLSA(r) => write!(f, "{r}"),
            RData::SSHFP(r) => write!(f, "{r}"),
            RData::CERT(r) => write!(f, "{r}"),
            RData::SMIMEA(r) => write!(f, "{r}"),
            RData::OPENPGPKEY(r) => write!(f, "{r}"),
            RData::DNSKEY(r) => write!(f, "{r}"),
            RData::DS(r) => write!(f, "{r}"),
            RData::RRSIG(r) => write!(f, "{r}"),
            RData::NSEC(r) => write!(f, "{r}"),
            RData::NSEC3(r) => write!(f, "{r}"),
            RData::NSEC3PARAM(r) => write!(f, "{r}"),
            RData::Unknown(r) => write!(f, "{r}"),
        }
    }
}

/// Trait for RDATA types.
pub trait RDataType: Sized {
    /// Parses the RDATA from wire format bytes.
    fn parse(data: &[u8]) -> Result<Self>;

    /// Returns the wire format length.
    fn wire_len(&self) -> usize;

    /// Writes the RDATA to wire format.
    fn write_to(&self, buf: &mut BytesMut);
}

/// Trait for RDATA types that contain domain names (need full message for parsing).
pub trait RDataWithNames: Sized {
    /// Parses the RDATA from wire format with message context for compression.
    fn parse_with_message(message: &[u8], offset: usize) -> Result<Self>;
}
