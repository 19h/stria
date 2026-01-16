//! DNS record types.
//!
//! This module defines all DNS record types from various RFCs including standard
//! types (RFC 1035), DNSSEC types, and modern types like HTTPS/SVCB.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use std::fmt;

/// DNS record type.
///
/// This enum covers all widely-used record types as well as DNSSEC and
/// modern service binding types. See RFC 1035, RFC 3596, RFC 4034, RFC 9460, etc.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    IntoPrimitive,
    TryFromPrimitive,
    Serialize,
    Deserialize,
)]
#[repr(u16)]
pub enum RecordType {
    // =========================================================================
    // Standard Record Types (RFC 1035)
    // =========================================================================
    /// IPv4 address - RFC 1035
    A = 1,

    /// Authoritative name server - RFC 1035
    NS = 2,

    /// Mail destination (obsolete, use MX) - RFC 1035
    #[deprecated(note = "Use MX instead")]
    MD = 3,

    /// Mail forwarder (obsolete, use MX) - RFC 1035
    #[deprecated(note = "Use MX instead")]
    MF = 4,

    /// Canonical name (alias) - RFC 1035
    CNAME = 5,

    /// Start of authority - RFC 1035
    SOA = 6,

    /// Mailbox domain name - RFC 1035
    MB = 7,

    /// Mail group member - RFC 1035
    MG = 8,

    /// Mail rename domain name - RFC 1035
    MR = 9,

    /// Null record - RFC 1035
    NULL = 10,

    /// Well-known services - RFC 1035
    WKS = 11,

    /// Domain name pointer - RFC 1035
    PTR = 12,

    /// Host information - RFC 1035
    HINFO = 13,

    /// Mailbox information - RFC 1035
    MINFO = 14,

    /// Mail exchange - RFC 1035
    MX = 15,

    /// Text strings - RFC 1035
    TXT = 16,

    // =========================================================================
    // Extended Record Types
    // =========================================================================
    /// Responsible person - RFC 1183
    RP = 17,

    /// AFS database location - RFC 1183
    AFSDB = 18,

    /// X.25 address - RFC 1183
    X25 = 19,

    /// ISDN address - RFC 1183
    ISDN = 20,

    /// Route through - RFC 1183
    RT = 21,

    /// NSAP address - RFC 1706
    NSAP = 22,

    /// NSAP pointer - RFC 1706
    #[allow(non_camel_case_types)]
    NSAP_PTR = 23,

    /// Signature (obsolete, see RRSIG) - RFC 2535
    SIG = 24,

    /// Key (obsolete, see DNSKEY) - RFC 2535
    KEY = 25,

    /// X.400 pointer - RFC 2163
    PX = 26,

    /// Geographical position - RFC 1712
    GPOS = 27,

    /// IPv6 address - RFC 3596
    AAAA = 28,

    /// Location - RFC 1876
    LOC = 29,

    /// Next domain (obsolete, see NSEC) - RFC 2535
    NXT = 30,

    /// Server selection - RFC 2782
    SRV = 33,

    /// Naming authority pointer - RFC 2915, RFC 3403
    NAPTR = 35,

    /// Key exchange - RFC 2230
    KX = 36,

    /// Certificate - RFC 4398
    CERT = 37,

    /// IPv6 address (deprecated) - RFC 2874
    #[deprecated(note = "Use AAAA instead")]
    A6 = 38,

    /// Delegation name - RFC 6672
    DNAME = 39,

    /// EDNS(0) option pseudo-record - RFC 6891
    OPT = 41,

    /// Address prefix list - RFC 3123
    APL = 42,

    /// Delegation signer - RFC 4034
    DS = 43,

    /// SSH key fingerprint - RFC 4255
    SSHFP = 44,

    /// IPsec key - RFC 4025
    IPSECKEY = 45,

    /// DNSSEC signature - RFC 4034
    RRSIG = 46,

    /// Next secure - RFC 4034
    NSEC = 47,

    /// DNS public key - RFC 4034
    DNSKEY = 48,

    /// DHCP identifier - RFC 4701
    DHCID = 49,

    /// Next secure v3 - RFC 5155
    NSEC3 = 50,

    /// NSEC3 parameters - RFC 5155
    NSEC3PARAM = 51,

    /// TLSA certificate association - RFC 6698
    TLSA = 52,

    /// S/MIME certificate association - RFC 8162
    SMIMEA = 53,

    /// Host identity protocol - RFC 8005
    HIP = 55,

    /// Child DS - RFC 7344
    CDS = 59,

    /// Child DNSKEY - RFC 7344
    CDNSKEY = 60,

    /// OpenPGP public key - RFC 7929
    OPENPGPKEY = 61,

    /// Child-to-parent synchronization - RFC 7477
    CSYNC = 62,

    /// Zone message digest - RFC 8976
    ZONEMD = 63,

    /// Service binding - RFC 9460
    SVCB = 64,

    /// HTTPS service binding - RFC 9460
    HTTPS = 65,

    /// Sender policy framework - RFC 7208
    SPF = 99,

    /// Node identifier - RFC 6742
    NID = 104,

    /// 32-bit locator - RFC 6742
    L32 = 105,

    /// 64-bit locator - RFC 6742
    L64 = 106,

    /// Locator pointer - RFC 6742
    LP = 107,

    /// EUI-48 address - RFC 7043
    EUI48 = 108,

    /// EUI-64 address - RFC 7043
    EUI64 = 109,

    /// DNSSEC Trust Authorities - experimental
    TA = 32768,

    /// DNSSEC Lookaside Validation - RFC 4431
    DLV = 32769,

    // =========================================================================
    // Query Types (QTYPEs)
    // =========================================================================
    /// Transaction key - RFC 2930
    TKEY = 249,

    /// Transaction signature - RFC 8945
    TSIG = 250,

    /// Incremental zone transfer - RFC 1995
    IXFR = 251,

    /// Full zone transfer - RFC 5936
    AXFR = 252,

    /// Mailbox records (MB, MG, MR) - RFC 1035
    MAILB = 253,

    /// Mail agent records (obsolete) - RFC 1035
    #[deprecated(note = "Use MX instead")]
    MAILA = 254,

    /// Any record type - RFC 1035, RFC 8482
    ANY = 255,

    /// URI - RFC 7553
    URI = 256,

    /// Certification authority authorization - RFC 8659
    CAA = 257,

    /// Application visibility and control
    AVC = 258,

    /// DNSSEC validation information
    DOA = 259,

    /// Automatic multicast DNS name - RFC 8490
    AMTRELAY = 260,

    /// Resolver information - draft
    RESINFO = 261,

    /// WALLET - experimental
    WALLET = 262,
}

impl RecordType {
    /// Returns the numeric value of the record type.
    #[inline]
    pub const fn to_u16(self) -> u16 {
        self as u16
    }

    /// Creates a record type from its numeric value.
    #[inline]
    pub fn from_u16(value: u16) -> Option<Self> {
        Self::try_from(value).ok()
    }

    /// Returns true if this is a DNSSEC-related record type.
    #[inline]
    pub const fn is_dnssec(self) -> bool {
        matches!(
            self,
            Self::DNSKEY
                | Self::DS
                | Self::RRSIG
                | Self::NSEC
                | Self::NSEC3
                | Self::NSEC3PARAM
                | Self::CDS
                | Self::CDNSKEY
                | Self::DLV
                | Self::TA
        )
    }

    /// Returns true if this is a query-only type (QTYPE).
    #[inline]
    pub const fn is_query_type(self) -> bool {
        matches!(
            self,
            Self::AXFR | Self::IXFR | Self::ANY | Self::MAILB | Self::TKEY | Self::TSIG
        )
    }

    /// Returns true if this type can be cached.
    #[inline]
    pub const fn is_cacheable(self) -> bool {
        !self.is_query_type() && !matches!(self, Self::OPT)
    }

    /// Returns true if this is a pseudo-record type.
    #[inline]
    pub const fn is_pseudo_record(self) -> bool {
        matches!(self, Self::OPT | Self::TSIG | Self::TKEY)
    }

    /// Returns true if this type contains an embedded domain name.
    #[inline]
    pub const fn has_embedded_name(self) -> bool {
        matches!(
            self,
            Self::NS
                | Self::CNAME
                | Self::SOA
                | Self::PTR
                | Self::MX
                | Self::DNAME
                | Self::SRV
                | Self::NAPTR
                | Self::AFSDB
                | Self::RT
                | Self::KX
                | Self::RP
                | Self::NSEC
                | Self::RRSIG
        )
    }

    /// Returns true if this type's RDATA has a fixed length.
    #[inline]
    pub const fn has_fixed_length(self) -> Option<usize> {
        match self {
            Self::A => Some(4),
            Self::AAAA => Some(16),
            Self::NULL => Some(0),
            _ => None,
        }
    }

    /// Returns the human-readable name of the record type.
    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::NS => "NS",
            #[allow(deprecated)]
            Self::MD => "MD",
            #[allow(deprecated)]
            Self::MF => "MF",
            Self::CNAME => "CNAME",
            Self::SOA => "SOA",
            Self::MB => "MB",
            Self::MG => "MG",
            Self::MR => "MR",
            Self::NULL => "NULL",
            Self::WKS => "WKS",
            Self::PTR => "PTR",
            Self::HINFO => "HINFO",
            Self::MINFO => "MINFO",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::RP => "RP",
            Self::AFSDB => "AFSDB",
            Self::X25 => "X25",
            Self::ISDN => "ISDN",
            Self::RT => "RT",
            Self::NSAP => "NSAP",
            Self::NSAP_PTR => "NSAP-PTR",
            Self::SIG => "SIG",
            Self::KEY => "KEY",
            Self::PX => "PX",
            Self::GPOS => "GPOS",
            Self::AAAA => "AAAA",
            Self::LOC => "LOC",
            Self::NXT => "NXT",
            Self::SRV => "SRV",
            Self::NAPTR => "NAPTR",
            Self::KX => "KX",
            Self::CERT => "CERT",
            #[allow(deprecated)]
            Self::A6 => "A6",
            Self::DNAME => "DNAME",
            Self::OPT => "OPT",
            Self::APL => "APL",
            Self::DS => "DS",
            Self::SSHFP => "SSHFP",
            Self::IPSECKEY => "IPSECKEY",
            Self::RRSIG => "RRSIG",
            Self::NSEC => "NSEC",
            Self::DNSKEY => "DNSKEY",
            Self::DHCID => "DHCID",
            Self::NSEC3 => "NSEC3",
            Self::NSEC3PARAM => "NSEC3PARAM",
            Self::TLSA => "TLSA",
            Self::SMIMEA => "SMIMEA",
            Self::HIP => "HIP",
            Self::CDS => "CDS",
            Self::CDNSKEY => "CDNSKEY",
            Self::OPENPGPKEY => "OPENPGPKEY",
            Self::CSYNC => "CSYNC",
            Self::ZONEMD => "ZONEMD",
            Self::SVCB => "SVCB",
            Self::HTTPS => "HTTPS",
            Self::SPF => "SPF",
            Self::NID => "NID",
            Self::L32 => "L32",
            Self::L64 => "L64",
            Self::LP => "LP",
            Self::EUI48 => "EUI48",
            Self::EUI64 => "EUI64",
            Self::TA => "TA",
            Self::DLV => "DLV",
            Self::TKEY => "TKEY",
            Self::TSIG => "TSIG",
            Self::IXFR => "IXFR",
            Self::AXFR => "AXFR",
            Self::MAILB => "MAILB",
            #[allow(deprecated)]
            Self::MAILA => "MAILA",
            Self::ANY => "ANY",
            Self::URI => "URI",
            Self::CAA => "CAA",
            Self::AVC => "AVC",
            Self::DOA => "DOA",
            Self::AMTRELAY => "AMTRELAY",
            Self::RESINFO => "RESINFO",
            Self::WALLET => "WALLET",
        }
    }

    /// Returns a description of the record type.
    #[inline]
    pub const fn description(self) -> &'static str {
        match self {
            Self::A => "IPv4 address",
            Self::AAAA => "IPv6 address",
            Self::CNAME => "Canonical name (alias)",
            Self::MX => "Mail exchange",
            Self::NS => "Name server",
            Self::PTR => "Pointer record (reverse DNS)",
            Self::SOA => "Start of authority",
            Self::TXT => "Text record",
            Self::SRV => "Service record",
            Self::CAA => "Certification Authority Authorization",
            Self::DNSKEY => "DNSSEC public key",
            Self::DS => "Delegation signer",
            Self::RRSIG => "DNSSEC signature",
            Self::NSEC => "Next secure record",
            Self::NSEC3 => "Next secure record v3",
            Self::HTTPS => "HTTPS service binding",
            Self::SVCB => "Service binding",
            Self::TLSA => "TLS certificate association",
            Self::SSHFP => "SSH key fingerprint",
            Self::OPT => "EDNS(0) options",
            _ => "DNS record",
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Default for RecordType {
    fn default() -> Self {
        Self::A
    }
}

/// A type value that can represent both standard types and unknown values.
///
/// This allows handling of type values that may not be in the defined enum,
/// which is important for forward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Type {
    /// A known, standard record type.
    Known(RecordType),
    /// An unknown type value (TYPE#### format per RFC 3597).
    Unknown(u16),
}

impl Type {
    /// Creates a type from a u16 value.
    #[inline]
    pub fn from_u16(value: u16) -> Self {
        RecordType::from_u16(value)
            .map(Self::Known)
            .unwrap_or(Self::Unknown(value))
    }

    /// Returns the numeric value.
    #[inline]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::Known(t) => t.to_u16(),
            Self::Unknown(v) => v,
        }
    }

    /// Returns the standard type if known.
    #[inline]
    pub const fn as_known(self) -> Option<RecordType> {
        match self {
            Self::Known(t) => Some(t),
            Self::Unknown(_) => None,
        }
    }

    /// Returns true if this is an A record type.
    #[inline]
    pub const fn is_a(self) -> bool {
        matches!(self, Self::Known(RecordType::A))
    }

    /// Returns true if this is an AAAA record type.
    #[inline]
    pub const fn is_aaaa(self) -> bool {
        matches!(self, Self::Known(RecordType::AAAA))
    }

    /// Returns true if this is a CNAME record type.
    #[inline]
    pub const fn is_cname(self) -> bool {
        matches!(self, Self::Known(RecordType::CNAME))
    }
}

impl From<RecordType> for Type {
    fn from(t: RecordType) -> Self {
        Self::Known(t)
    }
}

impl From<u16> for Type {
    fn from(value: u16) -> Self {
        Self::from_u16(value)
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(t) => write!(f, "{t}"),
            Self::Unknown(v) => write!(f, "TYPE{v}"),
        }
    }
}

impl Default for Type {
    fn default() -> Self {
        Self::Known(RecordType::A)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtype_values() {
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::AAAA.to_u16(), 28);
        assert_eq!(RecordType::HTTPS.to_u16(), 65);
        assert_eq!(RecordType::ANY.to_u16(), 255);
    }

    #[test]
    fn test_rtype_from_u16() {
        assert_eq!(RecordType::from_u16(1), Some(RecordType::A));
        assert_eq!(RecordType::from_u16(28), Some(RecordType::AAAA));
        assert_eq!(RecordType::from_u16(65535), None);
    }

    #[test]
    fn test_rtype_predicates() {
        assert!(RecordType::DNSKEY.is_dnssec());
        assert!(RecordType::RRSIG.is_dnssec());
        assert!(!RecordType::A.is_dnssec());

        assert!(RecordType::AXFR.is_query_type());
        assert!(RecordType::ANY.is_query_type());
        assert!(!RecordType::A.is_query_type());

        assert!(RecordType::OPT.is_pseudo_record());
        assert!(!RecordType::A.is_pseudo_record());
    }

    #[test]
    fn test_generic_type() {
        let t = Type::from_u16(1);
        assert!(t.is_a());
        assert_eq!(t.as_known(), Some(RecordType::A));

        let t = Type::from_u16(65534);
        assert!(!t.is_a());
        assert_eq!(t.as_known(), None);
        assert_eq!(t.to_string(), "TYPE65534");
    }
}
