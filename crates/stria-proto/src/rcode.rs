//! DNS response codes (RCODEs).
//!
//! Response codes indicate the status of a DNS operation.
//! Defined in RFC 1035 Section 4.1.1 with extensions from subsequent RFCs.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

/// DNS response code.
///
/// The RCODE field in the DNS header indicates the status of the response.
/// With EDNS0, the response code is extended to 12 bits (4 bits in header + 8 bits in OPT).
///
/// See RFC 1035, RFC 6895, and RFC 8914 (Extended DNS Errors) for details.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    IntoPrimitive,
    TryFromPrimitive,
    Serialize,
    Deserialize,
)]
#[repr(u16)]
pub enum ResponseCode {
    /// No error condition - RFC 1035
    NoError = 0,

    /// Format error - RFC 1035
    ///
    /// The name server was unable to interpret the query.
    FormErr = 1,

    /// Server failure - RFC 1035
    ///
    /// The name server was unable to process the query due to
    /// a problem with the name server.
    ServFail = 2,

    /// Name error - RFC 1035
    ///
    /// The domain name referenced in the query does not exist.
    /// Meaningful only for responses from an authoritative name server.
    NXDomain = 3,

    /// Not implemented - RFC 1035
    ///
    /// The name server does not support the requested kind of query.
    NotImp = 4,

    /// Query refused - RFC 1035
    ///
    /// The name server refuses to perform the specified operation
    /// for policy reasons.
    Refused = 5,

    /// Name exists when it should not - RFC 2136
    ///
    /// Used in dynamic updates.
    YXDomain = 6,

    /// RR set exists when it should not - RFC 2136
    ///
    /// Used in dynamic updates.
    YXRRSet = 7,

    /// RR set that should exist does not - RFC 2136
    ///
    /// Used in dynamic updates.
    NXRRSet = 8,

    /// Server not authoritative for zone - RFC 2136
    /// Also: Not authorized - RFC 8945
    NotAuth = 9,

    /// Name not contained in zone - RFC 2136
    NotZone = 10,

    /// DSO-TYPE not implemented - RFC 8490
    DsoTypeNI = 11,

    // Extended RCODEs (require EDNS0)
    /// Bad OPT Version / TSIG Signature Failure - RFC 6891, RFC 8945
    ///
    /// EDNS version not supported (BADVERS) or TSIG signature failure (BADSIG).
    /// These share the same code (16) and are distinguished by context.
    BadVers = 16,

    /// Key not recognized - RFC 8945
    BadKey = 17,

    /// Signature out of time window - RFC 8945
    BadTime = 18,

    /// Bad TKEY Mode - RFC 2930
    BadMode = 19,

    /// Duplicate key name - RFC 2930
    BadName = 20,

    /// Algorithm not supported - RFC 2930
    BadAlg = 21,

    /// Bad Truncation - RFC 8945
    BadTrunc = 22,

    /// Bad/missing Server Cookie - RFC 7873
    BadCookie = 23,
}

impl ResponseCode {
    /// Alias for BadVers - TSIG signature failure (RFC 8945).
    /// Same code as BadVers (16), distinguished by context.
    pub const BADSIG: Self = Self::BadVers;
    /// Returns the numeric value of the response code.
    #[inline]
    pub const fn to_u16(self) -> u16 {
        self as u16
    }

    /// Returns the 4-bit value for the header RCODE field.
    #[inline]
    pub const fn header_rcode(self) -> u8 {
        (self as u16 & 0x0F) as u8
    }

    /// Returns the 8-bit extended RCODE for the OPT record.
    #[inline]
    pub const fn extended_rcode(self) -> u8 {
        ((self as u16) >> 4) as u8
    }

    /// Combines header RCODE and extended RCODE into a full response code.
    #[inline]
    pub fn from_parts(header_rcode: u8, extended_rcode: u8) -> Option<Self> {
        let value = u16::from(extended_rcode) << 4 | u16::from(header_rcode & 0x0F);
        Self::try_from(value).ok()
    }

    /// Creates a response code from its 4-bit header value.
    #[inline]
    pub fn from_header(value: u8) -> Option<Self> {
        Self::try_from(u16::from(value & 0x0F)).ok()
    }

    /// Returns true if this response indicates success.
    #[inline]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::NoError)
    }

    /// Returns true if this response indicates the name does not exist.
    #[inline]
    pub const fn is_nxdomain(self) -> bool {
        matches!(self, Self::NXDomain)
    }

    /// Returns true if this response indicates a server error.
    #[inline]
    pub const fn is_server_error(self) -> bool {
        matches!(self, Self::ServFail)
    }

    /// Returns true if this is an extended RCODE (requires EDNS0).
    #[inline]
    pub const fn is_extended(self) -> bool {
        (self as u16) > 15
    }

    /// Returns true if this response should be cached.
    #[inline]
    pub const fn is_cacheable(self) -> bool {
        matches!(self, Self::NoError | Self::NXDomain)
    }

    /// Returns the human-readable name of the response code.
    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoError => "NOERROR",
            Self::FormErr => "FORMERR",
            Self::ServFail => "SERVFAIL",
            Self::NXDomain => "NXDOMAIN",
            Self::NotImp => "NOTIMP",
            Self::Refused => "REFUSED",
            Self::YXDomain => "YXDOMAIN",
            Self::YXRRSet => "YXRRSET",
            Self::NXRRSet => "NXRRSET",
            Self::NotAuth => "NOTAUTH",
            Self::NotZone => "NOTZONE",
            Self::DsoTypeNI => "DSOTYPENI",
            Self::BadVers => "BADVERS/BADSIG",
            Self::BadKey => "BADKEY",
            Self::BadTime => "BADTIME",
            Self::BadMode => "BADMODE",
            Self::BadName => "BADNAME",
            Self::BadAlg => "BADALG",
            Self::BadTrunc => "BADTRUNC",
            Self::BadCookie => "BADCOOKIE",
        }
    }

    /// Returns a description of the response code.
    #[inline]
    pub const fn description(self) -> &'static str {
        match self {
            Self::NoError => "No error condition",
            Self::FormErr => "Format error - unable to interpret query",
            Self::ServFail => "Server failure - unable to process query",
            Self::NXDomain => "Non-existent domain",
            Self::NotImp => "Not implemented",
            Self::Refused => "Query refused",
            Self::YXDomain => "Name exists when it should not",
            Self::YXRRSet => "RR set exists when it should not",
            Self::NXRRSet => "RR set that should exist does not",
            Self::NotAuth => "Not authoritative / Not authorized",
            Self::NotZone => "Name not contained in zone",
            Self::DsoTypeNI => "DSO-TYPE not implemented",
            Self::BadVers => "Bad OPT version / TSIG signature failure",
            Self::BadKey => "Key not recognized",
            Self::BadTime => "Signature out of time window",
            Self::BadMode => "Bad TKEY mode",
            Self::BadName => "Duplicate key name",
            Self::BadAlg => "Algorithm not supported",
            Self::BadTrunc => "Bad truncation",
            Self::BadCookie => "Bad/missing server cookie",
        }
    }
}

impl std::fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Default for ResponseCode {
    fn default() -> Self {
        Self::NoError
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rcode_values() {
        assert_eq!(ResponseCode::NoError.to_u16(), 0);
        assert_eq!(ResponseCode::FormErr.to_u16(), 1);
        assert_eq!(ResponseCode::ServFail.to_u16(), 2);
        assert_eq!(ResponseCode::NXDomain.to_u16(), 3);
        assert_eq!(ResponseCode::BadVers.to_u16(), 16);
    }

    #[test]
    fn test_rcode_parts() {
        assert_eq!(ResponseCode::NoError.header_rcode(), 0);
        assert_eq!(ResponseCode::NoError.extended_rcode(), 0);

        assert_eq!(ResponseCode::BadVers.header_rcode(), 0);
        assert_eq!(ResponseCode::BadVers.extended_rcode(), 1);

        assert_eq!(ResponseCode::from_parts(0, 1), Some(ResponseCode::BadVers));
        assert_eq!(ResponseCode::from_parts(3, 0), Some(ResponseCode::NXDomain));
    }

    #[test]
    fn test_rcode_predicates() {
        assert!(ResponseCode::NoError.is_success());
        assert!(!ResponseCode::NXDomain.is_success());

        assert!(ResponseCode::NXDomain.is_nxdomain());
        assert!(ResponseCode::ServFail.is_server_error());

        assert!(ResponseCode::BadVers.is_extended());
        assert!(!ResponseCode::NoError.is_extended());

        assert!(ResponseCode::NoError.is_cacheable());
        assert!(ResponseCode::NXDomain.is_cacheable());
        assert!(!ResponseCode::ServFail.is_cacheable());
    }
}
