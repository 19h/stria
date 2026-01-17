//! # Extended DNS Errors (RFC 8914)
//!
//! This crate implements Extended DNS Errors, providing detailed error
//! information beyond the basic RCODE system.
//!
//! ## Usage
//!
//! ```rust
//! use stria_ede::{ExtendedDnsError, EdeCode};
//!
//! let error = ExtendedDnsError::new(EdeCode::StaleAnswer)
//!     .with_text("cached data is stale but served anyway");
//! ```

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Extended DNS Error codes (RFC 8914).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive, Serialize, Deserialize,
)]
#[repr(u16)]
pub enum EdeCode {
    /// The resolver attempted to perform DNSSEC validation but no signatures
    /// are present.
    UnsupportedDnskeyAlgorithm = 1,

    /// The resolver attempted to perform DNSSEC validation but a DNSKEY
    /// RRset contained only unsupported DNSSEC algorithms.
    UnsupportedDsDigestType = 2,

    /// The resolver was unable to resolve the answer within its time limits.
    StaleAnswer = 3,

    /// The resolver policy prohibits the answer.
    ForgedAnswer = 4,

    /// DNSSEC Indeterminate.
    DnssecIndeterminate = 5,

    /// DNSSEC Bogus.
    DnssecBogus = 6,

    /// Signature Expired.
    SignatureExpired = 7,

    /// Signature Not Yet Valid.
    SignatureNotYetValid = 8,

    /// DNSKEY Missing.
    DnskeyMissing = 9,

    /// RRSIGs Missing.
    RrsigsMissing = 10,

    /// No Zone Key Bit Set.
    NoZoneKeyBitSet = 11,

    /// NSEC Missing.
    NsecMissing = 12,

    /// Cached Error.
    CachedError = 13,

    /// Not Ready.
    NotReady = 14,

    /// Blocked.
    Blocked = 15,

    /// Censored.
    Censored = 16,

    /// Filtered.
    Filtered = 17,

    /// Prohibited.
    Prohibited = 18,

    /// Stale NXDomain Answer.
    StaleNxdomainAnswer = 19,

    /// Not Authoritative.
    NotAuthoritative = 20,

    /// Not Supported.
    NotSupported = 21,

    /// No Reachable Authority.
    NoReachableAuthority = 22,

    /// Network Error.
    NetworkError = 23,

    /// Invalid Data.
    InvalidData = 24,

    /// Signature Expired before Valid.
    SignatureExpiredBeforeValid = 25,

    /// Too Early.
    TooEarly = 26,

    /// Unsupported NSEC3 Iterations Value.
    UnsupportedNsec3IterationsValue = 27,

    /// Unable to conform to policy.
    UnableToConformToPolicy = 28,

    /// Synthesized.
    Synthesized = 29,
}

impl EdeCode {
    /// Creates from u16 value.
    pub fn from_u16(value: u16) -> Option<Self> {
        Self::try_from(value).ok()
    }

    /// Returns the numeric value.
    pub const fn to_u16(self) -> u16 {
        self as u16
    }

    /// Returns the human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnsupportedDnskeyAlgorithm => "Unsupported DNSKEY Algorithm",
            Self::UnsupportedDsDigestType => "Unsupported DS Digest Type",
            Self::StaleAnswer => "Stale Answer",
            Self::ForgedAnswer => "Forged Answer",
            Self::DnssecIndeterminate => "DNSSEC Indeterminate",
            Self::DnssecBogus => "DNSSEC Bogus",
            Self::SignatureExpired => "Signature Expired",
            Self::SignatureNotYetValid => "Signature Not Yet Valid",
            Self::DnskeyMissing => "DNSKEY Missing",
            Self::RrsigsMissing => "RRSIGs Missing",
            Self::NoZoneKeyBitSet => "No Zone Key Bit Set",
            Self::NsecMissing => "NSEC Missing",
            Self::CachedError => "Cached Error",
            Self::NotReady => "Not Ready",
            Self::Blocked => "Blocked",
            Self::Censored => "Censored",
            Self::Filtered => "Filtered",
            Self::Prohibited => "Prohibited",
            Self::StaleNxdomainAnswer => "Stale NXDomain Answer",
            Self::NotAuthoritative => "Not Authoritative",
            Self::NotSupported => "Not Supported",
            Self::NoReachableAuthority => "No Reachable Authority",
            Self::NetworkError => "Network Error",
            Self::InvalidData => "Invalid Data",
            Self::SignatureExpiredBeforeValid => "Signature Expired Before Valid",
            Self::TooEarly => "Too Early",
            Self::UnsupportedNsec3IterationsValue => "Unsupported NSEC3 Iterations Value",
            Self::UnableToConformToPolicy => "Unable to Conform to Policy",
            Self::Synthesized => "Synthesized",
        }
    }

    /// Returns a description of the error code.
    pub const fn description(self) -> &'static str {
        match self {
            Self::UnsupportedDnskeyAlgorithm => {
                "The resolver attempted to perform DNSSEC validation but no signatures are present"
            }
            Self::UnsupportedDsDigestType => {
                "A DNSKEY RRset contained only unsupported DNSSEC algorithms"
            }
            Self::StaleAnswer => {
                "The resolver was unable to resolve within its time limits and is returning stale data"
            }
            Self::ForgedAnswer => "The resolver policy prohibits this answer",
            Self::DnssecIndeterminate => "DNSSEC validation could not determine validity",
            Self::DnssecBogus => "DNSSEC validation determined the answer is bogus",
            Self::SignatureExpired => "The DNSSEC signature has expired",
            Self::SignatureNotYetValid => "The DNSSEC signature is not yet valid",
            Self::DnskeyMissing => "Required DNSKEY record is missing",
            Self::RrsigsMissing => "Required RRSIG records are missing",
            Self::NoZoneKeyBitSet => "No DNSKEY has the Zone Key bit set",
            Self::NsecMissing => "Required NSEC/NSEC3 record is missing",
            Self::CachedError => "The answer is a cached previous error",
            Self::NotReady => "The server is not ready to serve this zone",
            Self::Blocked => "The query was blocked by policy",
            Self::Censored => "The query was blocked due to censorship",
            Self::Filtered => "The query was blocked by filtering policy",
            Self::Prohibited => "The query is prohibited by policy",
            Self::StaleNxdomainAnswer => "Returning stale NXDOMAIN answer",
            Self::NotAuthoritative => "The server is not authoritative for the zone",
            Self::NotSupported => "This operation is not supported",
            Self::NoReachableAuthority => "Unable to reach any authoritative servers",
            Self::NetworkError => "A network error occurred",
            Self::InvalidData => "The received data is invalid",
            Self::SignatureExpiredBeforeValid => "Signature expired before it became valid",
            Self::TooEarly => "Request arrived before the server was ready",
            Self::UnsupportedNsec3IterationsValue => "NSEC3 iterations value is not supported",
            Self::UnableToConformToPolicy => "Unable to conform to required policy",
            Self::Synthesized => "The answer was synthesized",
        }
    }

    /// Returns true if this error is DNSSEC-related.
    pub const fn is_dnssec_related(self) -> bool {
        matches!(
            self,
            Self::UnsupportedDnskeyAlgorithm
                | Self::UnsupportedDsDigestType
                | Self::DnssecIndeterminate
                | Self::DnssecBogus
                | Self::SignatureExpired
                | Self::SignatureNotYetValid
                | Self::DnskeyMissing
                | Self::RrsigsMissing
                | Self::NoZoneKeyBitSet
                | Self::NsecMissing
                | Self::SignatureExpiredBeforeValid
                | Self::UnsupportedNsec3IterationsValue
        )
    }

    /// Returns true if this is a blocking/filtering error.
    pub const fn is_blocking(self) -> bool {
        matches!(
            self,
            Self::Blocked | Self::Censored | Self::Filtered | Self::Prohibited
        )
    }

    /// Returns true if this is a stale data error.
    pub const fn is_stale(self) -> bool {
        matches!(self, Self::StaleAnswer | Self::StaleNxdomainAnswer)
    }
}

impl fmt::Display for EdeCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Extended DNS Error with optional extra text.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExtendedDnsError {
    /// The error code.
    code: EdeCode,

    /// Extra text information.
    text: Option<compact_str::CompactString>,
}

impl ExtendedDnsError {
    /// Creates a new Extended DNS Error.
    pub const fn new(code: EdeCode) -> Self {
        Self { code, text: None }
    }

    /// Creates an error with text.
    pub fn with_text(mut self, text: impl Into<compact_str::CompactString>) -> Self {
        self.text = Some(text.into());
        self
    }

    /// Returns the error code.
    pub const fn code(&self) -> EdeCode {
        self.code
    }

    /// Returns the code as u16.
    pub const fn code_u16(&self) -> u16 {
        self.code.to_u16()
    }

    /// Returns the extra text.
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// Sets the extra text.
    pub fn set_text(&mut self, text: impl Into<compact_str::CompactString>) {
        self.text = Some(text.into());
    }

    // Common error constructors

    /// Creates a "Blocked" error.
    pub fn blocked() -> Self {
        Self::new(EdeCode::Blocked)
    }

    /// Creates a "Filtered" error.
    pub fn filtered() -> Self {
        Self::new(EdeCode::Filtered)
    }

    /// Creates a "Stale Answer" error.
    pub fn stale_answer() -> Self {
        Self::new(EdeCode::StaleAnswer)
    }

    /// Creates a "Network Error" error.
    pub fn network_error() -> Self {
        Self::new(EdeCode::NetworkError)
    }

    /// Creates a "DNSSEC Bogus" error.
    pub fn dnssec_bogus() -> Self {
        Self::new(EdeCode::DnssecBogus)
    }

    /// Creates a "No Reachable Authority" error.
    pub fn no_reachable_authority() -> Self {
        Self::new(EdeCode::NoReachableAuthority)
    }
}

impl fmt::Display for ExtendedDnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EDE {}: {}", self.code.to_u16(), self.code.name())?;
        if let Some(text) = &self.text {
            write!(f, " ({})", text)?;
        }
        Ok(())
    }
}

impl From<EdeCode> for ExtendedDnsError {
    fn from(code: EdeCode) -> Self {
        Self::new(code)
    }
}

impl std::error::Error for ExtendedDnsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ede_code() {
        assert_eq!(EdeCode::Blocked.to_u16(), 15);
        assert_eq!(EdeCode::from_u16(15), Some(EdeCode::Blocked));
    }

    #[test]
    fn test_ede_classification() {
        assert!(EdeCode::DnssecBogus.is_dnssec_related());
        assert!(!EdeCode::NetworkError.is_dnssec_related());

        assert!(EdeCode::Blocked.is_blocking());
        assert!(EdeCode::Filtered.is_blocking());
        assert!(!EdeCode::NetworkError.is_blocking());

        assert!(EdeCode::StaleAnswer.is_stale());
    }

    #[test]
    fn test_extended_dns_error() {
        let err = ExtendedDnsError::blocked().with_text("domain is on blocklist");
        assert_eq!(err.code(), EdeCode::Blocked);
        assert_eq!(err.text(), Some("domain is on blocklist"));
    }

    #[test]
    fn test_ede_display() {
        let err = ExtendedDnsError::new(EdeCode::NetworkError).with_text("connection refused");
        let display = err.to_string();
        assert!(display.contains("23"));
        assert!(display.contains("Network Error"));
        assert!(display.contains("connection refused"));
    }
}
