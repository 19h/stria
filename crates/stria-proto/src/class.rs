//! DNS record classes.
//!
//! The class field identifies the protocol family of the resource record.
//! While multiple classes were envisioned, IN (Internet) is used almost exclusively.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use std::fmt;

/// DNS record class.
///
/// The CLASS field in DNS resource records identifies the protocol family.
/// See RFC 1035 Section 3.2.4 and RFC 6895 for the complete registry.
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
pub enum RecordClass {
    /// Internet - RFC 1035
    ///
    /// The Internet class is used for nearly all DNS queries and records.
    IN = 1,

    /// CSNET - RFC 1035 (obsolete)
    ///
    /// Used for the CSNET network, which no longer exists.
    #[deprecated(note = "Obsolete - CSNET no longer exists")]
    CS = 2,

    /// CHAOS - RFC 1035
    ///
    /// Used for the CHAOS network. Also used by some servers for
    /// special queries like `version.bind` and `hostname.bind`.
    CH = 3,

    /// Hesiod - RFC 1035
    ///
    /// Used for the Hesiod naming system from MIT Project Athena.
    HS = 4,

    /// Query class: NONE - RFC 2136
    ///
    /// Used in dynamic updates.
    NONE = 254,

    /// Query class: ANY - RFC 1035
    ///
    /// Matches any class. Only valid in queries, not in resource records.
    ANY = 255,
}

impl RecordClass {
    /// Returns the numeric value of the class.
    #[inline]
    pub const fn to_u16(self) -> u16 {
        self as u16
    }

    /// Creates a class from its numeric value.
    #[inline]
    pub fn from_u16(value: u16) -> Option<Self> {
        Self::try_from(value).ok()
    }

    /// Returns true if this is a query-only class (NONE or ANY).
    #[inline]
    pub const fn is_query_class(self) -> bool {
        matches!(self, Self::NONE | Self::ANY)
    }

    /// Returns true if this is the Internet class.
    #[inline]
    pub const fn is_internet(self) -> bool {
        matches!(self, Self::IN)
    }

    /// Returns the human-readable name of the class.
    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            Self::IN => "IN",
            #[allow(deprecated)]
            Self::CS => "CS",
            Self::CH => "CH",
            Self::HS => "HS",
            Self::NONE => "NONE",
            Self::ANY => "ANY",
        }
    }

    /// Returns a description of the class.
    #[inline]
    pub const fn description(self) -> &'static str {
        match self {
            Self::IN => "Internet",
            #[allow(deprecated)]
            Self::CS => "CSNET (obsolete)",
            Self::CH => "CHAOS",
            Self::HS => "Hesiod",
            Self::NONE => "None",
            Self::ANY => "Any class",
        }
    }
}

impl fmt::Display for RecordClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Default for RecordClass {
    fn default() -> Self {
        Self::IN
    }
}

/// A class value that can represent both standard classes and unknown values.
///
/// This allows handling of class values that may not be in the defined enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Class {
    /// A known, standard class.
    Known(RecordClass),
    /// An unknown class value.
    Unknown(u16),
}

impl Class {
    /// Creates a class from a u16 value.
    #[inline]
    pub fn from_u16(value: u16) -> Self {
        RecordClass::from_u16(value)
            .map(Self::Known)
            .unwrap_or(Self::Unknown(value))
    }

    /// Returns the numeric value.
    #[inline]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::Known(c) => c.to_u16(),
            Self::Unknown(v) => v,
        }
    }

    /// Returns the standard class if known.
    #[inline]
    pub const fn as_known(self) -> Option<RecordClass> {
        match self {
            Self::Known(c) => Some(c),
            Self::Unknown(_) => None,
        }
    }

    /// Returns true if this is the Internet class.
    #[inline]
    pub const fn is_internet(self) -> bool {
        matches!(self, Self::Known(RecordClass::IN))
    }
}

impl From<RecordClass> for Class {
    fn from(c: RecordClass) -> Self {
        Self::Known(c)
    }
}

impl From<u16> for Class {
    fn from(value: u16) -> Self {
        Self::from_u16(value)
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(c) => write!(f, "{c}"),
            Self::Unknown(v) => write!(f, "CLASS{v}"),
        }
    }
}

impl Default for Class {
    fn default() -> Self {
        Self::Known(RecordClass::IN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_class_values() {
        assert_eq!(RecordClass::IN.to_u16(), 1);
        assert_eq!(RecordClass::CH.to_u16(), 3);
        assert_eq!(RecordClass::ANY.to_u16(), 255);
    }

    #[test]
    fn test_class_from_u16() {
        assert_eq!(RecordClass::from_u16(1), Some(RecordClass::IN));
        assert_eq!(RecordClass::from_u16(255), Some(RecordClass::ANY));
        assert_eq!(RecordClass::from_u16(1000), None);
    }

    #[test]
    fn test_class_predicates() {
        assert!(RecordClass::IN.is_internet());
        assert!(!RecordClass::CH.is_internet());
        assert!(RecordClass::ANY.is_query_class());
        assert!(!RecordClass::IN.is_query_class());
    }

    #[test]
    fn test_generic_class() {
        let c = Class::from_u16(1);
        assert!(c.is_internet());
        assert_eq!(c.as_known(), Some(RecordClass::IN));

        let c = Class::from_u16(12345);
        assert!(!c.is_internet());
        assert_eq!(c.as_known(), None);
        assert_eq!(c.to_string(), "CLASS12345");
    }
}
