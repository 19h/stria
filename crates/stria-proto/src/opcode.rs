//! DNS operation codes (OpCodes).
//!
//! OpCodes specify the kind of query in a DNS message header.
//! Defined in RFC 1035 Section 4.1.1 with extensions from subsequent RFCs.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

/// DNS operation code.
///
/// The OpCode field in the DNS header specifies the kind of query.
/// See RFC 1035 Section 4.1.1 and RFC 6895 for the complete registry.
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
#[repr(u8)]
pub enum OpCode {
    /// Standard query (QUERY) - RFC 1035
    ///
    /// A standard query contains questions for which answers are sought.
    Query = 0,

    /// Inverse query (IQUERY) - RFC 1035 (obsoleted by RFC 3425)
    ///
    /// An inverse query specifies a resource record and asks for the
    /// corresponding name. This is rarely used and officially obsolete.
    #[deprecated(note = "Obsoleted by RFC 3425")]
    IQuery = 1,

    /// Server status request (STATUS) - RFC 1035
    ///
    /// A status query requests server status information.
    Status = 2,

    /// Notify - RFC 1996
    ///
    /// A notify message is used by primary servers to inform secondary
    /// servers when zone data has changed and should be refreshed.
    Notify = 4,

    /// Update - RFC 2136
    ///
    /// A dynamic update message for modifying zone data.
    Update = 5,

    /// DNS Stateful Operations (DSO) - RFC 8490
    ///
    /// Used for establishing and maintaining stateful DNS sessions.
    Dso = 6,
}

impl OpCode {
    /// Returns the numeric value of the opcode.
    #[inline]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Creates an opcode from its numeric value.
    ///
    /// Returns `None` for reserved or unassigned values.
    #[inline]
    pub fn from_u8(value: u8) -> Option<Self> {
        Self::try_from(value).ok()
    }

    /// Returns true if this opcode expects a response.
    #[inline]
    pub const fn expects_response(self) -> bool {
        matches!(self, Self::Query | Self::Status | Self::Notify | Self::Update)
    }

    /// Returns the human-readable name of the opcode.
    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            #[allow(deprecated)]
            Self::Query => "QUERY",
            Self::IQuery => "IQUERY",
            Self::Status => "STATUS",
            Self::Notify => "NOTIFY",
            Self::Update => "UPDATE",
            Self::Dso => "DSO",
        }
    }
}

impl std::fmt::Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Default for OpCode {
    fn default() -> Self {
        Self::Query
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_values() {
        assert_eq!(OpCode::Query.to_u8(), 0);
        #[allow(deprecated)]
        {
            assert_eq!(OpCode::IQuery.to_u8(), 1);
        }
        assert_eq!(OpCode::Status.to_u8(), 2);
        assert_eq!(OpCode::Notify.to_u8(), 4);
        assert_eq!(OpCode::Update.to_u8(), 5);
        assert_eq!(OpCode::Dso.to_u8(), 6);
    }

    #[test]
    fn test_opcode_from_u8() {
        assert_eq!(OpCode::from_u8(0), Some(OpCode::Query));
        assert_eq!(OpCode::from_u8(4), Some(OpCode::Notify));
        assert_eq!(OpCode::from_u8(3), None); // Reserved
        assert_eq!(OpCode::from_u8(15), None);
    }

    #[test]
    fn test_opcode_display() {
        assert_eq!(OpCode::Query.to_string(), "QUERY");
        assert_eq!(OpCode::Update.to_string(), "UPDATE");
    }
}
