//! Unknown/opaque record type handling.

use crate::error::Result;
use bytes::BytesMut;
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Unknown record type - preserves raw RDATA.
///
/// This represents record types that don't have explicit parsing support.
/// The raw RDATA is preserved and can be serialized back to wire format.
///
/// Per RFC 3597, unknown record types should be rendered in the format:
/// `\# <length> <hex-data>`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Unknown {
    /// The record type code.
    type_code: u16,
    /// The raw RDATA bytes.
    data: Vec<u8>,
}

impl Unknown {
    /// Creates a new unknown record type.
    pub fn new(type_code: u16, data: impl Into<Vec<u8>>) -> Self {
        Self {
            type_code,
            data: data.into(),
        }
    }

    /// Returns the record type code.
    #[inline]
    pub const fn type_code(&self) -> u16 {
        self.type_code
    }

    /// Returns the raw RDATA.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the RDATA as a hex string.
    pub fn data_hex(&self) -> String {
        HEXLOWER.encode(&self.data)
    }

    /// Parses an unknown record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        Ok(Self {
            type_code: 0, // Will be set by caller
            data: data.to_vec(),
        })
    }

    /// Returns the wire format length.
    #[inline]
    pub fn wire_len(&self) -> usize {
        self.data.len()
    }

    /// Writes the unknown record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.data);
    }
}

impl fmt::Display for Unknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // RFC 3597 format: \# <length> <hex>
        write!(f, "\\# {} {}", self.data.len(), self.data_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_record() {
        let unknown = Unknown::new(65534, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(unknown.type_code(), 65534);
        assert_eq!(unknown.data(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(unknown.data_hex(), "01020304");
    }

    #[test]
    fn test_unknown_display() {
        let unknown = Unknown::new(65534, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(unknown.to_string(), "\\# 4 deadbeef");
    }

    #[test]
    fn test_unknown_roundtrip() {
        let original = Unknown::new(12345, vec![0x01, 0x02, 0x03]);
        let mut buf = BytesMut::new();
        original.write_to(&mut buf);
        assert_eq!(buf.as_ref(), &[0x01, 0x02, 0x03]);
    }
}
