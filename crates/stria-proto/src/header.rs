//! DNS message header.
//!
//! The DNS header is a fixed 12-byte structure at the start of every DNS message.
//! It contains control information and counts of the sections that follow.

use crate::error::{Error, Result};
use crate::opcode::OpCode;
use crate::rcode::ResponseCode;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Size of the DNS header in bytes.
pub const HEADER_SIZE: usize = 12;

bitflags! {
    /// DNS header flags.
    ///
    /// These flags control various aspects of DNS message processing
    /// and indicate the status of the response.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct HeaderFlags: u16 {
        /// Query/Response flag: 0 = query, 1 = response
        const QR = 0x8000;

        /// Authoritative Answer: server is authoritative for the domain
        const AA = 0x0400;

        /// Truncation: message was truncated
        const TC = 0x0200;

        /// Recursion Desired: client wants recursive resolution
        const RD = 0x0100;

        /// Recursion Available: server supports recursion
        const RA = 0x0080;

        /// Reserved for future use (must be zero)
        const Z = 0x0040;

        /// Authentic Data: response data is authenticated (DNSSEC)
        const AD = 0x0020;

        /// Checking Disabled: disable DNSSEC validation
        const CD = 0x0010;
    }
}

impl Default for HeaderFlags {
    fn default() -> Self {
        Self::empty()
    }
}

/// DNS message header.
///
/// The header contains:
/// - A 16-bit message ID for matching requests to responses
/// - Flags indicating query/response, opcode, response status, etc.
/// - Counts of questions, answers, authority records, and additional records
///
/// # Wire Format
///
/// ```text
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Message identifier for matching requests to responses.
    pub id: u16,

    /// Query/Response flag and other flags.
    pub flags: HeaderFlags,

    /// Operation code.
    pub opcode: OpCode,

    /// Response code (4-bit, extended with EDNS0).
    pub rcode: ResponseCode,

    /// Number of questions.
    pub qd_count: u16,

    /// Number of answer records.
    pub an_count: u16,

    /// Number of authority records.
    pub ns_count: u16,

    /// Number of additional records.
    pub ar_count: u16,
}

impl Header {
    /// Creates a new header with the given message ID.
    #[inline]
    pub const fn new(id: u16) -> Self {
        Self {
            id,
            flags: HeaderFlags::empty(),
            opcode: OpCode::Query,
            rcode: ResponseCode::NoError,
            qd_count: 0,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }

    /// Creates a new query header with a random ID.
    pub fn query() -> Self {
        Self {
            id: rand::random(),
            flags: HeaderFlags::RD, // Request recursion by default
            opcode: OpCode::Query,
            rcode: ResponseCode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }

    /// Creates a response header from a query header.
    pub fn response_from(query: &Header) -> Self {
        Self {
            id: query.id,
            flags: HeaderFlags::QR | (query.flags & HeaderFlags::RD),
            opcode: query.opcode,
            rcode: ResponseCode::NoError,
            qd_count: query.qd_count,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }

    /// Returns true if this is a query.
    #[inline]
    pub fn is_query(&self) -> bool {
        !self.flags.contains(HeaderFlags::QR)
    }

    /// Returns true if this is a response.
    #[inline]
    pub fn is_response(&self) -> bool {
        self.flags.contains(HeaderFlags::QR)
    }

    /// Returns true if the response is from an authoritative server.
    #[inline]
    pub fn is_authoritative(&self) -> bool {
        self.flags.contains(HeaderFlags::AA)
    }

    /// Returns true if the message was truncated.
    #[inline]
    pub fn is_truncated(&self) -> bool {
        self.flags.contains(HeaderFlags::TC)
    }

    /// Returns true if recursion was requested.
    #[inline]
    pub fn recursion_desired(&self) -> bool {
        self.flags.contains(HeaderFlags::RD)
    }

    /// Returns true if recursion is available.
    #[inline]
    pub fn recursion_available(&self) -> bool {
        self.flags.contains(HeaderFlags::RA)
    }

    /// Returns true if the response data is authenticated (DNSSEC).
    #[inline]
    pub fn is_authentic_data(&self) -> bool {
        self.flags.contains(HeaderFlags::AD)
    }

    /// Returns true if DNSSEC checking is disabled.
    #[inline]
    pub fn checking_disabled(&self) -> bool {
        self.flags.contains(HeaderFlags::CD)
    }

    /// Sets the QR flag (marks as response).
    #[inline]
    pub fn set_response(&mut self, response: bool) {
        if response {
            self.flags.insert(HeaderFlags::QR);
        } else {
            self.flags.remove(HeaderFlags::QR);
        }
    }

    /// Sets the AA flag.
    #[inline]
    pub fn set_authoritative(&mut self, aa: bool) {
        if aa {
            self.flags.insert(HeaderFlags::AA);
        } else {
            self.flags.remove(HeaderFlags::AA);
        }
    }

    /// Sets the TC flag.
    #[inline]
    pub fn set_truncated(&mut self, tc: bool) {
        if tc {
            self.flags.insert(HeaderFlags::TC);
        } else {
            self.flags.remove(HeaderFlags::TC);
        }
    }

    /// Sets the RD flag.
    #[inline]
    pub fn set_recursion_desired(&mut self, rd: bool) {
        if rd {
            self.flags.insert(HeaderFlags::RD);
        } else {
            self.flags.remove(HeaderFlags::RD);
        }
    }

    /// Sets the RA flag.
    #[inline]
    pub fn set_recursion_available(&mut self, ra: bool) {
        if ra {
            self.flags.insert(HeaderFlags::RA);
        } else {
            self.flags.remove(HeaderFlags::RA);
        }
    }

    /// Sets the AD flag.
    #[inline]
    pub fn set_authentic_data(&mut self, ad: bool) {
        if ad {
            self.flags.insert(HeaderFlags::AD);
        } else {
            self.flags.remove(HeaderFlags::AD);
        }
    }

    /// Sets the CD flag.
    #[inline]
    pub fn set_checking_disabled(&mut self, cd: bool) {
        if cd {
            self.flags.insert(HeaderFlags::CD);
        } else {
            self.flags.remove(HeaderFlags::CD);
        }
    }

    /// Returns the total record count across all sections.
    #[inline]
    pub fn total_record_count(&self) -> usize {
        self.an_count as usize + self.ns_count as usize + self.ar_count as usize
    }

    /// Parses a header from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::buffer_too_short(HEADER_SIZE, data.len()));
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags_raw = u16::from_be_bytes([data[2], data[3]]);

        // Extract opcode (bits 11-14)
        let opcode_value = ((flags_raw >> 11) & 0x0F) as u8;
        let opcode = OpCode::from_u8(opcode_value)
            .ok_or(Error::InvalidOpCode { value: opcode_value })?;

        // Extract rcode (bits 0-3)
        let rcode_value = (flags_raw & 0x0F) as u16;
        let rcode = ResponseCode::from_header(rcode_value as u8)
            .ok_or(Error::InvalidResponseCode { value: rcode_value })?;

        // Extract flags (mask out opcode and rcode)
        let flags_mask = HeaderFlags::QR.bits()
            | HeaderFlags::AA.bits()
            | HeaderFlags::TC.bits()
            | HeaderFlags::RD.bits()
            | HeaderFlags::RA.bits()
            | HeaderFlags::Z.bits()
            | HeaderFlags::AD.bits()
            | HeaderFlags::CD.bits();
        let flags = HeaderFlags::from_bits_truncate(flags_raw & flags_mask);

        let qd_count = u16::from_be_bytes([data[4], data[5]]);
        let an_count = u16::from_be_bytes([data[6], data[7]]);
        let ns_count = u16::from_be_bytes([data[8], data[9]]);
        let ar_count = u16::from_be_bytes([data[10], data[11]]);

        Ok(Self {
            id,
            flags,
            opcode,
            rcode,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        })
    }

    /// Serializes the header to wire format.
    pub fn to_wire(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];

        buf[0..2].copy_from_slice(&self.id.to_be_bytes());

        // Build flags word
        let mut flags_raw = self.flags.bits();
        flags_raw |= (self.opcode.to_u8() as u16) << 11;
        flags_raw |= self.rcode.header_rcode() as u16;

        buf[2..4].copy_from_slice(&flags_raw.to_be_bytes());
        buf[4..6].copy_from_slice(&self.qd_count.to_be_bytes());
        buf[6..8].copy_from_slice(&self.an_count.to_be_bytes());
        buf[8..10].copy_from_slice(&self.ns_count.to_be_bytes());
        buf[10..12].copy_from_slice(&self.ar_count.to_be_bytes());

        buf
    }

    /// Writes the header to a buffer.
    pub fn write_to(&self, buf: &mut bytes::BytesMut) {
        buf.extend_from_slice(&self.to_wire());
    }
}

impl Default for Header {
    fn default() -> Self {
        Self::new(0)
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ID:{:04X} {} {} {}",
            self.id,
            if self.is_query() { "QR" } else { "RD" },
            self.opcode,
            self.rcode
        )?;

        if self.is_authoritative() {
            write!(f, " AA")?;
        }
        if self.is_truncated() {
            write!(f, " TC")?;
        }
        if self.recursion_desired() {
            write!(f, " RD")?;
        }
        if self.recursion_available() {
            write!(f, " RA")?;
        }
        if self.is_authentic_data() {
            write!(f, " AD")?;
        }
        if self.checking_disabled() {
            write!(f, " CD")?;
        }

        write!(
            f,
            " QD:{} AN:{} NS:{} AR:{}",
            self.qd_count, self.an_count, self.ns_count, self.ar_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let mut header = Header::query();
        header.id = 0x1234;
        header.opcode = OpCode::Query;
        header.set_recursion_desired(true);
        header.qd_count = 1;

        let wire = header.to_wire();
        let parsed = Header::parse(&wire).unwrap();

        assert_eq!(header.id, parsed.id);
        assert_eq!(header.opcode, parsed.opcode);
        assert_eq!(header.recursion_desired(), parsed.recursion_desired());
        assert_eq!(header.qd_count, parsed.qd_count);
    }

    #[test]
    fn test_header_flags() {
        let mut header = Header::new(0);

        header.set_response(true);
        assert!(header.is_response());
        assert!(!header.is_query());

        header.set_authoritative(true);
        assert!(header.is_authoritative());

        header.set_truncated(true);
        assert!(header.is_truncated());

        header.set_authentic_data(true);
        assert!(header.is_authentic_data());
    }

    #[test]
    fn test_header_parse_too_short() {
        let result = Header::parse(&[0; 10]);
        assert!(matches!(result, Err(Error::BufferTooShort { .. })));
    }

    #[test]
    fn test_response_from_query() {
        let query = Header::query();
        let response = Header::response_from(&query);

        assert_eq!(query.id, response.id);
        assert!(query.is_query());
        assert!(response.is_response());
        assert_eq!(query.recursion_desired(), response.recursion_desired());
    }

    #[test]
    fn test_header_display() {
        let mut header = Header::query();
        header.id = 0xABCD;
        header.set_authoritative(true);

        let display = header.to_string();
        assert!(display.contains("ABCD"));
        assert!(display.contains("QUERY"));
    }
}
