//! Authority record types (SOA).

use crate::error::{Error, Result};
use crate::name::{Name, NameParser};
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use std::fmt;

/// SOA record - Start of Authority (RFC 1035).
///
/// The SOA record provides information about the zone including:
/// - The primary name server
/// - The responsible person's email
/// - Zone serial number
/// - Timing parameters for zone transfers
///
/// # Wire Format
///
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /                     MNAME                     /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /                     RNAME                     /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    SERIAL                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    REFRESH                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     RETRY                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    EXPIRE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    MINIMUM                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SOA {
    /// Primary name server for the zone.
    mname: Name,
    /// Email of the responsible person (@ replaced with .).
    rname: Name,
    /// Zone serial number.
    serial: u32,
    /// Refresh interval (seconds).
    refresh: u32,
    /// Retry interval (seconds).
    retry: u32,
    /// Expire time (seconds).
    expire: u32,
    /// Minimum TTL / negative caching TTL (seconds).
    minimum: u32,
}

impl SOA {
    /// Creates a new SOA record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Self {
        Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    }

    /// Returns the primary name server.
    #[inline]
    pub fn mname(&self) -> &Name {
        &self.mname
    }

    /// Returns the responsible person's email (in DNS format).
    #[inline]
    pub fn rname(&self) -> &Name {
        &self.rname
    }

    /// Returns the email address as a string (with @ instead of .).
    pub fn email(&self) -> String {
        let rname_str = self.rname.to_string();
        // Find the first unescaped dot and replace it with @
        let mut result = String::with_capacity(rname_str.len());
        let mut chars = rname_str.chars().peekable();
        let mut found_at = false;

        while let Some(c) = chars.next() {
            if c == '\\' {
                // Escaped character
                result.push(c);
                if let Some(next) = chars.next() {
                    result.push(next);
                }
            } else if c == '.' && !found_at {
                // First unescaped dot becomes @
                result.push('@');
                found_at = true;
            } else {
                result.push(c);
            }
        }

        // Remove trailing dot if present
        if result.ends_with('.') {
            result.pop();
        }

        result
    }

    /// Returns the zone serial number.
    #[inline]
    pub const fn serial(&self) -> u32 {
        self.serial
    }

    /// Returns the refresh interval in seconds.
    #[inline]
    pub const fn refresh(&self) -> u32 {
        self.refresh
    }

    /// Returns the retry interval in seconds.
    #[inline]
    pub const fn retry(&self) -> u32 {
        self.retry
    }

    /// Returns the expire time in seconds.
    #[inline]
    pub const fn expire(&self) -> u32 {
        self.expire
    }

    /// Returns the minimum TTL (negative caching TTL) in seconds.
    #[inline]
    pub const fn minimum(&self) -> u32 {
        self.minimum
    }

    /// Returns the negative caching TTL per RFC 2308.
    ///
    /// This is the same as `minimum()` but with a more descriptive name.
    #[inline]
    pub const fn negative_ttl(&self) -> u32 {
        self.minimum
    }

    /// Parses an SOA record from wire format.
    pub fn parse(message: &[u8], offset: usize) -> Result<Self> {
        let parser = NameParser::new(message);

        let (mname, mname_len) = parser.parse_name(offset)?;
        let (rname, rname_len) = parser.parse_name(offset + mname_len)?;

        let nums_offset = offset + mname_len + rname_len;
        if nums_offset + 20 > message.len() {
            return Err(Error::buffer_too_short(nums_offset + 20, message.len()));
        }

        let serial = u32::from_be_bytes(message[nums_offset..nums_offset + 4].try_into().unwrap());
        let refresh = u32::from_be_bytes(
            message[nums_offset + 4..nums_offset + 8]
                .try_into()
                .unwrap(),
        );
        let retry = u32::from_be_bytes(
            message[nums_offset + 8..nums_offset + 12]
                .try_into()
                .unwrap(),
        );
        let expire = u32::from_be_bytes(
            message[nums_offset + 12..nums_offset + 16]
                .try_into()
                .unwrap(),
        );
        let minimum = u32::from_be_bytes(
            message[nums_offset + 16..nums_offset + 20]
                .try_into()
                .unwrap(),
        );

        Ok(Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        self.mname.wire_len() + self.rname.wire_len() + 20
    }

    /// Writes the SOA record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        self.mname.write_wire(buf);
        self.rname.write_wire(buf);
        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&self.refresh.to_be_bytes());
        buf.extend_from_slice(&self.retry.to_be_bytes());
        buf.extend_from_slice(&self.expire.to_be_bytes());
        buf.extend_from_slice(&self.minimum.to_be_bytes());
    }

    /// Checks if serial1 is "greater than" serial2 using RFC 1982 serial arithmetic.
    ///
    /// This handles wraparound correctly for 32-bit serial numbers.
    pub fn serial_gt(serial1: u32, serial2: u32) -> bool {
        if serial1 == serial2 {
            return false;
        }
        // RFC 1982: s1 > s2 iff (s1 < s2 and s2 - s1 > 2^31) or (s1 > s2 and s1 - s2 < 2^31)
        let diff = serial1.wrapping_sub(serial2);
        diff > 0 && diff < 0x8000_0000
    }

    /// Checks if this SOA's serial is newer than another using RFC 1982 arithmetic.
    pub fn is_newer_than(&self, other: &SOA) -> bool {
        Self::serial_gt(self.serial, other.serial)
    }
}

impl fmt::Display for SOA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {}",
            self.mname,
            self.rname,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_soa_record() {
        let soa = SOA::new(
            Name::from_str("ns1.example.com").unwrap(),
            Name::from_str("hostmaster.example.com").unwrap(),
            2024010101,
            3600,
            900,
            604800,
            86400,
        );

        assert_eq!(soa.mname().to_string(), "ns1.example.com.");
        assert_eq!(soa.rname().to_string(), "hostmaster.example.com.");
        assert_eq!(soa.serial(), 2024010101);
        assert_eq!(soa.refresh(), 3600);
        assert_eq!(soa.retry(), 900);
        assert_eq!(soa.expire(), 604800);
        assert_eq!(soa.minimum(), 86400);
    }

    #[test]
    fn test_soa_email() {
        let soa = SOA::new(
            Name::from_str("ns1.example.com").unwrap(),
            Name::from_str("hostmaster.example.com").unwrap(),
            1,
            3600,
            900,
            604800,
            86400,
        );

        assert_eq!(soa.email(), "hostmaster@example.com");
    }

    #[test]
    fn test_serial_arithmetic() {
        // Simple case
        assert!(SOA::serial_gt(2, 1));
        assert!(!SOA::serial_gt(1, 2));
        assert!(!SOA::serial_gt(1, 1));

        // Wraparound case
        assert!(SOA::serial_gt(1, 0xFFFF_FFFF));
        assert!(!SOA::serial_gt(0xFFFF_FFFF, 1));

        // Large difference
        assert!(!SOA::serial_gt(0, 0x8000_0000));
    }

    #[test]
    fn test_soa_display() {
        let soa = SOA::new(
            Name::from_str("ns1.example.com").unwrap(),
            Name::from_str("hostmaster.example.com").unwrap(),
            2024010101,
            3600,
            900,
            604800,
            86400,
        );

        let display = soa.to_string();
        assert!(display.contains("ns1.example.com"));
        assert!(display.contains("2024010101"));
    }
}
