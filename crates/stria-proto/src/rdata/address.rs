//! Address record types (A, AAAA).

use crate::error::{Error, Result};
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A record - IPv4 address (RFC 1035).
///
/// The A record maps a domain name to an IPv4 address.
///
/// # Wire Format
///
/// The RDATA is exactly 4 bytes containing the IPv4 address in network byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct A {
    /// The IPv4 address.
    address: Ipv4Addr,
}

impl A {
    /// Creates a new A record.
    #[inline]
    pub const fn new(address: Ipv4Addr) -> Self {
        Self { address }
    }

    /// Returns the IPv4 address.
    #[inline]
    pub const fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Parses an A record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 4 {
            return Err(Error::RDataLengthMismatch {
                rtype: "A".to_string(),
                expected: 4,
                actual: data.len(),
            });
        }

        let octets: [u8; 4] = data[..4].try_into().unwrap();
        Ok(Self {
            address: Ipv4Addr::from(octets),
        })
    }

    /// Returns the wire format length (always 4).
    #[inline]
    pub const fn wire_len(&self) -> usize {
        4
    }

    /// Writes the A record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.address.octets());
    }
}

impl From<Ipv4Addr> for A {
    fn from(address: Ipv4Addr) -> Self {
        Self::new(address)
    }
}

impl From<A> for Ipv4Addr {
    fn from(a: A) -> Self {
        a.address
    }
}

impl From<[u8; 4]> for A {
    fn from(octets: [u8; 4]) -> Self {
        Self::new(Ipv4Addr::from(octets))
    }
}

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

/// AAAA record - IPv6 address (RFC 3596).
///
/// The AAAA record maps a domain name to an IPv6 address.
///
/// # Wire Format
///
/// The RDATA is exactly 16 bytes containing the IPv6 address in network byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AAAA {
    /// The IPv6 address.
    address: Ipv6Addr,
}

impl AAAA {
    /// Creates a new AAAA record.
    #[inline]
    pub const fn new(address: Ipv6Addr) -> Self {
        Self { address }
    }

    /// Returns the IPv6 address.
    #[inline]
    pub const fn address(&self) -> Ipv6Addr {
        self.address
    }

    /// Parses an AAAA record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 16 {
            return Err(Error::RDataLengthMismatch {
                rtype: "AAAA".to_string(),
                expected: 16,
                actual: data.len(),
            });
        }

        let octets: [u8; 16] = data[..16].try_into().unwrap();
        Ok(Self {
            address: Ipv6Addr::from(octets),
        })
    }

    /// Returns the wire format length (always 16).
    #[inline]
    pub const fn wire_len(&self) -> usize {
        16
    }

    /// Writes the AAAA record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.address.octets());
    }

    /// Returns true if this is a link-local address.
    #[inline]
    pub fn is_link_local(&self) -> bool {
        // fe80::/10
        let segments = self.address.segments();
        (segments[0] & 0xffc0) == 0xfe80
    }

    /// Returns true if this is a loopback address.
    #[inline]
    pub fn is_loopback(&self) -> bool {
        self.address == Ipv6Addr::LOCALHOST
    }

    /// Returns true if this is an IPv4-mapped IPv6 address.
    #[inline]
    pub fn is_ipv4_mapped(&self) -> bool {
        matches!(self.address.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
    }

    /// Converts an IPv4-mapped address to IPv4, if applicable.
    pub fn to_ipv4_mapped(&self) -> Option<Ipv4Addr> {
        if self.is_ipv4_mapped() {
            let segments = self.address.segments();
            Some(Ipv4Addr::new(
                (segments[6] >> 8) as u8,
                segments[6] as u8,
                (segments[7] >> 8) as u8,
                segments[7] as u8,
            ))
        } else {
            None
        }
    }
}

impl From<Ipv6Addr> for AAAA {
    fn from(address: Ipv6Addr) -> Self {
        Self::new(address)
    }
}

impl From<AAAA> for Ipv6Addr {
    fn from(aaaa: AAAA) -> Self {
        aaaa.address
    }
}

impl From<[u8; 16]> for AAAA {
    fn from(octets: [u8; 16]) -> Self {
        Self::new(Ipv6Addr::from(octets))
    }
}

impl fmt::Display for AAAA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_record() {
        let a = A::new(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(a.address(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(a.wire_len(), 4);
        assert_eq!(a.to_string(), "192.0.2.1");
    }

    #[test]
    fn test_a_parse() {
        let data = [192, 0, 2, 1];
        let a = A::parse(&data).unwrap();
        assert_eq!(a.address(), Ipv4Addr::new(192, 0, 2, 1));
    }

    #[test]
    fn test_a_roundtrip() {
        let original = A::new(Ipv4Addr::new(10, 0, 0, 1));
        let mut buf = BytesMut::new();
        original.write_to(&mut buf);
        let parsed = A::parse(&buf).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_aaaa_record() {
        let aaaa = AAAA::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(aaaa.wire_len(), 16);
        assert_eq!(aaaa.to_string(), "2001:db8::1");
    }

    #[test]
    fn test_aaaa_parse() {
        let data: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let aaaa = AAAA::parse(&data).unwrap();
        assert_eq!(
            aaaa.address(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
        );
    }

    #[test]
    fn test_aaaa_roundtrip() {
        let original = AAAA::new(Ipv6Addr::LOCALHOST);
        let mut buf = BytesMut::new();
        original.write_to(&mut buf);
        let parsed = AAAA::parse(&buf).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_aaaa_ipv4_mapped() {
        let aaaa = AAAA::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201));
        assert!(aaaa.is_ipv4_mapped());
        assert_eq!(aaaa.to_ipv4_mapped(), Some(Ipv4Addr::new(192, 0, 2, 1)));
    }
}
