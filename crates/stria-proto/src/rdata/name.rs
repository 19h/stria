//! Name-based record types (NS, CNAME, PTR, DNAME, MX).

use crate::error::{Error, Result};
use crate::name::{Name, NameParser};
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use std::fmt;

/// NS record - Name server (RFC 1035).
///
/// The NS record specifies an authoritative name server for the domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NS {
    /// The name server domain name.
    nsdname: Name,
}

impl NS {
    /// Creates a new NS record.
    #[inline]
    pub fn new(nsdname: Name) -> Self {
        Self { nsdname }
    }

    /// Returns the name server name.
    #[inline]
    pub fn nsdname(&self) -> &Name {
        &self.nsdname
    }

    /// Parses an NS record from wire format.
    pub fn parse(message: &[u8], offset: usize) -> Result<Self> {
        let parser = NameParser::new(message);
        let (nsdname, _) = parser.parse_name(offset)?;
        Ok(Self { nsdname })
    }

    /// Returns the wire format length.
    #[inline]
    pub fn wire_len(&self) -> usize {
        self.nsdname.wire_len()
    }

    /// Writes the NS record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        self.nsdname.write_wire(buf);
    }
}

impl fmt::Display for NS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.nsdname)
    }
}

/// CNAME record - Canonical name (RFC 1035).
///
/// The CNAME record specifies that the domain name is an alias for another name.
/// When a resolver encounters a CNAME, it should restart the query with the canonical name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CNAME {
    /// The canonical domain name.
    cname: Name,
}

impl CNAME {
    /// Creates a new CNAME record.
    #[inline]
    pub fn new(cname: Name) -> Self {
        Self { cname }
    }

    /// Returns the canonical name (target).
    #[inline]
    pub fn target(&self) -> &Name {
        &self.cname
    }

    /// Parses a CNAME record from wire format.
    pub fn parse(message: &[u8], offset: usize) -> Result<Self> {
        let parser = NameParser::new(message);
        let (cname, _) = parser.parse_name(offset)?;
        Ok(Self { cname })
    }

    /// Returns the wire format length.
    #[inline]
    pub fn wire_len(&self) -> usize {
        self.cname.wire_len()
    }

    /// Writes the CNAME record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        self.cname.write_wire(buf);
    }
}

impl fmt::Display for CNAME {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.cname)
    }
}

/// PTR record - Pointer (RFC 1035).
///
/// The PTR record is used for reverse DNS lookups, mapping an IP address
/// back to a domain name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PTR {
    /// The pointed-to domain name.
    ptrdname: Name,
}

impl PTR {
    /// Creates a new PTR record.
    #[inline]
    pub fn new(ptrdname: Name) -> Self {
        Self { ptrdname }
    }

    /// Returns the pointed-to domain name.
    #[inline]
    pub fn ptrdname(&self) -> &Name {
        &self.ptrdname
    }

    /// Parses a PTR record from wire format.
    pub fn parse(message: &[u8], offset: usize) -> Result<Self> {
        let parser = NameParser::new(message);
        let (ptrdname, _) = parser.parse_name(offset)?;
        Ok(Self { ptrdname })
    }

    /// Returns the wire format length.
    #[inline]
    pub fn wire_len(&self) -> usize {
        self.ptrdname.wire_len()
    }

    /// Writes the PTR record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        self.ptrdname.write_wire(buf);
    }
}

impl fmt::Display for PTR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.ptrdname)
    }
}

/// DNAME record - Delegation name (RFC 6672).
///
/// The DNAME record provides redirection for a subtree of the domain name tree.
/// Unlike CNAME which is for a single name, DNAME applies to all names in a subtree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DNAME {
    /// The target domain name.
    target: Name,
}

impl DNAME {
    /// Creates a new DNAME record.
    #[inline]
    pub fn new(target: Name) -> Self {
        Self { target }
    }

    /// Returns the target domain name.
    #[inline]
    pub fn target(&self) -> &Name {
        &self.target
    }

    /// Parses a DNAME record from wire format.
    pub fn parse(message: &[u8], offset: usize) -> Result<Self> {
        let parser = NameParser::new(message);
        let (target, _) = parser.parse_name(offset)?;
        Ok(Self { target })
    }

    /// Returns the wire format length.
    #[inline]
    pub fn wire_len(&self) -> usize {
        self.target.wire_len()
    }

    /// Writes the DNAME record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        self.target.write_wire(buf);
    }

    /// Applies this DNAME to a query name to compute the synthesized CNAME target.
    ///
    /// Given a query for `child.source.example.` and a DNAME at `source.example.`
    /// pointing to `target.example.`, this returns `child.target.example.`.
    pub fn synthesize_cname(&self, qname: &Name, owner: &Name) -> Option<Name> {
        // Check that qname is a subdomain of owner
        if !qname.is_subdomain_of(owner) || qname == owner {
            return None;
        }

        // Get the labels of qname that are not part of owner
        let qname_labels: Vec<_> = qname.labels().collect();
        let owner_labels: Vec<_> = owner.labels().collect();

        // Number of labels to preserve from qname
        let extra_labels = qname_labels.len() - owner_labels.len();

        // Build the new name by prepending extra labels to target
        let mut result = self.target.clone();
        for i in (0..extra_labels).rev() {
            result = result.prepend_label(&qname_labels[i].to_string()).ok()?;
        }

        Some(result)
    }
}

impl fmt::Display for DNAME {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.target)
    }
}

/// MX record - Mail exchange (RFC 1035).
///
/// The MX record specifies a mail server responsible for accepting email
/// messages on behalf of a domain name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MX {
    /// The preference (lower is more preferred).
    preference: u16,
    /// The mail exchange domain name.
    exchange: Name,
}

impl MX {
    /// Creates a new MX record.
    #[inline]
    pub fn new(preference: u16, exchange: Name) -> Self {
        Self {
            preference,
            exchange,
        }
    }

    /// Returns the preference value.
    #[inline]
    pub const fn preference(&self) -> u16 {
        self.preference
    }

    /// Returns the mail exchange domain name.
    #[inline]
    pub fn exchange(&self) -> &Name {
        &self.exchange
    }

    /// Parses an MX record from wire format.
    pub fn parse(message: &[u8], offset: usize) -> Result<Self> {
        if offset + 2 > message.len() {
            return Err(Error::buffer_too_short(offset + 2, message.len()));
        }

        let preference = u16::from_be_bytes([message[offset], message[offset + 1]]);

        let parser = NameParser::new(message);
        let (exchange, _) = parser.parse_name(offset + 2)?;

        Ok(Self {
            preference,
            exchange,
        })
    }

    /// Returns the wire format length.
    #[inline]
    pub fn wire_len(&self) -> usize {
        2 + self.exchange.wire_len()
    }

    /// Writes the MX record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.preference.to_be_bytes());
        self.exchange.write_wire(buf);
    }
}

impl fmt::Display for MX {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchange)
    }
}

impl PartialOrd for MX {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MX {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Lower preference = higher priority
        self.preference.cmp(&other.preference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ns_record() {
        let ns = NS::new(Name::from_str("ns1.example.com").unwrap());
        assert_eq!(ns.nsdname().to_string(), "ns1.example.com.");
    }

    #[test]
    fn test_cname_record() {
        let cname = CNAME::new(Name::from_str("www.example.com").unwrap());
        assert_eq!(cname.target().to_string(), "www.example.com.");
    }

    #[test]
    fn test_ptr_record() {
        let ptr = PTR::new(Name::from_str("host.example.com").unwrap());
        assert_eq!(ptr.ptrdname().to_string(), "host.example.com.");
    }

    #[test]
    fn test_mx_record() {
        let mx = MX::new(10, Name::from_str("mail.example.com").unwrap());
        assert_eq!(mx.preference(), 10);
        assert_eq!(mx.exchange().to_string(), "mail.example.com.");
        assert_eq!(mx.to_string(), "10 mail.example.com.");
    }

    #[test]
    fn test_mx_ordering() {
        let mx1 = MX::new(10, Name::from_str("mail1.example.com").unwrap());
        let mx2 = MX::new(20, Name::from_str("mail2.example.com").unwrap());
        let mx3 = MX::new(10, Name::from_str("mail3.example.com").unwrap());

        assert!(mx1 < mx2);
        assert_eq!(mx1.cmp(&mx3), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_dname_synthesize() {
        let dname = DNAME::new(Name::from_str("target.example").unwrap());
        let owner = Name::from_str("source.example").unwrap();

        // Query for child.source.example should be redirected to child.target.example
        let qname = Name::from_str("child.source.example").unwrap();
        let result = dname.synthesize_cname(&qname, &owner);
        assert_eq!(result.unwrap().to_string(), "child.target.example.");

        // Query for grandchild.child.source.example
        let qname2 = Name::from_str("grandchild.child.source.example").unwrap();
        let result2 = dname.synthesize_cname(&qname2, &owner);
        assert_eq!(
            result2.unwrap().to_string(),
            "grandchild.child.target.example."
        );

        // Query for the owner itself should not match
        let result3 = dname.synthesize_cname(&owner, &owner);
        assert!(result3.is_none());
    }
}
