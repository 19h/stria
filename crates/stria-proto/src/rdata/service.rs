//! Service-related record types (SRV, NAPTR, SVCB, HTTPS, CAA).

use crate::error::{Error, Result};
use crate::name::{Name, NameParser};
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// SRV record - Service locator (RFC 2782).
///
/// The SRV record specifies the location of services. It's used by protocols
/// like SIP, XMPP, and LDAP to find service endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SRV {
    /// Priority (lower is more preferred).
    priority: u16,
    /// Weight for load balancing among equal priority.
    weight: u16,
    /// TCP/UDP port number.
    port: u16,
    /// Target host name.
    target: Name,
}

impl SRV {
    /// Creates a new SRV record.
    pub fn new(priority: u16, weight: u16, port: u16, target: Name) -> Self {
        Self {
            priority,
            weight,
            port,
            target,
        }
    }

    /// Returns the priority (lower = more preferred).
    #[inline]
    pub const fn priority(&self) -> u16 {
        self.priority
    }

    /// Returns the weight for load balancing.
    #[inline]
    pub const fn weight(&self) -> u16 {
        self.weight
    }

    /// Returns the port number.
    #[inline]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the target host name.
    #[inline]
    pub fn target(&self) -> &Name {
        &self.target
    }

    /// Returns true if this SRV indicates the service is not available.
    ///
    /// Per RFC 2782, a target of "." means the service is not available.
    pub fn is_unavailable(&self) -> bool {
        self.target.is_root()
    }

    /// Parses an SRV record from wire format.
    pub fn parse(message: &[u8], offset: usize) -> Result<Self> {
        if offset + 6 > message.len() {
            return Err(Error::buffer_too_short(offset + 6, message.len()));
        }

        let priority = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let weight = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        let port = u16::from_be_bytes([message[offset + 4], message[offset + 5]]);

        let parser = NameParser::new(message);
        let (target, _) = parser.parse_name(offset + 6)?;

        Ok(Self {
            priority,
            weight,
            port,
            target,
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        6 + self.target.wire_len()
    }

    /// Writes the SRV record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.priority.to_be_bytes());
        buf.extend_from_slice(&self.weight.to_be_bytes());
        buf.extend_from_slice(&self.port.to_be_bytes());
        self.target.write_wire(buf);
    }
}

impl fmt::Display for SRV {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.priority, self.weight, self.port, self.target
        )
    }
}

/// NAPTR record - Naming Authority Pointer (RFC 3403).
///
/// The NAPTR record is used for URI scheme routing and other DDDS applications.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NAPTR {
    /// Order (lower = processed first).
    order: u16,
    /// Preference among equal order values.
    preference: u16,
    /// Flags controlling interpretation.
    flags: Vec<u8>,
    /// Service field.
    service: Vec<u8>,
    /// Regular expression for rewriting.
    regexp: Vec<u8>,
    /// Replacement domain name.
    replacement: Name,
}

impl NAPTR {
    /// Creates a new NAPTR record.
    pub fn new(
        order: u16,
        preference: u16,
        flags: impl Into<Vec<u8>>,
        service: impl Into<Vec<u8>>,
        regexp: impl Into<Vec<u8>>,
        replacement: Name,
    ) -> Self {
        Self {
            order,
            preference,
            flags: flags.into(),
            service: service.into(),
            regexp: regexp.into(),
            replacement,
        }
    }

    /// Returns the order value.
    #[inline]
    pub const fn order(&self) -> u16 {
        self.order
    }

    /// Returns the preference value.
    #[inline]
    pub const fn preference(&self) -> u16 {
        self.preference
    }

    /// Returns the flags.
    pub fn flags(&self) -> &[u8] {
        &self.flags
    }

    /// Returns the service field.
    pub fn service(&self) -> &[u8] {
        &self.service
    }

    /// Returns the regexp.
    pub fn regexp(&self) -> &[u8] {
        &self.regexp
    }

    /// Returns the replacement domain.
    pub fn replacement(&self) -> &Name {
        &self.replacement
    }

    /// Parses a NAPTR record from wire format.
    pub fn parse(message: &[u8], offset: usize, rdlength: u16) -> Result<Self> {
        if offset + 4 > message.len() {
            return Err(Error::buffer_too_short(offset + 4, message.len()));
        }

        let order = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let preference = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);

        let mut pos = offset + 4;

        // Flags
        if pos >= message.len() {
            return Err(Error::unexpected_eof(pos));
        }
        let flags_len = message[pos] as usize;
        pos += 1;
        if pos + flags_len > message.len() {
            return Err(Error::unexpected_eof(pos + flags_len));
        }
        let flags = message[pos..pos + flags_len].to_vec();
        pos += flags_len;

        // Service
        if pos >= message.len() {
            return Err(Error::unexpected_eof(pos));
        }
        let service_len = message[pos] as usize;
        pos += 1;
        if pos + service_len > message.len() {
            return Err(Error::unexpected_eof(pos + service_len));
        }
        let service = message[pos..pos + service_len].to_vec();
        pos += service_len;

        // Regexp
        if pos >= message.len() {
            return Err(Error::unexpected_eof(pos));
        }
        let regexp_len = message[pos] as usize;
        pos += 1;
        if pos + regexp_len > message.len() {
            return Err(Error::unexpected_eof(pos + regexp_len));
        }
        let regexp = message[pos..pos + regexp_len].to_vec();
        pos += regexp_len;

        // Replacement
        let parser = NameParser::new(message);
        let (replacement, _) = parser.parse_name(pos)?;

        Ok(Self {
            order,
            preference,
            flags,
            service,
            regexp,
            replacement,
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        4 + 1
            + self.flags.len()
            + 1
            + self.service.len()
            + 1
            + self.regexp.len()
            + self.replacement.wire_len()
    }

    /// Writes the NAPTR record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.order.to_be_bytes());
        buf.extend_from_slice(&self.preference.to_be_bytes());
        buf.extend_from_slice(&[self.flags.len() as u8]);
        buf.extend_from_slice(&self.flags);
        buf.extend_from_slice(&[self.service.len() as u8]);
        buf.extend_from_slice(&self.service);
        buf.extend_from_slice(&[self.regexp.len() as u8]);
        buf.extend_from_slice(&self.regexp);
        self.replacement.write_wire(buf);
    }
}

impl fmt::Display for NAPTR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} \"{}\" \"{}\" \"{}\" {}",
            self.order,
            self.preference,
            String::from_utf8_lossy(&self.flags),
            String::from_utf8_lossy(&self.service),
            String::from_utf8_lossy(&self.regexp),
            self.replacement
        )
    }
}

/// SVCB/HTTPS Service Parameter keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u16)]
pub enum SvcParamKey {
    /// Mandatory parameters.
    Mandatory = 0,
    /// Application Layer Protocol Negotiation.
    Alpn = 1,
    /// No default ALPN.
    NoDefaultAlpn = 2,
    /// Port number.
    Port = 3,
    /// IPv4 address hints.
    Ipv4Hint = 4,
    /// Encrypted ClientHello config.
    Ech = 5,
    /// IPv6 address hints.
    Ipv6Hint = 6,
    /// DNS over Designated Resolver (DDR).
    Dohpath = 7,
}

impl SvcParamKey {
    /// Creates from u16 value.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Mandatory),
            1 => Some(Self::Alpn),
            2 => Some(Self::NoDefaultAlpn),
            3 => Some(Self::Port),
            4 => Some(Self::Ipv4Hint),
            5 => Some(Self::Ech),
            6 => Some(Self::Ipv6Hint),
            7 => Some(Self::Dohpath),
            _ => None,
        }
    }
}

/// Service parameter value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SvcParamValue {
    /// Mandatory keys.
    Mandatory(Vec<u16>),
    /// ALPN protocol IDs.
    Alpn(Vec<String>),
    /// No default ALPN (no value).
    NoDefaultAlpn,
    /// Port number.
    Port(u16),
    /// IPv4 address hints.
    Ipv4Hint(Vec<Ipv4Addr>),
    /// Encrypted ClientHello config.
    Ech(Vec<u8>),
    /// IPv6 address hints.
    Ipv6Hint(Vec<Ipv6Addr>),
    /// DoH path template.
    DohPath(String),
    /// Unknown parameter.
    Unknown(u16, Vec<u8>),
}

/// SVCB record - Service Binding (RFC 9460).
///
/// The SVCB record provides information for connection establishment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SVCB {
    /// Priority (0 = alias mode, >0 = service mode).
    priority: u16,
    /// Target name.
    target: Name,
    /// Service parameters.
    params: BTreeMap<u16, SvcParamValue>,
}

impl SVCB {
    /// Creates a new SVCB record.
    pub fn new(priority: u16, target: Name, params: BTreeMap<u16, SvcParamValue>) -> Self {
        Self {
            priority,
            target,
            params,
        }
    }

    /// Creates an alias mode record (priority 0).
    pub fn alias(target: Name) -> Self {
        Self::new(0, target, BTreeMap::new())
    }

    /// Returns the priority.
    #[inline]
    pub const fn priority(&self) -> u16 {
        self.priority
    }

    /// Returns true if this is alias mode.
    #[inline]
    pub const fn is_alias(&self) -> bool {
        self.priority == 0
    }

    /// Returns the target name.
    #[inline]
    pub fn target(&self) -> &Name {
        &self.target
    }

    /// Returns the service parameters.
    pub fn params(&self) -> &BTreeMap<u16, SvcParamValue> {
        &self.params
    }

    /// Returns the port if specified.
    pub fn port(&self) -> Option<u16> {
        self.params.get(&3).and_then(|v| {
            if let SvcParamValue::Port(p) = v {
                Some(*p)
            } else {
                None
            }
        })
    }

    /// Returns the ALPN protocols if specified.
    pub fn alpn(&self) -> Option<&Vec<String>> {
        self.params.get(&1).and_then(|v| {
            if let SvcParamValue::Alpn(a) = v {
                Some(a)
            } else {
                None
            }
        })
    }

    /// Parses an SVCB record from wire format.
    pub fn parse(message: &[u8], offset: usize, rdlength: u16) -> Result<Self> {
        if offset + 2 > message.len() {
            return Err(Error::buffer_too_short(offset + 2, message.len()));
        }

        let priority = u16::from_be_bytes([message[offset], message[offset + 1]]);

        let parser = NameParser::new(message);
        let (target, name_len) = parser.parse_name(offset + 2)?;

        let mut params = BTreeMap::new();
        let mut pos = offset + 2 + name_len;
        let end = offset + rdlength as usize;

        while pos + 4 <= end {
            let key = u16::from_be_bytes([message[pos], message[pos + 1]]);
            let value_len = u16::from_be_bytes([message[pos + 2], message[pos + 3]]) as usize;
            pos += 4;

            if pos + value_len > end {
                return Err(Error::unexpected_eof(pos + value_len));
            }

            let value_data = &message[pos..pos + value_len];
            pos += value_len;

            let value = match SvcParamKey::from_u16(key) {
                Some(SvcParamKey::Mandatory) => {
                    let mut keys = Vec::new();
                    for chunk in value_data.chunks(2) {
                        if chunk.len() == 2 {
                            keys.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                        }
                    }
                    SvcParamValue::Mandatory(keys)
                }
                Some(SvcParamKey::Alpn) => {
                    let mut alpns = Vec::new();
                    let mut p = 0;
                    while p < value_data.len() {
                        let len = value_data[p] as usize;
                        p += 1;
                        if p + len <= value_data.len() {
                            if let Ok(s) = String::from_utf8(value_data[p..p + len].to_vec()) {
                                alpns.push(s);
                            }
                        }
                        p += len;
                    }
                    SvcParamValue::Alpn(alpns)
                }
                Some(SvcParamKey::NoDefaultAlpn) => SvcParamValue::NoDefaultAlpn,
                Some(SvcParamKey::Port) => {
                    if value_data.len() >= 2 {
                        SvcParamValue::Port(u16::from_be_bytes([value_data[0], value_data[1]]))
                    } else {
                        SvcParamValue::Unknown(key, value_data.to_vec())
                    }
                }
                Some(SvcParamKey::Ipv4Hint) => {
                    let mut addrs = Vec::new();
                    for chunk in value_data.chunks(4) {
                        if chunk.len() == 4 {
                            addrs.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                        }
                    }
                    SvcParamValue::Ipv4Hint(addrs)
                }
                Some(SvcParamKey::Ech) => SvcParamValue::Ech(value_data.to_vec()),
                Some(SvcParamKey::Ipv6Hint) => {
                    let mut addrs = Vec::new();
                    for chunk in value_data.chunks(16) {
                        if chunk.len() == 16 {
                            let octets: [u8; 16] = chunk.try_into().unwrap();
                            addrs.push(Ipv6Addr::from(octets));
                        }
                    }
                    SvcParamValue::Ipv6Hint(addrs)
                }
                Some(SvcParamKey::Dohpath) => {
                    SvcParamValue::DohPath(String::from_utf8_lossy(value_data).to_string())
                }
                None => SvcParamValue::Unknown(key, value_data.to_vec()),
            };

            params.insert(key, value);
        }

        Ok(Self {
            priority,
            target,
            params,
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        let mut len = 2 + self.target.wire_len();
        for (_, value) in &self.params {
            len += 4; // key + length
            len += match value {
                SvcParamValue::Mandatory(keys) => keys.len() * 2,
                SvcParamValue::Alpn(alpns) => alpns.iter().map(|a| 1 + a.len()).sum(),
                SvcParamValue::NoDefaultAlpn => 0,
                SvcParamValue::Port(_) => 2,
                SvcParamValue::Ipv4Hint(addrs) => addrs.len() * 4,
                SvcParamValue::Ech(data) => data.len(),
                SvcParamValue::Ipv6Hint(addrs) => addrs.len() * 16,
                SvcParamValue::DohPath(path) => path.len(),
                SvcParamValue::Unknown(_, data) => data.len(),
            };
        }
        len
    }

    /// Writes the SVCB record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.priority.to_be_bytes());
        self.target.write_wire(buf);

        for (&key, value) in &self.params {
            buf.extend_from_slice(&key.to_be_bytes());

            let value_bytes = match value {
                SvcParamValue::Mandatory(keys) => {
                    let mut v = Vec::new();
                    for k in keys {
                        v.extend_from_slice(&k.to_be_bytes());
                    }
                    v
                }
                SvcParamValue::Alpn(alpns) => {
                    let mut v = Vec::new();
                    for a in alpns {
                        v.push(a.len() as u8);
                        v.extend_from_slice(a.as_bytes());
                    }
                    v
                }
                SvcParamValue::NoDefaultAlpn => Vec::new(),
                SvcParamValue::Port(p) => p.to_be_bytes().to_vec(),
                SvcParamValue::Ipv4Hint(addrs) => addrs.iter().flat_map(|a| a.octets()).collect(),
                SvcParamValue::Ech(data) => data.clone(),
                SvcParamValue::Ipv6Hint(addrs) => addrs.iter().flat_map(|a| a.octets()).collect(),
                SvcParamValue::DohPath(path) => path.as_bytes().to_vec(),
                SvcParamValue::Unknown(_, data) => data.clone(),
            };

            buf.extend_from_slice(&(value_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(&value_bytes);
        }
    }
}

impl fmt::Display for SVCB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.priority, self.target)?;
        for (key, value) in &self.params {
            write!(f, " {}=", key)?;
            match value {
                SvcParamValue::Port(p) => write!(f, "{}", p)?,
                SvcParamValue::Alpn(alpns) => write!(f, "{}", alpns.join(","))?,
                SvcParamValue::NoDefaultAlpn => {}
                SvcParamValue::Ipv4Hint(addrs) => {
                    write!(
                        f,
                        "{}",
                        addrs
                            .iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    )?;
                }
                SvcParamValue::Ipv6Hint(addrs) => {
                    write!(
                        f,
                        "{}",
                        addrs
                            .iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    )?;
                }
                _ => write!(f, "...")?,
            }
        }
        Ok(())
    }
}

/// HTTPS record - HTTPS Service Binding (RFC 9460).
///
/// The HTTPS record is a specialized SVCB record for HTTPS services.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HTTPS(SVCB);

impl HTTPS {
    /// Creates a new HTTPS record.
    pub fn new(priority: u16, target: Name, params: BTreeMap<u16, SvcParamValue>) -> Self {
        Self(SVCB::new(priority, target, params))
    }

    /// Creates an alias mode record.
    pub fn alias(target: Name) -> Self {
        Self(SVCB::alias(target))
    }

    /// Returns the inner SVCB record.
    pub fn inner(&self) -> &SVCB {
        &self.0
    }

    /// Returns the priority.
    #[inline]
    pub const fn priority(&self) -> u16 {
        self.0.priority()
    }

    /// Returns true if this is alias mode.
    #[inline]
    pub const fn is_alias(&self) -> bool {
        self.0.is_alias()
    }

    /// Returns the target name.
    #[inline]
    pub fn target(&self) -> &Name {
        self.0.target()
    }

    /// Returns the service parameters.
    pub fn params(&self) -> &BTreeMap<u16, SvcParamValue> {
        self.0.params()
    }

    /// Parses an HTTPS record from wire format.
    pub fn parse(message: &[u8], offset: usize, rdlength: u16) -> Result<Self> {
        Ok(Self(SVCB::parse(message, offset, rdlength)?))
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        self.0.wire_len()
    }

    /// Writes the HTTPS record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        self.0.write_to(buf)
    }
}

impl fmt::Display for HTTPS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// CAA record - Certification Authority Authorization (RFC 8659).
///
/// The CAA record allows domain owners to specify which CAs are authorized
/// to issue certificates for the domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CAA {
    /// Critical flag.
    critical: bool,
    /// Property tag.
    tag: String,
    /// Property value.
    value: Vec<u8>,
}

impl CAA {
    /// Creates a new CAA record.
    pub fn new(critical: bool, tag: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            critical,
            tag: tag.into(),
            value: value.into(),
        }
    }

    /// Creates an "issue" CAA record.
    pub fn issue(issuer: impl Into<String>) -> Self {
        Self::new(false, "issue", issuer.into().into_bytes())
    }

    /// Creates an "issuewild" CAA record.
    pub fn issuewild(issuer: impl Into<String>) -> Self {
        Self::new(false, "issuewild", issuer.into().into_bytes())
    }

    /// Creates an "iodef" CAA record.
    pub fn iodef(uri: impl Into<String>) -> Self {
        Self::new(false, "iodef", uri.into().into_bytes())
    }

    /// Returns true if the critical flag is set.
    #[inline]
    pub const fn is_critical(&self) -> bool {
        self.critical
    }

    /// Returns the property tag.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Returns the property value.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns the value as a string if valid UTF-8.
    pub fn value_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }

    /// Parses a CAA record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::invalid_rdata("CAA", "too short"));
        }

        let flags = data[0];
        let critical = (flags & 0x80) != 0;

        let tag_len = data[1] as usize;
        if 2 + tag_len > data.len() {
            return Err(Error::invalid_rdata("CAA", "truncated tag"));
        }

        let tag = String::from_utf8(data[2..2 + tag_len].to_vec())
            .map_err(|_| Error::invalid_rdata("CAA", "invalid tag encoding"))?;

        let value = data[2 + tag_len..].to_vec();

        Ok(Self {
            critical,
            tag,
            value,
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        2 + self.tag.len() + self.value.len()
    }

    /// Writes the CAA record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        let flags = if self.critical { 0x80 } else { 0x00 };
        buf.extend_from_slice(&[flags, self.tag.len() as u8]);
        buf.extend_from_slice(self.tag.as_bytes());
        buf.extend_from_slice(&self.value);
    }
}

impl fmt::Display for CAA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} \"{}\"",
            if self.critical { 128 } else { 0 },
            self.tag,
            String::from_utf8_lossy(&self.value)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_srv_record() {
        let srv = SRV::new(10, 20, 443, Name::from_str("server.example.com").unwrap());
        assert_eq!(srv.priority(), 10);
        assert_eq!(srv.weight(), 20);
        assert_eq!(srv.port(), 443);
        assert!(!srv.is_unavailable());
    }

    #[test]
    fn test_srv_unavailable() {
        let srv = SRV::new(0, 0, 0, Name::root());
        assert!(srv.is_unavailable());
    }

    #[test]
    fn test_caa_record() {
        let caa = CAA::issue("letsencrypt.org");
        assert!(!caa.is_critical());
        assert_eq!(caa.tag(), "issue");
        assert_eq!(caa.value_str(), Some("letsencrypt.org"));
    }

    #[test]
    fn test_caa_roundtrip() {
        let original = CAA::new(true, "issue", "ca.example.com");
        let mut buf = BytesMut::new();
        original.write_to(&mut buf);
        let parsed = CAA::parse(&buf).unwrap();
        assert_eq!(original, parsed);
    }
}
