//! EDNS(0) support (RFC 6891).
//!
//! EDNS(0) - Extension Mechanisms for DNS - allows for larger UDP
//! payloads and additional functionality through the OPT pseudo-RR.

use crate::error::{Error, Result};
use crate::name::Name;
use crate::rcode::ResponseCode;
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// EDNS option codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum EdnsOptionCode {
    /// Reserved (0)
    Reserved = 0,
    /// Long-Lived Queries (RFC 8764)
    Llq = 1,
    /// Update Lease (draft)
    Ul = 2,
    /// Name Server Identifier (RFC 5001)
    Nsid = 3,
    /// DNSSEC Algorithm Understood (RFC 6975)
    Dau = 5,
    /// DS Hash Understood (RFC 6975)
    Dhu = 6,
    /// NSEC3 Hash Understood (RFC 6975)
    N3u = 7,
    /// Client Subnet (RFC 7871)
    ClientSubnet = 8,
    /// EDNS Expire (RFC 7314)
    Expire = 9,
    /// DNS Cookie (RFC 7873)
    Cookie = 10,
    /// TCP Keepalive (RFC 7828)
    TcpKeepalive = 11,
    /// Padding (RFC 7830)
    Padding = 12,
    /// CHAIN query (RFC 7901)
    Chain = 13,
    /// Key Tag (RFC 8145)
    KeyTag = 14,
    /// Extended DNS Error (RFC 8914)
    ExtendedDnsError = 15,
    /// DNS-over-Dedicated-Resolver (draft)
    Ddr = 16,
}

impl EdnsOptionCode {
    /// Creates from u16 value.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Reserved),
            1 => Some(Self::Llq),
            2 => Some(Self::Ul),
            3 => Some(Self::Nsid),
            5 => Some(Self::Dau),
            6 => Some(Self::Dhu),
            7 => Some(Self::N3u),
            8 => Some(Self::ClientSubnet),
            9 => Some(Self::Expire),
            10 => Some(Self::Cookie),
            11 => Some(Self::TcpKeepalive),
            12 => Some(Self::Padding),
            13 => Some(Self::Chain),
            14 => Some(Self::KeyTag),
            15 => Some(Self::ExtendedDnsError),
            16 => Some(Self::Ddr),
            _ => None,
        }
    }
}

/// EDNS option value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdnsOption {
    /// Name Server Identifier.
    Nsid(Vec<u8>),

    /// Client subnet information.
    ClientSubnet {
        /// Address family (1=IPv4, 2=IPv6).
        family: u16,
        /// Source prefix length.
        source_prefix: u8,
        /// Scope prefix length.
        scope_prefix: u8,
        /// Address bytes.
        address: Vec<u8>,
    },

    /// DNS Cookie.
    Cookie {
        /// Client cookie (8 bytes).
        client: [u8; 8],
        /// Server cookie (8-32 bytes, optional).
        server: Option<Vec<u8>>,
    },

    /// TCP Keepalive timeout.
    TcpKeepalive(Option<u16>),

    /// Padding bytes.
    Padding(Vec<u8>),

    /// EDNS Expire timer.
    Expire(Option<u32>),

    /// Extended DNS Error.
    ExtendedDnsError {
        /// Info code.
        code: u16,
        /// Extra text (optional).
        text: String,
    },

    /// Key tags for trust anchor signaling.
    KeyTag(Vec<u16>),

    /// Unknown option.
    Unknown {
        /// Option code.
        code: u16,
        /// Option data.
        data: Vec<u8>,
    },
}

impl EdnsOption {
    /// Returns the option code.
    pub fn code(&self) -> u16 {
        match self {
            Self::Nsid(_) => 3,
            Self::ClientSubnet { .. } => 8,
            Self::Cookie { .. } => 10,
            Self::TcpKeepalive(_) => 11,
            Self::Padding(_) => 12,
            Self::Expire(_) => 9,
            Self::ExtendedDnsError { .. } => 15,
            Self::KeyTag(_) => 14,
            Self::Unknown { code, .. } => *code,
        }
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        4 + match self {
            Self::Nsid(data) => data.len(),
            Self::ClientSubnet { address, .. } => 4 + address.len(),
            Self::Cookie { server, .. } => 8 + server.as_ref().map(|s| s.len()).unwrap_or(0),
            Self::TcpKeepalive(timeout) => if timeout.is_some() { 2 } else { 0 },
            Self::Padding(data) => data.len(),
            Self::Expire(value) => if value.is_some() { 4 } else { 0 },
            Self::ExtendedDnsError { text, .. } => 2 + text.len(),
            Self::KeyTag(tags) => tags.len() * 2,
            Self::Unknown { data, .. } => data.len(),
        }
    }

    /// Writes the option to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.code().to_be_bytes());

        match self {
            Self::Nsid(data) => {
                buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                buf.extend_from_slice(data);
            }
            Self::ClientSubnet {
                family,
                source_prefix,
                scope_prefix,
                address,
            } => {
                buf.extend_from_slice(&((4 + address.len()) as u16).to_be_bytes());
                buf.extend_from_slice(&family.to_be_bytes());
                buf.extend_from_slice(&[*source_prefix, *scope_prefix]);
                buf.extend_from_slice(address);
            }
            Self::Cookie { client, server } => {
                let len = 8 + server.as_ref().map(|s| s.len()).unwrap_or(0);
                buf.extend_from_slice(&(len as u16).to_be_bytes());
                buf.extend_from_slice(client);
                if let Some(s) = server {
                    buf.extend_from_slice(s);
                }
            }
            Self::TcpKeepalive(timeout) => {
                if let Some(t) = timeout {
                    buf.extend_from_slice(&2u16.to_be_bytes());
                    buf.extend_from_slice(&t.to_be_bytes());
                } else {
                    buf.extend_from_slice(&0u16.to_be_bytes());
                }
            }
            Self::Padding(data) => {
                buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                buf.extend_from_slice(data);
            }
            Self::Expire(value) => {
                if let Some(v) = value {
                    buf.extend_from_slice(&4u16.to_be_bytes());
                    buf.extend_from_slice(&v.to_be_bytes());
                } else {
                    buf.extend_from_slice(&0u16.to_be_bytes());
                }
            }
            Self::ExtendedDnsError { code, text } => {
                buf.extend_from_slice(&((2 + text.len()) as u16).to_be_bytes());
                buf.extend_from_slice(&code.to_be_bytes());
                buf.extend_from_slice(text.as_bytes());
            }
            Self::KeyTag(tags) => {
                buf.extend_from_slice(&((tags.len() * 2) as u16).to_be_bytes());
                for tag in tags {
                    buf.extend_from_slice(&tag.to_be_bytes());
                }
            }
            Self::Unknown { data, .. } => {
                buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                buf.extend_from_slice(data);
            }
        }
    }

    /// Parses an option from wire format.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            return Err(Error::buffer_too_short(4, data.len()));
        }

        let code = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if 4 + length > data.len() {
            return Err(Error::buffer_too_short(4 + length, data.len()));
        }

        let option_data = &data[4..4 + length];

        let option = match EdnsOptionCode::from_u16(code) {
            Some(EdnsOptionCode::Nsid) => Self::Nsid(option_data.to_vec()),
            Some(EdnsOptionCode::ClientSubnet) if length >= 4 => {
                let family = u16::from_be_bytes([option_data[0], option_data[1]]);
                let source_prefix = option_data[2];
                let scope_prefix = option_data[3];
                let address = option_data[4..].to_vec();
                Self::ClientSubnet {
                    family,
                    source_prefix,
                    scope_prefix,
                    address,
                }
            }
            Some(EdnsOptionCode::Cookie) if length >= 8 => {
                let mut client = [0u8; 8];
                client.copy_from_slice(&option_data[..8]);
                let server = if length > 8 {
                    Some(option_data[8..].to_vec())
                } else {
                    None
                };
                Self::Cookie { client, server }
            }
            Some(EdnsOptionCode::TcpKeepalive) => {
                let timeout = if length >= 2 {
                    Some(u16::from_be_bytes([option_data[0], option_data[1]]))
                } else {
                    None
                };
                Self::TcpKeepalive(timeout)
            }
            Some(EdnsOptionCode::Padding) => Self::Padding(option_data.to_vec()),
            Some(EdnsOptionCode::Expire) => {
                let value = if length >= 4 {
                    Some(u32::from_be_bytes(option_data[..4].try_into().unwrap()))
                } else {
                    None
                };
                Self::Expire(value)
            }
            Some(EdnsOptionCode::ExtendedDnsError) if length >= 2 => {
                let error_code = u16::from_be_bytes([option_data[0], option_data[1]]);
                let text = String::from_utf8_lossy(&option_data[2..]).to_string();
                Self::ExtendedDnsError {
                    code: error_code,
                    text,
                }
            }
            Some(EdnsOptionCode::KeyTag) => {
                let mut tags = Vec::new();
                for chunk in option_data.chunks(2) {
                    if chunk.len() == 2 {
                        tags.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                    }
                }
                Self::KeyTag(tags)
            }
            _ => Self::Unknown {
                code,
                data: option_data.to_vec(),
            },
        };

        Ok((option, 4 + length))
    }
}

impl fmt::Display for EdnsOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nsid(data) => {
                write!(f, "NSID: {}", String::from_utf8_lossy(data))
            }
            Self::ClientSubnet {
                family,
                source_prefix,
                scope_prefix,
                address,
            } => {
                let addr_str = match *family {
                    1 if address.len() >= 4 => {
                        Ipv4Addr::new(address[0], address[1], address[2], address[3]).to_string()
                    }
                    2 if address.len() >= 16 => {
                        let octets: [u8; 16] = address[..16].try_into().unwrap_or([0; 16]);
                        Ipv6Addr::from(octets).to_string()
                    }
                    _ => format!("{:?}", address),
                };
                write!(f, "CLIENT-SUBNET: {}/{}/{}", addr_str, source_prefix, scope_prefix)
            }
            Self::Cookie { client, server } => {
                write!(
                    f,
                    "COOKIE: client={}, server={:?}",
                    data_encoding::HEXLOWER.encode(client),
                    server.as_ref().map(|s| data_encoding::HEXLOWER.encode(s))
                )
            }
            Self::TcpKeepalive(timeout) => {
                write!(f, "TCP-KEEPALIVE: {:?}", timeout)
            }
            Self::Padding(data) => {
                write!(f, "PADDING: {} bytes", data.len())
            }
            Self::Expire(value) => {
                write!(f, "EXPIRE: {:?}", value)
            }
            Self::ExtendedDnsError { code, text } => {
                write!(f, "EDE: {} {}", code, text)
            }
            Self::KeyTag(tags) => {
                write!(f, "KEY-TAG: {:?}", tags)
            }
            Self::Unknown { code, data } => {
                write!(f, "UNKNOWN({}): {} bytes", code, data.len())
            }
        }
    }
}

/// EDNS(0) OPT pseudo-RR data.
///
/// The OPT record is placed in the additional section and carries
/// EDNS information including version, flags, and options.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Edns {
    /// EDNS version (must be 0).
    version: u8,
    /// UDP payload size.
    udp_size: u16,
    /// Extended RCODE (upper 8 bits).
    extended_rcode: u8,
    /// DNSSEC OK flag.
    dnssec_ok: bool,
    /// EDNS options.
    options: SmallVec<[EdnsOption; 2]>,
}

impl Edns {
    /// Default UDP payload size for EDNS.
    pub const DEFAULT_UDP_SIZE: u16 = 4096;

    /// Creates a new EDNS with default settings.
    pub fn new() -> Self {
        Self {
            version: 0,
            udp_size: Self::DEFAULT_UDP_SIZE,
            extended_rcode: 0,
            dnssec_ok: false,
            options: SmallVec::new(),
        }
    }

    /// Creates EDNS with DNSSEC OK flag set.
    pub fn with_dnssec() -> Self {
        Self {
            version: 0,
            udp_size: Self::DEFAULT_UDP_SIZE,
            extended_rcode: 0,
            dnssec_ok: true,
            options: SmallVec::new(),
        }
    }

    /// Returns the EDNS version.
    #[inline]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns the advertised UDP payload size.
    #[inline]
    pub const fn udp_size(&self) -> u16 {
        self.udp_size
    }

    /// Sets the UDP payload size.
    pub fn set_udp_size(&mut self, size: u16) {
        self.udp_size = size;
    }

    /// Returns the extended RCODE.
    #[inline]
    pub const fn extended_rcode(&self) -> u8 {
        self.extended_rcode
    }

    /// Sets the extended RCODE.
    pub fn set_extended_rcode(&mut self, rcode: u8) {
        self.extended_rcode = rcode;
    }

    /// Returns true if the DNSSEC OK flag is set.
    #[inline]
    pub const fn dnssec_ok(&self) -> bool {
        self.dnssec_ok
    }

    /// Sets the DNSSEC OK flag.
    pub fn set_dnssec_ok(&mut self, ok: bool) {
        self.dnssec_ok = ok;
    }

    /// Returns the EDNS options.
    pub fn options(&self) -> &[EdnsOption] {
        &self.options
    }

    /// Adds an option.
    pub fn add_option(&mut self, option: EdnsOption) {
        self.options.push(option);
    }

    /// Returns the full response code combining header and extended.
    pub fn full_rcode(&self, header_rcode: u8) -> u16 {
        u16::from(self.extended_rcode) << 4 | u16::from(header_rcode & 0x0F)
    }

    /// Returns the client cookie if present.
    pub fn cookie(&self) -> Option<&[u8; 8]> {
        self.options.iter().find_map(|o| match o {
            EdnsOption::Cookie { client, .. } => Some(client),
            _ => None,
        })
    }

    /// Returns the server cookie if present.
    pub fn server_cookie(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|o| match o {
            EdnsOption::Cookie { server, .. } => server.as_deref(),
            _ => None,
        })
    }

    /// Returns the Extended DNS Error if present.
    pub fn ede(&self) -> Option<(u16, &str)> {
        self.options.iter().find_map(|o| match o {
            EdnsOption::ExtendedDnsError { code, text } => Some((*code, text.as_str())),
            _ => None,
        })
    }

    /// Parses EDNS from an OPT record's class, TTL, and RDATA.
    pub fn parse(class: u16, ttl: u32, rdata: &[u8]) -> Result<Self> {
        let udp_size = class;
        let extended_rcode = (ttl >> 24) as u8;
        let version = ((ttl >> 16) & 0xFF) as u8;
        let flags = (ttl & 0xFFFF) as u16;
        let dnssec_ok = (flags & 0x8000) != 0;

        if version != 0 {
            // We only support EDNS version 0
            return Err(Error::InvalidEdnsOption {
                code: 0,
                message: format!("unsupported EDNS version {}", version),
            });
        }

        let mut options = SmallVec::new();
        let mut offset = 0;

        while offset < rdata.len() {
            let (option, consumed) = EdnsOption::parse(&rdata[offset..])?;
            options.push(option);
            offset += consumed;
        }

        Ok(Self {
            version,
            udp_size,
            extended_rcode,
            dnssec_ok,
            options,
        })
    }

    /// Returns the wire format length for the OPT RDATA.
    pub fn rdata_len(&self) -> usize {
        self.options.iter().map(|o| o.wire_len()).sum()
    }

    /// Returns the full wire format length (as a pseudo-RR).
    pub fn wire_len(&self) -> usize {
        // . (1) + TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) + RDATA
        1 + 2 + 2 + 4 + 2 + self.rdata_len()
    }

    /// Writes the OPT pseudo-RR to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        // Root name (empty)
        buf.extend_from_slice(&[0]);

        // TYPE = OPT (41)
        buf.extend_from_slice(&41u16.to_be_bytes());

        // CLASS = UDP payload size
        buf.extend_from_slice(&self.udp_size.to_be_bytes());

        // TTL = extended RCODE + version + flags
        let flags = if self.dnssec_ok { 0x8000u16 } else { 0 };
        let ttl = u32::from(self.extended_rcode) << 24 | u32::from(self.version) << 16 | u32::from(flags);
        buf.extend_from_slice(&ttl.to_be_bytes());

        // RDLENGTH
        buf.extend_from_slice(&(self.rdata_len() as u16).to_be_bytes());

        // Options
        for option in &self.options {
            option.write_to(buf);
        }
    }
}

impl fmt::Display for Edns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EDNS(version={}, udp={}, dnssec_ok={})",
            self.version, self.udp_size, self.dnssec_ok
        )?;

        for option in &self.options {
            write!(f, " [{}]", option)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edns_new() {
        let edns = Edns::new();
        assert_eq!(edns.version(), 0);
        assert_eq!(edns.udp_size(), 4096);
        assert!(!edns.dnssec_ok());
    }

    #[test]
    fn test_edns_with_dnssec() {
        let edns = Edns::with_dnssec();
        assert!(edns.dnssec_ok());
    }

    #[test]
    fn test_edns_roundtrip() {
        let mut original = Edns::new();
        original.set_dnssec_ok(true);
        original.add_option(EdnsOption::Nsid(b"test-server".to_vec()));

        let mut buf = BytesMut::new();
        original.write_to(&mut buf);

        // Parse: skip name (1), type (2), extract class, ttl, rdlength
        let class = u16::from_be_bytes([buf[3], buf[4]]);
        let ttl = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        let rdlength = u16::from_be_bytes([buf[9], buf[10]]);
        let rdata = &buf[11..11 + rdlength as usize];

        let parsed = Edns::parse(class, ttl, rdata).unwrap();

        assert_eq!(original.version(), parsed.version());
        assert_eq!(original.udp_size(), parsed.udp_size());
        assert_eq!(original.dnssec_ok(), parsed.dnssec_ok());
        assert_eq!(original.options().len(), parsed.options().len());
    }

    #[test]
    fn test_cookie_option() {
        let mut edns = Edns::new();
        edns.add_option(EdnsOption::Cookie {
            client: [1, 2, 3, 4, 5, 6, 7, 8],
            server: Some(vec![9, 10, 11, 12]),
        });

        assert_eq!(edns.cookie(), Some(&[1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(edns.server_cookie(), Some(&[9, 10, 11, 12][..]));
    }

    #[test]
    fn test_extended_dns_error() {
        let mut edns = Edns::new();
        edns.add_option(EdnsOption::ExtendedDnsError {
            code: 23, // Network Error
            text: "Connection refused".to_string(),
        });

        assert_eq!(edns.ede(), Some((23, "Connection refused")));
    }
}
