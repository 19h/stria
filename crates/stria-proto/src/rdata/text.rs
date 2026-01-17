//! Text-based record types (TXT, HINFO, RP).

use crate::error::{Error, Result};
use crate::name::{Name, NameParser};
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::fmt;

/// TXT record - Text (RFC 1035).
///
/// The TXT record holds arbitrary text strings. It's commonly used for:
/// - SPF (Sender Policy Framework) records
/// - DKIM (DomainKeys Identified Mail) records
/// - Domain verification
/// - General purpose text data
///
/// A TXT record can contain multiple strings, each up to 255 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TXT {
    /// The text strings (each up to 255 bytes).
    strings: SmallVec<[Vec<u8>; 2]>,
}

impl TXT {
    /// Creates a new TXT record with the given strings.
    pub fn new(strings: impl IntoIterator<Item = impl Into<Vec<u8>>>) -> Self {
        Self {
            strings: strings.into_iter().map(Into::into).collect(),
        }
    }

    /// Creates a TXT record from a single string.
    pub fn from_string(s: impl Into<Vec<u8>>) -> Self {
        Self {
            strings: smallvec::smallvec![s.into()],
        }
    }

    /// Returns the text strings.
    pub fn strings(&self) -> &[Vec<u8>] {
        &self.strings
    }

    /// Returns all strings concatenated as a single string.
    ///
    /// This is the semantic value for protocols like SPF that span multiple
    /// character-strings.
    pub fn data(&self) -> Vec<u8> {
        self.strings
            .iter()
            .flat_map(|s| s.iter().copied())
            .collect()
    }

    /// Returns the data as a UTF-8 string if valid.
    pub fn text(&self) -> Option<String> {
        String::from_utf8(self.data()).ok()
    }

    /// Parses a TXT record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut strings = SmallVec::new();
        let mut pos = 0;

        while pos < data.len() {
            let len = data[pos] as usize;
            pos += 1;

            if pos + len > data.len() {
                return Err(Error::invalid_rdata(
                    "TXT",
                    format!("string length {} exceeds remaining data", len),
                ));
            }

            strings.push(data[pos..pos + len].to_vec());
            pos += len;
        }

        Ok(Self { strings })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        self.strings.iter().map(|s| 1 + s.len()).sum()
    }

    /// Writes the TXT record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        for s in &self.strings {
            // Split into 255-byte chunks if necessary
            for chunk in s.chunks(255) {
                buf.extend_from_slice(&[chunk.len() as u8]);
                buf.extend_from_slice(chunk);
            }
        }
    }

    /// Returns true if this appears to be an SPF record.
    pub fn is_spf(&self) -> bool {
        self.text()
            .map(|t| t.starts_with("v=spf1"))
            .unwrap_or(false)
    }

    /// Returns true if this appears to be a DKIM record.
    pub fn is_dkim(&self) -> bool {
        self.text().map(|t| t.contains("v=DKIM1")).unwrap_or(false)
    }

    /// Returns true if this appears to be a DMARC record.
    pub fn is_dmarc(&self) -> bool {
        self.text()
            .map(|t| t.starts_with("v=DMARC1"))
            .unwrap_or(false)
    }
}

impl fmt::Display for TXT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for s in &self.strings {
            if !first {
                write!(f, " ")?;
            }
            first = false;

            write!(f, "\"")?;
            for &byte in s {
                if byte == b'"' || byte == b'\\' {
                    write!(f, "\\{}", byte as char)?;
                } else if byte.is_ascii_graphic() || byte == b' ' {
                    write!(f, "{}", byte as char)?;
                } else {
                    write!(f, "\\{:03}", byte)?;
                }
            }
            write!(f, "\"")?;
        }
        Ok(())
    }
}

/// HINFO record - Host information (RFC 1035).
///
/// The HINFO record contains information about the host computer.
/// This record type is rarely used today due to security concerns.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HINFO {
    /// CPU type.
    cpu: Vec<u8>,
    /// Operating system.
    os: Vec<u8>,
}

impl HINFO {
    /// Creates a new HINFO record.
    pub fn new(cpu: impl Into<Vec<u8>>, os: impl Into<Vec<u8>>) -> Self {
        Self {
            cpu: cpu.into(),
            os: os.into(),
        }
    }

    /// Returns the CPU type.
    pub fn cpu(&self) -> &[u8] {
        &self.cpu
    }

    /// Returns the CPU type as a string if valid UTF-8.
    pub fn cpu_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.cpu).ok()
    }

    /// Returns the operating system.
    pub fn os(&self) -> &[u8] {
        &self.os
    }

    /// Returns the OS as a string if valid UTF-8.
    pub fn os_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.os).ok()
    }

    /// Parses an HINFO record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::invalid_rdata("HINFO", "empty data"));
        }

        let cpu_len = data[0] as usize;
        if 1 + cpu_len >= data.len() {
            return Err(Error::invalid_rdata("HINFO", "truncated CPU string"));
        }

        let cpu = data[1..1 + cpu_len].to_vec();

        let os_start = 1 + cpu_len;
        let os_len = data[os_start] as usize;
        if os_start + 1 + os_len > data.len() {
            return Err(Error::invalid_rdata("HINFO", "truncated OS string"));
        }

        let os = data[os_start + 1..os_start + 1 + os_len].to_vec();

        Ok(Self { cpu, os })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        2 + self.cpu.len() + self.os.len()
    }

    /// Writes the HINFO record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&[self.cpu.len() as u8]);
        buf.extend_from_slice(&self.cpu);
        buf.extend_from_slice(&[self.os.len() as u8]);
        buf.extend_from_slice(&self.os);
    }
}

impl fmt::Display for HINFO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\"{}\" \"{}\"",
            String::from_utf8_lossy(&self.cpu),
            String::from_utf8_lossy(&self.os)
        )
    }
}

/// RP record - Responsible person (RFC 1183).
///
/// The RP record specifies the mailbox of the person responsible
/// for the domain and a reference to a TXT record with more information.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RP {
    /// Mailbox of responsible person (@ replaced with .).
    mbox: Name,
    /// Domain name for TXT record with additional information.
    txt: Name,
}

impl RP {
    /// Creates a new RP record.
    pub fn new(mbox: Name, txt: Name) -> Self {
        Self { mbox, txt }
    }

    /// Returns the mailbox name.
    pub fn mbox(&self) -> &Name {
        &self.mbox
    }

    /// Returns the mailbox as an email address.
    pub fn email(&self) -> String {
        let mbox_str = self.mbox.to_string();
        // Find the first unescaped dot and replace it with @
        let mut result = String::with_capacity(mbox_str.len());
        let mut chars = mbox_str.chars().peekable();
        let mut found_at = false;

        while let Some(c) = chars.next() {
            if c == '\\' {
                result.push(c);
                if let Some(next) = chars.next() {
                    result.push(next);
                }
            } else if c == '.' && !found_at {
                result.push('@');
                found_at = true;
            } else {
                result.push(c);
            }
        }

        if result.ends_with('.') {
            result.pop();
        }

        result
    }

    /// Returns the TXT reference domain.
    pub fn txt(&self) -> &Name {
        &self.txt
    }

    /// Parses an RP record from wire format.
    pub fn parse(message: &[u8], offset: usize) -> Result<Self> {
        let parser = NameParser::new(message);

        let (mbox, mbox_len) = parser.parse_name(offset)?;
        let (txt, _) = parser.parse_name(offset + mbox_len)?;

        Ok(Self { mbox, txt })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        self.mbox.wire_len() + self.txt.wire_len()
    }

    /// Writes the RP record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        self.mbox.write_wire(buf);
        self.txt.write_wire(buf);
    }
}

impl fmt::Display for RP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.mbox, self.txt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_txt_record() {
        let txt = TXT::from_string("Hello, World!");
        assert_eq!(txt.text(), Some("Hello, World!".to_string()));
    }

    #[test]
    fn test_txt_multiple_strings() {
        let txt = TXT::new(vec!["Hello, ", "World!"]);
        assert_eq!(txt.data(), b"Hello, World!");
        assert_eq!(txt.strings().len(), 2);
    }

    #[test]
    fn test_txt_spf() {
        let txt = TXT::from_string("v=spf1 include:_spf.google.com ~all");
        assert!(txt.is_spf());
        assert!(!txt.is_dkim());
    }

    #[test]
    fn test_txt_roundtrip() {
        let original = TXT::from_string("test string");
        let mut buf = BytesMut::new();
        original.write_to(&mut buf);
        let parsed = TXT::parse(&buf).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_hinfo_record() {
        let hinfo = HINFO::new("Intel", "Linux");
        assert_eq!(hinfo.cpu_str(), Some("Intel"));
        assert_eq!(hinfo.os_str(), Some("Linux"));
    }

    #[test]
    fn test_rp_record() {
        let rp = RP::new(
            Name::from_str("admin.example.com").unwrap(),
            Name::from_str("info.example.com").unwrap(),
        );

        assert_eq!(rp.email(), "admin@example.com");
    }
}
