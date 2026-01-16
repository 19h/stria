//! Certificate-related record types (TLSA, SSHFP, CERT, SMIMEA, OPENPGPKEY).

use crate::error::{Error, Result};
use bytes::BytesMut;
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use std::fmt;

/// TLSA record - TLS Certificate Association (RFC 6698).
///
/// The TLSA record is used for DANE (DNS-based Authentication of Named Entities)
/// to associate certificates or public keys with domain names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TLSA {
    /// Certificate usage (0-3).
    usage: u8,
    /// Selector (0-1).
    selector: u8,
    /// Matching type (0-2).
    matching_type: u8,
    /// Certificate association data.
    data: Vec<u8>,
}

/// TLSA certificate usage values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsaUsage {
    /// CA constraint.
    CaConstraint = 0,
    /// Service certificate constraint.
    ServiceCertificateConstraint = 1,
    /// Trust anchor assertion.
    TrustAnchorAssertion = 2,
    /// Domain-issued certificate.
    DomainIssuedCertificate = 3,
}

/// TLSA selector values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsaSelector {
    /// Full certificate.
    FullCertificate = 0,
    /// Subject public key info.
    SubjectPublicKeyInfo = 1,
}

/// TLSA matching type values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsaMatchingType {
    /// No hash, full content.
    NoHash = 0,
    /// SHA-256 hash.
    Sha256 = 1,
    /// SHA-512 hash.
    Sha512 = 2,
}

impl TLSA {
    /// Creates a new TLSA record.
    pub fn new(usage: u8, selector: u8, matching_type: u8, data: impl Into<Vec<u8>>) -> Self {
        Self {
            usage,
            selector,
            matching_type,
            data: data.into(),
        }
    }

    /// Returns the certificate usage.
    #[inline]
    pub const fn usage(&self) -> u8 {
        self.usage
    }

    /// Returns the selector.
    #[inline]
    pub const fn selector(&self) -> u8 {
        self.selector
    }

    /// Returns the matching type.
    #[inline]
    pub const fn matching_type(&self) -> u8 {
        self.matching_type
    }

    /// Returns the certificate association data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the data as a hex string.
    pub fn data_hex(&self) -> String {
        HEXLOWER.encode(&self.data)
    }

    /// Parses a TLSA record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            return Err(Error::invalid_rdata("TLSA", "too short"));
        }

        Ok(Self {
            usage: data[0],
            selector: data[1],
            matching_type: data[2],
            data: data[3..].to_vec(),
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        3 + self.data.len()
    }

    /// Writes the TLSA record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&[self.usage, self.selector, self.matching_type]);
        buf.extend_from_slice(&self.data);
    }
}

impl fmt::Display for TLSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.usage,
            self.selector,
            self.matching_type,
            self.data_hex()
        )
    }
}

/// SSHFP record - SSH Fingerprint (RFC 4255).
///
/// The SSHFP record publishes SSH public key fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SSHFP {
    /// Algorithm number.
    algorithm: u8,
    /// Fingerprint type.
    fp_type: u8,
    /// Fingerprint data.
    fingerprint: Vec<u8>,
}

/// SSHFP algorithm values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SshfpAlgorithm {
    /// RSA.
    Rsa = 1,
    /// DSA.
    Dsa = 2,
    /// ECDSA.
    Ecdsa = 3,
    /// Ed25519.
    Ed25519 = 4,
    /// Ed448.
    Ed448 = 6,
}

/// SSHFP fingerprint type values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SshfpFingerprintType {
    /// SHA-1.
    Sha1 = 1,
    /// SHA-256.
    Sha256 = 2,
}

impl SSHFP {
    /// Creates a new SSHFP record.
    pub fn new(algorithm: u8, fp_type: u8, fingerprint: impl Into<Vec<u8>>) -> Self {
        Self {
            algorithm,
            fp_type,
            fingerprint: fingerprint.into(),
        }
    }

    /// Returns the algorithm number.
    #[inline]
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Returns the fingerprint type.
    #[inline]
    pub const fn fp_type(&self) -> u8 {
        self.fp_type
    }

    /// Returns the fingerprint data.
    pub fn fingerprint(&self) -> &[u8] {
        &self.fingerprint
    }

    /// Returns the fingerprint as a hex string.
    pub fn fingerprint_hex(&self) -> String {
        HEXLOWER.encode(&self.fingerprint)
    }

    /// Parses an SSHFP record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::invalid_rdata("SSHFP", "too short"));
        }

        Ok(Self {
            algorithm: data[0],
            fp_type: data[1],
            fingerprint: data[2..].to_vec(),
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        2 + self.fingerprint.len()
    }

    /// Writes the SSHFP record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&[self.algorithm, self.fp_type]);
        buf.extend_from_slice(&self.fingerprint);
    }
}

impl fmt::Display for SSHFP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.algorithm,
            self.fp_type,
            self.fingerprint_hex()
        )
    }
}

/// CERT record - Certificate (RFC 4398).
///
/// The CERT record stores certificates and related revocation lists.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CERT {
    /// Certificate type.
    cert_type: u16,
    /// Key tag.
    key_tag: u16,
    /// Algorithm.
    algorithm: u8,
    /// Certificate data.
    certificate: Vec<u8>,
}

impl CERT {
    /// Creates a new CERT record.
    pub fn new(
        cert_type: u16,
        key_tag: u16,
        algorithm: u8,
        certificate: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            cert_type,
            key_tag,
            algorithm,
            certificate: certificate.into(),
        }
    }

    /// Returns the certificate type.
    #[inline]
    pub const fn cert_type(&self) -> u16 {
        self.cert_type
    }

    /// Returns the key tag.
    #[inline]
    pub const fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Returns the algorithm.
    #[inline]
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Returns the certificate data.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// Parses a CERT record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(Error::invalid_rdata("CERT", "too short"));
        }

        Ok(Self {
            cert_type: u16::from_be_bytes([data[0], data[1]]),
            key_tag: u16::from_be_bytes([data[2], data[3]]),
            algorithm: data[4],
            certificate: data[5..].to_vec(),
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        5 + self.certificate.len()
    }

    /// Writes the CERT record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.cert_type.to_be_bytes());
        buf.extend_from_slice(&self.key_tag.to_be_bytes());
        buf.extend_from_slice(&[self.algorithm]);
        buf.extend_from_slice(&self.certificate);
    }
}

impl fmt::Display for CERT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} ({} bytes)",
            self.cert_type,
            self.key_tag,
            self.algorithm,
            self.certificate.len()
        )
    }
}

/// SMIMEA record - S/MIME Certificate Association (RFC 8162).
///
/// The SMIMEA record is used for S/MIME email certificate association,
/// similar to TLSA but for email.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SMIMEA {
    /// Certificate usage.
    usage: u8,
    /// Selector.
    selector: u8,
    /// Matching type.
    matching_type: u8,
    /// Certificate association data.
    data: Vec<u8>,
}

impl SMIMEA {
    /// Creates a new SMIMEA record.
    pub fn new(usage: u8, selector: u8, matching_type: u8, data: impl Into<Vec<u8>>) -> Self {
        Self {
            usage,
            selector,
            matching_type,
            data: data.into(),
        }
    }

    /// Returns the certificate usage.
    #[inline]
    pub const fn usage(&self) -> u8 {
        self.usage
    }

    /// Returns the selector.
    #[inline]
    pub const fn selector(&self) -> u8 {
        self.selector
    }

    /// Returns the matching type.
    #[inline]
    pub const fn matching_type(&self) -> u8 {
        self.matching_type
    }

    /// Returns the certificate association data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Parses an SMIMEA record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            return Err(Error::invalid_rdata("SMIMEA", "too short"));
        }

        Ok(Self {
            usage: data[0],
            selector: data[1],
            matching_type: data[2],
            data: data[3..].to_vec(),
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        3 + self.data.len()
    }

    /// Writes the SMIMEA record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&[self.usage, self.selector, self.matching_type]);
        buf.extend_from_slice(&self.data);
    }
}

impl fmt::Display for SMIMEA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.usage,
            self.selector,
            self.matching_type,
            HEXLOWER.encode(&self.data)
        )
    }
}

/// OPENPGPKEY record - OpenPGP Public Key (RFC 7929).
///
/// The OPENPGPKEY record publishes OpenPGP public keys in DNS.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OPENPGPKEY {
    /// The OpenPGP public key.
    public_key: Vec<u8>,
}

impl OPENPGPKEY {
    /// Creates a new OPENPGPKEY record.
    pub fn new(public_key: impl Into<Vec<u8>>) -> Self {
        Self {
            public_key: public_key.into(),
        }
    }

    /// Returns the public key data.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns the public key as base64.
    pub fn public_key_base64(&self) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.public_key)
    }

    /// Parses an OPENPGPKEY record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        Ok(Self {
            public_key: data.to_vec(),
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        self.public_key.len()
    }

    /// Writes the OPENPGPKEY record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.public_key);
    }
}

impl fmt::Display for OPENPGPKEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({} bytes)", self.public_key.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlsa_record() {
        let tlsa = TLSA::new(3, 1, 1, vec![0xab, 0xcd, 0xef]);
        assert_eq!(tlsa.usage(), 3);
        assert_eq!(tlsa.selector(), 1);
        assert_eq!(tlsa.matching_type(), 1);
        assert_eq!(tlsa.data_hex(), "abcdef");
    }

    #[test]
    fn test_tlsa_roundtrip() {
        let original = TLSA::new(3, 1, 1, vec![0xde, 0xad, 0xbe, 0xef]);
        let mut buf = BytesMut::new();
        original.write_to(&mut buf);
        let parsed = TLSA::parse(&buf).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_sshfp_record() {
        let sshfp = SSHFP::new(2, 1, vec![0x12, 0x34, 0x56]);
        assert_eq!(sshfp.algorithm(), 2);
        assert_eq!(sshfp.fp_type(), 1);
        assert_eq!(sshfp.fingerprint_hex(), "123456");
    }

    #[test]
    fn test_cert_record() {
        let cert = CERT::new(1, 12345, 5, vec![0x01, 0x02, 0x03]);
        assert_eq!(cert.cert_type(), 1);
        assert_eq!(cert.key_tag(), 12345);
        assert_eq!(cert.algorithm(), 5);
    }
}
