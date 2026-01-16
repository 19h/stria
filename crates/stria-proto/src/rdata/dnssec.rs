//! DNSSEC record types (DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM).

use crate::error::{Error, Result};
use crate::name::{Name, NameParser};
use crate::rtype::RecordType;
use bytes::BytesMut;
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use std::fmt;

/// DNSSEC algorithm numbers (RFC 8624).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DnsSecAlgorithm {
    /// RSA/MD5 (deprecated)
    RsaMd5 = 1,
    /// Diffie-Hellman
    Dh = 2,
    /// DSA/SHA1
    Dsa = 3,
    /// RSA/SHA-1
    RsaSha1 = 5,
    /// DSA-NSEC3-SHA1
    DsaNsec3Sha1 = 6,
    /// RSA/SHA-1 NSEC3
    RsaSha1Nsec3Sha1 = 7,
    /// RSA/SHA-256
    RsaSha256 = 8,
    /// RSA/SHA-512
    RsaSha512 = 10,
    /// GOST R 34.10-2001
    EccGost = 12,
    /// ECDSA Curve P-256 with SHA-256
    EcdsaP256Sha256 = 13,
    /// ECDSA Curve P-384 with SHA-384
    EcdsaP384Sha384 = 14,
    /// Ed25519
    Ed25519 = 15,
    /// Ed448
    Ed448 = 16,
}

impl DnsSecAlgorithm {
    /// Creates from u8 value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::RsaMd5),
            2 => Some(Self::Dh),
            3 => Some(Self::Dsa),
            5 => Some(Self::RsaSha1),
            6 => Some(Self::DsaNsec3Sha1),
            7 => Some(Self::RsaSha1Nsec3Sha1),
            8 => Some(Self::RsaSha256),
            10 => Some(Self::RsaSha512),
            12 => Some(Self::EccGost),
            13 => Some(Self::EcdsaP256Sha256),
            14 => Some(Self::EcdsaP384Sha384),
            15 => Some(Self::Ed25519),
            16 => Some(Self::Ed448),
            _ => None,
        }
    }

    /// Returns true if this algorithm is recommended for use.
    pub const fn is_recommended(&self) -> bool {
        matches!(
            self,
            Self::RsaSha256
                | Self::EcdsaP256Sha256
                | Self::EcdsaP384Sha384
                | Self::Ed25519
                | Self::Ed448
        )
    }
}

/// DNSSEC digest types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DigestType {
    /// SHA-1 (deprecated)
    Sha1 = 1,
    /// SHA-256
    Sha256 = 2,
    /// GOST R 34.11-94
    GostR34_11_94 = 3,
    /// SHA-384
    Sha384 = 4,
}

impl DigestType {
    /// Creates from u8 value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Sha1),
            2 => Some(Self::Sha256),
            3 => Some(Self::GostR34_11_94),
            4 => Some(Self::Sha384),
            _ => None,
        }
    }

    /// Returns the expected digest length in bytes.
    pub const fn digest_len(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::GostR34_11_94 => 32,
            Self::Sha384 => 48,
        }
    }
}

/// DNSKEY record - DNS Public Key (RFC 4034).
///
/// The DNSKEY record holds a public key used for DNSSEC.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DNSKEY {
    /// Flags (zone key, SEP, etc.).
    flags: u16,
    /// Protocol (must be 3).
    protocol: u8,
    /// Algorithm number.
    algorithm: u8,
    /// Public key data.
    public_key: Vec<u8>,
}

impl DNSKEY {
    /// Zone Key flag bit.
    pub const FLAG_ZONE_KEY: u16 = 0x0100;
    /// Secure Entry Point flag bit.
    pub const FLAG_SEP: u16 = 0x0001;

    /// Creates a new DNSKEY record.
    pub fn new(flags: u16, protocol: u8, algorithm: u8, public_key: impl Into<Vec<u8>>) -> Self {
        Self {
            flags,
            protocol,
            algorithm,
            public_key: public_key.into(),
        }
    }

    /// Returns the flags.
    #[inline]
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// Returns true if this is a zone signing key.
    #[inline]
    pub const fn is_zone_key(&self) -> bool {
        (self.flags & Self::FLAG_ZONE_KEY) != 0
    }

    /// Returns true if this is a secure entry point (KSK).
    #[inline]
    pub const fn is_sep(&self) -> bool {
        (self.flags & Self::FLAG_SEP) != 0
    }

    /// Returns the protocol.
    #[inline]
    pub const fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Returns the algorithm number.
    #[inline]
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Returns the algorithm as an enum if known.
    pub fn algorithm_enum(&self) -> Option<DnsSecAlgorithm> {
        DnsSecAlgorithm::from_u8(self.algorithm)
    }

    /// Returns the public key data.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Calculates the key tag (RFC 4034 Appendix B).
    pub fn key_tag(&self) -> u16 {
        let mut buf = BytesMut::new();
        self.write_to(&mut buf);

        let mut ac: u32 = 0;
        for (i, &byte) in buf.iter().enumerate() {
            if i & 1 == 0 {
                ac += u32::from(byte) << 8;
            } else {
                ac += u32::from(byte);
            }
        }
        ac += ac >> 16;
        (ac & 0xFFFF) as u16
    }

    /// Parses a DNSKEY record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::invalid_rdata("DNSKEY", "too short"));
        }

        Ok(Self {
            flags: u16::from_be_bytes([data[0], data[1]]),
            protocol: data[2],
            algorithm: data[3],
            public_key: data[4..].to_vec(),
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        4 + self.public_key.len()
    }

    /// Writes the DNSKEY record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&[self.protocol, self.algorithm]);
        buf.extend_from_slice(&self.public_key);
    }
}

impl fmt::Display for DNSKEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} ({} bytes, tag={})",
            self.flags,
            self.protocol,
            self.algorithm,
            self.public_key.len(),
            self.key_tag()
        )
    }
}

/// DS record - Delegation Signer (RFC 4034).
///
/// The DS record links a child zone to its parent by providing a hash
/// of the child's KSK.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DS {
    /// Key tag of the DNSKEY.
    key_tag: u16,
    /// Algorithm number.
    algorithm: u8,
    /// Digest type.
    digest_type: u8,
    /// Digest data.
    digest: Vec<u8>,
}

impl DS {
    /// Creates a new DS record.
    pub fn new(key_tag: u16, algorithm: u8, digest_type: u8, digest: impl Into<Vec<u8>>) -> Self {
        Self {
            key_tag,
            algorithm,
            digest_type,
            digest: digest.into(),
        }
    }

    /// Returns the key tag.
    #[inline]
    pub const fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Returns the algorithm number.
    #[inline]
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Returns the digest type.
    #[inline]
    pub const fn digest_type(&self) -> u8 {
        self.digest_type
    }

    /// Returns the digest type as an enum if known.
    pub fn digest_type_enum(&self) -> Option<DigestType> {
        DigestType::from_u8(self.digest_type)
    }

    /// Returns the digest data.
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Returns the digest as a hex string.
    pub fn digest_hex(&self) -> String {
        HEXLOWER.encode(&self.digest)
    }

    /// Parses a DS record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::invalid_rdata("DS", "too short"));
        }

        Ok(Self {
            key_tag: u16::from_be_bytes([data[0], data[1]]),
            algorithm: data[2],
            digest_type: data[3],
            digest: data[4..].to_vec(),
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        4 + self.digest.len()
    }

    /// Writes the DS record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.key_tag.to_be_bytes());
        buf.extend_from_slice(&[self.algorithm, self.digest_type]);
        buf.extend_from_slice(&self.digest);
    }
}

impl fmt::Display for DS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.key_tag,
            self.algorithm,
            self.digest_type,
            self.digest_hex()
        )
    }
}

/// RRSIG record - DNSSEC Signature (RFC 4034).
///
/// The RRSIG record contains a digital signature over an RRset.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RRSIG {
    /// Type covered by this signature.
    type_covered: u16,
    /// Algorithm number.
    algorithm: u8,
    /// Number of labels in the original owner name.
    labels: u8,
    /// Original TTL.
    original_ttl: u32,
    /// Signature expiration time (Unix timestamp).
    expiration: u32,
    /// Signature inception time (Unix timestamp).
    inception: u32,
    /// Key tag of the signing key.
    key_tag: u16,
    /// Signer's name.
    signer: Name,
    /// Signature data.
    signature: Vec<u8>,
}

impl RRSIG {
    /// Creates a new RRSIG record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer: Name,
        signature: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            signature: signature.into(),
        }
    }

    /// Returns the type covered by this signature.
    #[inline]
    pub const fn type_covered(&self) -> u16 {
        self.type_covered
    }

    /// Returns the algorithm number.
    #[inline]
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Returns the number of labels.
    #[inline]
    pub const fn labels(&self) -> u8 {
        self.labels
    }

    /// Returns the original TTL.
    #[inline]
    pub const fn original_ttl(&self) -> u32 {
        self.original_ttl
    }

    /// Returns the expiration time.
    #[inline]
    pub const fn expiration(&self) -> u32 {
        self.expiration
    }

    /// Returns the inception time.
    #[inline]
    pub const fn inception(&self) -> u32 {
        self.inception
    }

    /// Returns the key tag.
    #[inline]
    pub const fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Returns the signer's name.
    #[inline]
    pub fn signer(&self) -> &Name {
        &self.signer
    }

    /// Returns the signature data.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns true if the signature is currently valid (time-wise).
    pub fn is_valid_at(&self, now: u32) -> bool {
        now >= self.inception && now <= self.expiration
    }

    /// Parses an RRSIG record from wire format.
    pub fn parse(message: &[u8], offset: usize, rdlength: u16) -> Result<Self> {
        if offset + 18 > message.len() {
            return Err(Error::invalid_rdata("RRSIG", "too short"));
        }

        let type_covered = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let algorithm = message[offset + 2];
        let labels = message[offset + 3];
        let original_ttl =
            u32::from_be_bytes(message[offset + 4..offset + 8].try_into().unwrap());
        let expiration = u32::from_be_bytes(message[offset + 8..offset + 12].try_into().unwrap());
        let inception = u32::from_be_bytes(message[offset + 12..offset + 16].try_into().unwrap());
        let key_tag = u16::from_be_bytes([message[offset + 16], message[offset + 17]]);

        let parser = NameParser::new(message);
        let (signer, name_len) = parser.parse_name(offset + 18)?;

        let sig_start = offset + 18 + name_len;
        let sig_end = offset + rdlength as usize;
        let signature = message[sig_start..sig_end].to_vec();

        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            signature,
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        18 + self.signer.wire_len() + self.signature.len()
    }

    /// Writes the RRSIG record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.type_covered.to_be_bytes());
        buf.extend_from_slice(&[self.algorithm, self.labels]);
        buf.extend_from_slice(&self.original_ttl.to_be_bytes());
        buf.extend_from_slice(&self.expiration.to_be_bytes());
        buf.extend_from_slice(&self.inception.to_be_bytes());
        buf.extend_from_slice(&self.key_tag.to_be_bytes());
        self.signer.write_wire(buf);
        buf.extend_from_slice(&self.signature);
    }
}

impl fmt::Display for RRSIG {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_name = RecordType::try_from(self.type_covered)
            .map(|t| t.name().to_string())
            .unwrap_or_else(|_| format!("TYPE{}", self.type_covered));

        write!(
            f,
            "{} {} {} {} {} {} {} {}",
            type_name,
            self.algorithm,
            self.labels,
            self.original_ttl,
            self.expiration,
            self.inception,
            self.key_tag,
            self.signer
        )
    }
}

/// NSEC record - Next Secure (RFC 4034).
///
/// The NSEC record provides authenticated denial of existence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NSEC {
    /// Next domain name in canonical order.
    next_name: Name,
    /// Type bitmap of record types at this name.
    type_bitmap: Vec<u8>,
}

impl NSEC {
    /// Creates a new NSEC record.
    pub fn new(next_name: Name, type_bitmap: impl Into<Vec<u8>>) -> Self {
        Self {
            next_name,
            type_bitmap: type_bitmap.into(),
        }
    }

    /// Returns the next domain name.
    pub fn next_name(&self) -> &Name {
        &self.next_name
    }

    /// Returns the raw type bitmap.
    pub fn type_bitmap(&self) -> &[u8] {
        &self.type_bitmap
    }

    /// Returns the record types present according to the bitmap.
    pub fn types(&self) -> Vec<u16> {
        let mut types = Vec::new();
        let mut pos = 0;

        while pos + 2 <= self.type_bitmap.len() {
            let window = self.type_bitmap[pos] as u16;
            let bitmap_len = self.type_bitmap[pos + 1] as usize;
            pos += 2;

            if pos + bitmap_len > self.type_bitmap.len() {
                break;
            }

            for (byte_idx, &byte) in self.type_bitmap[pos..pos + bitmap_len].iter().enumerate() {
                for bit in 0..8 {
                    if (byte & (0x80 >> bit)) != 0 {
                        let type_num = window * 256 + byte_idx as u16 * 8 + bit as u16;
                        types.push(type_num);
                    }
                }
            }

            pos += bitmap_len;
        }

        types
    }

    /// Parses an NSEC record from wire format.
    pub fn parse(message: &[u8], offset: usize, rdlength: u16) -> Result<Self> {
        let parser = NameParser::new(message);
        let (next_name, name_len) = parser.parse_name(offset)?;

        let bitmap_start = offset + name_len;
        let bitmap_end = offset + rdlength as usize;
        let type_bitmap = message[bitmap_start..bitmap_end].to_vec();

        Ok(Self {
            next_name,
            type_bitmap,
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        self.next_name.wire_len() + self.type_bitmap.len()
    }

    /// Writes the NSEC record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        self.next_name.write_wire(buf);
        buf.extend_from_slice(&self.type_bitmap);
    }
}

impl fmt::Display for NSEC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.next_name)?;
        for type_num in self.types() {
            let type_name = RecordType::try_from(type_num)
                .map(|t| t.name().to_string())
                .unwrap_or_else(|_| format!("TYPE{}", type_num));
            write!(f, " {}", type_name)?;
        }
        Ok(())
    }
}

/// NSEC3 record - Next Secure v3 (RFC 5155).
///
/// The NSEC3 record provides authenticated denial of existence
/// using hashed owner names to prevent zone enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NSEC3 {
    /// Hash algorithm (1 = SHA-1).
    hash_algorithm: u8,
    /// Flags (opt-out, etc.).
    flags: u8,
    /// Number of hash iterations.
    iterations: u16,
    /// Salt.
    salt: Vec<u8>,
    /// Next hashed owner name.
    next_hashed: Vec<u8>,
    /// Type bitmap.
    type_bitmap: Vec<u8>,
}

impl NSEC3 {
    /// Opt-out flag bit.
    pub const FLAG_OPT_OUT: u8 = 0x01;

    /// Creates a new NSEC3 record.
    pub fn new(
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: impl Into<Vec<u8>>,
        next_hashed: impl Into<Vec<u8>>,
        type_bitmap: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            hash_algorithm,
            flags,
            iterations,
            salt: salt.into(),
            next_hashed: next_hashed.into(),
            type_bitmap: type_bitmap.into(),
        }
    }

    /// Returns the hash algorithm.
    #[inline]
    pub const fn hash_algorithm(&self) -> u8 {
        self.hash_algorithm
    }

    /// Returns the flags.
    #[inline]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns true if opt-out is enabled.
    #[inline]
    pub const fn is_opt_out(&self) -> bool {
        (self.flags & Self::FLAG_OPT_OUT) != 0
    }

    /// Returns the number of iterations.
    #[inline]
    pub const fn iterations(&self) -> u16 {
        self.iterations
    }

    /// Returns the salt.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Returns the next hashed owner name.
    pub fn next_hashed(&self) -> &[u8] {
        &self.next_hashed
    }

    /// Returns the type bitmap.
    pub fn type_bitmap(&self) -> &[u8] {
        &self.type_bitmap
    }

    /// Parses an NSEC3 record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(Error::invalid_rdata("NSEC3", "too short"));
        }

        let hash_algorithm = data[0];
        let flags = data[1];
        let iterations = u16::from_be_bytes([data[2], data[3]]);
        let salt_len = data[4] as usize;

        let mut pos = 5;
        if pos + salt_len > data.len() {
            return Err(Error::invalid_rdata("NSEC3", "salt truncated"));
        }
        let salt = data[pos..pos + salt_len].to_vec();
        pos += salt_len;

        if pos >= data.len() {
            return Err(Error::invalid_rdata("NSEC3", "missing hash length"));
        }
        let hash_len = data[pos] as usize;
        pos += 1;

        if pos + hash_len > data.len() {
            return Err(Error::invalid_rdata("NSEC3", "hash truncated"));
        }
        let next_hashed = data[pos..pos + hash_len].to_vec();
        pos += hash_len;

        let type_bitmap = data[pos..].to_vec();

        Ok(Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed,
            type_bitmap,
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        5 + self.salt.len() + 1 + self.next_hashed.len() + self.type_bitmap.len()
    }

    /// Writes the NSEC3 record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&[self.hash_algorithm, self.flags]);
        buf.extend_from_slice(&self.iterations.to_be_bytes());
        buf.extend_from_slice(&[self.salt.len() as u8]);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&[self.next_hashed.len() as u8]);
        buf.extend_from_slice(&self.next_hashed);
        buf.extend_from_slice(&self.type_bitmap);
    }
}

impl fmt::Display for NSEC3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let salt_hex = if self.salt.is_empty() {
            "-".to_string()
        } else {
            HEXLOWER.encode(&self.salt)
        };

        write!(
            f,
            "{} {} {} {} {}",
            self.hash_algorithm,
            self.flags,
            self.iterations,
            salt_hex,
            data_encoding::BASE32_NOPAD.encode(&self.next_hashed)
        )
    }
}

/// NSEC3PARAM record - NSEC3 Parameters (RFC 5155).
///
/// The NSEC3PARAM record indicates the parameters to use for NSEC3 hashing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NSEC3PARAM {
    /// Hash algorithm.
    hash_algorithm: u8,
    /// Flags.
    flags: u8,
    /// Number of iterations.
    iterations: u16,
    /// Salt.
    salt: Vec<u8>,
}

impl NSEC3PARAM {
    /// Creates a new NSEC3PARAM record.
    pub fn new(hash_algorithm: u8, flags: u8, iterations: u16, salt: impl Into<Vec<u8>>) -> Self {
        Self {
            hash_algorithm,
            flags,
            iterations,
            salt: salt.into(),
        }
    }

    /// Returns the hash algorithm.
    #[inline]
    pub const fn hash_algorithm(&self) -> u8 {
        self.hash_algorithm
    }

    /// Returns the flags.
    #[inline]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the number of iterations.
    #[inline]
    pub const fn iterations(&self) -> u16 {
        self.iterations
    }

    /// Returns the salt.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Parses an NSEC3PARAM record from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(Error::invalid_rdata("NSEC3PARAM", "too short"));
        }

        let hash_algorithm = data[0];
        let flags = data[1];
        let iterations = u16::from_be_bytes([data[2], data[3]]);
        let salt_len = data[4] as usize;

        if 5 + salt_len > data.len() {
            return Err(Error::invalid_rdata("NSEC3PARAM", "salt truncated"));
        }

        let salt = data[5..5 + salt_len].to_vec();

        Ok(Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
        })
    }

    /// Returns the wire format length.
    pub fn wire_len(&self) -> usize {
        5 + self.salt.len()
    }

    /// Writes the NSEC3PARAM record to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&[self.hash_algorithm, self.flags]);
        buf.extend_from_slice(&self.iterations.to_be_bytes());
        buf.extend_from_slice(&[self.salt.len() as u8]);
        buf.extend_from_slice(&self.salt);
    }
}

impl fmt::Display for NSEC3PARAM {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let salt_hex = if self.salt.is_empty() {
            "-".to_string()
        } else {
            HEXLOWER.encode(&self.salt)
        };

        write!(
            f,
            "{} {} {} {}",
            self.hash_algorithm, self.flags, self.iterations, salt_hex
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_dnskey_key_tag() {
        // Test key tag calculation
        let key = DNSKEY::new(256, 3, 8, vec![0x01, 0x02, 0x03, 0x04]);
        let tag = key.key_tag();
        assert!(tag > 0);
    }

    #[test]
    fn test_dnskey_flags() {
        let zsk = DNSKEY::new(256, 3, 8, vec![]);
        assert!(zsk.is_zone_key());
        assert!(!zsk.is_sep());

        let ksk = DNSKEY::new(257, 3, 8, vec![]);
        assert!(ksk.is_zone_key());
        assert!(ksk.is_sep());
    }

    #[test]
    fn test_ds_roundtrip() {
        let original = DS::new(12345, 8, 2, vec![0xde, 0xad, 0xbe, 0xef]);
        let mut buf = BytesMut::new();
        original.write_to(&mut buf);
        let parsed = DS::parse(&buf).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_nsec_types() {
        // Create a bitmap for A (1), NS (2), SOA (6), MX (15)
        // Window 0: types 0-255
        // Type 1: byte 0, bit 6 (0x40)
        // Type 2: byte 0, bit 5 (0x20)
        // Type 6: byte 0, bit 1 (0x02)
        // Type 15: byte 1, bit 0 (0x01)
        let bitmap = vec![
            0u8, 2, // Window 0, 2 bytes
            0x62,   // Types 1, 2, 6
            0x01,   // Type 15
        ];

        let nsec = NSEC::new(Name::from_str("next.example.com").unwrap(), bitmap);
        let types = nsec.types();
        assert!(types.contains(&1));
        assert!(types.contains(&2));
        assert!(types.contains(&6));
        assert!(types.contains(&15));
    }

    #[test]
    fn test_algorithm_recommended() {
        assert!(DnsSecAlgorithm::EcdsaP256Sha256.is_recommended());
        assert!(DnsSecAlgorithm::Ed25519.is_recommended());
        assert!(!DnsSecAlgorithm::RsaMd5.is_recommended());
    }
}
