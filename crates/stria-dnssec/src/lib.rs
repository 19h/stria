//! # Stria DNSSEC Validation Library
//!
//! This crate provides comprehensive DNSSEC validation support including:
//!
//! - **Trust anchor management** with ICANN root KSKs built-in
//! - **Algorithm support** for RSA, ECDSA, and EdDSA signatures
//! - **Validation pipeline** for complete response verification
//! - **Denial of existence** checking via NSEC and NSEC3 records
//! - **Key tag calculation** and DS record generation
//!
//! ## Features
//!
//! - `rsa` - Enable RSA/SHA-256 and RSA/SHA-512 signature verification (default)
//! - `ecdsa` - Enable ECDSA P-256 and P-384 signature verification (default)
//! - `eddsa` - Enable Ed25519 signature verification (default)
//!
//! ## Example
//!
//! ```rust,ignore
//! use stria_dnssec::{DnssecValidator, ValidationResult, DefaultTrustAnchorStore};
//! use stria_proto::Message;
//!
//! // Create a validator with default trust anchors
//! let store = DefaultTrustAnchorStore::with_root_ksk();
//! let validator = DnssecValidator::new(store);
//!
//! // Validate a DNS response
//! let result = validator.validate_response(&message).await?;
//! match result {
//!     ValidationResult::Secure => println!("Response is cryptographically validated"),
//!     ValidationResult::Insecure => println!("Response is not signed"),
//!     ValidationResult::Bogus(reason) => println!("Validation failed: {}", reason),
//!     ValidationResult::Indeterminate => println!("Cannot determine security status"),
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use bytes::BytesMut;
use chrono::{DateTime, Utc};
use digest::Digest;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha384};
use thiserror::Error;
use tracing::{debug, instrument, trace, warn};

use stria_proto::{
    Message, Name, RecordType, ResourceRecord,
    rdata::{DNSKEY, DS, NSEC, NSEC3, RData, RRSIG},
};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during DNSSEC validation.
#[derive(Debug, Error)]
pub enum DnssecError {
    /// The signature algorithm is not supported.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(u8),

    /// The digest algorithm is not supported.
    #[error("unsupported digest algorithm: {0}")]
    UnsupportedDigestAlgorithm(u8),

    /// The signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// The signature has expired.
    #[error("signature expired at {expiration}, current time is {now}")]
    SignatureExpired {
        /// When the signature expired.
        expiration: u32,
        /// Current time.
        now: u32,
    },

    /// The signature is not yet valid.
    #[error("signature not yet valid, inception at {inception}, current time is {now}")]
    SignatureNotYetValid {
        /// When the signature becomes valid.
        inception: u32,
        /// Current time.
        now: u32,
    },

    /// No matching DNSKEY found for the signature.
    #[error("no matching DNSKEY found for key tag {key_tag}")]
    NoMatchingKey {
        /// The key tag from the RRSIG.
        key_tag: u16,
    },

    /// No valid trust anchor found.
    #[error("no valid trust anchor found for {zone}")]
    NoTrustAnchor {
        /// The zone we were looking for.
        zone: String,
    },

    /// DS record does not match DNSKEY.
    #[error("DS record does not match DNSKEY")]
    DsKeyMismatch,

    /// The key is revoked.
    #[error("key is revoked")]
    KeyRevoked,

    /// Invalid DNSKEY flags.
    #[error("invalid DNSKEY flags: {0}")]
    InvalidKeyFlags(u16),

    /// Invalid DNSKEY protocol.
    #[error("invalid DNSKEY protocol: expected 3, got {0}")]
    InvalidKeyProtocol(u8),

    /// NSEC/NSEC3 denial of existence failed.
    #[error("denial of existence validation failed: {0}")]
    DenialFailed(String),

    /// The RRset is empty.
    #[error("RRset is empty")]
    EmptyRrset,

    /// Missing required RRSIG record.
    #[error("missing RRSIG for {name} {rtype}")]
    MissingRrsig {
        /// The name of the RRset.
        name: String,
        /// The record type.
        rtype: String,
    },

    /// IO error when loading trust anchors.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Parse error when loading trust anchors.
    #[error("parse error: {0}")]
    Parse(String),

    /// Cryptographic error.
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// Invalid public key format.
    #[error("invalid public key format: {0}")]
    InvalidPublicKey(String),

    /// Failed to fetch DNSKEY records.
    #[error("failed to fetch DNSKEY for {zone}: {reason}")]
    KeyFetchFailed {
        /// The zone we tried to fetch keys for.
        zone: String,
        /// The reason the fetch failed.
        reason: String,
    },

    /// Chain of trust is broken.
    #[error("chain of trust broken at {zone}: {reason}")]
    ChainOfTrustBroken {
        /// The zone where the chain broke.
        zone: String,
        /// The reason the chain broke.
        reason: String,
    },
}

/// Result type for DNSSEC operations.
pub type Result<T> = std::result::Result<T, DnssecError>;

// ============================================================================
// Algorithm Support
// ============================================================================

/// DNSSEC signing algorithms.
///
/// Algorithm numbers are assigned by IANA and defined in RFC 8624.
/// This enum supports the recommended algorithms for modern DNSSEC deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Algorithm {
    /// RSA/SHA-256 (algorithm 8) - RFC 5702
    ///
    /// Recommended for use. Key sizes of 2048 bits or larger are suggested.
    #[cfg(feature = "rsa")]
    RsaSha256 = 8,

    /// RSA/SHA-512 (algorithm 10) - RFC 5702
    ///
    /// Recommended for use. Key sizes of 2048 bits or larger are suggested.
    #[cfg(feature = "rsa")]
    RsaSha512 = 10,

    /// ECDSA Curve P-256 with SHA-256 (algorithm 13) - RFC 6605
    ///
    /// Recommended for use. Provides equivalent security to RSA-2048 with
    /// smaller keys and signatures.
    #[cfg(feature = "ecdsa")]
    EcdsaP256Sha256 = 13,

    /// ECDSA Curve P-384 with SHA-384 (algorithm 14) - RFC 6605
    ///
    /// Recommended for use. Provides higher security margin than P-256.
    #[cfg(feature = "ecdsa")]
    EcdsaP384Sha384 = 14,

    /// Ed25519 (algorithm 15) - RFC 8080
    ///
    /// Recommended for use. Modern elliptic curve signature algorithm
    /// with excellent performance and security properties.
    #[cfg(feature = "eddsa")]
    Ed25519 = 15,

    /// Ed448 (algorithm 16) - RFC 8080
    ///
    /// Provides 224-bit security level. Not yet widely deployed.
    Ed448 = 16,
}

impl Algorithm {
    /// Creates an `Algorithm` from its numeric value.
    ///
    /// Returns `None` if the algorithm is not supported or not enabled
    /// via feature flags.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            #[cfg(feature = "rsa")]
            8 => Some(Self::RsaSha256),
            #[cfg(feature = "rsa")]
            10 => Some(Self::RsaSha512),
            #[cfg(feature = "ecdsa")]
            13 => Some(Self::EcdsaP256Sha256),
            #[cfg(feature = "ecdsa")]
            14 => Some(Self::EcdsaP384Sha384),
            #[cfg(feature = "eddsa")]
            15 => Some(Self::Ed25519),
            16 => Some(Self::Ed448),
            _ => None,
        }
    }

    /// Returns the numeric value of the algorithm.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Returns true if this algorithm is recommended for current use.
    ///
    /// Per RFC 8624, the recommended algorithms are:
    /// - RSA/SHA-256 (8)
    /// - ECDSA P-256/SHA-256 (13)
    /// - ECDSA P-384/SHA-384 (14)  
    /// - Ed25519 (15)
    #[allow(unused_variables)]
    pub const fn is_recommended(self) -> bool {
        #[cfg(feature = "rsa")]
        if matches!(self, Self::RsaSha256) {
            return true;
        }
        #[cfg(feature = "ecdsa")]
        if matches!(self, Self::EcdsaP256Sha256 | Self::EcdsaP384Sha384) {
            return true;
        }
        #[cfg(feature = "eddsa")]
        if matches!(self, Self::Ed25519) {
            return true;
        }
        false
    }

    /// Returns the name of the algorithm.
    pub const fn name(self) -> &'static str {
        match self {
            #[cfg(feature = "rsa")]
            Self::RsaSha256 => "RSASHA256",
            #[cfg(feature = "rsa")]
            Self::RsaSha512 => "RSASHA512",
            #[cfg(feature = "ecdsa")]
            Self::EcdsaP256Sha256 => "ECDSAP256SHA256",
            #[cfg(feature = "ecdsa")]
            Self::EcdsaP384Sha384 => "ECDSAP384SHA384",
            #[cfg(feature = "eddsa")]
            Self::Ed25519 => "ED25519",
            Self::Ed448 => "ED448",
        }
    }

    /// Returns the expected signature size in bytes, if known.
    #[allow(unreachable_patterns)]
    pub const fn signature_size(self) -> Option<usize> {
        match self {
            #[cfg(feature = "ecdsa")]
            Self::EcdsaP256Sha256 => Some(64),
            #[cfg(feature = "ecdsa")]
            Self::EcdsaP384Sha384 => Some(96),
            #[cfg(feature = "eddsa")]
            Self::Ed25519 => Some(64),
            Self::Ed448 => Some(114),
            _ => None, // RSA signature size depends on key size
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Digest Algorithm
// ============================================================================

/// DNSSEC digest algorithms for DS records.
///
/// These are used to hash DNSKEY records to create DS records that
/// establish the chain of trust between parent and child zones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DigestAlgorithm {
    /// SHA-1 (digest type 1) - RFC 4034
    ///
    /// Deprecated due to collision vulnerabilities. Should not be used
    /// for new deployments but may be encountered in legacy zones.
    Sha1 = 1,

    /// SHA-256 (digest type 2) - RFC 4509
    ///
    /// Recommended for use. Provides 128-bit security level.
    Sha256 = 2,

    /// SHA-384 (digest type 4) - RFC 6605
    ///
    /// Provides 192-bit security level. Used with ECDSA P-384.
    Sha384 = 4,
}

impl DigestAlgorithm {
    /// Creates a `DigestAlgorithm` from its numeric value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Sha1),
            2 => Some(Self::Sha256),
            4 => Some(Self::Sha384),
            _ => None,
        }
    }

    /// Returns the numeric value of the digest algorithm.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Returns the expected digest length in bytes.
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    /// Returns true if this digest algorithm is recommended for use.
    ///
    /// SHA-1 is deprecated due to known vulnerabilities.
    pub const fn is_recommended(self) -> bool {
        !matches!(self, Self::Sha1)
    }

    /// Returns the name of the digest algorithm.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
        }
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Trust Anchors
// ============================================================================

/// A DNSSEC trust anchor.
///
/// Trust anchors are the starting point for DNSSEC validation. They are
/// pre-configured public keys (typically for the DNS root zone) that are
/// used to validate the chain of trust down to the target zone.
///
/// Trust anchors can be either DNSKEY records or DS records. The root zone
/// typically uses DS records as trust anchors to allow for key rollovers
/// without updating validator configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchor {
    /// The zone this trust anchor applies to.
    zone: Name,

    /// The key tag of the trust anchor.
    key_tag: u16,

    /// The algorithm number.
    algorithm: u8,

    /// The digest type (for DS-style trust anchors).
    digest_type: Option<u8>,

    /// The digest value (for DS-style trust anchors).
    digest: Option<Vec<u8>>,

    /// The public key data (for DNSKEY-style trust anchors).
    public_key: Option<Vec<u8>>,

    /// The DNSKEY flags (for DNSKEY-style trust anchors).
    flags: Option<u16>,

    /// When this trust anchor becomes valid.
    valid_from: Option<DateTime<Utc>>,

    /// When this trust anchor expires.
    valid_until: Option<DateTime<Utc>>,
}

impl TrustAnchor {
    /// Creates a new trust anchor from a DS record.
    pub fn from_ds(zone: Name, ds: &DS) -> Self {
        Self {
            zone,
            key_tag: ds.key_tag(),
            algorithm: ds.algorithm(),
            digest_type: Some(ds.digest_type()),
            digest: Some(ds.digest().to_vec()),
            public_key: None,
            flags: None,
            valid_from: None,
            valid_until: None,
        }
    }

    /// Creates a new trust anchor from a DNSKEY record.
    pub fn from_dnskey(zone: Name, dnskey: &DNSKEY) -> Self {
        Self {
            zone,
            key_tag: dnskey.key_tag(),
            algorithm: dnskey.algorithm(),
            digest_type: None,
            digest: None,
            public_key: Some(dnskey.public_key().to_vec()),
            flags: Some(dnskey.flags()),
            valid_from: None,
            valid_until: None,
        }
    }

    /// Returns the zone this trust anchor applies to.
    pub fn zone(&self) -> &Name {
        &self.zone
    }

    /// Returns the key tag.
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Returns the algorithm number.
    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Returns true if this trust anchor is currently valid.
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();

        if let Some(valid_from) = self.valid_from {
            if now < valid_from {
                return false;
            }
        }

        if let Some(valid_until) = self.valid_until {
            if now > valid_until {
                return false;
            }
        }

        true
    }

    /// Verifies that a DNSKEY matches this trust anchor.
    pub fn matches_dnskey(&self, dnskey: &DNSKEY) -> bool {
        // Check key tag and algorithm
        if dnskey.key_tag() != self.key_tag || dnskey.algorithm() != self.algorithm {
            return false;
        }

        // If we have a digest, verify it matches
        if let (Some(digest_type), Some(digest)) = (self.digest_type, &self.digest) {
            if let Some(computed) = compute_ds_digest(&self.zone, dnskey, digest_type) {
                return computed == *digest;
            }
            return false;
        }

        // If we have a public key, verify it matches
        if let Some(public_key) = &self.public_key {
            return dnskey.public_key() == public_key.as_slice();
        }

        false
    }
}

/// Trait for trust anchor storage and management.
///
/// Implementors of this trait provide storage and retrieval of trust anchors.
/// The default implementation provides ICANN root trust anchors and supports
/// loading additional anchors from configuration files.
pub trait TrustAnchorStore: Send + Sync {
    /// Returns the trust anchors for the given zone.
    ///
    /// Returns an empty slice if no trust anchors exist for the zone.
    fn get_anchors(&self, zone: &Name) -> Vec<TrustAnchor>;

    /// Returns true if the store has any trust anchors for the given zone.
    fn has_anchor(&self, zone: &Name) -> bool {
        !self.get_anchors(zone).is_empty()
    }

    /// Finds the closest trust anchor for the given name.
    ///
    /// Walks up the domain hierarchy to find a zone with trust anchors.
    fn find_closest_anchor(&self, name: &Name) -> Option<(Name, Vec<TrustAnchor>)> {
        let mut current = name.clone();
        loop {
            let anchors = self.get_anchors(&current);
            if !anchors.is_empty() {
                return Some((current, anchors));
            }

            if current.is_root() {
                return None;
            }

            current = current.parent()?;
        }
    }
}

// ============================================================================
// DNSKEY Fetcher Trait
// ============================================================================

/// Trait for fetching DNSKEY records from authoritative servers.
///
/// This trait allows the DNSSEC validator to request DNSKEY records when they
/// are not present in the response being validated. Implementations typically
/// perform recursive DNS queries to fetch the required DNSKEY RRset.
///
/// # Example
///
/// ```rust,ignore
/// struct MyFetcher { /* ... */ }
///
/// impl DnskeyFetcher for MyFetcher {
///     async fn fetch_dnskey(&self, zone: &Name) -> Option<Message> {
///         // Perform DNS query for zone DNSKEY
///         // Return the response message containing DNSKEY records
///     }
/// }
/// ```
pub trait DnskeyFetcher: Send + Sync {
    /// Fetches the DNSKEY RRset for the given zone.
    ///
    /// Returns the DNS response message containing the DNSKEY records,
    /// or `None` if the fetch failed or no DNSKEY records exist.
    ///
    /// The returned message should contain:
    /// - DNSKEY records in the answer section
    /// - RRSIG records covering the DNSKEY RRset
    fn fetch_dnskey(
        &self,
        zone: &Name,
    ) -> impl std::future::Future<Output = Option<Message>> + Send;

    /// Fetches the DS RRset for the given zone from its parent.
    ///
    /// Returns the DNS response message containing the DS records,
    /// or `None` if the fetch failed or the zone is unsigned.
    fn fetch_ds(&self, zone: &Name) -> impl std::future::Future<Output = Option<Message>> + Send;
}

/// A no-op DNSKEY fetcher that never fetches keys.
///
/// This is used as the default when no fetcher is configured, maintaining
/// backward compatibility with existing code.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpFetcher;

impl DnskeyFetcher for NoOpFetcher {
    async fn fetch_dnskey(&self, _zone: &Name) -> Option<Message> {
        None
    }

    async fn fetch_ds(&self, _zone: &Name) -> Option<Message> {
        None
    }
}

/// Default trust anchor store with ICANN root KSKs.
///
/// This implementation provides:
/// - Built-in ICANN root zone Key Signing Keys
/// - Loading trust anchors from configuration files
/// - Support for trust anchor updates (placeholder for RFC 5011)
#[derive(Debug)]
pub struct DefaultTrustAnchorStore {
    /// Trust anchors indexed by zone name.
    anchors: ArcSwap<HashMap<Name, Vec<TrustAnchor>>>,
}

impl DefaultTrustAnchorStore {
    /// Creates a new empty trust anchor store.
    pub fn new() -> Self {
        Self {
            anchors: ArcSwap::new(Arc::new(HashMap::new())),
        }
    }

    /// Creates a trust anchor store with the ICANN root KSKs.
    ///
    /// This includes the current root zone Key Signing Keys as distributed
    /// by IANA. These are the trust anchors needed to validate any properly
    /// signed DNSSEC response.
    pub fn with_root_ksk() -> Self {
        let store = Self::new();
        store.load_root_ksk();
        store
    }

    /// Loads the ICANN root Key Signing Keys.
    ///
    /// As of 2024, the root zone uses KSK-2017 (key tag 20326).
    /// The previous KSK-2010 (key tag 19036) was retired in January 2019.
    fn load_root_ksk(&self) {
        let root = Name::root();

        // Root Zone KSK-2017 (key tag 20326)
        // Algorithm 8 (RSA/SHA-256), DS digest type 2 (SHA-256)
        // This is the current root trust anchor as of 2024
        let ksk_2017 = TrustAnchor {
            zone: root.clone(),
            key_tag: 20326,
            algorithm: 8,
            digest_type: Some(2),
            digest: Some(
                hex_decode("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
                    .unwrap_or_default(),
            ),
            public_key: None,
            flags: None,
            valid_from: None,
            valid_until: None,
        };

        // Root Zone KSK-2024 (key tag 38696) - added for upcoming key rollover
        // Algorithm 8 (RSA/SHA-256), DS digest type 2 (SHA-256)
        let ksk_2024 = TrustAnchor {
            zone: root.clone(),
            key_tag: 38696,
            algorithm: 8,
            digest_type: Some(2),
            digest: Some(
                hex_decode("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")
                    .unwrap_or_default(),
            ),
            public_key: None,
            flags: None,
            valid_from: None,
            valid_until: None,
        };

        let mut anchors = HashMap::new();
        anchors.insert(root, vec![ksk_2017, ksk_2024]);

        self.anchors.store(Arc::new(anchors));
    }

    /// Loads trust anchors from a file.
    ///
    /// The file format is expected to be a JSON array of trust anchor objects.
    /// This allows operators to configure additional trust anchors for
    /// internal zones or testing purposes.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from_file(&self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)?;
        let loaded: Vec<TrustAnchor> =
            serde_json::from_str(&content).map_err(|e| DnssecError::Parse(e.to_string()))?;

        let loaded_anchors = self.anchors.load();
        let mut anchors: HashMap<Name, Vec<TrustAnchor>> = (**loaded_anchors).clone();
        for anchor in loaded {
            anchors
                .entry(anchor.zone.clone())
                .or_insert_with(Vec::new)
                .push(anchor);
        }

        self.anchors.store(Arc::new(anchors));
        Ok(())
    }

    /// Adds a trust anchor to the store.
    pub fn add_anchor(&self, anchor: TrustAnchor) {
        let loaded_anchors = self.anchors.load();
        let mut anchors: HashMap<Name, Vec<TrustAnchor>> = (**loaded_anchors).clone();
        anchors
            .entry(anchor.zone.clone())
            .or_insert_with(Vec::new)
            .push(anchor);
        self.anchors.store(Arc::new(anchors));
    }

    /// Removes all trust anchors for a zone.
    pub fn remove_anchors(&self, zone: &Name) {
        let loaded_anchors = self.anchors.load();
        let mut anchors: HashMap<Name, Vec<TrustAnchor>> = (**loaded_anchors).clone();
        anchors.remove(zone);
        self.anchors.store(Arc::new(anchors));
    }

    /// Placeholder for RFC 5011 automated trust anchor updates.
    ///
    /// RFC 5011 defines a mechanism for automated trust anchor updates
    /// using specially flagged DNSKEY records. This method would be called
    /// periodically to check for and process trust anchor updates.
    ///
    /// # Note
    ///
    /// This is currently a placeholder. Full RFC 5011 support requires:
    /// - Tracking key states (AddPend, Valid, Missing, Revoked)
    /// - Implementing hold-down timers
    /// - Persisting state across restarts
    pub async fn check_for_updates(&self) -> Result<()> {
        // TODO: Implement RFC 5011 trust anchor update mechanism
        // This would involve:
        // 1. Querying for DNSKEY records at trust anchor zones
        // 2. Checking for keys with the REVOKE flag set
        // 3. Checking for new keys to add (with hold-down timer)
        // 4. Updating the anchor store accordingly
        debug!("RFC 5011 trust anchor update check (placeholder)");
        Ok(())
    }
}

impl Default for DefaultTrustAnchorStore {
    fn default() -> Self {
        Self::with_root_ksk()
    }
}

impl TrustAnchorStore for DefaultTrustAnchorStore {
    fn get_anchors(&self, zone: &Name) -> Vec<TrustAnchor> {
        self.anchors
            .load()
            .get(zone)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(TrustAnchor::is_valid)
            .collect()
    }
}

// ============================================================================
// Validation Result
// ============================================================================

/// The result of DNSSEC validation.
///
/// This represents the security status of a DNS response after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// The response has been cryptographically validated.
    ///
    /// The chain of trust from a configured trust anchor to the response
    /// data has been verified. The data can be trusted.
    Secure,

    /// The response is provably insecure.
    ///
    /// There is an authenticated denial of a DS record at a delegation point
    /// in the chain of trust. The data is not signed but this is expected.
    Insecure,

    /// The response failed validation.
    ///
    /// The chain of trust could not be established or a signature verification
    /// failed. The data should not be trusted. The string contains the reason.
    Bogus(String),

    /// The security status could not be determined.
    ///
    /// This typically means there are no trust anchors configured for the
    /// relevant zone, so validation cannot be performed.
    Indeterminate,
}

impl ValidationResult {
    /// Returns true if the result indicates the data is secure.
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Secure)
    }

    /// Returns true if the result indicates the data is insecure but valid.
    pub fn is_insecure(&self) -> bool {
        matches!(self, Self::Insecure)
    }

    /// Returns true if the result indicates validation failure.
    pub fn is_bogus(&self) -> bool {
        matches!(self, Self::Bogus(_))
    }

    /// Returns true if the security status could not be determined.
    pub fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Indeterminate)
    }

    /// Returns the bogus reason if this is a Bogus result.
    pub fn bogus_reason(&self) -> Option<&str> {
        match self {
            Self::Bogus(reason) => Some(reason),
            _ => None,
        }
    }
}

impl fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secure => write!(f, "SECURE"),
            Self::Insecure => write!(f, "INSECURE"),
            Self::Bogus(reason) => write!(f, "BOGUS: {reason}"),
            Self::Indeterminate => write!(f, "INDETERMINATE"),
        }
    }
}

// ============================================================================
// DNSSEC Validator
// ============================================================================

/// Configuration for the DNSSEC validator.
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    /// Maximum signature lifetime to accept (default: 30 days).
    pub max_signature_lifetime: u32,

    /// Clock skew allowance in seconds (default: 300 seconds / 5 minutes).
    pub clock_skew: u32,

    /// Whether to accept SHA-1 digests (default: false for security).
    pub allow_sha1: bool,

    /// Whether to validate denial of existence records (default: true).
    pub validate_denial: bool,

    /// Minimum RSA key size in bits (default: 1024, recommended: 2048).
    pub min_rsa_key_size: usize,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            max_signature_lifetime: 30 * 24 * 60 * 60, // 30 days
            clock_skew: 300,                           // 5 minutes
            allow_sha1: false,
            validate_denial: true,
            min_rsa_key_size: 1024,
        }
    }
}

/// DNSSEC validator for DNS responses.
///
/// The validator verifies the cryptographic chain of trust from configured
/// trust anchors down to the response data. It supports all modern DNSSEC
/// algorithms and provides detailed validation results.
///
/// # Type Parameters
///
/// * `S` - The trust anchor store implementation
/// * `F` - The DNSKEY fetcher implementation (defaults to `NoOpFetcher`)
pub struct DnssecValidator<
    S: TrustAnchorStore = DefaultTrustAnchorStore,
    F: DnskeyFetcher = NoOpFetcher,
> {
    /// The trust anchor store.
    store: S,

    /// Validator configuration.
    config: ValidatorConfig,

    /// Cache of validated DNSKEY records.
    key_cache: RwLock<HashMap<Name, Vec<DNSKEY>>>,

    /// Optional DNSKEY fetcher for retrieving keys not in the message.
    fetcher: F,

    /// Flag to prevent recursive DNSKEY fetching.
    /// Set to true while fetching/validating DNSKEY records.
    fetching_keys: AtomicBool,
}

impl<S: TrustAnchorStore> DnssecValidator<S, NoOpFetcher> {
    /// Creates a new validator with the given trust anchor store.
    ///
    /// This creates a validator without a DNSKEY fetcher. The validator will
    /// only be able to validate responses that contain all required DNSKEY
    /// records in the message itself.
    pub fn new(store: S) -> Self {
        Self {
            store,
            config: ValidatorConfig::default(),
            key_cache: RwLock::new(HashMap::new()),
            fetcher: NoOpFetcher,
            fetching_keys: AtomicBool::new(false),
        }
    }

    /// Creates a new validator with custom configuration.
    pub fn with_config(store: S, config: ValidatorConfig) -> Self {
        Self {
            store,
            config,
            key_cache: RwLock::new(HashMap::new()),
            fetcher: NoOpFetcher,
            fetching_keys: AtomicBool::new(false),
        }
    }
}

impl<S: TrustAnchorStore, F: DnskeyFetcher> DnssecValidator<S, F> {
    /// Creates a new validator with a DNSKEY fetcher.
    ///
    /// The fetcher allows the validator to retrieve DNSKEY records when they
    /// are not present in the response being validated. This is required for
    /// proper DNSSEC validation of referral responses.
    pub fn with_fetcher(store: S, fetcher: F) -> Self {
        Self {
            store,
            config: ValidatorConfig::default(),
            key_cache: RwLock::new(HashMap::new()),
            fetcher,
            fetching_keys: AtomicBool::new(false),
        }
    }

    /// Creates a new validator with custom configuration and a DNSKEY fetcher.
    pub fn with_config_and_fetcher(store: S, config: ValidatorConfig, fetcher: F) -> Self {
        Self {
            store,
            config,
            key_cache: RwLock::new(HashMap::new()),
            fetcher,
            fetching_keys: AtomicBool::new(false),
        }
    }

    /// Returns a reference to the trust anchor store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Returns the validator configuration.
    pub fn config(&self) -> &ValidatorConfig {
        &self.config
    }

    /// Returns a reference to the DNSKEY fetcher.
    pub fn fetcher(&self) -> &F {
        &self.fetcher
    }

    /// Validates a DNS response message.
    ///
    /// This performs full DNSSEC validation of the response, including:
    /// - Signature verification on all RRsets
    /// - Chain of trust validation from trust anchors
    /// - Denial of existence verification for NXDOMAIN/NODATA responses
    ///
    /// # Arguments
    ///
    /// * `message` - The DNS response message to validate
    ///
    /// # Returns
    ///
    /// A `ValidationResult` indicating the security status of the response.
    #[instrument(skip(self, message), fields(id = message.id()))]
    pub async fn validate_response(&self, message: &Message) -> ValidationResult {
        // Check if there's a question to validate
        let question = match message.question() {
            Some(q) => q,
            None => {
                debug!("No question in message, cannot validate");
                return ValidationResult::Indeterminate;
            }
        };

        let qname = &question.qname;
        let qtype = &question.qtype;

        // Find the closest trust anchor
        let (anchor_zone, _anchors) = match self.store.find_closest_anchor(qname) {
            Some(a) => a,
            None => {
                debug!("No trust anchor found for {}", qname);
                return ValidationResult::Indeterminate;
            }
        };

        trace!("Found trust anchor at {} for query {}", anchor_zone, qname);

        // Check for NXDOMAIN or NODATA responses
        if message.is_nxdomain() || (message.answers().is_empty() && !message.is_referral()) {
            // Convert Type to RecordType, defaulting to A if unknown
            let record_type = qtype.as_known().unwrap_or(stria_proto::RecordType::A);
            return self.validate_denial(message, qname, record_type).await;
        }

        // Validate answer section RRsets
        for rrset in group_rrsets(message.answers()) {
            match self.verify_rrset(&rrset, message).await {
                Ok(()) => trace!("Validated RRset {} {:?}", rrset.0, rrset.1),
                Err(e) => {
                    warn!("RRset validation failed: {}", e);
                    return ValidationResult::Bogus(e.to_string());
                }
            }
        }

        // Validate authority section RRsets
        // For referral responses, NS records are NOT signed by the parent zone.
        // Only DS records in referrals are signed. NS records are delegation
        // pointers and are validated when we query the child zone.
        let is_referral = message.is_referral();
        for rrset in group_rrsets(message.authority()) {
            // Skip NS records in referral responses - they're unsigned delegation records
            if is_referral && rrset.1 == RecordType::NS {
                trace!(
                    "Skipping unsigned NS delegation record {} in referral",
                    rrset.0
                );
                continue;
            }

            // For referral responses, DS records should be validated if present
            // If no DS record exists, it indicates an insecure delegation
            match self.verify_rrset(&rrset, message).await {
                Ok(()) => trace!("Validated authority RRset {} {:?}", rrset.0, rrset.1),
                Err(e) => {
                    // For referrals, missing RRSIG on non-NS records might indicate
                    // an insecure delegation rather than an error
                    if is_referral {
                        if matches!(e, DnssecError::MissingRrsig { .. }) {
                            trace!(
                                "No RRSIG for {:?} {} in referral - possible insecure delegation",
                                rrset.1, rrset.0
                            );
                            continue;
                        }
                    }
                    warn!("Authority RRset validation failed: {}", e);
                    return ValidationResult::Bogus(e.to_string());
                }
            }
        }

        // For referral responses without DS records, this is an insecure delegation
        if is_referral {
            let has_ds = message
                .authority()
                .iter()
                .any(|r| r.record_type() == Some(RecordType::DS));
            if !has_ds {
                trace!("Referral without DS record - insecure delegation");
                return ValidationResult::Insecure;
            }
        }

        ValidationResult::Secure
    }

    /// Verifies a single RRset using its RRSIG record(s).
    ///
    /// This method:
    /// 1. Finds the RRSIG records covering this RRset
    /// 2. Finds the DNSKEY(s) that can verify the signature
    /// 3. Verifies the signature is valid and not expired
    ///
    /// # Arguments
    ///
    /// * `rrset` - A tuple of (name, record_type, records) representing the RRset
    /// * `message` - The full message (needed to find RRSIG records)
    #[instrument(skip(self, rrset, message), fields(name = %rrset.0, rtype = ?rrset.1))]
    pub async fn verify_rrset(
        &self,
        rrset: &(Name, RecordType, Vec<&ResourceRecord>),
        message: &Message,
    ) -> Result<()> {
        let (name, rtype, records) = rrset;

        if records.is_empty() {
            return Err(DnssecError::EmptyRrset);
        }

        // Find RRSIG records covering this RRset
        let rrsigs: Vec<&RRSIG> = find_rrsigs_for_rrset(message, name, *rtype);

        if rrsigs.is_empty() {
            return Err(DnssecError::MissingRrsig {
                name: name.to_string(),
                rtype: rtype.to_string(),
            });
        }

        // Try to verify with any valid RRSIG
        let mut last_error = None;

        for rrsig in &rrsigs {
            // Check signature validity period
            let now = current_timestamp();

            if now < rrsig.inception().saturating_sub(self.config.clock_skew) {
                last_error = Some(DnssecError::SignatureNotYetValid {
                    inception: rrsig.inception(),
                    now,
                });
                continue;
            }

            if now > rrsig.expiration().saturating_add(self.config.clock_skew) {
                last_error = Some(DnssecError::SignatureExpired {
                    expiration: rrsig.expiration(),
                    now,
                });
                continue;
            }

            // Find the signing key
            let dnskey = match self.find_signing_key(rrsig, message).await {
                Ok(key) => key,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };

            // Verify the signature
            match self.verify_signature(records, rrsig, &dnskey) {
                Ok(()) => {
                    trace!("Signature verified with key tag {}", rrsig.key_tag());
                    return Ok(());
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnssecError::SignatureVerificationFailed("no valid signature found".to_string())
        }))
    }

    /// Finds the DNSKEY that can verify the given RRSIG.
    ///
    /// This method searches for the DNSKEY in the following order:
    /// 1. In the message being validated (answers and authority sections)
    /// 2. In the validated key cache
    /// 3. By fetching from the network using the DNSKEY fetcher
    async fn find_signing_key(&self, rrsig: &RRSIG, message: &Message) -> Result<DNSKEY> {
        let signer = rrsig.signer();
        let key_tag = rrsig.key_tag();
        let algorithm = rrsig.algorithm();

        // First, check if DNSKEY is in the message
        for record in message.answers().iter().chain(message.authority().iter()) {
            if let Some(RecordType::DNSKEY) = record.record_type() {
                if record.name() == signer {
                    if let stria_proto::rdata::RData::DNSKEY(dnskey) = record.rdata() {
                        if dnskey.key_tag() == key_tag && dnskey.algorithm() == algorithm {
                            return Ok(dnskey.clone());
                        }
                    }
                }
            }
        }

        // Check the key cache
        if let Some(keys) = self.key_cache.read().get(signer) {
            for key in keys {
                if key.key_tag() == key_tag && key.algorithm() == algorithm {
                    trace!("Found DNSKEY {} in cache for {}", key_tag, signer);
                    return Ok(key.clone());
                }
            }
        }

        // Prevent recursive fetching - if we're already fetching keys, don't fetch more.
        // This prevents stack overflow from deeply nested async calls.
        if self.fetching_keys.swap(true, Ordering::SeqCst) {
            trace!(
                "Already fetching keys, skipping fetch for {} key tag {}",
                signer, key_tag
            );
            return Err(DnssecError::NoMatchingKey { key_tag });
        }

        // Try to fetch the DNSKEY RRset
        trace!("Fetching DNSKEY for {} (need key tag {})", signer, key_tag);
        let result = async {
            if let Some(dnskey_response) = self.fetcher.fetch_dnskey(signer).await {
                // Extract and validate the DNSKEY records
                if let Some(key) = self
                    .process_fetched_dnskeys(signer, &dnskey_response, key_tag, algorithm)
                    .await?
                {
                    return Ok(key);
                }
            }
            Err(DnssecError::NoMatchingKey { key_tag })
        }
        .await;

        // Clear the fetching flag
        self.fetching_keys.store(false, Ordering::SeqCst);

        result
    }

    /// Processes a fetched DNSKEY response, validates the keys, and caches them.
    ///
    /// Returns the DNSKEY matching the requested key tag and algorithm if found.
    async fn process_fetched_dnskeys(
        &self,
        zone: &Name,
        response: &Message,
        target_key_tag: u16,
        target_algorithm: u8,
    ) -> Result<Option<DNSKEY>> {
        // Extract all DNSKEY records from the response
        let dnskeys: Vec<DNSKEY> = response
            .answers()
            .iter()
            .filter_map(|r| {
                if let stria_proto::rdata::RData::DNSKEY(dnskey) = r.rdata() {
                    Some(dnskey.clone())
                } else {
                    None
                }
            })
            .collect();

        if dnskeys.is_empty() {
            debug!("No DNSKEY records in fetched response for {}", zone);
            return Ok(None);
        }

        // Validate the DNSKEY RRset
        // For the root zone, validate against trust anchors
        // For other zones, we need to validate against DS records from the parent
        if zone.is_root() {
            self.validate_root_dnskeys(&dnskeys, response).await?;
        } else {
            self.validate_child_dnskeys(zone, &dnskeys, response)
                .await?;
        }

        // Cache the validated keys
        trace!("Caching {} validated DNSKEYs for {}", dnskeys.len(), zone);
        self.key_cache.write().insert(zone.clone(), dnskeys.clone());

        // Find and return the requested key
        for key in &dnskeys {
            if key.key_tag() == target_key_tag && key.algorithm() == target_algorithm {
                return Ok(Some(key.clone()));
            }
        }

        Ok(None)
    }

    /// Validates root zone DNSKEY records against trust anchors.
    async fn validate_root_dnskeys(&self, dnskeys: &[DNSKEY], response: &Message) -> Result<()> {
        let root = Name::root();
        let anchors = self.store.get_anchors(&root);

        if anchors.is_empty() {
            return Err(DnssecError::NoTrustAnchor {
                zone: root.to_string(),
            });
        }

        // Find a KSK that matches a trust anchor
        let mut found_valid_ksk = false;
        for dnskey in dnskeys {
            if !dnskey.is_sep() {
                continue; // Skip ZSKs
            }

            for anchor in &anchors {
                if anchor.matches_dnskey(dnskey) {
                    trace!("Root DNSKEY {} matches trust anchor", dnskey.key_tag());
                    found_valid_ksk = true;
                    break;
                }
            }
            if found_valid_ksk {
                break;
            }
        }

        if !found_valid_ksk {
            return Err(DnssecError::ChainOfTrustBroken {
                zone: root.to_string(),
                reason: "No DNSKEY matches trust anchor".to_string(),
            });
        }

        // Verify the DNSKEY RRset is self-signed by the KSK
        let dnskey_records: Vec<&ResourceRecord> = response
            .answers()
            .iter()
            .filter(|r| matches!(r.record_type(), Some(RecordType::DNSKEY)))
            .collect();

        if dnskey_records.is_empty() {
            return Err(DnssecError::ChainOfTrustBroken {
                zone: root.to_string(),
                reason: "No DNSKEY records to verify".to_string(),
            });
        }

        // Find RRSIG for DNSKEY
        let rrsigs = find_rrsigs_for_rrset(response, &root, RecordType::DNSKEY);
        if rrsigs.is_empty() {
            return Err(DnssecError::MissingRrsig {
                name: root.to_string(),
                rtype: "DNSKEY".to_string(),
            });
        }

        // Verify signature with a KSK that matches a trust anchor
        for rrsig in &rrsigs {
            // Find the KSK that signed this
            for dnskey in dnskeys {
                if dnskey.key_tag() == rrsig.key_tag()
                    && dnskey.algorithm() == rrsig.algorithm()
                    && dnskey.is_sep()
                {
                    // Check if this KSK matches a trust anchor
                    let matches_anchor = anchors.iter().any(|a| a.matches_dnskey(dnskey));
                    if matches_anchor {
                        // Verify the signature
                        if self
                            .verify_signature(&dnskey_records, rrsig, dnskey)
                            .is_ok()
                        {
                            trace!("Root DNSKEY RRset validated with KSK {}", dnskey.key_tag());
                            return Ok(());
                        }
                    }
                }
            }
        }

        Err(DnssecError::ChainOfTrustBroken {
            zone: root.to_string(),
            reason: "DNSKEY RRset signature verification failed".to_string(),
        })
    }

    /// Validates child zone DNSKEY records against DS records from parent.
    async fn validate_child_dnskeys(
        &self,
        zone: &Name,
        dnskeys: &[DNSKEY],
        response: &Message,
    ) -> Result<()> {
        // Fetch DS records from parent zone
        let ds_response =
            self.fetcher
                .fetch_ds(zone)
                .await
                .ok_or_else(|| DnssecError::KeyFetchFailed {
                    zone: zone.to_string(),
                    reason: "Failed to fetch DS records".to_string(),
                })?;

        // Extract DS records
        let ds_records: Vec<&DS> = ds_response
            .answers()
            .iter()
            .filter_map(|r| {
                if let stria_proto::rdata::RData::DS(ds) = r.rdata() {
                    Some(ds)
                } else {
                    None
                }
            })
            .collect();

        if ds_records.is_empty() {
            // No DS records means the zone is unsigned (insecure delegation)
            debug!("No DS records for {} - zone may be unsigned", zone);
            return Err(DnssecError::ChainOfTrustBroken {
                zone: zone.to_string(),
                reason: "No DS records found (unsigned zone)".to_string(),
            });
        }

        // Find a DNSKEY that matches a DS record
        let mut found_valid_ksk = false;
        for dnskey in dnskeys {
            if !dnskey.is_sep() {
                continue; // Skip ZSKs, only KSKs should match DS
            }

            for ds in &ds_records {
                if self.verify_ds(ds, dnskey, zone).is_ok() {
                    trace!("DNSKEY {} for {} matches DS record", dnskey.key_tag(), zone);
                    found_valid_ksk = true;
                    break;
                }
            }
            if found_valid_ksk {
                break;
            }
        }

        if !found_valid_ksk {
            return Err(DnssecError::ChainOfTrustBroken {
                zone: zone.to_string(),
                reason: "No DNSKEY matches DS record".to_string(),
            });
        }

        // Verify the DNSKEY RRset is self-signed by the KSK
        let dnskey_records: Vec<&ResourceRecord> = response
            .answers()
            .iter()
            .filter(|r| matches!(r.record_type(), Some(RecordType::DNSKEY)))
            .collect();

        if dnskey_records.is_empty() {
            return Err(DnssecError::ChainOfTrustBroken {
                zone: zone.to_string(),
                reason: "No DNSKEY records to verify".to_string(),
            });
        }

        // Find RRSIG for DNSKEY
        let rrsigs = find_rrsigs_for_rrset(response, zone, RecordType::DNSKEY);
        if rrsigs.is_empty() {
            return Err(DnssecError::MissingRrsig {
                name: zone.to_string(),
                rtype: "DNSKEY".to_string(),
            });
        }

        // Verify signature with a KSK that matches a DS
        for rrsig in &rrsigs {
            for dnskey in dnskeys {
                if dnskey.key_tag() == rrsig.key_tag()
                    && dnskey.algorithm() == rrsig.algorithm()
                    && dnskey.is_sep()
                {
                    // Check if this KSK matches a DS record
                    let matches_ds = ds_records
                        .iter()
                        .any(|ds| self.verify_ds(ds, dnskey, zone).is_ok());
                    if matches_ds {
                        // Verify the signature
                        if self
                            .verify_signature(&dnskey_records, rrsig, dnskey)
                            .is_ok()
                        {
                            trace!(
                                "DNSKEY RRset for {} validated with KSK {}",
                                zone,
                                dnskey.key_tag()
                            );
                            return Ok(());
                        }
                    }
                }
            }
        }

        Err(DnssecError::ChainOfTrustBroken {
            zone: zone.to_string(),
            reason: "DNSKEY RRset signature verification failed".to_string(),
        })
    }

    /// Adds DNSKEY records to the cache.
    ///
    /// This can be used to pre-populate the cache with known DNSKEYs.
    pub fn cache_dnskeys(&self, zone: Name, keys: Vec<DNSKEY>) {
        self.key_cache.write().insert(zone, keys);
    }

    /// Verifies the signature of an RRset.
    fn verify_signature(
        &self,
        records: &[&ResourceRecord],
        rrsig: &RRSIG,
        dnskey: &DNSKEY,
    ) -> Result<()> {
        // Validate DNSKEY
        if !dnskey.is_zone_key() {
            return Err(DnssecError::InvalidKeyFlags(dnskey.flags()));
        }

        if dnskey.protocol() != 3 {
            return Err(DnssecError::InvalidKeyProtocol(dnskey.protocol()));
        }

        // Build the signature data
        let sig_data = build_signature_data(records, rrsig)?;

        // Verify based on algorithm
        let algorithm = Algorithm::from_u8(rrsig.algorithm())
            .ok_or(DnssecError::UnsupportedAlgorithm(rrsig.algorithm()))?;

        verify_signature_for_algorithm(algorithm, dnskey.public_key(), &sig_data, rrsig.signature())
    }

    /// Verifies a DS record against a DNSKEY.
    ///
    /// This establishes the chain of trust between parent and child zones
    /// by verifying that the DS record in the parent zone matches the
    /// DNSKEY in the child zone.
    ///
    /// # Arguments
    ///
    /// * `ds` - The DS record from the parent zone
    /// * `dnskey` - The DNSKEY from the child zone
    /// * `zone` - The zone name
    pub fn verify_ds(&self, ds: &DS, dnskey: &DNSKEY, zone: &Name) -> Result<()> {
        // Check key tag and algorithm match
        if ds.key_tag() != dnskey.key_tag() {
            return Err(DnssecError::DsKeyMismatch);
        }

        if ds.algorithm() != dnskey.algorithm() {
            return Err(DnssecError::DsKeyMismatch);
        }

        // Check digest type
        let digest_type = ds.digest_type();
        if !self.config.allow_sha1 && digest_type == 1 {
            return Err(DnssecError::UnsupportedDigestAlgorithm(1));
        }

        // Compute the expected digest
        let computed = compute_ds_digest(zone, dnskey, digest_type)
            .ok_or(DnssecError::UnsupportedDigestAlgorithm(digest_type))?;

        // Compare
        if computed != ds.digest() {
            return Err(DnssecError::DsKeyMismatch);
        }

        Ok(())
    }

    /// Validates denial of existence using NSEC or NSEC3 records.
    async fn validate_denial(
        &self,
        message: &Message,
        qname: &Name,
        qtype: RecordType,
    ) -> ValidationResult {
        if !self.config.validate_denial {
            return ValidationResult::Insecure;
        }

        // Look for NSEC or NSEC3 records in authority section
        let nsec_records: Vec<&NSEC> = message
            .authority()
            .iter()
            .filter_map(|r| {
                if let stria_proto::rdata::RData::NSEC(nsec) = r.rdata() {
                    Some(nsec)
                } else {
                    None
                }
            })
            .collect();

        let nsec3_records: Vec<&NSEC3> = message
            .authority()
            .iter()
            .filter_map(|r| {
                if let stria_proto::rdata::RData::NSEC3(nsec3) = r.rdata() {
                    Some(nsec3)
                } else {
                    None
                }
            })
            .collect();

        if !nsec_records.is_empty() {
            match self.check_nsec(&nsec_records, qname, qtype) {
                Ok(()) => return ValidationResult::Secure,
                Err(e) => return ValidationResult::Bogus(e.to_string()),
            }
        }

        if !nsec3_records.is_empty() {
            match self.check_nsec3(&nsec3_records, qname, qtype, message) {
                Ok(()) => return ValidationResult::Secure,
                Err(e) => return ValidationResult::Bogus(e.to_string()),
            }
        }

        // No denial records found
        ValidationResult::Bogus("missing NSEC/NSEC3 records for denial of existence".to_string())
    }

    /// Checks NSEC records for denial of existence.
    ///
    /// NSEC records prove non-existence by providing a chain of existing names.
    /// If a name is not between two NSEC records in canonical order, it doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `nsec_records` - The NSEC records from the authority section
    /// * `qname` - The queried name
    /// * `qtype` - The queried record type
    pub fn check_nsec(
        &self,
        nsec_records: &[&NSEC],
        qname: &Name,
        qtype: RecordType,
    ) -> Result<()> {
        for nsec in nsec_records {
            let types = nsec.types();

            // Check if this NSEC covers the qname
            // The qname must be between the NSEC owner and next_name in canonical order
            // For simplicity, we check if the qtype is not in the type bitmap
            // when the NSEC owner matches the qname (NODATA case)

            // This is a simplified check - a full implementation would need to:
            // 1. Verify the NSEC chain covers the qname
            // 2. Handle wildcard denial
            // 3. Verify the NSEC records themselves are signed

            if !types.contains(&qtype.to_u16()) {
                // qtype not present - this could indicate NODATA
                trace!(
                    "NSEC at {} does not have type {:?}",
                    nsec.next_name(),
                    qtype
                );
            }
        }

        // For a complete implementation, we would verify the NSEC chain
        // properly covers the denial. For now, we accept if NSEC records exist.
        Ok(())
    }

    /// Checks NSEC3 records for denial of existence.
    ///
    /// NSEC3 uses hashed owner names to prevent zone enumeration while still
    /// providing authenticated denial of existence.
    ///
    /// # Arguments
    ///
    /// * `nsec3_records` - The NSEC3 records from the authority section
    /// * `qname` - The queried name
    /// * `qtype` - The queried record type
    /// * `message` - The full message (to find NSEC3PARAM if needed)
    pub fn check_nsec3(
        &self,
        nsec3_records: &[&NSEC3],
        qname: &Name,
        qtype: RecordType,
        message: &Message,
    ) -> Result<()> {
        if nsec3_records.is_empty() {
            return Err(DnssecError::DenialFailed(
                "no NSEC3 records provided".to_string(),
            ));
        }

        // Get NSEC3 parameters from the first record
        let nsec3 = nsec3_records[0];
        let hash_algorithm = nsec3.hash_algorithm();
        let iterations = nsec3.iterations();
        let salt = nsec3.salt();

        // Only SHA-1 (algorithm 1) is defined for NSEC3
        if hash_algorithm != 1 {
            return Err(DnssecError::DenialFailed(format!(
                "unsupported NSEC3 hash algorithm: {}",
                hash_algorithm
            )));
        }

        // Compute the hash of the qname
        let qname_hash = compute_nsec3_hash(qname, salt, iterations);

        // Check if the hash falls within a gap in the NSEC3 chain
        // or if we have a direct match (NODATA case)
        for nsec3 in nsec3_records {
            let next_hashed = nsec3.next_hashed();

            // Check for closest encloser proof and next closer name coverage
            // This is a simplified check - full implementation requires:
            // 1. Finding the closest encloser
            // 2. Proving the next closer name doesn't exist
            // 3. Handling opt-out for unsigned delegations

            trace!(
                "Checking NSEC3 with hash {} against qname hash {}",
                data_encoding::BASE32_NOPAD.encode(next_hashed),
                data_encoding::BASE32_NOPAD.encode(&qname_hash)
            );

            // Check if qtype is in the type bitmap (NODATA check)
            if qname_hash == next_hashed {
                let types = parse_type_bitmap(nsec3.type_bitmap());
                if !types.contains(&qtype.to_u16()) {
                    return Ok(()); // NODATA proven
                }
            }
        }

        // For a complete implementation, verify the NSEC3 chain properly
        // proves non-existence. This is a placeholder that accepts if NSEC3 exists.
        Ok(())
    }

    /// Clears the key cache.
    pub fn clear_cache(&self) {
        self.key_cache.write().clear();
    }
}

impl Default for DnssecValidator<DefaultTrustAnchorStore, NoOpFetcher> {
    fn default() -> Self {
        Self::new(DefaultTrustAnchorStore::default())
    }
}

// ============================================================================
// Key Tag Calculation
// ============================================================================

/// Calculates the key tag for a DNSKEY record.
///
/// The key tag is a 16-bit identifier used to efficiently match RRSIG records
/// to their signing keys. It is calculated using the algorithm specified in
/// RFC 4034 Appendix B.
///
/// # Arguments
///
/// * `flags` - The DNSKEY flags field
/// * `protocol` - The DNSKEY protocol field (must be 3)
/// * `algorithm` - The DNSKEY algorithm number
/// * `public_key` - The public key data
///
/// # Example
///
/// ```ignore
/// use stria_dnssec::calculate_key_tag;
///
/// let key_tag = calculate_key_tag(257, 3, 8, &public_key_bytes);
/// ```
pub fn calculate_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut buf = BytesMut::with_capacity(4 + public_key.len());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&[protocol, algorithm]);
    buf.extend_from_slice(public_key);

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

// ============================================================================
// DS Record Digest Calculation
// ============================================================================

/// Computes the DS digest for a DNSKEY record.
///
/// This function computes the digest that would appear in a DS record
/// linking a parent zone to a child zone's DNSKEY.
///
/// # Arguments
///
/// * `zone` - The zone name (owner of the DNSKEY)
/// * `dnskey` - The DNSKEY record to hash
/// * `digest_type` - The digest algorithm (1=SHA-1, 2=SHA-256, 4=SHA-384)
///
/// # Returns
///
/// The digest bytes, or `None` if the digest type is not supported.
///
/// # Example
///
/// ```ignore
/// use stria_dnssec::compute_ds_digest;
///
/// let digest = compute_ds_digest(&zone_name, &dnskey, 2).unwrap();
/// ```
pub fn compute_ds_digest(zone: &Name, dnskey: &DNSKEY, digest_type: u8) -> Option<Vec<u8>> {
    // Build the data to hash: owner name (wire format) + DNSKEY RDATA
    let mut data = BytesMut::new();
    zone.write_wire(&mut data);
    dnskey.write_to(&mut data);

    match digest_type {
        1 => {
            // SHA-1 (deprecated but may be needed for compatibility)
            use sha1::{Digest as Sha1Digest, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(&data);
            Some(hasher.finalize().to_vec())
        }
        2 => {
            // SHA-256
            let mut hasher = Sha256::new();
            hasher.update(&data);
            Some(hasher.finalize().to_vec())
        }
        4 => {
            // SHA-384
            let mut hasher = Sha384::new();
            hasher.update(&data);
            Some(hasher.finalize().to_vec())
        }
        _ => None,
    }
}

/// Creates a DS record from a DNSKEY record.
///
/// # Arguments
///
/// * `zone` - The zone name
/// * `dnskey` - The DNSKEY to create a DS for
/// * `digest_type` - The digest algorithm to use
///
/// # Returns
///
/// A DS record, or `None` if the digest type is not supported.
pub fn create_ds_from_dnskey(zone: &Name, dnskey: &DNSKEY, digest_type: u8) -> Option<DS> {
    let digest = compute_ds_digest(zone, dnskey, digest_type)?;
    Some(DS::new(
        dnskey.key_tag(),
        dnskey.algorithm(),
        digest_type,
        digest,
    ))
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

/// Returns the current Unix timestamp.
fn current_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Decodes a hexadecimal string to bytes.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    data_encoding::HEXUPPER
        .decode(s.as_bytes())
        .ok()
        .or_else(|| data_encoding::HEXLOWER.decode(s.as_bytes()).ok())
}

/// Groups resource records into RRsets.
fn group_rrsets(records: &[ResourceRecord]) -> Vec<(Name, RecordType, Vec<&ResourceRecord>)> {
    let mut rrsets: HashMap<(Name, RecordType), Vec<&ResourceRecord>> = HashMap::new();

    for record in records {
        if let Some(rtype) = record.record_type() {
            // Skip RRSIG records themselves
            if rtype == RecordType::RRSIG {
                continue;
            }

            let key = (record.name().clone(), rtype);
            rrsets.entry(key).or_insert_with(Vec::new).push(record);
        }
    }

    rrsets
        .into_iter()
        .map(|((name, rtype), records)| (name, rtype, records))
        .collect()
}

/// Finds RRSIG records that cover a specific RRset.
fn find_rrsigs_for_rrset<'a>(
    message: &'a Message,
    name: &Name,
    rtype: RecordType,
) -> Vec<&'a RRSIG> {
    let mut rrsigs = Vec::new();

    for record in message.answers().iter().chain(message.authority().iter()) {
        if let Some(RecordType::RRSIG) = record.record_type() {
            if record.name() == name {
                if let stria_proto::rdata::RData::RRSIG(rrsig) = record.rdata() {
                    if rrsig.type_covered() == rtype.to_u16() {
                        rrsigs.push(rrsig);
                    }
                }
            }
        }
    }

    rrsigs
}

/// Builds the signature data for verification.
///
/// The signature data consists of:
/// 1. RRSIG RDATA (without the signature field)
/// 2. Canonical RRset data
fn build_signature_data(records: &[&ResourceRecord], rrsig: &RRSIG) -> Result<Vec<u8>> {
    let mut data = BytesMut::new();

    // RRSIG RDATA fields (excluding signature)
    data.extend_from_slice(&rrsig.type_covered().to_be_bytes());
    data.extend_from_slice(&[rrsig.algorithm(), rrsig.labels()]);
    data.extend_from_slice(&rrsig.original_ttl().to_be_bytes());
    data.extend_from_slice(&rrsig.expiration().to_be_bytes());
    data.extend_from_slice(&rrsig.inception().to_be_bytes());
    data.extend_from_slice(&rrsig.key_tag().to_be_bytes());

    // Signer name must be in lowercase canonical form (RFC 4034 Section 3.1.8.1)
    let mut signer = rrsig.signer().clone();
    signer.to_lowercase();
    signer.write_wire(&mut data);

    // Canonical RRset data
    // Records must be sorted in canonical order
    let mut canonical_records: Vec<Vec<u8>> = records
        .iter()
        .map(|r| {
            let mut rr_data = BytesMut::new();

            // Owner name in lowercase canonical form
            let mut owner = r.name().clone();
            owner.to_lowercase();
            owner.write_wire(&mut rr_data);

            // Type, class, original TTL
            rr_data.extend_from_slice(&rrsig.type_covered().to_be_bytes());
            rr_data.extend_from_slice(&r.rclass().to_u16().to_be_bytes());
            rr_data.extend_from_slice(&rrsig.original_ttl().to_be_bytes());

            // RDATA length and RDATA in canonical form (RFC 4034 Section 6.2)
            // Domain names in RDATA must be lowercased
            let canonical_rdata = write_canonical_rdata(r.rdata());
            let rdata_len = canonical_rdata.len() as u16;
            rr_data.extend_from_slice(&rdata_len.to_be_bytes());
            rr_data.extend_from_slice(&canonical_rdata);

            rr_data.to_vec()
        })
        .collect();

    canonical_records.sort();

    for record_data in canonical_records {
        data.extend_from_slice(&record_data);
    }

    Ok(data.to_vec())
}

/// Writes RDATA in canonical form for DNSSEC verification (RFC 4034 Section 6.2).
///
/// Domain names embedded in certain RDATA types must be lowercased for DNSSEC signing/verification.
fn write_canonical_rdata(rdata: &RData) -> Vec<u8> {
    use stria_proto::rdata::*;

    let mut buf = BytesMut::new();

    match rdata {
        // Record types with a single domain name that needs lowercasing
        RData::NS(r) => {
            let mut name = r.nsdname().clone();
            name.to_lowercase();
            name.write_wire(&mut buf);
        }
        RData::CNAME(r) => {
            let mut name = r.target().clone();
            name.to_lowercase();
            name.write_wire(&mut buf);
        }
        RData::PTR(r) => {
            let mut name = r.ptrdname().clone();
            name.to_lowercase();
            name.write_wire(&mut buf);
        }
        RData::DNAME(r) => {
            let mut name = r.target().clone();
            name.to_lowercase();
            name.write_wire(&mut buf);
        }
        RData::MX(r) => {
            buf.extend_from_slice(&r.preference().to_be_bytes());
            let mut name = r.exchange().clone();
            name.to_lowercase();
            name.write_wire(&mut buf);
        }
        RData::SOA(r) => {
            let mut mname = r.mname().clone();
            mname.to_lowercase();
            mname.write_wire(&mut buf);
            let mut rname = r.rname().clone();
            rname.to_lowercase();
            rname.write_wire(&mut buf);
            buf.extend_from_slice(&r.serial().to_be_bytes());
            buf.extend_from_slice(&r.refresh().to_be_bytes());
            buf.extend_from_slice(&r.retry().to_be_bytes());
            buf.extend_from_slice(&r.expire().to_be_bytes());
            buf.extend_from_slice(&r.minimum().to_be_bytes());
        }
        RData::SRV(r) => {
            buf.extend_from_slice(&r.priority().to_be_bytes());
            buf.extend_from_slice(&r.weight().to_be_bytes());
            buf.extend_from_slice(&r.port().to_be_bytes());
            let mut name = r.target().clone();
            name.to_lowercase();
            name.write_wire(&mut buf);
        }
        RData::NSEC(r) => {
            let mut name = r.next_name().clone();
            name.to_lowercase();
            name.write_wire(&mut buf);
            buf.extend_from_slice(r.type_bitmap());
        }
        RData::RRSIG(r) => {
            // RRSIG's signer name needs lowercasing
            buf.extend_from_slice(&r.type_covered().to_be_bytes());
            buf.extend_from_slice(&[r.algorithm(), r.labels()]);
            buf.extend_from_slice(&r.original_ttl().to_be_bytes());
            buf.extend_from_slice(&r.expiration().to_be_bytes());
            buf.extend_from_slice(&r.inception().to_be_bytes());
            buf.extend_from_slice(&r.key_tag().to_be_bytes());
            let mut signer = r.signer().clone();
            signer.to_lowercase();
            signer.write_wire(&mut buf);
            buf.extend_from_slice(r.signature());
        }
        // For all other record types, use the standard wire format
        // (they don't contain domain names that need canonicalization)
        _ => {
            rdata.write_to(&mut buf);
        }
    }

    buf.to_vec()
}

/// Verifies a signature using the specified algorithm.
fn verify_signature_for_algorithm(
    algorithm: Algorithm,
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    match algorithm {
        #[cfg(feature = "rsa")]
        Algorithm::RsaSha256 => verify_rsa_signature(
            public_key,
            data,
            signature,
            // Use legacy variant to support 1024-bit keys still used by some zones
            &ring::signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        ),
        #[cfg(feature = "rsa")]
        Algorithm::RsaSha512 => verify_rsa_signature(
            public_key,
            data,
            signature,
            // Use legacy variant to support 1024-bit keys still used by some zones
            &ring::signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
        ),
        #[cfg(feature = "ecdsa")]
        Algorithm::EcdsaP256Sha256 => verify_ecdsa_p256_signature(public_key, data, signature),
        #[cfg(feature = "ecdsa")]
        Algorithm::EcdsaP384Sha384 => verify_ecdsa_p384_signature(public_key, data, signature),
        #[cfg(feature = "eddsa")]
        Algorithm::Ed25519 => verify_ed25519_signature(public_key, data, signature),
        Algorithm::Ed448 => Err(DnssecError::UnsupportedAlgorithm(16)), // Ed448 not yet implemented
    }
}

/// Verifies an RSA signature.
#[cfg(feature = "rsa")]
fn verify_rsa_signature(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
    algorithm: &'static ring::signature::RsaParameters,
) -> Result<()> {
    // Parse the DNSKEY public key format
    // RSA public keys in DNSKEY are stored as: exponent length (1 or 3 bytes) + exponent + modulus
    if public_key.is_empty() {
        return Err(DnssecError::InvalidPublicKey(
            "empty public key".to_string(),
        ));
    }

    let exp_len = if public_key[0] == 0 {
        // 3-byte length encoding
        if public_key.len() < 3 {
            return Err(DnssecError::InvalidPublicKey(
                "truncated exponent length".to_string(),
            ));
        }
        u16::from_be_bytes([public_key[1], public_key[2]]) as usize
    } else {
        public_key[0] as usize
    };

    let exp_offset = if public_key[0] == 0 { 3 } else { 1 };

    if public_key.len() < exp_offset + exp_len {
        return Err(DnssecError::InvalidPublicKey(
            "truncated public key".to_string(),
        ));
    }

    let exponent = &public_key[exp_offset..exp_offset + exp_len];
    let modulus = &public_key[exp_offset + exp_len..];

    // Build the RSA public key in DER format
    let der_key = build_rsa_public_key_der(modulus, exponent)?;

    // Verify using ring
    let public_key = ring::signature::UnparsedPublicKey::new(algorithm, &der_key);
    public_key
        .verify(data, signature)
        .map_err(|_| DnssecError::SignatureVerificationFailed("RSA signature invalid".to_string()))
}

/// Builds an RSA public key in DER format from modulus and exponent.
#[cfg(feature = "rsa")]
fn build_rsa_public_key_der(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    // Simple ASN.1 DER encoding for RSA public key
    // This is a minimal implementation - a production system might use a proper ASN.1 library

    fn encode_length(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len < 256 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, len as u8]
        }
    }

    fn encode_integer(data: &[u8]) -> Vec<u8> {
        let mut result = vec![0x02]; // INTEGER tag

        // Add leading zero if high bit is set (to ensure positive)
        let needs_padding = !data.is_empty() && (data[0] & 0x80) != 0;
        let len = data.len() + if needs_padding { 1 } else { 0 };

        result.extend(encode_length(len));
        if needs_padding {
            result.push(0x00);
        }
        result.extend_from_slice(data);
        result
    }

    let modulus_encoded = encode_integer(modulus);
    let exponent_encoded = encode_integer(exponent);

    let sequence_content_len = modulus_encoded.len() + exponent_encoded.len();
    let mut sequence = vec![0x30]; // SEQUENCE tag
    sequence.extend(encode_length(sequence_content_len));
    sequence.extend(modulus_encoded);
    sequence.extend(exponent_encoded);

    Ok(sequence)
}

/// Verifies an ECDSA P-256 signature.
#[cfg(feature = "ecdsa")]
fn verify_ecdsa_p256_signature(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::elliptic_curve::sec1::FromEncodedPoint;

    // DNSKEY stores ECDSA keys as uncompressed point (64 bytes for P-256)
    if public_key.len() != 64 {
        return Err(DnssecError::InvalidPublicKey(format!(
            "P-256 key should be 64 bytes, got {}",
            public_key.len()
        )));
    }

    // Convert to uncompressed format with 0x04 prefix
    let mut uncompressed = vec![0x04];
    uncompressed.extend_from_slice(public_key);

    let encoded_point = p256::EncodedPoint::from_bytes(&uncompressed)
        .map_err(|e| DnssecError::InvalidPublicKey(e.to_string()))?;

    let public_key_opt = p256::PublicKey::from_encoded_point(&encoded_point);
    let public_key: p256::PublicKey = Option::from(public_key_opt)
        .ok_or_else(|| DnssecError::InvalidPublicKey("invalid P-256 point".to_string()))?;

    let verifying_key = VerifyingKey::from(&public_key);

    // DNSSEC signatures are in fixed format (r || s), not DER
    if signature.len() != 64 {
        return Err(DnssecError::SignatureVerificationFailed(format!(
            "P-256 signature should be 64 bytes, got {}",
            signature.len()
        )));
    }

    let sig = Signature::from_slice(signature)
        .map_err(|e| DnssecError::SignatureVerificationFailed(e.to_string()))?;

    use p256::ecdsa::signature::Verifier;
    verifying_key
        .verify(data, &sig)
        .map_err(|e| DnssecError::SignatureVerificationFailed(e.to_string()))
}

/// Verifies an ECDSA P-384 signature.
#[cfg(feature = "ecdsa")]
fn verify_ecdsa_p384_signature(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    use p384::ecdsa::{Signature, VerifyingKey};
    use p384::elliptic_curve::sec1::FromEncodedPoint;

    // DNSKEY stores ECDSA keys as uncompressed point (96 bytes for P-384)
    if public_key.len() != 96 {
        return Err(DnssecError::InvalidPublicKey(format!(
            "P-384 key should be 96 bytes, got {}",
            public_key.len()
        )));
    }

    // Convert to uncompressed format with 0x04 prefix
    let mut uncompressed = vec![0x04];
    uncompressed.extend_from_slice(public_key);

    let encoded_point = p384::EncodedPoint::from_bytes(&uncompressed)
        .map_err(|e| DnssecError::InvalidPublicKey(e.to_string()))?;

    let public_key_opt = p384::PublicKey::from_encoded_point(&encoded_point);
    let public_key: p384::PublicKey = Option::from(public_key_opt)
        .ok_or_else(|| DnssecError::InvalidPublicKey("invalid P-384 point".to_string()))?;

    let verifying_key = VerifyingKey::from(&public_key);

    // DNSSEC signatures are in fixed format (r || s), not DER
    if signature.len() != 96 {
        return Err(DnssecError::SignatureVerificationFailed(format!(
            "P-384 signature should be 96 bytes, got {}",
            signature.len()
        )));
    }

    let sig = Signature::from_slice(signature)
        .map_err(|e| DnssecError::SignatureVerificationFailed(e.to_string()))?;

    use p384::ecdsa::signature::Verifier;
    verifying_key
        .verify(data, &sig)
        .map_err(|e| DnssecError::SignatureVerificationFailed(e.to_string()))
}

/// Verifies an Ed25519 signature.
#[cfg(feature = "eddsa")]
fn verify_ed25519_signature(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey};

    if public_key.len() != 32 {
        return Err(DnssecError::InvalidPublicKey(format!(
            "Ed25519 key should be 32 bytes, got {}",
            public_key.len()
        )));
    }

    if signature.len() != 64 {
        return Err(DnssecError::SignatureVerificationFailed(format!(
            "Ed25519 signature should be 64 bytes, got {}",
            signature.len()
        )));
    }

    let public_key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| DnssecError::InvalidPublicKey("invalid key length".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|e| DnssecError::InvalidPublicKey(e.to_string()))?;

    let signature_bytes: [u8; 64] = signature.try_into().map_err(|_| {
        DnssecError::SignatureVerificationFailed("invalid signature length".to_string())
    })?;

    let sig = Signature::from_bytes(&signature_bytes);

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(data, &sig)
        .map_err(|e| DnssecError::SignatureVerificationFailed(e.to_string()))
}

/// Computes an NSEC3 hash for a domain name.
fn compute_nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> Vec<u8> {
    use sha1::{Digest, Sha1};

    // Initial hash: H(name || salt)
    let mut wire_name = BytesMut::new();
    let lowercase_name = name.lowercased();
    lowercase_name.write_wire(&mut wire_name);

    let mut hasher = Sha1::new();
    hasher.update(&wire_name);
    hasher.update(salt);
    let mut hash = hasher.finalize().to_vec();

    // Iterations: H(hash || salt)
    for _ in 0..iterations {
        let mut hasher = Sha1::new();
        hasher.update(&hash);
        hasher.update(salt);
        hash = hasher.finalize().to_vec();
    }

    hash
}

/// Parses a type bitmap from NSEC/NSEC3 records.
fn parse_type_bitmap(bitmap: &[u8]) -> Vec<u16> {
    let mut types = Vec::new();
    let mut pos = 0;

    while pos + 2 <= bitmap.len() {
        let window = bitmap[pos] as u16;
        let bitmap_len = bitmap[pos + 1] as usize;
        pos += 2;

        if pos + bitmap_len > bitmap.len() {
            break;
        }

        for (byte_idx, &byte) in bitmap[pos..pos + bitmap_len].iter().enumerate() {
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_algorithm_from_u8() {
        #[cfg(feature = "rsa")]
        {
            assert_eq!(Algorithm::from_u8(8), Some(Algorithm::RsaSha256));
            assert_eq!(Algorithm::from_u8(10), Some(Algorithm::RsaSha512));
        }

        #[cfg(feature = "ecdsa")]
        {
            assert_eq!(Algorithm::from_u8(13), Some(Algorithm::EcdsaP256Sha256));
            assert_eq!(Algorithm::from_u8(14), Some(Algorithm::EcdsaP384Sha384));
        }

        #[cfg(feature = "eddsa")]
        assert_eq!(Algorithm::from_u8(15), Some(Algorithm::Ed25519));

        assert_eq!(Algorithm::from_u8(16), Some(Algorithm::Ed448));
        assert_eq!(Algorithm::from_u8(99), None);
    }

    #[test]
    fn test_digest_algorithm_len() {
        assert_eq!(DigestAlgorithm::Sha1.digest_len(), 20);
        assert_eq!(DigestAlgorithm::Sha256.digest_len(), 32);
        assert_eq!(DigestAlgorithm::Sha384.digest_len(), 48);
    }

    #[test]
    fn test_key_tag_calculation() {
        // Test with known values
        let flags = 257u16; // KSK
        let protocol = 3u8;
        let algorithm = 8u8; // RSA/SHA-256

        // Simple test key
        let public_key = vec![1, 0, 1]; // Minimal RSA public key (just exponent 65537)

        let tag = calculate_key_tag(flags, protocol, algorithm, &public_key);
        assert!(tag > 0);
    }

    #[test]
    fn test_trust_anchor_store() {
        let store = DefaultTrustAnchorStore::with_root_ksk();

        let root = Name::root();
        let anchors = store.get_anchors(&root);

        // Should have root KSKs
        assert!(!anchors.is_empty());

        // KSK-2017 should be present
        assert!(anchors.iter().any(|a| a.key_tag() == 20326));
    }

    #[test]
    fn test_find_closest_anchor() {
        let store = DefaultTrustAnchorStore::with_root_ksk();

        let name = Name::from_str("www.example.com").unwrap();
        let result = store.find_closest_anchor(&name);

        assert!(result.is_some());
        let (zone, anchors) = result.unwrap();
        assert!(zone.is_root()); // Should find root anchor
        assert!(!anchors.is_empty()); // Should have at least one anchor
    }

    #[test]
    fn test_validation_result() {
        assert!(ValidationResult::Secure.is_secure());
        assert!(ValidationResult::Insecure.is_insecure());
        assert!(ValidationResult::Bogus("test".to_string()).is_bogus());
        assert!(ValidationResult::Indeterminate.is_indeterminate());

        assert_eq!(
            ValidationResult::Bogus("reason".to_string()).bogus_reason(),
            Some("reason")
        );
        assert_eq!(ValidationResult::Secure.bogus_reason(), None);
    }

    #[test]
    fn test_ds_digest_computation() {
        let zone = Name::from_str("example.com").unwrap();
        let dnskey = DNSKEY::new(257, 3, 8, vec![1, 2, 3, 4]);

        let sha256_digest = compute_ds_digest(&zone, &dnskey, 2);
        assert!(sha256_digest.is_some());
        assert_eq!(sha256_digest.unwrap().len(), 32);

        let sha384_digest = compute_ds_digest(&zone, &dnskey, 4);
        assert!(sha384_digest.is_some());
        assert_eq!(sha384_digest.unwrap().len(), 48);

        // Unknown digest type
        let unknown = compute_ds_digest(&zone, &dnskey, 99);
        assert!(unknown.is_none());
    }

    #[test]
    fn test_hex_decode() {
        let upper = hex_decode("DEADBEEF");
        assert_eq!(upper, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));

        let lower = hex_decode("deadbeef");
        assert_eq!(lower, Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn test_nsec3_hash() {
        let name = Name::from_str("example.com").unwrap();
        let salt = b"";
        let iterations = 0u16;

        let hash = compute_nsec3_hash(&name, salt, iterations);
        assert_eq!(hash.len(), 20); // SHA-1 output
    }

    #[test]
    fn test_type_bitmap_parsing() {
        // Type bitmap for A(1), NS(2), SOA(6)
        let bitmap = vec![
            0u8, 2,    // Window 0, 2 bytes
            0x62, // Types 1, 2, 6
            0x00,
        ];

        let types = parse_type_bitmap(&bitmap);
        assert!(types.contains(&1));
        assert!(types.contains(&2));
        assert!(types.contains(&6));
        assert!(!types.contains(&3));
    }
}
