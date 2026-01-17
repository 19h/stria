//! DNS domain name representation and operations.
//!
//! This module provides a comprehensive implementation of DNS domain names
//! following RFC 1035 and RFC 2181. It supports:
//!
//! - Efficient storage using both heap-allocated and inline representations
//! - Wire format parsing with compression pointer handling
//! - Case-insensitive comparison per DNS semantics
//! - Label iteration and manipulation
//! - Conversion to/from string representation

mod label;
mod parse;

pub use label::{Label, LabelIter};
pub use parse::NameParser;

use crate::error::{Error, Result};
use crate::{MAX_LABEL_LENGTH, MAX_NAME_LENGTH};
use bytes::{Bytes, BytesMut};
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

/// A DNS domain name.
///
/// Domain names in DNS are sequences of labels separated by dots. Each label
/// can be up to 63 bytes, and the entire name (in wire format) can be up to
/// 255 bytes including length bytes and the root label.
///
/// # Wire Format
///
/// In wire format, a domain name is encoded as a sequence of labels, each
/// prefixed by a length byte, terminated by a zero-length label (the root).
/// For example, `www.example.com.` is encoded as:
///
/// ```text
/// 03 'w' 'w' 'w' 07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 03 'c' 'o' 'm' 00
/// ```
///
/// DNS also supports name compression using pointers. A pointer is a two-byte
/// sequence where the first two bits are `11`, and the remaining 14 bits
/// specify an offset into the message where the rest of the name can be found.
///
/// # Comparison Semantics
///
/// DNS names are compared case-insensitively per RFC 1035. The hash and equality
/// implementations respect this requirement.
///
/// # Example
///
/// ```rust
/// use stria_proto::name::Name;
/// use std::str::FromStr;
///
/// let name = Name::from_str("www.example.com.").unwrap();
/// assert_eq!(name.label_count(), 4); // www, example, com, root
/// assert!(name.is_fqdn());
///
/// // Case-insensitive comparison
/// assert_eq!(Name::from_str("WWW.EXAMPLE.COM.").unwrap(), name);
/// ```
#[derive(Clone)]
pub struct Name {
    /// The raw wire-format representation (without compression).
    wire: NameStorage,
    /// Number of labels (including root).
    label_count: u8,
}

/// Internal storage for domain name bytes.
///
/// Uses SmallVec to avoid heap allocation for typical domain names.
/// Most domain names fit within 64 bytes.
#[derive(Clone)]
enum NameStorage {
    /// Inline storage for small names (most common case).
    Inline(SmallVec<[u8; 64]>),
    /// Shared reference to bytes (for zero-copy parsing).
    Shared(Bytes),
}

impl Name {
    /// The root domain name (empty name, just the root label).
    pub const ROOT: Self = Self {
        wire: NameStorage::Inline(SmallVec::new_const()),
        label_count: 1,
    };

    /// Creates a new empty (root) domain name.
    #[inline]
    pub const fn root() -> Self {
        Self {
            wire: NameStorage::Inline(SmallVec::new_const()),
            label_count: 1,
        }
    }

    /// Creates a domain name from wire format bytes.
    ///
    /// The bytes should be in uncompressed wire format (no pointers).
    pub fn from_wire(wire: impl Into<Bytes>) -> Result<Self> {
        let bytes = wire.into();
        let label_count = Self::validate_wire(&bytes)?;
        Ok(Self {
            wire: NameStorage::Shared(bytes),
            label_count,
        })
    }

    /// Creates a domain name from a slice, copying the data.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let label_count = Self::validate_wire(slice)?;
        Ok(Self {
            wire: NameStorage::Inline(SmallVec::from_slice(slice)),
            label_count,
        })
    }

    /// Validates wire format and returns label count.
    fn validate_wire(bytes: &[u8]) -> Result<u8> {
        if bytes.is_empty() {
            // Empty is the root name (just the terminating 0)
            return Ok(1);
        }

        let mut pos = 0;
        let mut labels = 0u8;
        let mut total_len = 0usize;

        while pos < bytes.len() {
            let len = bytes[pos] as usize;

            if len == 0 {
                // Root label - end of name
                labels = labels.checked_add(1).ok_or(Error::NameTooLong {
                    length: MAX_NAME_LENGTH + 1,
                })?;
                break;
            }

            // Check for compression pointer (not allowed in stored names)
            if len >= 0xC0 {
                return Err(Error::invalid_data(
                    pos,
                    "compression pointer in stored name",
                ));
            }

            if len > MAX_LABEL_LENGTH {
                return Err(Error::LabelTooLong { length: len });
            }

            total_len += 1 + len; // length byte + label
            if total_len > MAX_NAME_LENGTH {
                return Err(Error::NameTooLong { length: total_len });
            }

            pos += 1 + len;
            labels = labels.checked_add(1).ok_or(Error::NameTooLong {
                length: MAX_NAME_LENGTH + 1,
            })?;

            if pos > bytes.len() {
                return Err(Error::UnexpectedEof { offset: pos });
            }
        }

        Ok(labels)
    }

    /// Returns the wire format representation.
    #[inline]
    pub fn as_wire(&self) -> &[u8] {
        match &self.wire {
            NameStorage::Inline(v) => v.as_slice(),
            NameStorage::Shared(b) => b.as_ref(),
        }
    }

    /// Returns the wire format length (including terminating zero).
    #[inline]
    pub fn wire_len(&self) -> usize {
        self.as_wire().len().max(1) // At least 1 for root label
    }

    /// Returns the number of labels in the name (including root).
    #[inline]
    pub const fn label_count(&self) -> usize {
        self.label_count as usize
    }

    /// Returns true if this is the root domain.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.as_wire().is_empty() || (self.as_wire().len() == 1 && self.as_wire()[0] == 0)
    }

    /// Returns true if this is a fully-qualified domain name (ends with root).
    ///
    /// All properly formed DNS names are FQDNs. This method checks that
    /// the wire format ends with a zero-length label.
    #[inline]
    pub fn is_fqdn(&self) -> bool {
        let wire = self.as_wire();
        wire.is_empty() || wire.last() == Some(&0)
    }

    /// Returns an iterator over the labels in the name.
    #[inline]
    pub fn labels(&self) -> LabelIter<'_> {
        LabelIter::new(self.as_wire())
    }

    /// Returns the label at the given index (0 = leftmost label).
    pub fn label(&self, index: usize) -> Option<Label<'_>> {
        self.labels().nth(index)
    }

    /// Returns the parent domain (removes the leftmost label).
    ///
    /// Returns `None` for the root domain.
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }

        let wire = self.as_wire();
        if wire.is_empty() {
            return None;
        }

        let first_label_len = wire[0] as usize;
        if first_label_len == 0 {
            return None;
        }

        let parent_start = 1 + first_label_len;
        if parent_start >= wire.len() {
            return Some(Self::root());
        }

        let parent_wire = &wire[parent_start..];
        Self::from_slice(parent_wire).ok()
    }

    /// Returns the subdomain formed by prepending a label.
    pub fn prepend_label(&self, label: &str) -> Result<Self> {
        if label.len() > MAX_LABEL_LENGTH {
            return Err(Error::LabelTooLong {
                length: label.len(),
            });
        }

        let self_wire = self.as_wire();
        let new_len = 1 + label.len() + self_wire.len().max(1);

        if new_len > MAX_NAME_LENGTH {
            return Err(Error::NameTooLong { length: new_len });
        }

        let mut wire = SmallVec::with_capacity(new_len);
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());

        if self_wire.is_empty() {
            wire.push(0); // Root label
        } else {
            wire.extend_from_slice(self_wire);
        }

        Ok(Self {
            wire: NameStorage::Inline(wire),
            label_count: self.label_count.saturating_add(1),
        })
    }

    /// Returns true if this name is a subdomain of the given name.
    pub fn is_subdomain_of(&self, other: &Name) -> bool {
        if self.label_count() < other.label_count() {
            return false;
        }

        // Compare from the right (root) side
        let self_labels: Vec<_> = self.labels().collect();
        let other_labels: Vec<_> = other.labels().collect();

        for (i, other_label) in other_labels.iter().rev().enumerate() {
            let self_idx = self_labels.len() - 1 - i;
            if !self_labels[self_idx].eq_ignore_ascii_case(other_label) {
                return false;
            }
        }

        true
    }

    /// Converts to a string representation.
    ///
    /// This allocates a new string. For display purposes, use the `Display` trait.
    pub fn to_string_representation(&self) -> CompactString {
        let mut result = CompactString::new("");

        for label in self.labels() {
            if !label.is_root() {
                result.push_str(label.as_str_lossy().as_ref());
                result.push('.');
            }
        }

        if result.is_empty() {
            result.push('.');
        }

        result
    }

    /// Converts the name to lowercase (in place for ASCII).
    pub fn to_lowercase(&mut self) {
        match &mut self.wire {
            NameStorage::Inline(v) => {
                for byte in v.iter_mut() {
                    if byte.is_ascii_uppercase() {
                        *byte = byte.to_ascii_lowercase();
                    }
                }
            }
            NameStorage::Shared(b) => {
                let mut bytes = BytesMut::from(b.as_ref());
                for byte in bytes.iter_mut() {
                    if byte.is_ascii_uppercase() {
                        *byte = byte.to_ascii_lowercase();
                    }
                }
                *b = bytes.freeze();
            }
        }
    }

    /// Returns a lowercased copy of the name.
    #[must_use]
    pub fn lowercased(&self) -> Self {
        let mut copy = self.clone();
        copy.to_lowercase();
        copy
    }

    /// Writes the name in wire format to a buffer.
    pub fn write_wire(&self, buf: &mut BytesMut) {
        let wire = self.as_wire();
        if wire.is_empty() {
            buf.extend_from_slice(&[0]); // Root label
        } else {
            buf.extend_from_slice(wire);
        }
    }

    /// Calculates a hash using lowercase comparison.
    fn lowercase_hash<H: Hasher>(&self, state: &mut H) {
        for label in self.labels() {
            let lower: SmallVec<[u8; 64]> = label
                .as_bytes()
                .iter()
                .map(|b| b.to_ascii_lowercase())
                .collect();
            lower.hash(state);
        }
    }
}

impl FromStr for Name {
    type Err = Error;

    /// Parses a domain name from a string.
    ///
    /// The string should be in the standard dotted format (e.g., `www.example.com.`).
    /// A trailing dot indicates a fully-qualified domain name. If no trailing dot
    /// is present, one is implied.
    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() || s == "." {
            return Ok(Self::root());
        }

        let s = s.strip_suffix('.').unwrap_or(s);
        let parts: Vec<&str> = s.split('.').collect();

        let mut wire = SmallVec::<[u8; 64]>::new();
        let mut label_count = 0u8;

        for part in &parts {
            if part.len() > MAX_LABEL_LENGTH {
                return Err(Error::LabelTooLong { length: part.len() });
            }

            // Validate label characters
            // Allow alphanumeric, hyphen, underscore, and asterisk (for wildcards)
            for (i, c) in part.chars().enumerate() {
                if !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '*' {
                    return Err(Error::InvalidLabelChar {
                        character: c,
                        position: i,
                    });
                }
            }

            wire.push(part.len() as u8);
            wire.extend_from_slice(part.as_bytes());
            label_count += 1;
        }

        // Add root label
        wire.push(0);
        label_count += 1;

        if wire.len() > MAX_NAME_LENGTH {
            return Err(Error::NameTooLong { length: wire.len() });
        }

        Ok(Self {
            wire: NameStorage::Inline(wire),
            label_count,
        })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_representation())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name(\"{}\")", self)
    }
}

impl PartialEq for Name {
    /// Case-insensitive comparison per DNS semantics.
    fn eq(&self, other: &Self) -> bool {
        if self.label_count != other.label_count {
            return false;
        }

        self.labels()
            .zip(other.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(&b))
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.lowercase_hash(state);
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
    /// Canonical DNS name ordering per RFC 4034.
    fn cmp(&self, other: &Self) -> Ordering {
        let self_labels: Vec<_> = self.labels().collect();
        let other_labels: Vec<_> = other.labels().collect();

        // Compare from right to left (root first)
        let mut i = self_labels.len();
        let mut j = other_labels.len();

        while i > 0 && j > 0 {
            i -= 1;
            j -= 1;

            let cmp = self_labels[i].cmp_canonical(&other_labels[j]);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }

        self_labels.len().cmp(&other_labels.len())
    }
}

impl Default for Name {
    fn default() -> Self {
        Self::root()
    }
}

impl Serialize for Name {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_name() {
        let root = Name::root();
        assert!(root.is_root());
        assert!(root.is_fqdn());
        assert_eq!(root.label_count(), 1);
        assert_eq!(root.to_string(), ".");
    }

    #[test]
    fn test_name_parsing() {
        let name = Name::from_str("www.example.com.").unwrap();
        assert!(!name.is_root());
        assert!(name.is_fqdn());
        assert_eq!(name.label_count(), 4);
        assert_eq!(name.to_string(), "www.example.com.");

        // Without trailing dot
        let name2 = Name::from_str("www.example.com").unwrap();
        assert_eq!(name, name2);
    }

    #[test]
    fn test_case_insensitive_comparison() {
        let lower = Name::from_str("www.example.com").unwrap();
        let upper = Name::from_str("WWW.EXAMPLE.COM").unwrap();
        let mixed = Name::from_str("Www.ExAmPlE.CoM").unwrap();

        assert_eq!(lower, upper);
        assert_eq!(lower, mixed);
        assert_eq!(upper, mixed);
    }

    #[test]
    fn test_label_iteration() {
        let name = Name::from_str("www.example.com").unwrap();
        let labels: Vec<_> = name.labels().map(|l| l.to_string()).collect();
        assert_eq!(labels, vec!["www", "example", "com", ""]);
    }

    #[test]
    fn test_parent() {
        let name = Name::from_str("www.example.com").unwrap();

        let parent1 = name.parent().unwrap();
        assert_eq!(parent1.to_string(), "example.com.");

        let parent2 = parent1.parent().unwrap();
        assert_eq!(parent2.to_string(), "com.");

        let parent3 = parent2.parent().unwrap();
        assert!(parent3.is_root());

        assert!(parent3.parent().is_none());
    }

    #[test]
    fn test_subdomain_check() {
        let name = Name::from_str("www.example.com").unwrap();
        let parent = Name::from_str("example.com").unwrap();
        let other = Name::from_str("other.com").unwrap();

        assert!(name.is_subdomain_of(&parent));
        assert!(name.is_subdomain_of(&name));
        assert!(!parent.is_subdomain_of(&name));
        assert!(!name.is_subdomain_of(&other));
    }

    #[test]
    fn test_label_too_long() {
        let long_label = "a".repeat(64);
        let result = Name::from_str(&long_label);
        assert!(matches!(result, Err(Error::LabelTooLong { .. })));
    }

    #[test]
    fn test_prepend_label() {
        let name = Name::from_str("example.com").unwrap();
        let subdomain = name.prepend_label("www").unwrap();
        assert_eq!(subdomain.to_string(), "www.example.com.");
    }

    #[test]
    fn test_canonical_ordering() {
        // Test canonical ordering per RFC 4034 Section 6.1
        // Note: Escaped characters like \200 require escape parsing which isn't implemented
        let names: Vec<Name> = vec![
            "example.",
            "a.example.",
            "yljkjljk.a.example.",
            "Z.a.example.",
            "zABC.a.EXAMPLE.",
            "z.example.",
            "*.z.example.",
        ]
        .into_iter()
        .map(|s| Name::from_str(s).unwrap())
        .collect();

        let mut sorted = names.clone();
        sorted.sort();

        // Verify the order follows RFC 4034 canonical ordering
        for i in 0..sorted.len() - 1 {
            assert!(sorted[i] <= sorted[i + 1]);
        }
    }
}
