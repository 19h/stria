//! DNS label handling.
//!
//! A label is a single component of a domain name, up to 63 bytes.

use smallvec::SmallVec;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;

/// A single DNS label (component of a domain name).
///
/// Labels are the individual parts of a domain name separated by dots.
/// For example, in `www.example.com`, the labels are `www`, `example`, `com`,
/// and the implicit root label (empty).
#[derive(Clone)]
pub struct Label<'a> {
    /// The raw bytes of the label (without length prefix).
    bytes: Cow<'a, [u8]>,
}

impl<'a> Label<'a> {
    /// Creates a label from a byte slice.
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes: Cow::Borrowed(bytes),
        }
    }

    /// Creates an owned label from bytes.
    #[inline]
    pub fn from_owned(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Cow::Owned(bytes),
        }
    }

    /// Creates the root label (empty).
    #[inline]
    pub const fn root() -> Self {
        Self {
            bytes: Cow::Borrowed(&[]),
        }
    }

    /// Returns the raw bytes of the label.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the length of the label in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if this is the root label (empty).
    #[inline]
    pub fn is_root(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns true if this label is empty (same as root).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the label as a string, if it's valid UTF-8.
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes).ok()
    }

    /// Returns the label as a string, with invalid UTF-8 replaced.
    #[inline]
    pub fn as_str_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }

    /// Converts to an owned version.
    #[inline]
    pub fn into_owned(self) -> Label<'static> {
        Label {
            bytes: Cow::Owned(self.bytes.into_owned()),
        }
    }

    /// Returns a lowercase version of the label.
    #[inline]
    pub fn to_lowercase(&self) -> Label<'static> {
        let lower: Vec<u8> = self.bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
        Label {
            bytes: Cow::Owned(lower),
        }
    }

    /// Case-insensitive comparison with another label.
    #[inline]
    pub fn eq_ignore_ascii_case(&self, other: &Label) -> bool {
        if self.len() != other.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(other.bytes.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// Canonical comparison per RFC 4034.
    ///
    /// This compares labels in a case-insensitive manner suitable for
    /// DNSSEC canonical ordering.
    pub fn cmp_canonical(&self, other: &Label) -> Ordering {
        let len_cmp = self.len().cmp(&other.len());
        if len_cmp != Ordering::Equal {
            return len_cmp;
        }

        for (a, b) in self.bytes.iter().zip(other.bytes.iter()) {
            let a_lower = a.to_ascii_lowercase();
            let b_lower = b.to_ascii_lowercase();
            match a_lower.cmp(&b_lower) {
                Ordering::Equal => continue,
                other => return other,
            }
        }

        Ordering::Equal
    }

    /// Returns true if this label matches a wildcard pattern.
    #[inline]
    pub fn is_wildcard(&self) -> bool {
        self.bytes.as_ref() == b"*"
    }
}

impl<'a> fmt::Display for Label<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Handle special characters that need escaping
        for &byte in self.bytes.iter() {
            if byte == b'.' || byte == b'\\' {
                write!(f, "\\{}", byte as char)?;
            } else if byte.is_ascii_graphic() || byte == b' ' {
                write!(f, "{}", byte as char)?;
            } else {
                // Escape non-printable characters as \DDD
                write!(f, "\\{:03}", byte)?;
            }
        }
        Ok(())
    }
}

impl<'a> fmt::Debug for Label<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Label(\"{}\")", self)
    }
}

impl<'a> PartialEq for Label<'a> {
    /// Case-insensitive equality per DNS semantics.
    fn eq(&self, other: &Self) -> bool {
        self.eq_ignore_ascii_case(other)
    }
}

impl<'a> Eq for Label<'a> {}

impl<'a> PartialOrd for Label<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp_canonical(other))
    }
}

impl<'a> Ord for Label<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_canonical(other)
    }
}

/// Iterator over labels in a domain name.
pub struct LabelIter<'a> {
    /// The wire format bytes.
    wire: &'a [u8],
    /// Current position in the wire data.
    pos: usize,
    /// Whether we've reached the end.
    done: bool,
}

impl<'a> LabelIter<'a> {
    /// Creates a new label iterator from wire format bytes.
    #[inline]
    pub fn new(wire: &'a [u8]) -> Self {
        Self {
            wire,
            pos: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = Label<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if self.pos >= self.wire.len() {
            self.done = true;
            return Some(Label::root());
        }

        let len = self.wire[self.pos] as usize;

        if len == 0 {
            self.done = true;
            return Some(Label::root());
        }

        let start = self.pos + 1;
        let end = start + len;

        if end > self.wire.len() {
            self.done = true;
            return None;
        }

        let label = Label::from_bytes(&self.wire[start..end]);
        self.pos = end;
        Some(label)
    }
}

impl<'a> std::iter::FusedIterator for LabelIter<'a> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_basics() {
        let label = Label::from_bytes(b"example");
        assert_eq!(label.len(), 7);
        assert!(!label.is_root());
        assert_eq!(label.as_str(), Some("example"));
        assert_eq!(label.to_string(), "example");
    }

    #[test]
    fn test_root_label() {
        let root = Label::root();
        assert!(root.is_root());
        assert!(root.is_empty());
        assert_eq!(root.len(), 0);
    }

    #[test]
    fn test_case_insensitive_comparison() {
        let lower = Label::from_bytes(b"example");
        let upper = Label::from_bytes(b"EXAMPLE");
        let mixed = Label::from_bytes(b"ExAmPlE");

        assert!(lower.eq_ignore_ascii_case(&upper));
        assert!(lower.eq_ignore_ascii_case(&mixed));
        assert_eq!(lower, upper);
    }

    #[test]
    fn test_wildcard() {
        let wildcard = Label::from_bytes(b"*");
        assert!(wildcard.is_wildcard());

        let not_wildcard = Label::from_bytes(b"www");
        assert!(!not_wildcard.is_wildcard());
    }

    #[test]
    fn test_canonical_ordering() {
        let a = Label::from_bytes(b"a");
        let b = Label::from_bytes(b"B");
        let aa = Label::from_bytes(b"aa");

        // Single chars should compare case-insensitively
        assert!(a < b);

        // Longer labels come after shorter ones with same prefix
        assert!(a < aa);
    }
}
