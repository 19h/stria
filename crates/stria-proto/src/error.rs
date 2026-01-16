//! DNS protocol error types.
//!
//! This module provides comprehensive error handling for DNS protocol operations
//! including parsing, serialization, and validation errors.

use thiserror::Error;

/// Result type alias for DNS protocol operations.
pub type Result<T> = std::result::Result<T, Error>;

/// DNS protocol errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // =========================================================================
    // Wire Format Parsing Errors
    // =========================================================================
    /// Buffer is too short to contain the expected data.
    #[error("buffer too short: expected at least {expected} bytes, got {actual}")]
    BufferTooShort {
        /// Expected minimum size.
        expected: usize,
        /// Actual buffer size.
        actual: usize,
    },

    /// Buffer overflow during serialization.
    #[error("buffer overflow: cannot write {needed} bytes to buffer with {available} available")]
    BufferOverflow {
        /// Bytes needed to write.
        needed: usize,
        /// Available space in buffer.
        available: usize,
    },

    /// Unexpected end of data while parsing.
    #[error("unexpected end of data at offset {offset}")]
    UnexpectedEof {
        /// Byte offset where EOF was encountered.
        offset: usize,
    },

    /// Invalid data encountered during parsing.
    #[error("invalid data at offset {offset}: {message}")]
    InvalidData {
        /// Byte offset of the invalid data.
        offset: usize,
        /// Description of the error.
        message: String,
    },

    // =========================================================================
    // Domain Name Errors
    // =========================================================================
    /// Label exceeds maximum length of 63 bytes.
    #[error("label too long: {length} bytes exceeds maximum of 63")]
    LabelTooLong {
        /// Actual label length.
        length: usize,
    },

    /// Domain name exceeds maximum length of 255 bytes.
    #[error("name too long: {length} bytes exceeds maximum of 255")]
    NameTooLong {
        /// Actual name length in wire format.
        length: usize,
    },

    /// Empty label in the middle of a domain name.
    #[error("empty label at position {position} (only allowed at end for root)")]
    EmptyLabel {
        /// Position of the empty label.
        position: usize,
    },

    /// Invalid label character.
    #[error("invalid character '{character}' in label at position {position}")]
    InvalidLabelChar {
        /// The invalid character.
        character: char,
        /// Position in the label.
        position: usize,
    },

    /// Invalid compression pointer.
    #[error("invalid compression pointer at offset {offset}: points to {target}")]
    InvalidCompressionPointer {
        /// Offset of the pointer.
        offset: usize,
        /// Target offset the pointer references.
        target: usize,
    },

    /// Compression pointer loop detected.
    #[error("compression pointer loop detected at offset {offset}")]
    CompressionLoop {
        /// Offset where the loop was detected.
        offset: usize,
    },

    /// Too many compression pointer jumps.
    #[error("too many compression pointer jumps (>{max_jumps})")]
    TooManyCompressionJumps {
        /// Maximum allowed jumps.
        max_jumps: usize,
    },

    // =========================================================================
    // Header Errors
    // =========================================================================
    /// Invalid opcode value.
    #[error("invalid opcode: {value}")]
    InvalidOpCode {
        /// The invalid opcode value.
        value: u8,
    },

    /// Invalid response code value.
    #[error("invalid response code: {value}")]
    InvalidResponseCode {
        /// The invalid rcode value.
        value: u16,
    },

    // =========================================================================
    // Record Type/Class Errors
    // =========================================================================
    /// Invalid or unsupported record type.
    #[error("invalid record type: {value}")]
    InvalidRecordType {
        /// The invalid type value.
        value: u16,
    },

    /// Invalid or unsupported record class.
    #[error("invalid record class: {value}")]
    InvalidRecordClass {
        /// The invalid class value.
        value: u16,
    },

    // =========================================================================
    // RDATA Errors
    // =========================================================================
    /// RDATA length mismatch.
    #[error("RDATA length mismatch for {rtype}: expected {expected}, got {actual}")]
    RDataLengthMismatch {
        /// Record type.
        rtype: String,
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Invalid RDATA content.
    #[error("invalid RDATA for {rtype}: {message}")]
    InvalidRData {
        /// Record type.
        rtype: String,
        /// Error description.
        message: String,
    },

    /// Invalid IP address.
    #[error("invalid IP address: {message}")]
    InvalidIpAddress {
        /// Error description.
        message: String,
    },

    // =========================================================================
    // EDNS Errors
    // =========================================================================
    /// Invalid EDNS option.
    #[error("invalid EDNS option {code}: {message}")]
    InvalidEdnsOption {
        /// Option code.
        code: u16,
        /// Error description.
        message: String,
    },

    /// Multiple OPT records in message.
    #[error("multiple OPT records in message (only one allowed)")]
    MultipleOptRecords,

    /// OPT record in wrong section.
    #[error("OPT record found in {section} section (must be in additional)")]
    OptInWrongSection {
        /// Section where OPT was found.
        section: String,
    },

    // =========================================================================
    // Message Errors
    // =========================================================================
    /// Message ID mismatch.
    #[error("message ID mismatch: expected {expected}, got {actual}")]
    MessageIdMismatch {
        /// Expected message ID.
        expected: u16,
        /// Actual message ID.
        actual: u16,
    },

    /// Response to wrong question.
    #[error("response does not match query")]
    ResponseMismatch,

    /// Message exceeds maximum size.
    #[error("message too large: {size} bytes exceeds maximum of {max_size}")]
    MessageTooLarge {
        /// Actual message size.
        size: usize,
        /// Maximum allowed size.
        max_size: usize,
    },

    // =========================================================================
    // DNSSEC Errors
    // =========================================================================
    /// Invalid DNSSEC algorithm.
    #[error("invalid DNSSEC algorithm: {value}")]
    InvalidDnsSecAlgorithm {
        /// The invalid algorithm value.
        value: u8,
    },

    /// Invalid digest type.
    #[error("invalid digest type: {value}")]
    InvalidDigestType {
        /// The invalid digest type value.
        value: u8,
    },

    /// Invalid NSEC3 hash algorithm.
    #[error("invalid NSEC3 hash algorithm: {value}")]
    InvalidNsec3HashAlgorithm {
        /// The invalid algorithm value.
        value: u8,
    },

    // =========================================================================
    // Miscellaneous
    // =========================================================================
    /// Feature not implemented.
    #[error("not implemented: {feature}")]
    NotImplemented {
        /// The unimplemented feature.
        feature: String,
    },

    /// Internal error.
    #[error("internal error: {message}")]
    Internal {
        /// Error description.
        message: String,
    },
}

impl Error {
    /// Creates a new `BufferTooShort` error.
    #[inline]
    pub fn buffer_too_short(expected: usize, actual: usize) -> Self {
        Self::BufferTooShort { expected, actual }
    }

    /// Creates a new `BufferOverflow` error.
    #[inline]
    pub fn buffer_overflow(needed: usize, available: usize) -> Self {
        Self::BufferOverflow { needed, available }
    }

    /// Creates a new `UnexpectedEof` error.
    #[inline]
    pub fn unexpected_eof(offset: usize) -> Self {
        Self::UnexpectedEof { offset }
    }

    /// Creates a new `InvalidData` error.
    #[inline]
    pub fn invalid_data(offset: usize, message: impl Into<String>) -> Self {
        Self::InvalidData {
            offset,
            message: message.into(),
        }
    }

    /// Creates a new `LabelTooLong` error.
    #[inline]
    pub fn label_too_long(length: usize) -> Self {
        Self::LabelTooLong { length }
    }

    /// Creates a new `NameTooLong` error.
    #[inline]
    pub fn name_too_long(length: usize) -> Self {
        Self::NameTooLong { length }
    }

    /// Creates a new `InvalidRData` error.
    #[inline]
    pub fn invalid_rdata(rtype: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidRData {
            rtype: rtype.into(),
            message: message.into(),
        }
    }

    /// Creates a new `InvalidEdnsOption` error.
    #[inline]
    pub fn invalid_edns_option(code: u16, message: impl Into<String>) -> Self {
        Self::InvalidEdnsOption {
            code,
            message: message.into(),
        }
    }

    /// Returns true if this error indicates a malformed message that should be dropped.
    #[inline]
    pub fn is_malformed(&self) -> bool {
        matches!(
            self,
            Self::BufferTooShort { .. }
                | Self::UnexpectedEof { .. }
                | Self::InvalidData { .. }
                | Self::CompressionLoop { .. }
                | Self::InvalidCompressionPointer { .. }
        )
    }

    /// Returns true if this error indicates a format error (FORMERR).
    #[inline]
    pub fn is_format_error(&self) -> bool {
        matches!(
            self,
            Self::LabelTooLong { .. }
                | Self::NameTooLong { .. }
                | Self::InvalidRecordType { .. }
                | Self::InvalidRecordClass { .. }
                | Self::MultipleOptRecords
                | Self::OptInWrongSection { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::buffer_too_short(12, 8);
        assert_eq!(
            err.to_string(),
            "buffer too short: expected at least 12 bytes, got 8"
        );

        let err = Error::label_too_long(64);
        assert_eq!(
            err.to_string(),
            "label too long: 64 bytes exceeds maximum of 63"
        );
    }

    #[test]
    fn test_error_classification() {
        assert!(Error::buffer_too_short(10, 5).is_malformed());
        assert!(Error::CompressionLoop { offset: 0 }.is_malformed());
        assert!(Error::LabelTooLong { length: 64 }.is_format_error());
        assert!(Error::MultipleOptRecords.is_format_error());
    }
}
