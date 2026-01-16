//! Wire format utilities.
//!
//! This module provides helper functions and types for reading and writing
//! DNS wire format data.

use crate::error::{Error, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// A cursor for reading DNS wire format data.
///
/// This provides safe access to wire format data with bounds checking
/// and position tracking.
#[derive(Debug, Clone)]
pub struct WireReader<'a> {
    /// The underlying data.
    data: &'a [u8],
    /// Current position.
    pos: usize,
}

impl<'a> WireReader<'a> {
    /// Creates a new wire reader.
    #[inline]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Returns the underlying data.
    #[inline]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the current position.
    #[inline]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Returns the remaining bytes.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Returns true if there are no remaining bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Sets the position.
    #[inline]
    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Advances the position by the given amount.
    #[inline]
    pub fn advance(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.data.len() {
            return Err(Error::unexpected_eof(self.pos + n));
        }
        self.pos += n;
        Ok(())
    }

    /// Reads a single byte.
    #[inline]
    pub fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::unexpected_eof(self.pos));
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    /// Reads a big-endian u16.
    #[inline]
    pub fn read_u16(&mut self) -> Result<u16> {
        if self.pos + 2 > self.data.len() {
            return Err(Error::unexpected_eof(self.pos + 2));
        }
        let value = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }

    /// Reads a big-endian u32.
    #[inline]
    pub fn read_u32(&mut self) -> Result<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(Error::unexpected_eof(self.pos + 4));
        }
        let value = u32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(value)
    }

    /// Reads a slice of bytes.
    #[inline]
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return Err(Error::unexpected_eof(self.pos + len));
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Peeks at a single byte without advancing.
    #[inline]
    pub fn peek_u8(&self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::unexpected_eof(self.pos));
        }
        Ok(self.data[self.pos])
    }

    /// Returns a slice at the given offset without advancing.
    #[inline]
    pub fn slice_at(&self, offset: usize, len: usize) -> Result<&'a [u8]> {
        if offset + len > self.data.len() {
            return Err(Error::buffer_too_short(offset + len, self.data.len()));
        }
        Ok(&self.data[offset..offset + len])
    }
}

/// A writer for DNS wire format data.
///
/// Wraps a `BytesMut` and provides helper methods for writing DNS data.
#[derive(Debug)]
pub struct WireWriter {
    /// The underlying buffer.
    buf: BytesMut,
    /// Maximum size (for truncation).
    max_size: Option<usize>,
}

impl WireWriter {
    /// Creates a new wire writer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(capacity),
            max_size: None,
        }
    }

    /// Creates a wire writer with a maximum size limit.
    pub fn with_max_size(capacity: usize, max_size: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(capacity.min(max_size)),
            max_size: Some(max_size),
        }
    }

    /// Returns the current length.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns true if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns the remaining capacity before max size.
    pub fn remaining(&self) -> usize {
        self.max_size
            .map(|max| max.saturating_sub(self.buf.len()))
            .unwrap_or(usize::MAX)
    }

    /// Returns true if adding `n` bytes would exceed max size.
    pub fn would_overflow(&self, n: usize) -> bool {
        self.max_size
            .map(|max| self.buf.len() + n > max)
            .unwrap_or(false)
    }

    /// Writes a single byte.
    #[inline]
    pub fn write_u8(&mut self, value: u8) -> Result<()> {
        if self.would_overflow(1) {
            return Err(Error::buffer_overflow(1, self.remaining()));
        }
        self.buf.put_u8(value);
        Ok(())
    }

    /// Writes a big-endian u16.
    #[inline]
    pub fn write_u16(&mut self, value: u16) -> Result<()> {
        if self.would_overflow(2) {
            return Err(Error::buffer_overflow(2, self.remaining()));
        }
        self.buf.put_u16(value);
        Ok(())
    }

    /// Writes a big-endian u32.
    #[inline]
    pub fn write_u32(&mut self, value: u32) -> Result<()> {
        if self.would_overflow(4) {
            return Err(Error::buffer_overflow(4, self.remaining()));
        }
        self.buf.put_u32(value);
        Ok(())
    }

    /// Writes a slice of bytes.
    #[inline]
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if self.would_overflow(bytes.len()) {
            return Err(Error::buffer_overflow(bytes.len(), self.remaining()));
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Returns the underlying buffer.
    #[inline]
    pub fn into_bytes(self) -> BytesMut {
        self.buf
    }

    /// Returns the data as frozen bytes.
    #[inline]
    pub fn freeze(self) -> Bytes {
        self.buf.freeze()
    }

    /// Returns a reference to the underlying buffer.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Writes at a specific position (for filling in length fields).
    pub fn write_at(&mut self, offset: usize, bytes: &[u8]) {
        if offset + bytes.len() <= self.buf.len() {
            self.buf[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
    }
}

/// Calculates a simple DNS-style checksum (used for key tags, etc.).
pub fn dns_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i & 1 == 0 {
            sum += u32::from(byte) << 8;
        } else {
            sum += u32::from(byte);
        }
    }

    sum += sum >> 16;
    (sum & 0xFFFF) as u16
}

/// Applies 0x20 bit encoding to randomize the case of a domain name.
///
/// This is a cache poisoning countermeasure that encodes entropy in the
/// case of query names.
pub fn apply_0x20_encoding(name: &mut [u8], entropy: &[u8]) {
    let mut entropy_idx = 0;
    let mut pos = 0;

    while pos < name.len() {
        let label_len = name[pos] as usize;
        if label_len == 0 {
            break;
        }

        pos += 1;
        for i in 0..label_len {
            if pos + i >= name.len() {
                break;
            }

            let c = name[pos + i];
            if c.is_ascii_alphabetic() {
                let bit = if entropy_idx < entropy.len() * 8 {
                    (entropy[entropy_idx / 8] >> (7 - (entropy_idx % 8))) & 1
                } else {
                    0
                };
                entropy_idx += 1;

                if bit == 1 {
                    name[pos + i] = c.to_ascii_uppercase();
                } else {
                    name[pos + i] = c.to_ascii_lowercase();
                }
            }
        }

        pos += label_len;
    }
}

/// Generates random bytes for 0x20 encoding.
pub fn generate_0x20_entropy(name_len: usize) -> Vec<u8> {
    use rand::RngCore;
    let bytes_needed = (name_len + 7) / 8;
    let mut entropy = vec![0u8; bytes_needed];
    rand::thread_rng().fill_bytes(&mut entropy);
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_reader() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut reader = WireReader::new(&data);

        assert_eq!(reader.read_u8().unwrap(), 0x12);
        assert_eq!(reader.read_u16().unwrap(), 0x3456);
        assert_eq!(reader.remaining(), 2);
        assert_eq!(reader.read_bytes(2).unwrap(), &[0x78, 0x9A]);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_wire_reader_bounds() {
        let data = [0x12, 0x34];
        let mut reader = WireReader::new(&data);

        assert!(reader.read_u32().is_err());
    }

    #[test]
    fn test_wire_writer() {
        let mut writer = WireWriter::new(16);

        writer.write_u8(0x12).unwrap();
        writer.write_u16(0x3456).unwrap();
        writer.write_u32(0x789ABCDE).unwrap();

        assert_eq!(writer.len(), 7);
        assert_eq!(
            writer.as_bytes(),
            &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE]
        );
    }

    #[test]
    fn test_wire_writer_max_size() {
        let mut writer = WireWriter::with_max_size(100, 4);

        writer.write_u16(0x1234).unwrap();
        assert!(writer.write_u32(0x12345678).is_err());
    }

    #[test]
    fn test_dns_checksum() {
        let data = [0x01, 0x00, 0x03, 0x08];
        let checksum = dns_checksum(&data);
        assert!(checksum > 0);
    }

    #[test]
    fn test_0x20_encoding() {
        // Wire format for "example.com"
        let mut name = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];

        let entropy = vec![0b10101010, 0b01010101];
        apply_0x20_encoding(&mut name, &entropy);

        // The name should have mixed case now
        let result: String = name[1..8]
            .iter()
            .chain(name[9..12].iter())
            .map(|&c| c as char)
            .collect();

        // Should have some uppercase letters
        assert!(result.chars().any(|c| c.is_ascii_uppercase()));
    }
}
