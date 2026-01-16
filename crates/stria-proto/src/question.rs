//! DNS question section.
//!
//! The question section contains queries for information.
//! Each question has a domain name, query type, and query class.

use crate::class::{Class, RecordClass};
use crate::error::{Error, Result};
use crate::name::{Name, NameParser};
use crate::rtype::{RecordType, Type};
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A DNS question.
///
/// Questions specify what information is being requested from the DNS.
/// A typical query has one question, though the protocol allows multiple.
///
/// # Wire Format
///
/// ```text
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /                     QNAME                     /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QTYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QCLASS                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Question {
    /// The domain name being queried.
    pub qname: Name,

    /// The type of record being requested.
    pub qtype: Type,

    /// The class of the query (usually IN for Internet).
    pub qclass: Class,
}

impl Question {
    /// Creates a new question.
    #[inline]
    pub fn new(qname: Name, qtype: RecordType, qclass: RecordClass) -> Self {
        Self {
            qname,
            qtype: Type::Known(qtype),
            qclass: Class::Known(qclass),
        }
    }

    /// Creates a new question with generic type and class.
    #[inline]
    pub fn new_generic(qname: Name, qtype: Type, qclass: Class) -> Self {
        Self { qname, qtype, qclass }
    }

    /// Creates a question for an A record lookup.
    #[inline]
    pub fn a(name: Name) -> Self {
        Self::new(name, RecordType::A, RecordClass::IN)
    }

    /// Creates a question for an AAAA record lookup.
    #[inline]
    pub fn aaaa(name: Name) -> Self {
        Self::new(name, RecordType::AAAA, RecordClass::IN)
    }

    /// Creates a question for an MX record lookup.
    #[inline]
    pub fn mx(name: Name) -> Self {
        Self::new(name, RecordType::MX, RecordClass::IN)
    }

    /// Creates a question for a TXT record lookup.
    #[inline]
    pub fn txt(name: Name) -> Self {
        Self::new(name, RecordType::TXT, RecordClass::IN)
    }

    /// Creates a question for an ANY record lookup.
    #[inline]
    pub fn any(name: Name) -> Self {
        Self::new(name, RecordType::ANY, RecordClass::IN)
    }

    /// Creates a question for a PTR (reverse DNS) lookup.
    #[inline]
    pub fn ptr(name: Name) -> Self {
        Self::new(name, RecordType::PTR, RecordClass::IN)
    }

    /// Returns true if this is an A or AAAA query.
    #[inline]
    pub fn is_address_query(&self) -> bool {
        matches!(
            self.qtype,
            Type::Known(RecordType::A) | Type::Known(RecordType::AAAA)
        )
    }

    /// Returns the record type if known.
    #[inline]
    pub fn record_type(&self) -> Option<RecordType> {
        self.qtype.as_known()
    }

    /// Returns the record class if known.
    #[inline]
    pub fn record_class(&self) -> Option<RecordClass> {
        self.qclass.as_known()
    }

    /// Parses a question from wire format.
    ///
    /// Returns the question and the number of bytes consumed.
    pub fn parse(data: &[u8], offset: usize) -> Result<(Self, usize)> {
        let parser = NameParser::new(data);
        let (qname, name_len) = parser.parse_name(offset)?;

        let qtype_offset = offset + name_len;
        if qtype_offset + 4 > data.len() {
            return Err(Error::buffer_too_short(qtype_offset + 4, data.len()));
        }

        let qtype_value = u16::from_be_bytes([data[qtype_offset], data[qtype_offset + 1]]);
        let qclass_value = u16::from_be_bytes([data[qtype_offset + 2], data[qtype_offset + 3]]);

        let qtype = Type::from_u16(qtype_value);
        let qclass = Class::from_u16(qclass_value);

        Ok((
            Self { qname, qtype, qclass },
            name_len + 4,
        ))
    }

    /// Returns the wire format length of this question.
    pub fn wire_len(&self) -> usize {
        self.qname.wire_len() + 4 // name + 2 bytes type + 2 bytes class
    }

    /// Writes the question to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        self.qname.write_wire(buf);
        buf.extend_from_slice(&self.qtype.to_u16().to_be_bytes());
        buf.extend_from_slice(&self.qclass.to_u16().to_be_bytes());
    }

    /// Converts the question to wire format bytes.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(self.wire_len());
        self.write_to(&mut buf);
        buf.to_vec()
    }

    /// Returns true if this question matches a response question.
    ///
    /// Matching is case-insensitive for the name, and exact for type and class.
    pub fn matches(&self, other: &Question) -> bool {
        self.qname == other.qname && self.qtype == other.qtype && self.qclass == other.qclass
    }

    /// Returns true if a record would answer this question.
    pub fn is_answered_by(&self, name: &Name, rtype: Type, rclass: Class) -> bool {
        // Name must match (case-insensitive)
        if &self.qname != name {
            return false;
        }

        // Class must match (ANY matches everything)
        if self.qclass.to_u16() != rclass.to_u16()
            && !matches!(self.qclass, Class::Known(RecordClass::ANY))
        {
            return false;
        }

        // Type must match (ANY matches everything, CNAME matches A/AAAA)
        if self.qtype.to_u16() == rtype.to_u16() {
            return true;
        }

        if matches!(self.qtype, Type::Known(RecordType::ANY)) {
            return true;
        }

        // CNAME can answer A/AAAA queries
        if self.is_address_query() && matches!(rtype, Type::Known(RecordType::CNAME)) {
            return true;
        }

        false
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.qname, self.qclass, self.qtype)
    }
}

/// Parser for the question section.
#[derive(Debug)]
pub struct QuestionParser<'a> {
    /// The message data.
    data: &'a [u8],
    /// Current offset in the message.
    offset: usize,
    /// Number of questions remaining.
    remaining: u16,
}

impl<'a> QuestionParser<'a> {
    /// Creates a new question parser.
    #[inline]
    pub const fn new(data: &'a [u8], offset: usize, count: u16) -> Self {
        Self {
            data,
            offset,
            remaining: count,
        }
    }

    /// Returns the current offset.
    #[inline]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the number of remaining questions.
    #[inline]
    pub const fn remaining(&self) -> u16 {
        self.remaining
    }

    /// Parses the next question.
    pub fn next(&mut self) -> Result<Option<Question>> {
        if self.remaining == 0 {
            return Ok(None);
        }

        let (question, consumed) = Question::parse(self.data, self.offset)?;
        self.offset += consumed;
        self.remaining -= 1;

        Ok(Some(question))
    }

    /// Collects all remaining questions into a vector.
    pub fn collect_all(&mut self) -> Result<Vec<Question>> {
        let mut questions = Vec::with_capacity(self.remaining as usize);
        while let Some(q) = self.next()? {
            questions.push(q);
        }
        Ok(questions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_question_creation() {
        let name = Name::from_str("example.com").unwrap();
        let q = Question::a(name.clone());

        assert_eq!(q.qname, name);
        assert_eq!(q.qtype, Type::Known(RecordType::A));
        assert_eq!(q.qclass, Class::Known(RecordClass::IN));
    }

    #[test]
    fn test_question_roundtrip() {
        let name = Name::from_str("www.example.com").unwrap();
        let original = Question::aaaa(name);

        let wire = original.to_wire();
        let (parsed, consumed) = Question::parse(&wire, 0).unwrap();

        assert_eq!(consumed, wire.len());
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_question_display() {
        let name = Name::from_str("example.com").unwrap();
        let q = Question::mx(name);

        let display = q.to_string();
        assert!(display.contains("example.com"));
        assert!(display.contains("MX"));
        assert!(display.contains("IN"));
    }

    #[test]
    fn test_question_matching() {
        let name = Name::from_str("example.com").unwrap();
        let q1 = Question::a(name.clone());
        let q2 = Question::a(Name::from_str("EXAMPLE.COM").unwrap());
        let q3 = Question::aaaa(name);

        assert!(q1.matches(&q2)); // Case insensitive
        assert!(!q1.matches(&q3)); // Different type
    }

    #[test]
    fn test_is_answered_by() {
        let name = Name::from_str("example.com").unwrap();
        let q = Question::a(name.clone());

        // A record answers A query
        assert!(q.is_answered_by(&name, Type::Known(RecordType::A), Class::Known(RecordClass::IN)));

        // CNAME answers A query
        assert!(q.is_answered_by(
            &name,
            Type::Known(RecordType::CNAME),
            Class::Known(RecordClass::IN)
        ));

        // AAAA doesn't answer A query
        assert!(!q.is_answered_by(
            &name,
            Type::Known(RecordType::AAAA),
            Class::Known(RecordClass::IN)
        ));

        // Wrong name doesn't match
        let other_name = Name::from_str("other.com").unwrap();
        assert!(!q.is_answered_by(
            &other_name,
            Type::Known(RecordType::A),
            Class::Known(RecordClass::IN)
        ));
    }
}
