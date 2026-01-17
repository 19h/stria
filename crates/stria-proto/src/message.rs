//! DNS message representation.
//!
//! A DNS message consists of a header, question section, and three
//! resource record sections (answer, authority, additional).

use crate::class::RecordClass;
use crate::edns::Edns;
use crate::error::{Error, Result};
use crate::header::{HEADER_SIZE, Header, HeaderFlags};
use crate::name::Name;
use crate::opcode::OpCode;
use crate::question::{Question, QuestionParser};
use crate::rcode::ResponseCode;
use crate::record::{RecordParser, ResourceRecord};
use crate::rtype::RecordType;
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A complete DNS message.
///
/// DNS messages consist of:
/// - A fixed 12-byte header
/// - A question section (queries)
/// - An answer section (responses to queries)
/// - An authority section (NS records for referrals)
/// - An additional section (related records, including OPT for EDNS)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// The message header.
    header: Header,
    /// The question section.
    questions: Vec<Question>,
    /// The answer section.
    answers: Vec<ResourceRecord>,
    /// The authority section.
    authority: Vec<ResourceRecord>,
    /// The additional section (excluding OPT).
    additional: Vec<ResourceRecord>,
    /// EDNS(0) options (from OPT pseudo-RR).
    edns: Option<Edns>,
}

impl Message {
    /// Creates a new empty message with the given header.
    pub fn new(header: Header) -> Self {
        Self {
            header,
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: None,
        }
    }

    /// Creates a query message.
    pub fn query(question: Question) -> Self {
        let mut header = Header::query();
        header.qd_count = 1;

        Self {
            header,
            questions: vec![question],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: Some(Edns::new()),
        }
    }

    /// Creates a query message with DNSSEC requested.
    pub fn query_dnssec(question: Question) -> Self {
        let mut msg = Self::query(question);
        msg.edns = Some(Edns::with_dnssec());
        msg
    }

    /// Creates a response message from a query.
    pub fn response_from(query: &Message) -> Self {
        let mut header = Header::response_from(&query.header);
        header.qd_count = query.questions.len() as u16;

        Self {
            header,
            questions: query.questions.clone(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: query.edns.clone(),
        }
    }

    // =========================================================================
    // Header accessors
    // =========================================================================

    /// Returns the message header.
    #[inline]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Returns a mutable reference to the header.
    #[inline]
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    /// Returns the message ID.
    #[inline]
    pub fn id(&self) -> u16 {
        self.header.id
    }

    /// Sets the message ID.
    #[inline]
    pub fn set_id(&mut self, id: u16) {
        self.header.id = id;
    }

    /// Returns the opcode.
    #[inline]
    pub fn opcode(&self) -> OpCode {
        self.header.opcode
    }

    /// Returns the response code.
    #[inline]
    pub fn rcode(&self) -> ResponseCode {
        self.header.rcode
    }

    /// Sets the response code.
    #[inline]
    pub fn set_rcode(&mut self, rcode: ResponseCode) {
        self.header.rcode = rcode;
        // If extended, update EDNS too
        if rcode.is_extended() {
            if let Some(edns) = &mut self.edns {
                edns.set_extended_rcode(rcode.extended_rcode());
            }
        }
    }

    /// Returns true if this is a query.
    #[inline]
    pub fn is_query(&self) -> bool {
        self.header.is_query()
    }

    /// Returns true if this is a response.
    #[inline]
    pub fn is_response(&self) -> bool {
        self.header.is_response()
    }

    /// Returns true if the response is authoritative.
    #[inline]
    pub fn is_authoritative(&self) -> bool {
        self.header.is_authoritative()
    }

    /// Returns true if the message was truncated.
    #[inline]
    pub fn is_truncated(&self) -> bool {
        self.header.is_truncated()
    }

    /// Returns true if recursion was desired.
    #[inline]
    pub fn recursion_desired(&self) -> bool {
        self.header.recursion_desired()
    }

    /// Returns true if recursion is available.
    #[inline]
    pub fn recursion_available(&self) -> bool {
        self.header.recursion_available()
    }

    /// Returns true if the response is authenticated (AD flag).
    #[inline]
    pub fn is_authentic_data(&self) -> bool {
        self.header.is_authentic_data()
    }

    /// Returns true if checking is disabled (CD flag).
    #[inline]
    pub fn checking_disabled(&self) -> bool {
        self.header.checking_disabled()
    }

    // =========================================================================
    // Section accessors
    // =========================================================================

    /// Returns the question section.
    #[inline]
    pub fn questions(&self) -> &[Question] {
        &self.questions
    }

    /// Returns the first question if present.
    #[inline]
    pub fn question(&self) -> Option<&Question> {
        self.questions.first()
    }

    /// Returns the answer section.
    #[inline]
    pub fn answers(&self) -> &[ResourceRecord] {
        &self.answers
    }

    /// Returns the authority section.
    #[inline]
    pub fn authority(&self) -> &[ResourceRecord] {
        &self.authority
    }

    /// Returns the additional section (excluding OPT).
    #[inline]
    pub fn additional(&self) -> &[ResourceRecord] {
        &self.additional
    }

    /// Returns the EDNS information if present.
    #[inline]
    pub fn edns(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }

    /// Returns a mutable reference to EDNS.
    #[inline]
    pub fn edns_mut(&mut self) -> Option<&mut Edns> {
        self.edns.as_mut()
    }

    /// Sets the EDNS information.
    #[inline]
    pub fn set_edns(&mut self, edns: Option<Edns>) {
        self.edns = edns;
    }

    /// Ensures EDNS is present, creating default if needed.
    pub fn ensure_edns(&mut self) -> &mut Edns {
        if self.edns.is_none() {
            self.edns = Some(Edns::new());
        }
        self.edns.as_mut().unwrap()
    }

    /// Returns true if EDNS is present with DNSSEC OK.
    pub fn wants_dnssec(&self) -> bool {
        self.edns.as_ref().map(|e| e.dnssec_ok()).unwrap_or(false)
    }

    // =========================================================================
    // Section mutators
    // =========================================================================

    /// Adds a question.
    pub fn add_question(&mut self, question: Question) {
        self.questions.push(question);
        self.header.qd_count = self.questions.len() as u16;
    }

    /// Adds an answer record.
    pub fn add_answer(&mut self, record: ResourceRecord) {
        self.answers.push(record);
        self.header.an_count = self.answers.len() as u16;
    }

    /// Adds multiple answer records.
    pub fn add_answers(&mut self, records: impl IntoIterator<Item = ResourceRecord>) {
        self.answers.extend(records);
        self.header.an_count = self.answers.len() as u16;
    }

    /// Adds an authority record.
    pub fn add_authority(&mut self, record: ResourceRecord) {
        self.authority.push(record);
        self.header.ns_count = self.authority.len() as u16;
    }

    /// Adds multiple authority records.
    pub fn add_authority_records(&mut self, records: impl IntoIterator<Item = ResourceRecord>) {
        self.authority.extend(records);
        self.header.ns_count = self.authority.len() as u16;
    }

    /// Adds an additional record.
    pub fn add_additional(&mut self, record: ResourceRecord) {
        self.additional.push(record);
        self.update_ar_count();
    }

    /// Adds multiple additional records.
    pub fn add_additional_records(&mut self, records: impl IntoIterator<Item = ResourceRecord>) {
        self.additional.extend(records);
        self.update_ar_count();
    }

    fn update_ar_count(&mut self) {
        let edns_count = if self.edns.is_some() { 1 } else { 0 };
        self.header.ar_count = self.additional.len() as u16 + edns_count;
    }

    /// Clears all answer records.
    pub fn clear_answers(&mut self) {
        self.answers.clear();
        self.header.an_count = 0;
    }

    /// Clears all authority records.
    pub fn clear_authority(&mut self) {
        self.authority.clear();
        self.header.ns_count = 0;
    }

    /// Clears all additional records (but not EDNS).
    pub fn clear_additional(&mut self) {
        self.additional.clear();
        self.update_ar_count();
    }

    // =========================================================================
    // Response helpers
    // =========================================================================

    /// Returns true if this response indicates success (NOERROR with answers).
    pub fn is_success(&self) -> bool {
        self.rcode().is_success() && !self.answers.is_empty()
    }

    /// Returns true if this is an NXDOMAIN response.
    pub fn is_nxdomain(&self) -> bool {
        self.rcode().is_nxdomain()
    }

    /// Returns true if this is a SERVFAIL response.
    pub fn is_servfail(&self) -> bool {
        self.rcode().is_server_error()
    }

    /// Returns true if this response indicates no data (NOERROR but no answers).
    pub fn is_nodata(&self) -> bool {
        self.rcode().is_success() && self.answers.is_empty()
    }

    /// Returns true if this response is a referral (NS in authority, no answers).
    pub fn is_referral(&self) -> bool {
        self.answers.is_empty()
            && !self.authority.is_empty()
            && self
                .authority
                .iter()
                .any(|r| r.record_type() == Some(RecordType::NS))
    }

    /// Returns answer records of a specific type.
    pub fn answers_of_type(&self, rtype: RecordType) -> impl Iterator<Item = &ResourceRecord> {
        self.answers
            .iter()
            .filter(move |r| r.record_type() == Some(rtype))
    }

    /// Returns the first CNAME target in the answers.
    pub fn cname_target(&self) -> Option<&Name> {
        self.answers.iter().find_map(|r| r.rdata().as_cname())
    }

    /// Returns A record addresses from the answers.
    pub fn a_records(&self) -> impl Iterator<Item = std::net::Ipv4Addr> + '_ {
        self.answers.iter().filter_map(|r| r.rdata().as_a())
    }

    /// Returns AAAA record addresses from the answers.
    pub fn aaaa_records(&self) -> impl Iterator<Item = std::net::Ipv6Addr> + '_ {
        self.answers.iter().filter_map(|r| r.rdata().as_aaaa())
    }

    // =========================================================================
    // Wire format
    // =========================================================================

    /// Parses a DNS message from wire format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::buffer_too_short(HEADER_SIZE, data.len()));
        }

        let header = Header::parse(data)?;

        let mut offset = HEADER_SIZE;
        let mut questions = Vec::with_capacity(header.qd_count as usize);
        let mut answers = Vec::with_capacity(header.an_count as usize);
        let mut authority = Vec::with_capacity(header.ns_count as usize);
        let mut additional = Vec::with_capacity(header.ar_count as usize);
        let mut edns = None;

        // Parse questions
        let mut q_parser = QuestionParser::new(data, offset, header.qd_count);
        while let Some(q) = q_parser.next()? {
            questions.push(q);
        }
        offset = q_parser.offset();

        // Parse answer section
        let mut an_parser = RecordParser::new(data, offset, header.an_count);
        while let Some(r) = an_parser.next()? {
            answers.push(r);
        }
        offset = an_parser.offset();

        // Parse authority section
        let mut ns_parser = RecordParser::new(data, offset, header.ns_count);
        while let Some(r) = ns_parser.next()? {
            authority.push(r);
        }
        offset = ns_parser.offset();

        // Parse additional section (looking for OPT)
        let mut ar_parser = RecordParser::new(data, offset, header.ar_count);
        while let Some(r) = ar_parser.next()? {
            if r.record_type() == Some(RecordType::OPT) {
                // Parse EDNS from OPT record
                if edns.is_some() {
                    return Err(Error::MultipleOptRecords);
                }
                let class = r.rclass().to_u16();
                let ttl = r.ttl();
                let rdata_wire = {
                    let mut buf = BytesMut::new();
                    r.rdata().write_to(&mut buf);
                    buf
                };
                edns = Some(Edns::parse(class, ttl, &rdata_wire)?);
            } else {
                additional.push(r);
            }
        }

        // Update response code with extended bits from EDNS
        let mut header = header;
        if let Some(ref e) = edns {
            if let Some(full_rcode) =
                ResponseCode::from_parts(header.rcode.header_rcode(), e.extended_rcode())
            {
                header.rcode = full_rcode;
            }
        }

        Ok(Self {
            header,
            questions,
            answers,
            authority,
            additional,
            edns,
        })
    }

    /// Returns the wire format length of this message.
    pub fn wire_len(&self) -> usize {
        let mut len = HEADER_SIZE;

        for q in &self.questions {
            len += q.wire_len();
        }

        for r in &self.answers {
            len += r.wire_len();
        }

        for r in &self.authority {
            len += r.wire_len();
        }

        for r in &self.additional {
            len += r.wire_len();
        }

        if let Some(edns) = &self.edns {
            len += edns.wire_len();
        }

        len
    }

    /// Writes the message to wire format.
    pub fn write_to(&self, buf: &mut BytesMut) {
        // Update header counts before writing
        let mut header = self.header.clone();
        header.qd_count = self.questions.len() as u16;
        header.an_count = self.answers.len() as u16;
        header.ns_count = self.authority.len() as u16;
        header.ar_count = self.additional.len() as u16 + if self.edns.is_some() { 1 } else { 0 };

        header.write_to(buf);

        for q in &self.questions {
            q.write_to(buf);
        }

        for r in &self.answers {
            r.write_to(buf);
        }

        for r in &self.authority {
            r.write_to(buf);
        }

        for r in &self.additional {
            r.write_to(buf);
        }

        if let Some(edns) = &self.edns {
            edns.write_to(buf);
        }
    }

    /// Converts the message to wire format bytes.
    pub fn to_wire(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.wire_len());
        self.write_to(&mut buf);
        buf.freeze()
    }

    /// Truncates the message to fit within the given size limit.
    ///
    /// Sets the TC flag and removes records from additional, authority, then answer
    /// sections until the message fits.
    pub fn truncate_to(&mut self, max_size: usize) {
        while self.wire_len() > max_size {
            // First remove additional records
            if !self.additional.is_empty() {
                self.additional.pop();
                continue;
            }

            // Then authority records
            if !self.authority.is_empty() {
                self.authority.pop();
                continue;
            }

            // Finally answer records
            if !self.answers.is_empty() {
                self.answers.pop();
                continue;
            }

            // Nothing left to remove
            break;
        }

        // If we had to remove anything, set truncation flag
        if self.wire_len() > max_size
            || self.answers.len() < self.header.an_count as usize
            || self.authority.len() < self.header.ns_count as usize
            || self.additional.len() < self.header.ar_count as usize
        {
            self.header.set_truncated(true);
        }

        // Update header counts
        self.header.an_count = self.answers.len() as u16;
        self.header.ns_count = self.authority.len() as u16;
        self.update_ar_count();
    }
}

impl Default for Message {
    fn default() -> Self {
        Self::new(Header::default())
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, ";; ->>HEADER<<- {}", self.header)?;

        if let Some(edns) = &self.edns {
            writeln!(f, ";; OPT: {}", edns)?;
        }

        writeln!(f, "\n;; QUESTION SECTION:")?;
        for q in &self.questions {
            writeln!(f, ";{}", q)?;
        }

        if !self.answers.is_empty() {
            writeln!(f, "\n;; ANSWER SECTION:")?;
            for r in &self.answers {
                writeln!(f, "{}", r)?;
            }
        }

        if !self.authority.is_empty() {
            writeln!(f, "\n;; AUTHORITY SECTION:")?;
            for r in &self.authority {
                writeln!(f, "{}", r)?;
            }
        }

        if !self.additional.is_empty() {
            writeln!(f, "\n;; ADDITIONAL SECTION:")?;
            for r in &self.additional {
                writeln!(f, "{}", r)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_query_creation() {
        let q = Question::a(Name::from_str("example.com").unwrap());
        let msg = Message::query(q);

        assert!(msg.is_query());
        assert!(!msg.is_response());
        assert_eq!(msg.questions().len(), 1);
        assert!(msg.edns().is_some());
    }

    #[test]
    fn test_response_creation() {
        let q = Question::a(Name::from_str("example.com").unwrap());
        let query = Message::query(q);
        let mut response = Message::response_from(&query);

        response.add_answer(ResourceRecord::a(
            Name::from_str("example.com").unwrap(),
            300,
            std::net::Ipv4Addr::new(192, 0, 2, 1),
        ));

        assert!(response.is_response());
        assert_eq!(response.id(), query.id());
        assert_eq!(response.answers().len(), 1);
    }

    #[test]
    fn test_message_roundtrip() {
        let q = Question::a(Name::from_str("example.com").unwrap());
        let mut original = Message::query(q);
        original.set_id(0x1234);

        let wire = original.to_wire();
        let parsed = Message::parse(&wire).unwrap();

        assert_eq!(original.id(), parsed.id());
        assert_eq!(original.opcode(), parsed.opcode());
        assert_eq!(original.questions().len(), parsed.questions().len());
    }

    #[test]
    fn test_response_helpers() {
        let q = Question::a(Name::from_str("example.com").unwrap());
        let mut msg = Message::response_from(&Message::query(q));

        // NODATA
        assert!(msg.is_nodata());
        assert!(!msg.is_success());

        // Success with answer
        msg.add_answer(ResourceRecord::a(
            Name::from_str("example.com").unwrap(),
            300,
            std::net::Ipv4Addr::new(192, 0, 2, 1),
        ));
        assert!(msg.is_success());
        assert!(!msg.is_nodata());

        // NXDOMAIN
        msg.clear_answers();
        msg.set_rcode(ResponseCode::NXDomain);
        assert!(msg.is_nxdomain());
    }

    #[test]
    fn test_truncation() {
        let q = Question::a(Name::from_str("example.com").unwrap());
        let mut msg = Message::response_from(&Message::query(q));

        // Add a bunch of records
        for i in 0..100 {
            msg.add_answer(ResourceRecord::a(
                Name::from_str(&format!("host{}.example.com", i)).unwrap(),
                300,
                std::net::Ipv4Addr::new(192, 0, 2, i as u8),
            ));
        }

        let original_len = msg.wire_len();
        msg.truncate_to(512);

        assert!(msg.wire_len() <= 512);
        assert!(msg.is_truncated());
        assert!(msg.answers().len() < 100);
    }

    #[test]
    fn test_dnssec_query() {
        let q = Question::a(Name::from_str("example.com").unwrap());
        let msg = Message::query_dnssec(q);

        assert!(msg.wants_dnssec());
    }
}
