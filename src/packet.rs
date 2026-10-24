//! DNS wire format (RFC 1035): parsing of queries and building of responses.
//!
//! All input comes straight from the network and is untrusted, so every read
//! is bounds-checked and returns an error instead of panicking.

use std::fmt;

pub const HEADER_LEN: usize = 12;
pub const MAX_LABEL_LEN: usize = 63;
pub const MAX_NAME_LEN: usize = 255;

const FLAG_QR: u16 = 1 << 15;
const FLAG_AA: u16 = 1 << 10;
const FLAG_TC: u16 = 1 << 9;
const FLAG_RD: u16 = 1 << 8;
const FLAG_RA: u16 = 1 << 7;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    LabelTooLong,
    NameTooLong,
    CompressionInQuestion,
    NotOneQuestion,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Truncated => "packet is truncated",
            Self::LabelTooLong => "label longer than 63 bytes",
            Self::NameTooLong => "name longer than 255 bytes",
            Self::CompressionInQuestion => "compression pointer in question",
            Self::NotOneQuestion => "query must contain exactly one question",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NotImp = 4,
}

fn convert8to16(values: [u8; 2]) -> u16 {
    u16::from_be_bytes(values)
}

fn convert16to8(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

/// Bounds-checked big-endian reader over a byte slice.
struct Reader<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        let end = self.offset.checked_add(len).ok_or(ParseError::Truncated)?;
        let slice = self
            .buffer
            .get(self.offset..end)
            .ok_or(ParseError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let bytes = self.take(2)?;
        Ok(convert8to16([bytes[0], bytes[1]]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DNSHeader {
    pub fn parse(buffer: &[u8]) -> Result<Self, ParseError> {
        let mut reader = Reader::new(buffer);
        Ok(Self {
            id: reader.u16()?,
            flags: reader.u16()?,
            qdcount: reader.u16()?,
            ancount: reader.u16()?,
            nscount: reader.u16()?,
            arcount: reader.u16()?,
        })
    }

    pub fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }

    pub fn is_truncated(&self) -> bool {
        self.flags & FLAG_TC != 0
    }

    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0xF) as u8
    }

    fn recursion_desired(&self) -> bool {
        self.flags & FLAG_RD != 0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        [
            self.id,
            self.flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        ]
        .iter()
        .flat_map(|&value| convert16to8(value))
        .collect()
    }
}

/// Record types, named as in the RFCs.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RR {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    OPT,
    Other(u16),
}

impl From<u16> for RR {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            12 => Self::PTR,
            15 => Self::MX,
            16 => Self::TXT,
            28 => Self::AAAA,
            41 => Self::OPT,
            other => Self::Other(other),
        }
    }
}

impl From<RR> for u16 {
    fn from(value: RR) -> Self {
        match value {
            RR::A => 1,
            RR::NS => 2,
            RR::CNAME => 5,
            RR::SOA => 6,
            RR::PTR => 12,
            RR::MX => 15,
            RR::TXT => 16,
            RR::AAAA => 28,
            RR::OPT => 41,
            RR::Other(other) => other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    IN,
    CH,
    HS,
    Other(u16),
}

impl From<u16> for Class {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::IN,
            3 => Self::CH,
            4 => Self::HS,
            other => Self::Other(other),
        }
    }
}

impl From<Class> for u16 {
    fn from(value: Class) -> Self {
        match value {
            Class::IN => 1,
            Class::CH => 3,
            Class::HS => 4,
            Class::Other(other) => other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSQuery {
    /// Normalized (lowercase, dot separated, no trailing dot) name for lookups.
    pub name: String,
    pub qtype: RR,
    pub qclass: Class,
    /// The question section exactly as received (echoed back in responses).
    pub raw: Vec<u8>,
}

impl DNSQuery {
    fn parse(reader: &mut Reader) -> Result<Self, ParseError> {
        let start = reader.offset;
        let mut labels = Vec::new();
        let mut name_len = 0usize;

        loop {
            let len = reader.u8()? as usize;
            if len == 0 {
                break;
            }
            // Questions are never compressed, rejecting pointers rules out loops.
            if len & 0xC0 == 0xC0 {
                return Err(ParseError::CompressionInQuestion);
            }
            if len > MAX_LABEL_LEN {
                return Err(ParseError::LabelTooLong);
            }
            name_len += len + 1;
            if name_len > MAX_NAME_LEN {
                return Err(ParseError::NameTooLong);
            }
            labels.push(String::from_utf8_lossy(reader.take(len)?).to_ascii_lowercase());
        }

        let qtype = RR::from(reader.u16()?);
        let qclass = Class::from(reader.u16()?);

        Ok(Self {
            name: labels.join("."),
            qtype,
            qclass,
            raw: reader.buffer[start..reader.offset].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSRequest {
    pub header: DNSHeader,
    pub query: DNSQuery,
}

impl DNSRequest {
    pub fn parse(buffer: &[u8]) -> Result<Self, ParseError> {
        let mut reader = Reader::new(buffer);
        let header = DNSHeader::parse(reader.take(HEADER_LEN)?)?;

        if header.qdcount != 1 {
            return Err(ParseError::NotOneQuestion);
        }

        let query = DNSQuery::parse(&mut reader)?;
        Ok(Self { header, query })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub rr_type: RR,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl ResourceRecord {
    fn to_vec(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity(12 + self.rdata.len());
        // Name: compression pointer to the question name at offset 12.
        ret.extend(convert16to8(0xC000 | HEADER_LEN as u16));
        ret.extend(convert16to8(self.rr_type.into()));
        ret.extend(convert16to8(Class::IN.into()));
        ret.extend(self.ttl.to_be_bytes());
        ret.extend(convert16to8(self.rdata.len() as u16));
        ret.extend(&self.rdata);
        ret
    }
}

pub struct DNSResponse;

impl DNSResponse {
    /// Build an authoritative answer for a locally known name.
    pub fn answer(request: &DNSRequest, answers: &[ResourceRecord]) -> Vec<u8> {
        let mut ret = Self::header(&request.header, Rcode::NoError, true, answers.len() as u16);
        ret.extend(&request.query.raw);
        for answer in answers {
            ret.extend(answer.to_vec());
        }
        ret
    }

    /// Build an error response. If the question could not be parsed it is omitted.
    pub fn error(header: &DNSHeader, query: Option<&DNSQuery>, rcode: Rcode) -> Vec<u8> {
        let mut ret = Self::header(header, rcode, query.is_some(), 0);
        if let Some(query) = query {
            ret.extend(&query.raw);
        }
        ret
    }

    fn header(request: &DNSHeader, rcode: Rcode, with_question: bool, ancount: u16) -> Vec<u8> {
        let mut flags = FLAG_QR | FLAG_RA | ((request.opcode() as u16) << 11) | rcode as u16;
        if request.recursion_desired() {
            flags |= FLAG_RD;
        }
        if rcode == Rcode::NoError {
            flags |= FLAG_AA;
        }

        DNSHeader {
            id: request.id,
            flags,
            qdcount: with_question as u16,
            ancount,
            nscount: 0,
            arcount: 0,
        }
        .to_vec()
    }
}

/// Overwrite the transaction ID of a raw DNS message.
pub fn set_id(packet: &mut [u8], id: u16) {
    if packet.len() >= 2 {
        packet[..2].copy_from_slice(&convert16to8(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = DNSHeader {
            id: 0xBEEF,
            flags: FLAG_RD,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
        .to_vec();
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend(label.as_bytes());
        }
        packet.push(0);
        packet.extend(convert16to8(qtype));
        packet.extend(convert16to8(1));
        packet
    }

    #[test]
    fn parses_valid_query() {
        let request = DNSRequest::parse(&query("WWW.Example.org", 28)).unwrap();
        assert_eq!(request.header.id, 0xBEEF);
        assert_eq!(request.query.name, "www.example.org");
        assert_eq!(request.query.qtype, RR::AAAA);
        assert_eq!(request.query.qclass, Class::IN);
    }

    #[test]
    fn label_lengths_that_look_like_ascii_are_handled() {
        // A 48 byte label has the length byte '0' which broke the old parser.
        let label = "a".repeat(48);
        let request = DNSRequest::parse(&query(&format!("{label}.de"), 1)).unwrap();
        assert_eq!(request.query.name, format!("{label}.de"));
    }

    #[test]
    fn rejects_malformed_packets_without_panicking() {
        let valid = query("example.org", 1);
        // Every possible truncation of a valid packet must be a clean error.
        for len in 0..valid.len() {
            assert!(DNSRequest::parse(&valid[..len]).is_err(), "len {len}");
        }

        let mut pointer = valid.clone();
        pointer[12] = 0xC0;
        assert_eq!(
            DNSRequest::parse(&pointer),
            Err(ParseError::CompressionInQuestion)
        );

        let mut two_questions = valid.clone();
        two_questions[5] = 2;
        assert_eq!(
            DNSRequest::parse(&two_questions),
            Err(ParseError::NotOneQuestion)
        );

        let long_label = query(&"a".repeat(64), 1);
        assert_eq!(
            DNSRequest::parse(&long_label),
            Err(ParseError::LabelTooLong)
        );

        let long_name = query(&vec!["a".repeat(63); 5].join("."), 1);
        assert_eq!(DNSRequest::parse(&long_name), Err(ParseError::NameTooLong));
    }

    #[test]
    fn unknown_types_and_classes_do_not_panic() {
        let request = DNSRequest::parse(&query("example.org", 65000)).unwrap();
        assert_eq!(request.query.qtype, RR::Other(65000));
    }

    #[test]
    fn builds_answer() {
        let request = DNSRequest::parse(&query("mydomain.simoin", 1)).unwrap();
        let record = ResourceRecord {
            rr_type: RR::A,
            ttl: 300,
            rdata: vec![1, 2, 3, 4],
        };
        let response = DNSResponse::answer(&request, &[record]);

        let header = DNSHeader::parse(&response).unwrap();
        assert_eq!(header.id, 0xBEEF);
        assert!(header.is_response());
        assert_eq!(header.flags & 0xF, Rcode::NoError as u16);
        assert_eq!((header.qdcount, header.ancount), (1, 1));
        assert!(response.ends_with(&[0, 4, 1, 2, 3, 4]));
    }

    #[test]
    fn builds_error_without_question() {
        let header = DNSHeader::parse(&query("x.y", 1)).unwrap();
        let response = DNSResponse::error(&header, None, Rcode::FormErr);
        assert_eq!(response.len(), HEADER_LEN);
        assert_eq!(
            DNSHeader::parse(&response).unwrap().flags & 0xF,
            Rcode::FormErr as u16
        );
    }
}
