//! Local zone data, loaded from a simple text file:
//!
//! ```text
//! # name              type  value          [ttl]
//! mydomain.simoin     A     1.2.3.4
//! mydomain.simoin     AAAA  2001:db8::1    600
//! ```

use crate::packet::{ResourceRecord, RR};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

const DEFAULT_TTL: u32 = 300;

#[derive(Debug, Default)]
pub struct Records {
    entries: HashMap<String, Vec<ResourceRecord>>,
}

impl Records {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read records file {}", path.display()))?;
        Self::parse(&content).with_context(|| format!("invalid records file {}", path.display()))
    }

    pub fn parse(content: &str) -> Result<Self> {
        let mut records = Self::default();

        for (number, line) in content.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            let fields: Vec<&str> = line.split_whitespace().collect();
            let (name, rr_type, value, ttl) = match fields.as_slice() {
                [name, rr_type, value] => (name, rr_type, value, DEFAULT_TTL),
                [name, rr_type, value, ttl] => (
                    name,
                    rr_type,
                    value,
                    ttl.parse()
                        .with_context(|| format!("line {}: invalid TTL", number + 1))?,
                ),
                _ => bail!("line {}: expected `name type value [ttl]`", number + 1),
            };

            let record = match rr_type.to_ascii_uppercase().as_str() {
                "A" => ResourceRecord {
                    rr_type: RR::A,
                    ttl,
                    rdata: value
                        .parse::<Ipv4Addr>()
                        .with_context(|| format!("line {}: invalid IPv4 address", number + 1))?
                        .octets()
                        .to_vec(),
                },
                "AAAA" => ResourceRecord {
                    rr_type: RR::AAAA,
                    ttl,
                    rdata: value
                        .parse::<Ipv6Addr>()
                        .with_context(|| format!("line {}: invalid IPv6 address", number + 1))?
                        .octets()
                        .to_vec(),
                },
                other => bail!("line {}: unsupported record type {other}", number + 1),
            };

            records
                .entries
                .entry(name.trim_end_matches('.').to_ascii_lowercase())
                .or_default()
                .push(record);
        }

        Ok(records)
    }

    /// Records of the requested type, or None if the name is not local at all.
    pub fn lookup(&self, name: &str, rr_type: RR) -> Option<Vec<ResourceRecord>> {
        self.entries.get(name).map(|records| {
            records
                .iter()
                .filter(|r| r.rr_type == rr_type)
                .cloned()
                .collect()
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_records() {
        let records = Records::parse(
            "# comment\nMyDomain.Simoin. A 1.2.3.4\nmydomain.simoin AAAA 2001:db8::1 60 # v6\n",
        )
        .unwrap();

        let a = records.lookup("mydomain.simoin", RR::A).unwrap();
        assert_eq!(a[0].rdata, vec![1, 2, 3, 4]);
        assert_eq!(a[0].ttl, DEFAULT_TTL);

        let aaaa = records.lookup("mydomain.simoin", RR::AAAA).unwrap();
        assert_eq!(aaaa[0].ttl, 60);

        assert_eq!(records.lookup("mydomain.simoin", RR::MX), Some(vec![]));
        assert_eq!(records.lookup("unknown.org", RR::A), None);
    }

    #[test]
    fn rejects_invalid_lines() {
        assert!(Records::parse("a.b A 300.1.1.1").is_err());
        assert!(Records::parse("a.b MX mail.a.b").is_err());
        assert!(Records::parse("a.b A").is_err());
    }
}
