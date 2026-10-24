mod packet;
mod records;

use anyhow::{bail, Context, Result};
use packet::{set_id, Class, DNSHeader, DNSRequest, DNSResponse, Rcode, HEADER_LEN};
use records::Records;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::{timeout_at, Instant};

/// EDNS allows UDP messages above 512 bytes, 4096 is the common maximum.
const MAX_PACKET_SIZE: usize = 4096;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
/// Upper bound for concurrently handled requests (protects against floods).
const MAX_IN_FLIGHT: usize = 512;

const USAGE: &str = "Usage: dns [--bind ADDR:PORT] [--upstream ADDR:PORT] [--records FILE]

  --bind      address to listen on       (default: 127.0.0.1:1053)
  --upstream  resolver for other names   (default: 8.8.8.8:53)
  --records   local zone file            (default: records.txt, optional)";

struct Config {
    bind: SocketAddr,
    upstream: SocketAddr,
    records: PathBuf,
}

impl Config {
    fn from_args() -> Result<Self> {
        let mut config = Self {
            bind: "127.0.0.1:1053".parse()?,
            upstream: "8.8.8.8:53".parse()?,
            records: PathBuf::from("records.txt"),
        };

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            let mut value = || {
                args.next()
                    .with_context(|| format!("missing value for {arg}"))
            };
            match arg.as_str() {
                "--bind" => config.bind = value()?.parse().context("invalid --bind address")?,
                "--upstream" => {
                    config.upstream = value()?.parse().context("invalid --upstream address")?
                }
                "--records" => config.records = PathBuf::from(value()?),
                "-h" | "--help" => {
                    println!("{USAGE}");
                    std::process::exit(0);
                }
                other => bail!("unknown argument {other}\n\n{USAGE}"),
            }
        }

        Ok(config)
    }
}

struct Server {
    records: Records,
    upstream: SocketAddr,
}

impl Server {
    /// Produce the response for one incoming datagram, or None to drop it.
    async fn handle(&self, buffer: &[u8], source: SocketAddr) -> Option<Vec<u8>> {
        // Without a complete header there is nobody to answer to.
        let header = DNSHeader::parse(buffer.get(..HEADER_LEN)?).ok()?;

        // Never answer responses: prevents reflection loops between resolvers.
        if header.is_response() {
            return None;
        }

        let request = match DNSRequest::parse(buffer) {
            Ok(request) => request,
            Err(error) => {
                println!("{source} malformed request: {error}");
                return Some(DNSResponse::error(&header, None, Rcode::FormErr));
            }
        };

        if request.header.opcode() != 0 {
            return Some(DNSResponse::error(
                &header,
                Some(&request.query),
                Rcode::NotImp,
            ));
        }

        let query = &request.query;

        if query.qclass == Class::IN {
            if let Some(answers) = self.records.lookup(&query.name, query.qtype) {
                println!(
                    "{source} {} {:?} -> local ({} records)",
                    query.name,
                    query.qtype,
                    answers.len()
                );
                return Some(DNSResponse::answer(&request, &answers));
            }
        }

        println!(
            "{source} {} {:?} -> {}",
            query.name, query.qtype, self.upstream
        );

        match self.forward(buffer, &request).await {
            Ok(response) => Some(response),
            Err(error) => {
                println!("{source} {} upstream error: {error:#}", query.name);
                Some(DNSResponse::error(&header, Some(query), Rcode::ServFail))
            }
        }
    }

    /// Forward a request to the upstream resolver. A fresh socket (random source
    /// port) and a random transaction ID are used for every request, and only a
    /// reply matching both ID and question is accepted (anti-spoofing).
    async fn forward(&self, raw: &[u8], request: &DNSRequest) -> Result<Vec<u8>> {
        let bind_addr: SocketAddr = if self.upstream.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?;
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(self.upstream).await?;

        let upstream_id: u16 = rand::random();
        let mut packet = raw.to_vec();
        set_id(&mut packet, upstream_id);
        socket.send(&packet).await?;

        let deadline = Instant::now() + UPSTREAM_TIMEOUT;
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            let len = timeout_at(deadline, socket.recv(&mut buf))
                .await
                .context("timeout")??;
            let response = &buf[..len];

            let valid = DNSRequest::parse(response).is_ok_and(|reply| {
                reply.header.id == upstream_id
                    && reply.header.is_response()
                    && reply.query.raw == request.query.raw
            }) || DNSHeader::parse(response).is_ok_and(|reply| {
                // Truncated replies may lack the question, the TC bit tells the client to retry.
                reply.id == upstream_id && reply.is_response() && reply.is_truncated()
            });

            if valid {
                let mut response = response.to_vec();
                set_id(&mut response, request.header.id);
                return Ok(response);
            }
            // Anything else is ignored (late or spoofed packets).
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_args()?;

    let records = if config.records.exists() {
        Records::load(&config.records)?
    } else {
        println!(
            "No records file at {}, forwarding everything.",
            config.records.display()
        );
        Records::default()
    };

    let socket = Arc::new(
        UdpSocket::bind(config.bind)
            .await
            .with_context(|| format!("cannot bind {}", config.bind))?,
    );
    let server = Arc::new(Server {
        records,
        upstream: config.upstream,
    });
    let limit = Arc::new(Semaphore::new(MAX_IN_FLIGHT));

    println!(
        "Listening on {} ({} local names, upstream {})",
        config.bind,
        server.records.len(),
        config.upstream
    );

    let mut buf = vec![0u8; MAX_PACKET_SIZE];

    loop {
        let (len, source) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(error) => {
                // E.g. ICMP port unreachable reported on Windows; keep serving.
                println!("receive error: {error}");
                continue;
            }
        };

        let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
            println!("{source} dropped: too many requests in flight");
            continue;
        };

        let packet = buf[..len].to_vec();
        let socket = Arc::clone(&socket);
        let server = Arc::clone(&server);

        // Every request runs in its own task, a slow upstream never blocks others.
        tokio::spawn(async move {
            if let Some(response) = server.handle(&packet, source).await {
                if let Err(error) = socket.send_to(&response, source).await {
                    println!("{source} send error: {error}");
                }
            }
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet::RR;

    fn query(id: u16, flags: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = DNSHeader {
            id,
            flags,
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
        packet.extend([0, (qtype >> 8) as u8, qtype as u8, 0, 1]);
        packet
    }

    fn server() -> Server {
        Server {
            records: Records::parse("mydomain.simoin A 1.2.3.4").unwrap(),
            // Unroutable documentation address: forwarding must fail cleanly.
            upstream: "192.0.2.1:53".parse().unwrap(),
        }
    }

    fn source() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    fn rcode(response: &[u8]) -> u16 {
        DNSHeader::parse(response).unwrap().flags & 0xF
    }

    #[tokio::test]
    async fn answers_local_names() {
        let response = server()
            .handle(&query(7, 0x0100, "MyDomain.Simoin", 1), source())
            .await
            .unwrap();
        assert_eq!(DNSHeader::parse(&response).unwrap().id, 7);
        assert!(response.ends_with(&[1, 2, 3, 4]));
    }

    #[tokio::test]
    async fn local_name_without_matching_type_is_nodata() {
        let response = server()
            .handle(&query(7, 0x0100, "mydomain.simoin", 28), source())
            .await
            .unwrap();
        let header = DNSHeader::parse(&response).unwrap();
        assert_eq!(
            (rcode(&response), header.ancount),
            (Rcode::NoError as u16, 0)
        );
    }

    #[tokio::test]
    async fn garbage_is_dropped_or_formerr() {
        let server = server();
        assert_eq!(server.handle(&[0, 1, 2], source()).await, None);

        let mut bad = query(9, 0x0100, "example.org", 1);
        bad.truncate(15);
        assert_eq!(
            rcode(&server.handle(&bad, source()).await.unwrap()),
            Rcode::FormErr as u16
        );
    }

    #[tokio::test]
    async fn responses_are_never_answered() {
        assert_eq!(
            server()
                .handle(&query(1, 0x8180, "mydomain.simoin", 1), source())
                .await,
            None
        );
    }

    #[tokio::test]
    async fn unsupported_opcode_is_notimp() {
        let response = server()
            .handle(&query(1, 0x2000, "mydomain.simoin", 1), source())
            .await
            .unwrap();
        assert_eq!(rcode(&response), Rcode::NotImp as u16);
    }

    #[tokio::test(start_paused = true)]
    async fn upstream_failure_is_servfail() {
        let response = server()
            .handle(&query(3, 0x0100, "example.org", 1), source())
            .await
            .unwrap();
        assert_eq!(rcode(&response), Rcode::ServFail as u16);
    }

    #[test]
    fn rr_types_roundtrip() {
        for value in [1u16, 28, 41, 65000] {
            assert_eq!(u16::from(RR::from(value)), value);
        }
    }
}
