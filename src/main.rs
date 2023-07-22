use anyhow::Result;
use std::net::SocketAddr;
use std::ops::Range;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::channel;

fn bits(number: u16, range: Range<u16>) -> u16 {
    let shift = 16u16 - (range.end + 1);
    number >> shift & (2u32.pow(((range.end - range.start) + 1).into()) - 1) as u16
}

fn convert8to16(values: &[u8]) -> u16 {
    assert!(values.len() == 2);
    (values[0] as u16) << 8 | values[1] as u16
}

trait ConvertAs {
    type Item;
    fn as_tuple(&self) -> (Self::Item, Self::Item);
    fn as_slice(&self) -> [Self::Item; 2];
}

#[derive(Debug)]
struct Convert(u8, u8);

impl Convert {
    fn new(a: u8, b: u8) -> Self {
        Self(a, b)
    }
}

impl ConvertAs for Convert {
    type Item = u8;
    fn as_tuple(&self) -> (Self::Item, Self::Item) {
        (self.0, self.1)
    }
    fn as_slice(&self) -> [Self::Item; 2] {
        [self.0, self.1]
    }
}

//((value >> 8) as u8, (value & 0xFF) as u8)
fn convert16to8(value: u16) -> Convert {
    Convert::new((value >> 8) as u8, (value & 0xFF) as u8)
}

fn from8to16(buffer: &[u8]) -> Vec<u16> {
    buffer
        .chunks(2)
        .map(|v| convert8to16(v))
        .collect::<Vec<u16>>()
}

fn get_domain_name(buffer: &[u8]) -> String {
    buffer
        .iter()
        .enumerate()
        .filter(|(_, &v)| !(v.is_ascii_alphanumeric() || v.is_ascii_punctuation()))
        .map(|(i, &v)| {
            std::str::from_utf8(&buffer[i + 1..i + v as usize + 1]).expect("UTF-8 error")
        })
        .collect::<Vec<&str>>()
        .join(".")
}

#[derive(Debug, Clone)]
struct DNSHeader {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

macro_rules! splicevec {
    ( $($value:expr),* ) => {
        {
            let mut ret = Vec::<u8>::new();
            $(
                ret.extend(convert16to8($value).as_slice());
            )*
            ret
        }
    };
}

impl DNSHeader {
    fn new(id: u16, flags: u16, qdcount: u16, ancount: u16, nscount: u16, arcount: u16) -> Self {
        Self {
            id: id,
            flags: flags,
            qdcount: qdcount,
            ancount: ancount,
            nscount: nscount,
            arcount: arcount,
        }
    }

    fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    fn flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    fn qdcount(mut self, qdcount: u16) -> Self {
        self.qdcount = qdcount;
        self
    }

    fn ancount(mut self, ancount: u16) -> Self {
        self.ancount = ancount;
        self
    }

    fn nscount(mut self, nscount: u16) -> Self {
        self.nscount = nscount;
        self
    }

    fn arcount(mut self, arcount: u16) -> Self {
        self.arcount = arcount;
        self
    }

    async fn to_vec(&self) -> Vec<u8> {
        splicevec!(
            self.id,
            self.flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount
        )
    }

    async fn parse(buffer: &[u8], offset: &mut usize) -> Self {
        // TODO: Parse flags field

        let header = from8to16(&buffer[*offset..12]);
        let [id, flags, qdcount, ancount, nscount, arcount]: [u16; 6] = header.try_into().unwrap();

        *offset += 12;

        Self {
            id: id,
            flags: flags,
            qdcount: qdcount,
            ancount: ancount,
            nscount: nscount,
            arcount: arcount,
        }
    }
}

#[derive(Debug, Clone)]
struct Domain<'a> {
    name: String,
    buffer: &'a [u8],
}

impl<'a> Domain<'a> {
    fn new(name: String, buffer: &'a [u8]) -> Self {
        Self {
            name: name,
            buffer: buffer,
        }
    }
}

#[derive(Debug, Clone)]
struct DNSQuery<'a> {
    qname: Domain<'a>,
    qtype: RR,
    qclass: Class,
}

impl<'a> DNSQuery<'a> {
    fn new(qname: Domain<'a>, qtype: RR, qclass: Class) -> Self {
        Self {
            qname: qname,
            qtype: qtype,
            qclass: qclass,
        }
    }

    async fn to_vec(self) -> Vec<u8> {
        let mut ret = Vec::<u8>::new();

        let mut qname_buffer = self.qname.buffer.to_vec();
        qname_buffer.push(0);

        ret.extend(qname_buffer);
        ret.extend(convert16to8(self.qtype.into()).as_slice());
        ret.extend(convert16to8(self.qclass.into()).as_slice());
        ret
    }

    async fn parse(buffer: &'a [u8], offset: &mut usize) -> DNSQuery<'a> {
        let domain_name_end = buffer[*offset..].iter().position(|&i| i == 0).unwrap();

        let domain_raw = &buffer[*offset..*offset + domain_name_end];
        let domain = get_domain_name(domain_raw);

        *offset += domain_name_end + 1;

        let qtype_raw = &buffer[*offset..][..2];
        let qclass_raw = &buffer[*offset..][2..4];

        let qtype = RR::from(convert8to16(qtype_raw));
        let qclass = Class::from(convert8to16(qclass_raw));

        *offset += 4;

        Self {
            qname: Domain::new(domain, domain_raw),
            qtype: qtype,
            qclass: qclass,
        }
    }
}

#[derive(Debug, Clone)]
enum Class {
    IN,
    CS,
    CH,
    HS,
}

impl Into<u16> for Class {
    fn into(self) -> u16 {
        match self {
            Self::IN => 1,
            Self::CS => 2,
            Self::CH => 3,
            Self::HS => 4,
        }
    }
}

impl From<u16> for Class {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            _ => panic!("Error: invalid class code"),
        }
    }
}

#[derive(Debug, Clone)]
enum RR {
    A,
    AAAA,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    OPT,
}

impl Into<u16> for RR {
    fn into(self) -> u16 {
        match self {
            Self::A => 1,
            Self::NS => 2,
            Self::MD => 3,
            Self::MF => 4,
            Self::CNAME => 5,
            Self::SOA => 6,
            Self::MB => 7,
            Self::MG => 8,
            Self::MR => 9,
            Self::NULL => 10,
            Self::WKS => 11,
            Self::PTR => 12,
            Self::HINFO => 13,
            Self::MINFO => 14,
            Self::MX => 15,
            Self::TXT => 16,
            Self::AAAA => 28,
            Self::OPT => 41,
            _ => panic!("Resource record not found!"),
        }
    }
}

impl From<u16> for RR {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::NS,
            3 => Self::MD,
            4 => Self::MF,
            5 => Self::CNAME,
            6 => Self::SOA,
            7 => Self::MB,
            8 => Self::MG,
            9 => Self::MR,
            10 => Self::NULL,
            11 => Self::WKS,
            12 => Self::PTR,
            13 => Self::HINFO,
            14 => Self::MINFO,
            15 => Self::MX,
            16 => Self::TXT,
            28 => Self::AAAA,
            41 => Self::OPT,
            _ => panic!("Error: invalid resource record"),
        }
    }
}

#[derive(Debug)]
struct ResourceRecord {
    name: u16,
    rr_type: RR,
    class: Class,
    ttl: u32,
    rdlength: u16,
    rdata: String,
}

impl ResourceRecord {
    fn new(name: u16, rr_type: RR, class: Class, ttl: u32, rdlength: u16, rdata: String) -> Self {
        Self {
            name: name,
            rr_type: rr_type,
            class: class,
            ttl: ttl,
            rdlength: rdlength,
            rdata: rdata,
        }
    }

    async fn to_vec(self) -> Vec<u8> {
        let mut ret = Vec::<u8>::new();

        ret.extend(convert16to8(self.name).as_slice());
        ret.extend(convert16to8(self.rr_type.into()).as_slice());
        ret.extend(convert16to8(self.class.into()).as_slice());

        ret.extend([
            (self.ttl >> 24) as u8,
            ((self.ttl >> 16) & 0xFF) as u8,
            ((self.ttl >> 8) & 0xFF) as u8,
            (self.ttl & 0xFF) as u8,
        ]);

        ret.extend(convert16to8(self.rdlength).as_slice());

        ret.extend(
            self.rdata
                .split(".")
                .map(|octet| octet.parse::<u8>().expect("Parsing error"))
                .collect::<Vec<u8>>(),
        );

        ret
    }
}

#[derive(Debug)]
struct DNSOptional<'a> {
    name: &'a str,
    rr_type: RR,
    udp_payload_size: u16,
    extended_rcode: u8,
    edns_version: u8,
    additional_z: u16,
    data_length: u16,
    option: &'a [u8],
}

impl<'a> DNSOptional<'a> {
    async fn parse(buffer: &'a [u8], offset: &mut usize) -> DNSOptional<'a> {
        Self {
            name: match buffer[*offset..][0] {
                0 => "<Root>",
                _ => panic!("Name must be 0"),
            },
            rr_type: RR::from(convert8to16(&buffer[*offset..][1..3])),
            udp_payload_size: convert8to16(&buffer[*offset..][3..5]),
            extended_rcode: buffer[*offset..][5],
            edns_version: buffer[*offset..][6],
            additional_z: convert8to16(&buffer[*offset..][7..9]),
            data_length: convert8to16(&buffer[*offset..][9..11]),
            option: &buffer[*offset..][11..],
        }
    }
}

#[derive(Debug)]
struct DNSResponse<'a> {
    header: DNSHeader,
    query: DNSQuery<'a>,
    answer: Option<Vec<ResourceRecord>>,
    additional: Option<Vec<ResourceRecord>>,
}

impl<'a> DNSResponse<'a> {
    fn new(
        header: DNSHeader,
        query: DNSQuery<'a>,
        answer: Option<Vec<ResourceRecord>>,
        additional: Option<Vec<ResourceRecord>>,
    ) -> Self {
        Self {
            header: header,
            query: query,
            answer: answer,
            additional: additional,
        }
    }

    async fn to_vec(self) -> Vec<u8> {
        let mut ret = Vec::<u8>::new();

        ret.extend(self.header.to_vec().await);
        ret.extend(self.query.to_vec().await);

        if let Some(ans) = self.answer {
            for answer in ans {
                ret.extend(answer.to_vec().await);
            }
        }

        ret
    }
}

// TODO: Implement builder pattern for DNSResponse to build a new dns response "from scratch"

#[derive(Debug)]
struct DNSRequest<'a> {
    source: SocketAddr,
    header: DNSHeader,
    query: DNSQuery<'a>,
    raw: Vec<u8>,
    //additional: DNSOptional<'a>,
}

impl Into<Vec<u8>> for DNSRequest<'_> {
    fn into(self) -> Vec<u8> {
        // TODO: Use function or macro to "splice" all fields of DNSRequest to get Vec<u8>
        todo!()
    }
}

impl<'a> DNSRequest<'a> {
    async fn parse(buffer: &'a [u8], addr: SocketAddr) -> DNSRequest {
        let mut offset: usize = 0;

        Self {
            source: addr,
            header: DNSHeader::parse(buffer, &mut offset).await,
            query: DNSQuery::parse(buffer, &mut offset).await,
            raw: buffer.to_vec(),
            //additional: DNSOptional::parse(buffer, &mut offset).await,
        }
    }
}

macro_rules! hashmap {
    ( $(($key:expr, $value:expr)),* ) => {
        {
            let mut hm = rustc_hash::FxHashMap::<&str, &str>::default();
            $(
                hm.insert($key, $value);
            )*
            hm
        }
    };
}

async fn remote_request(buffer: Vec<u8>, addr: SocketAddr) -> Vec<u8> {
    tokio::spawn(async move {
        let socket = UdpSocket::bind("0.0.0.0:8081").await.expect("Error bind");
        socket.connect(addr).await.expect("Error connect");
        socket.send(&buffer).await.expect("Error send");

        let mut buf = [0u8; 512];
        let len = socket.recv(&mut buf).await.unwrap();

        buf[..len].to_vec()
    })
    .await
    .unwrap()
}

async fn resolve_domain_name<'a>(request: &DNSRequest<'_>) -> Vec<u8> {
    println!("{:?}", request);

    let db = hashmap!(
        ("simoin.net", "203.0.113.10"),
        ("origin7.de", "203.0.113.20"),
        ("blacklyger.com", "203.0.113.20"),
        ("mydomain.simoin", "1.2.3.4")
    );

    match db.iter().find(|(&key, _)| key == request.query.qname.name) {
        Some((_, &value)) => {
            println!("Handled by local server");

            let header = request
                .header
                .clone()
                .id(request.header.id)
                .ancount(1)
                .flags(0x8180)
                .arcount(0);

            let query = request.query.clone();
            let answer = vec![ResourceRecord::new(
                convert8to16(&[192, 12]),
                RR::A,
                Class::IN,
                300,
                4,
                value.to_string(),
            )];

            let response = DNSResponse::new(header, query, Some(answer), None);
            response.to_vec().await
        }
        None => {
            println!("Handled by 8.8.8.8");

            let data = request.raw.clone();

            remote_request(
                data,
                "8.8.8.8:53".parse::<SocketAddr>().expect("Addr error"),
            )
            .await
        }
    }
}

async fn handle_dns_request(request: DNSRequest<'_>, socket: &UdpSocket) {
    let response = match request.query.qtype {
        RR::A => resolve_domain_name(&request).await,
        RR::AAAA => resolve_domain_name(&request).await,
        RR::NS => {
            println!("{:?}", request);
            remote_request(
                request.raw,
                "8.8.8.8:53".parse::<SocketAddr>().expect("Error"),
            )
            .await
        }
        _ => panic!("Resource record not found!"),
    };

    socket.send_to(&response, request.source).await.unwrap();
}

async fn handle_request(buffer: &[u8], addr: SocketAddr, socket: &UdpSocket) {
    let dns_request = DNSRequest::parse(&buffer, addr).await;
    handle_dns_request(dns_request, &socket).await;
}

#[tokio::main]
async fn main() -> Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:8080").await?;
    let socket = Arc::new(udp_socket);
    let sockref = Arc::clone(&socket);
    let so = Arc::clone(&socket);

    let (tx, mut rx) = channel::<(Vec<u8>, std::net::SocketAddr)>(1000);

    tokio::spawn(async move {
        while let Some((ret, addr)) = rx.recv().await {
            handle_request(&ret, addr, &sockref).await;
        }
    });

    loop {
        let mut buf = [0u8; 512];
        let (len, addr) = socket.recv_from(&mut buf).await?;
        tx.send((buf[..len].to_vec(), addr)).await?;
    }
}
