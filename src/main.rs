use anyhow::Result;
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

fn convert16to8(value: u16) -> (u8, u8) {
    ((value >> 8) as u8, (value & 0xFF) as u8)
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

async fn parse_dns_request(buffer: Vec<u8>, socket: &UdpSocket, addr: std::net::SocketAddr) {
    // Header

    let header = from8to16(&buffer[..6 * 2]);
    let [id, flags, qdcount, ancount, nscount, arcount]: [u16; 6] = header.try_into().unwrap();

    // Question

    let question = &buffer[6 * 2..];
    let name_end = question.iter().position(|&i| i == 0).unwrap();
    let domain = get_domain_name(&question[..name_end]);
    let qtype = convert8to16(&question[name_end + 1..][..2]);
    let qclass = convert8to16(&question[name_end + 1..][2..4]);

    // Additional

    let additional = &question[name_end..][5..];
    let name = match additional[0] {
        0 => "<Root>",
        _ => panic!("NAME field must be 0"),
    };
    let rr_type = convert8to16(&additional[1..3]);
    let udp_payload_size = convert8to16(&additional[3..5]);
    let extended_rcode = &additional[5];
    let edns_version = &additional[6];
    let additional_z = convert8to16(&additional[7..9]);
    let additional_do_bit = bits(additional_z, 0..1);
    let additional_z_reserved = bits(additional_z, 1..15);
    let data_length = convert8to16(&additional[9..11]);
    let option = &additional[11..];

    /*let mut packet_bytes = [
        0xa0, 0xbc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x62, 0x6c,
        0x61, 0x63, 0x6b, 0x6c, 0x79, 0x67, 0x65, 0x72, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x23, 0x00, 0x04, 0x58,
        0xc6, 0xe5, 0x74, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let (id1, id2) = convert16to8(id);
    packet_bytes[0] = id1;
    packet_bytes[1] = id2;

    println!("{:?}", packet_bytes);

    socket.send_to(&packet_bytes, addr).await.unwrap();*/
}

#[tokio::main]
async fn main() -> Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:8080").await?;
    let socket = Arc::new(udp_socket);
    let sockref = Arc::clone(&socket);

    let (tx, mut rx) = channel::<(Vec<u8>, std::net::SocketAddr)>(1000);

    tokio::spawn(async move {
        while let Some((ret, addr)) = rx.recv().await {
            parse_dns_request(ret, &sockref, addr).await;
        }
    });

    loop {
        let mut buf = [0u8; 512];
        let (len, addr) = socket.recv_from(&mut buf).await?;
        tx.send((buf[..len].to_vec(), addr)).await?;
    }
}
