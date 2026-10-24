# dns – an asynchronous DNS server in Rust

A small but complete DNS server, written from scratch in Rust on top of `tokio`. It parses the
DNS wire format itself (RFC 1035) without a DNS library. Names from a local zone file are
answered directly, and every other query is forwarded to an upstream resolver.

Possible uses:

- Local names for the home network or a lab (`nas.home.arpa → 192.168.0.10`)
- Overriding single domains during development, e.g. pointing `api.example.com` to a test server
- Learning and experimenting: the code shows how DNS packets look on the wire

## Why this project

DNS is one of the oldest and most attacked protocols on the internet. A DNS server receives
binary data from unknown senders over UDP, and one parsing bug is enough to crash it or turn
it into an attack tool. The project is therefore mainly about **handling untrusted network
input safely**.

## Features

- Parses DNS queries and builds responses by hand (header, question, resource records, name compression pointers)
- **Local records** (`A` and `AAAA`) from a simple text file, matched case-insensitively. Several records per name are supported
- **Forwarding** of all other queries to a configurable upstream (default `8.8.8.8:53`)
- Fully asynchronous: every request runs in its own task, so a slow upstream never blocks other clients
- Correct response codes: `NOERROR`, `NODATA`, `FORMERR`, `SERVFAIL`, `NOTIMP`
- EDNS-sized messages (up to 4096 bytes)

## Security design

| Risk | Mitigation |
|---|---|
| **Crash by malformed packets (remote DoS)** | All parsing is bounds-checked and returns `Result`. There is no `unwrap`/`panic!` on network data. Label length (≤ 63) and name length (≤ 255) are enforced, and compression pointers in questions are rejected, which rules out pointer loops. Verified by unit tests that feed every possible truncation of a valid packet, and by a live fuzz run with 5,000 random datagrams. |
| **Cache poisoning / response spoofing** (Kaminsky attack) | Each forwarded query uses a fresh socket with an OS-chosen random source port and a random transaction ID. A reply is accepted only if both the ID and the question section match, and everything else is discarded. The client's original ID is restored afterwards. |
| **Reflection loops / amplification** | Packets with the QR (response) bit set are never answered. The default bind address is `127.0.0.1`, so the server is not an open resolver unless you configure it that way. |
| **Resource exhaustion** | At most 512 requests are processed at once, and excess packets are dropped. The upstream timeout is 3 s, so no task can hang forever. |
| **Unknown or unsupported input** | Unknown record types and classes are represented as `Other(u16)` instead of panicking, and other opcodes get `NOTIMP`. |

The original version of this server stopped answering completely after a single 3-byte UDP
packet: the parser panicked and took down the request handler. It also used a fixed source
port for upstream queries, which made spoofing much easier. Both problems were fixed during a
security review.

## Usage

Requirements: a Rust toolchain ([rustup.rs](https://rustup.rs)).

```bash
cargo build --release
./target/release/dns --bind 127.0.0.1:1053 --upstream 1.1.1.1:53 --records records.txt
```

Test it, e.g. with `dig`:

```bash
dig @127.0.0.1 -p 1053 mydomain.simoin A
dig @127.0.0.1 -p 1053 example.org AAAA
```

| Option | Default | Description |
|---|---|---|
| `--bind` | `127.0.0.1:1053` | Listen address. Port 53 needs root or `CAP_NET_BIND_SERVICE` |
| `--upstream` | `8.8.8.8:53` | Resolver for all non-local names |
| `--records` | `records.txt` | Local zone file. If it is missing, everything is forwarded |

### Zone file format

```text
# name                 type   value            [ttl, default 300]
mydomain.simoin        A      1.2.3.4
mydomain.simoin        AAAA   2001:db8::1234   600
router.home.arpa       A      192.168.0.1
```

## Tests

```bash
cargo test     # parser, response builder, zone file and server logic
cargo clippy --all-targets -- -D warnings
```

## Project structure

```
src/
├── main.rs      Server loop, request handling, hardened upstream forwarder, CLI
├── packet.rs    DNS wire format: bounds-checked parser and response builder
└── records.rs   Zone file parser and lookup
```

## Limitations

- UDP only. If an upstream answer is truncated (TC bit), it is passed on, but the TCP retry is not served.
- There is no response cache, so every forwarded query goes to the upstream.
- No DNSSEC validation. Validation is left to the upstream resolver.
- Local records support `A` and `AAAA`.
