"""Synthesise capture traffic, byte by byte.

Two reasons this exists, and neither is a toy:

1. **A first run with nothing to install and nothing to download.** Someone
   curious about the tool has no pcap on disk, and every tutorial that starts
   with "first, capture some traffic" loses a third of its readers.
   `pcaplens demo` writes a real capture containing a TCP handshake, DNS,
   HTTP and a TLS ClientHello, so the whole feature set is one command away.

2. **Binary fixtures are a liability.** A repo full of .pcap files cannot be
   reviewed, diffed or trusted; a capture built from visible Python can.
"""

from __future__ import annotations

import struct

ETH_IP4 = 0x0800


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip4_bytes(ip: str) -> bytes:
    return bytes(int(part) for part in ip.split("."))


def eth(src: str, dst: str, ethertype: int, payload: bytes) -> bytes:
    def mac(text: str) -> bytes:
        return bytes(int(b, 16) for b in text.split(":"))

    return mac(dst) + mac(src) + struct.pack(">H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ident: int = 0) -> bytes:
    total_len = 20 + len(payload)
    header = struct.pack(">BBHHHBBH", 0x45, 0, total_len, ident, 0, ttl, proto, 0)
    header += _ip4_bytes(src) + _ip4_bytes(dst)
    checksum = _checksum(header)
    return header[:10] + struct.pack(">H", checksum) + header[12:] + payload


def tcp(
    src_port: int,
    dst_port: int,
    seq: int = 1,
    ack: int = 0,
    flags: int = 0x10,
    payload: bytes = b"",
    src: str = "10.0.0.2",
    dst: str = "10.0.0.1",
    window: int = 65535,
) -> bytes:
    offset_flags = (5 << 12) | flags
    header = struct.pack(">HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, window, 0, 0)
    pseudo = _ip4_bytes(src) + _ip4_bytes(dst) + struct.pack(">BBH", 0, 6, 20 + len(payload))
    checksum = _checksum(pseudo + header + payload)
    return header[:16] + struct.pack(">H", checksum) + header[18:] + payload


def udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def dns_query(name: str, qtype: int = 1, transaction_id: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = b"".join(
        bytes([len(label)]) + label.encode() for label in name.split(".") if label
    ) + b"\x00"
    question += struct.pack(">HH", qtype, 1)
    return header + question


def dns_answer(name: str, addresses: list[str], transaction_id: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", transaction_id, 0x8180, 1, len(addresses), 0, 0)
    question = b"".join(
        bytes([len(label)]) + label.encode() for label in name.split(".") if label
    ) + b"\x00"
    question += struct.pack(">HH", 1, 1)
    answers = b""
    for address in addresses:
        answers += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + _ip4_bytes(address)
    return header + question + answers


def http_get(host: str, path: str = "/") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: pcaplens-synth/1.0\r\n"
        "Accept: */*\r\n"
        "\r\n"
    ).encode()


def http_response(status: int = 200, reason: str = "OK", body: str = "") -> bytes:
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
        + body
    ).encode()


def tls_client_hello(sni: str, ciphers: tuple[int, ...] = (0x1301, 0x1302, 0xC02F)) -> bytes:
    random = bytes(range(32))
    session_id = b""
    suites = b"".join(struct.pack(">H", c) for c in ciphers)

    def extension(etype: int, body: bytes) -> bytes:
        return struct.pack(">HH", etype, len(body)) + body

    name = sni.encode()
    sni_body = struct.pack(">HBH", 3 + len(name), 0, len(name)) + name
    extensions = extension(0, sni_body)
    alpn = b"".join(bytes([len(p)]) + p.encode() for p in ("h2", "http/1.1"))
    extensions += extension(16, struct.pack(">H", len(alpn)) + alpn)
    body = (
        struct.pack(">H", 0x0303) + random + bytes([len(session_id)]) + session_id
        + struct.pack(">H", len(suites)) + suites + b"\x01\x00"
        + struct.pack(">H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def demo_capture() -> list[tuple[float, bytes]]:
    """A small, real capture exercising every analysed protocol."""
    client_mac, gateway_mac = "02:00:00:00:00:02", "02:00:00:00:00:01"
    client, server, resolver = "10.0.0.2", "93.184.216.34", "10.0.0.1"

    def frame(ts: float, payload: bytes) -> tuple[float, bytes]:
        return ts, eth(client_mac, gateway_mac, ETH_IP4, payload)

    frames: list[tuple[float, bytes]] = [
        # DNS: query then a compressed-name answer
        frame(1.000001, ipv4(client, resolver, 17, udp(45122, 53, dns_query("example.com")))),
        frame(1.000002, ipv4(resolver, client, 17,
                             udp(53, 45122, dns_answer("example.com", [server])))),
        # TCP three-way handshake
        frame(1.100000, ipv4(client, server, 6, tcp(52344, 80, seq=1, flags=0x02, src=client, dst=server))),
        frame(1.100120, ipv4(server, client, 6, tcp(80, 52344, seq=1, ack=2, flags=0x12, src=server, dst=client))),
        frame(1.100240, ipv4(client, server, 6, tcp(52344, 80, seq=2, ack=2, flags=0x10, src=client, dst=server))),
        # HTTP request and response
        frame(1.200000, ipv4(client, server, 6,
                             tcp(52344, 80, seq=2, ack=2, flags=0x18, src=client, dst=server,
                                 payload=http_get("example.com", "/index.html")))),
        frame(1.300000, ipv4(server, client, 6,
                             tcp(80, 52344, seq=2, ack=120, flags=0x18, src=server, dst=client,
                                 payload=http_response(200, "OK", "<html>hi</html>")))),
        # a retransmission, so the heuristic has something to find
        frame(1.500000, ipv4(server, client, 6,
                             tcp(80, 52344, seq=2, ack=120, flags=0x18, src=server, dst=client,
                                 payload=http_response(200, "OK", "<html>hi</html>")))),
        # TLS ClientHello carrying an SNI
        frame(2.000000, ipv4(client, server, 6,
                             tcp(52345, 443, seq=1, flags=0x02, src=client, dst=server))),
        frame(2.010000, ipv4(client, server, 6,
                             tcp(52345, 443, seq=2, ack=2, flags=0x18, src=client, dst=server,
                                 payload=tls_client_hello("www.example.com")))),
        # an unanswered SYN, so "scan" is observable
        frame(3.000000, ipv4(client, "10.0.0.77", 6,
                             tcp(52346, 22, seq=1, flags=0x02, src=client, dst="10.0.0.77"))),
        frame(3.000001, ipv4(client, "10.0.0.78", 6,
                             tcp(52347, 3389, seq=1, flags=0x02, src=client, dst="10.0.0.78"))),
    ]
    return frames
