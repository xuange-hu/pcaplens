"""Layer-by-layer dissection, written against the RFCs rather than tshark.

Every layer records the **offset** at which it started and the raw bytes it
came from. That is not decoration: the whole premise of pcaplens is that an
agent reading our output must be able to check it. "This is a TLS
ClientHello" is an assertion; "bytes 0x36-0x37 of packet 4 are 0x01 0x00, and
the SNI string starts at 0x5b" is evidence.

The dissection is deliberately conservative. A field we cannot parse becomes
a note ("truncated after 34 of 40 header bytes") rather than a plausible
guess, because a confidently wrong parse is the worst possible output to
hand to a language model.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .pcap import LINK_ETHERNET, LINK_RAW, LINK_SLL, LINK_SLL2, Packet

ETH_IP4 = 0x0800
ETH_IP6 = 0x86DD
ETH_ARP = 0x0806
ETH_VLAN = 0x8100
ETH_VLAN_Q = 0x88A8

IP_PROTO = {1: "icmp", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre", 50: "esp", 51: "ah", 58: "icmpv6"}

IP6_EXT = {0: "hopopts", 43: "routing", 44: "fragment", 60: "dstopts", 135: "mobility"}

TCP_FLAGS = [
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
]

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS", 255: "ANY"}


@dataclass
class Layer:
    name: str
    offset: int            # byte offset inside the frame
    length: int
    fields: dict = field(default_factory=dict)


@dataclass
class DnsMessage:
    transaction_id: int
    is_response: bool
    opcode: int
    rcode: int
    questions: list[tuple[str, str]] = field(default_factory=list)   # (name, qtype)
    answers: list[tuple[str, str, str]] = field(default_factory=list)  # (name, type, value)


@dataclass
class HttpMessage:
    kind: str              # "request" | "response"
    method: str = ""
    uri: str = ""
    version: str = ""
    status: str = ""
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def host(self) -> str:
        return self.headers.get("host", "")


@dataclass
class TlsMessage:
    handshake_type: str
    version: str
    sni: str = ""
    cipher_suites: list[int] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)


@dataclass
class Frame:
    """A dissected packet: the packet itself, its layers, and what we inferred."""

    packet: Packet
    layers: list[Layer] = field(default_factory=list)
    src: str = ""
    dst: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    transport: str = ""        # tcp / udp / icmp / ...
    app: str = ""              # dns / http / tls / ...
    summary: str = ""
    dns: DnsMessage | None = None
    http: HttpMessage | None = None
    tls: TlsMessage | None = None
    tcp_flags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def number(self) -> int:
        return self.packet.number

    @property
    def timestamp(self) -> float:
        return self.packet.timestamp

    @property
    def length(self) -> int:
        return self.packet.captured_length

    def add(self, name: str, offset: int, length: int, **fields) -> None:
        self.layers.append(Layer(name=name, offset=offset, length=length, fields=fields))

    @property
    def conversation(self) -> str:
        """A canonical, direction-independent key for the flow."""
        a = f"{self.src}:{self.src_port}" if self.src_port is not None else self.src
        b = f"{self.dst}:{self.dst_port}" if self.dst_port is not None else self.dst
        return " <-> ".join(sorted([a, b]))

    def endpoint_pair(self) -> tuple[str, str]:
        return (self.src, self.dst)


def _hex(data: bytes, limit: int = 16) -> str:
    shown = data[:limit]
    out = " ".join(f"{b:02x}" for b in shown)
    return out + (" …" if len(data) > limit else "")


def _ip4(data: bytes) -> str:
    return ".".join(str(b) for b in data)


def _ip6(data: bytes) -> str:
    """RFC 5952-ish text form: lowercase, and the longest zero run as `::`."""
    groups = [struct.unpack(">H", data[i:i + 2])[0] for i in range(0, 16, 2)]
    best_start, best_len = -1, 0
    start = 0
    while start < 8:
        if groups[start] != 0:
            start += 1
            continue
        end = start
        while end < 8 and groups[end] == 0:
            end += 1
        if end - start > best_len:
            best_start, best_len = start, end - start
        start = end
    text = [f"{g:x}" for g in groups]
    if best_len >= 2:
        left = ":".join(text[:best_start])
        right = ":".join(text[best_start + best_len:])
        return f"{left}::{right}"
    return ":".join(text)


def _mac(data: bytes) -> str:
    return ":".join(f"{b:02x}" for b in data)


# --- name parsing (DNS) ---------------------------------------------------- #

def _dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly-compressed DNS name. Returns (name, next_offset)."""
    labels: list[str] = []
    jumped = False
    pos = offset
    end = offset
    seen: set[int] = set()
    while pos < len(data):
        if pos in seen:
            raise ValueError("DNS name compression loop")
        seen.add(pos)
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        kind = length & 0xC0
        if kind == 0xC0:  # compression pointer
            if pos + 1 >= len(data):
                raise ValueError("truncated compression pointer")
            target = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end = pos + 2
            jumped = True
            pos = target
            continue
        if kind != 0x00:
            raise ValueError(f"unsupported DNS label type 0x{kind:02x}")
        pos += 1
        labels.append(data[pos:pos + length].decode("latin-1"))
        pos += length
        if not jumped:
            end = pos
    return ".".join(labels) if labels else "<root>", end


# --- per-protocol parsers -------------------------------------------------- #

def _parse_dns(payload: bytes, frame: Frame) -> None:
    if len(payload) < 12:
        frame.notes.append(f"DNS header wants 12 bytes, got {len(payload)}")
        return
    tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", payload[:12])
    msg = DnsMessage(
        transaction_id=tid,
        is_response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0xF,
        rcode=flags & 0xF,
    )
    pos = 12
    try:
        for _ in range(qd):
            name, pos = _dns_name(payload, pos)
            if pos + 4 > len(payload):
                frame.notes.append("DNS question section truncated")
                break
            qtype, _qclass = struct.unpack(">HH", payload[pos:pos + 4])
            pos += 4
            msg.questions.append((name, DNS_TYPES.get(qtype, str(qtype))))
        for _ in range(an + ns + ar):
            name, pos = _dns_name(payload, pos)
            if pos + 10 > len(payload):
                frame.notes.append("DNS resource record truncated")
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", payload[pos:pos + 10])
            pos += 10
            rdata = payload[pos:pos + rdlen]
            pos += rdlen
            if rtype == 1 and len(rdata) == 4:
                value = _ip4(rdata)
            elif rtype == 28 and len(rdata) == 16:
                value = _ip6(rdata)
            elif rtype in (5, 2, 12):
                try:
                    value, _ = _dns_name(payload, pos - rdlen)
                except ValueError:
                    value = _hex(rdata)
            else:
                value = _hex(rdata, 24)
            msg.answers.append((name, DNS_TYPES.get(rtype, str(rtype)), value))
    except (ValueError, IndexError) as exc:
        frame.notes.append(f"DNS parse stopped: {exc}")
    frame.dns = msg
    frame.app = "dns"
    q = msg.questions[0][0] if msg.questions else ""
    qt = msg.questions[0][1] if msg.questions else ""
    first = f"{msg.answers[0][2]}" if msg.answers else ""
    frame.summary = f"DNS {'response' if msg.is_response else 'query'} {q} {qt}".strip()
    if first:
        frame.summary += f" -> {first}"


_HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT")


def _parse_http(payload: bytes, frame: Frame) -> bool:
    """Heuristic HTTP/1.x parse. Returns False if this is not HTTP."""
    if not payload:
        return False
    first_word = payload.split(b" ", 1)[0]
    is_request = first_word in _HTTP_METHODS
    is_response = payload.startswith(b"HTTP/")
    if not (is_request or is_response):
        return False

    try:
        head, _, _body = payload.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        msg = HttpMessage(kind="request" if is_request else "response")
        if is_request:
            parts = lines[0].split(b" ")
            msg.method = parts[0].decode("latin-1")
            msg.uri = parts[1].decode("latin-1") if len(parts) > 1 else ""
            msg.version = parts[2].decode("latin-1") if len(parts) > 2 else ""
        else:
            parts = lines[0].split(b" ", 2)
            msg.version = parts[0].decode("latin-1")
            msg.status = parts[1].decode("latin-1") if len(parts) > 1 else ""
            msg.reason = parts[2].decode("latin-1") if len(parts) > 2 else ""
        for line in lines[1:]:
            if b":" not in line:
                continue
            key, _, value = line.partition(b":")
            msg.headers[key.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()
        frame.http = msg
        frame.app = "http"
        if is_request:
            frame.summary = f"HTTP {msg.method} {msg.host}{msg.uri}"
        else:
            frame.summary = f"HTTP {msg.status} {msg.reason} ({msg.headers.get('content-type','')})"
        return True
    except UnicodeDecodeError:  # pragma: no cover
        return False


_TLS_VERSIONS = {
    0x0300: "SSLv3", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
    0x0303: "TLS1.2", 0x0304: "TLS1.3", 0x0305: "TLS1.4(draft)",
}
_TLS_HANDSHAKE = {0: "hello_request", 1: "client_hello", 2: "server_hello",
                  4: "new_session_ticket", 11: "certificate", 14: "server_hello_done"}


def _parse_tls(payload: bytes, frame: Frame, base: int = 0) -> bool:
    if len(payload) < 6:
        return False
    content_type = payload[0]
    if content_type not in (20, 21, 22, 23):
        return False
    version = struct.unpack(">H", payload[1:3])[0]
    length = struct.unpack(">H", payload[3:5])[0]
    body = payload[5:5 + length]
    if content_type != 22 or len(body) < 6:  # not a handshake
        frame.add("tls-record", base, min(len(payload), 5 + length),
                  content_type=content_type, version=_TLS_VERSIONS.get(version, hex(version)))
        frame.app = "tls"
        return True
    htype = body[0]
    if htype not in (1, 2):
        return False
    hlen = int.from_bytes(body[1:4], "big")
    hbody = body[4:4 + hlen]
    msg = TlsMessage(
        handshake_type=_TLS_HANDSHAKE.get(htype, str(htype)),
        version=_TLS_VERSIONS.get(struct.unpack(">H", hbody[0:2])[0], hex(version)) if len(hbody) >= 2 else "?",
    )
    pos = 34  # 2 version + 32 random
    if htype == 1:
        try:
            if pos >= len(hbody):
                frame.notes.append("ClientHello truncated before session id")
                return True
            sid_len = hbody[pos]
            pos += 1 + sid_len
            cs_len = struct.unpack(">H", hbody[pos:pos + 2])[0]
            pos += 2
            msg.cipher_suites = [
                struct.unpack(">H", hbody[i:i + 2])[0] for i in range(pos, pos + cs_len, 2)
            ]
            pos += cs_len
            comp_len = hbody[pos]
            pos += 1 + comp_len
            if pos + 2 <= len(hbody):
                ext_total = struct.unpack(">H", hbody[pos:pos + 2])[0]
                pos += 2
                ext_end = min(pos + ext_total, len(hbody))
                while pos + 4 <= ext_end:
                    etype, elen = struct.unpack(">HH", hbody[pos:pos + 4])
                    edata = hbody[pos + 4:pos + 4 + elen]
                    if etype == 0 and len(edata) > 5:  # server_name
                        name_len = struct.unpack(">H", edata[3:5])[0]
                        msg.sni = edata[5:5 + name_len].decode("latin-1", "replace")
                    elif etype == 16 and elen > 2:  # ALPN
                        alen = struct.unpack(">H", edata[:2])[0]
                        apos = 2
                        while apos < min(2 + alen, len(edata)):
                            plen = edata[apos]
                            msg.alpn.append(edata[apos + 1:apos + 1 + plen].decode("latin-1", "replace"))
                            apos += 1 + plen
                    pos += 4 + elen
        except (IndexError, struct.error):
            frame.notes.append("ClientHello truncated; SNI may be missing")
    else:
        try:
            if pos < len(hbody):
                sid_len = hbody[pos]
                pos += 1 + sid_len
                if pos + 2 <= len(hbody):
                    msg.cipher_suites = [struct.unpack(">H", hbody[pos:pos + 2])[0]]
        except (IndexError, struct.error):  # pragma: no cover
            pass
    frame.tls = msg
    frame.app = "tls"
    frame.add("tls-handshake", base, min(len(payload), 9 + len(hbody)))
    if htype == 1:
        frame.summary = f"TLS ClientHello SNI={msg.sni or '<none>'} {msg.version}"
    else:
        frame.summary = f"TLS ServerHello {msg.version} suite=0x{msg.cipher_suites[0]:04x}" if msg.cipher_suites else "TLS ServerHello"
    return True


def _parse_arp(payload: bytes, frame: Frame, base: int = 0) -> None:
    if len(payload) < 28:
        frame.notes.append(f"ARP needs 28 bytes, got {len(payload)}")
        return
    _ht, ptype, hlen, plen, op = struct.unpack(">HHBBH", payload[:8])
    if hlen != 6 or plen != 4:
        frame.notes.append(f"unexpected ARP address sizes (hw={hlen}, proto={plen})")
        return
    sha = payload[8:14]
    spa = payload[14:18]
    tha = payload[18:24]
    tpa = payload[24:28]
    frame.src, frame.dst = _ip4(spa), _ip4(tpa)
    frame.add("arp", base, 28,
              opcode="request" if op == 1 else "reply" if op == 2 else str(op),
              sender_mac=_mac(sha), sender_ip=_ip4(spa),
              target_mac=_mac(tha), target_ip=_ip4(tpa),
              protocol=hex(ptype))
    frame.app = "arp"
    frame.summary = f"ARP {'who-has' if op == 1 else 'is-at'} {_ip4(tpa)} tell {_ip4(spa)}"


def _parse_icmp(payload: bytes, frame: Frame, base: int = 0) -> None:
    if len(payload) < 2:
        return
    itype, code = payload[0], payload[1]
    frame.add("icmp", base, len(payload), type=itype, code=code)
    names = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request", 11: "time-exceeded"}
    frame.app = "icmp"
    frame.summary = f"ICMP {names.get(itype, f'type={itype}')} code={code}"


def _parse_udp(payload: bytes, frame: Frame, base: int = 0) -> None:
    if len(payload) < 8:
        frame.notes.append(f"UDP header truncated ({len(payload)}/8 bytes)")
        return
    sport, dport, ulen, _ck = struct.unpack(">HHHH", payload[:8])
    frame.src_port, frame.dst_port = sport, dport
    frame.transport = "udp"
    body = payload[8:]
    frame.add("udp", base, 8, src_port=sport, dst_port=dport, udp_length=ulen)
    if ulen != len(payload) and ulen >= 8:
        frame.notes.append(f"UDP length field {ulen} != captured {len(payload)}")
    if 53 in (sport, dport):
        _parse_dns(body, frame)
    elif not frame.app:
        frame.summary = f"UDP {sport} -> {dport} {len(body)}B"


def _parse_tcp(payload: bytes, frame: Frame, base: int = 0) -> None:
    if len(payload) < 20:
        frame.notes.append(f"TCP header truncated ({len(payload)}/20 bytes)")
        return
    sport, dport, seq, ack = struct.unpack(">HHII", payload[:12])
    doff_flags, _win, _ck, _urg = struct.unpack(">HHHH", payload[12:20])
    data_offset = (doff_flags >> 12) * 4
    flags = doff_flags & 0x1FF
    frame.src_port, frame.dst_port = sport, dport
    frame.transport = "tcp"
    frame.tcp_flags = [name for bit, name in TCP_FLAGS if flags & bit]
    frame.add("tcp", base, min(data_offset, len(payload)),
              src_port=sport, dst_port=dport, seq=seq, ack=ack,
              flags=",".join(frame.tcp_flags), data_offset=data_offset,
              window=_win)
    if data_offset < 20:
        frame.notes.append(f"TCP data offset {data_offset} is below the 20-byte minimum")
        return
    if data_offset > len(payload):
        frame.notes.append(f"TCP options extend past the captured bytes ({data_offset} > {len(payload)})")
        return
    body = payload[data_offset:]
    if not body:
        frame.summary = f"TCP {sport} -> {dport} [{','.join(frame.tcp_flags) or '-'}] seq={seq}"
        return
    if 53 in (sport, dport) and _looks_like_dns(body):
        _parse_dns(body[2:] if len(body) > 2 else body, frame)
    elif 443 in (sport, dport) or (body and body[0] in (20, 21, 22, 23) and _looks_like_tls(body)):
        _parse_tls(body, frame, base + data_offset)
    elif _parse_http(body, frame):
        pass
    else:
        frame.summary = (
            f"TCP {sport} -> {dport} [{','.join(frame.tcp_flags) or '-'}] "
            f"seq={seq} ack={ack} {len(body)}B"
        )


def _looks_like_dns(body: bytes) -> bool:
    """TCP DNS is prefixed with a 2-byte length; verify before trusting it."""
    if len(body) < 14:
        return False
    declared = struct.unpack(">H", body[:2])[0]
    return declared == len(body) - 2


def _looks_like_tls(body: bytes) -> bool:
    if len(body) < 5:
        return False
    version = struct.unpack(">H", body[1:3])[0]
    return version in _TLS_VERSIONS or (0x0300 <= version <= 0x0305)


def _parse_ipv4(payload: bytes, frame: Frame, offset: int) -> None:
    if len(payload) < 20:
        frame.notes.append(f"IPv4 header truncated ({len(payload)}/20 bytes)")
        return
    vihl, _tos, total_len, ident, frag, ttl, proto, _ck = struct.unpack(">BBHHHBBH", payload[:12])
    version = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    if version != 4:
        frame.notes.append(f"IPv4 header claims version {version}")
        return
    if ihl < 20:
        frame.notes.append(f"IPv4 IHL {ihl} is below the 20-byte minimum")
        return
    src, dst = _ip4(payload[12:16]), _ip4(payload[16:20])
    frame.src, frame.dst = src, dst
    frame.add("ipv4", offset, ihl, src=src, dst=dst, ttl=ttl, proto=IP_PROTO.get(proto, str(proto)),
              id=ident, total_length=total_len)
    frag_offset = (frag & 0x1FFF) * 8
    more = bool(frag & 0x2000)
    if frag_offset or more:
        frame.notes.append(
            f"IPv4 fragment offset={frag_offset} more={more}: this is a fragment, "
            "ports below it may be absent"
        )
    if total_len and total_len != len(payload) and not (frag_offset or more):
        frame.notes.append(f"IPv4 total length {total_len} != captured {len(payload)}")
    body = payload[ihl:]
    _dispatch_transport(body, proto, frame, offset + ihl)


def _parse_ipv6(payload: bytes, frame: Frame, offset: int) -> None:
    if len(payload) < 40:
        frame.notes.append(f"IPv6 header truncated ({len(payload)}/40 bytes)")
        return
    vtc = payload[0]
    if vtc >> 4 != 6:
        frame.notes.append(f"IPv6 header claims version {vtc >> 4}")
        return
    payload_len = struct.unpack(">H", payload[4:6])[0]
    next_header = payload[6]
    hop_limit = payload[7]
    src, dst = _ip6(payload[8:24]), _ip6(payload[24:40])
    frame.src, frame.dst = src, dst
    frame.add("ipv6", offset, 40, src=src, dst=dst, hop_limit=hop_limit,
              next_header=next_header, payload_length=payload_len)
    pos = 40
    while next_header in IP6_EXT:
        ext_name = IP6_EXT[next_header]
        if pos + 8 > len(payload):
            frame.notes.append(f"IPv6 extension header {ext_name} truncated")
            return
        if next_header == 44:
            frame.notes.append("IPv6 fragment header: payload below it is a fragment")
        following = payload[pos]
        ext_len = (payload[pos + 1] + 1) * 8
        if ext_len == 0:
            frame.notes.append(f"IPv6 {ext_name} declares a zero length; stopping")
            return
        frame.add(f"ipv6-{ext_name}", pos, ext_len, next_header=following)
        next_header = following
        pos += ext_len
    _dispatch_transport(payload[pos:], next_header, frame, offset + pos)


def _dispatch_transport(body: bytes, proto: int, frame: Frame, base: int = 0) -> None:
    if proto == 6:
        _parse_tcp(body, frame, base)
    elif proto == 17:
        _parse_udp(body, frame, base)
    elif proto in (1, 58):
        _parse_icmp(body, frame, base)
    else:
        frame.add("unknown-transport", base, len(body), proto=proto)
        frame.summary = f"IP proto {proto} {len(body)}B"


# --- link layers ----------------------------------------------------------- #

def _link_payload(packet: Packet, frame: Frame) -> tuple[bytes, int, int] | None:
    """Return (payload, ether/protocol type, payload_offset) or None."""
    data = packet.data
    lt = packet.link_type
    if lt == LINK_ETHERNET:
        if len(data) < 14:
            frame.notes.append(f"Ethernet frame truncated ({len(data)}/14 bytes)")
            return None
        dst, src = _mac(data[0:6]), _mac(data[6:12])
        etype = struct.unpack(">H", data[12:14])[0]
        frame.add("ethernet", 0, 14, src=src, dst=dst, ethertype=hex(etype))
        pos = 14
        vlans = []
        while etype in (ETH_VLAN, ETH_VLAN_Q) and pos + 4 <= len(data):
            tci = struct.unpack(">H", data[pos:pos + 2])[0]
            etype = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            vlans.append(tci & 0x0FFF)
            frame.add("vlan", pos, 4, id=tci & 0x0FFF, priority=tci >> 13, ethertype=hex(etype))
            pos += 4
        if vlans:
            frame.layers[0].fields["vlans"] = vlans
        return data[pos:], etype, pos

    if lt == LINK_SLL:
        if len(data) < 16:
            frame.notes.append(f"SLL header truncated ({len(data)}/16 bytes)")
            return None
        ptype = struct.unpack(">H", data[14:16])[0]
        addr = data[6:14]
        frame.add("linux-sll", 0, 16, packet_type=data[0], arphrd=struct.unpack(">H", data[2:4])[0],
                  addr_len=struct.unpack(">H", data[4:6])[0], addr=_mac(addr[:6]), ethertype=hex(ptype))
        return data[16:], ptype, 16

    if lt == LINK_SLL2:
        if len(data) < 20:
            frame.notes.append(f"SLL2 header truncated ({len(data)}/20 bytes)")
            return None
        ptype = struct.unpack(">H", data[0:2])[0]
        frame.add("linux-sll2", 0, 20, protocol=hex(ptype),
                  ifindex=struct.unpack(">I", data[4:8])[0], arphrd=struct.unpack(">H", data[8:10])[0])
        return data[20:], ptype, 20

    if lt == LINK_RAW:
        # no link header: guess the IP version from the first nibble
        if not data:
            return None
        version = data[0] >> 4
        return data, (ETH_IP4 if version == 4 else ETH_IP6), 0

    frame.notes.append(f"link layer '{packet.link_name}' is not dissected yet; only raw bytes are shown")
    return None


def dissect(packet: Packet) -> Frame:
    """Dissect one packet into layers, endpoints and an application summary."""
    frame = Frame(packet=packet)
    if packet.truncated:
        frame.notes.append(
            f"snaplen: captured {packet.captured_length} of {packet.original_length} bytes on the wire"
        )
    got = _link_payload(packet, frame)
    if got is None:
        frame.summary = f"{packet.link_name} {packet.captured_length}B (undissected)"
        return frame
    payload, etype, offset = got
    if etype == ETH_IP4:
        _parse_ipv4(payload, frame, offset)
    elif etype == ETH_IP6:
        _parse_ipv6(payload, frame, offset)
    elif etype == ETH_ARP:
        _parse_arp(payload, frame, offset)
    else:
        frame.add("unknown-network", offset, len(payload), ethertype=hex(etype))
        frame.summary = f"ethertype {etype:#06x} {len(payload)}B"
    if not frame.summary:
        frame.summary = f"{frame.app or frame.transport or packet.link_name} {packet.captured_length}B"
    return frame


def dissect_all(path: str, limit: int | None = None):
    """Dissect a whole file, optionally stopping after ``limit`` packets."""
    from .pcap import read as _read

    for packet in _read(path):
        if limit is not None and packet.number > limit:
            return
        yield dissect(packet)
