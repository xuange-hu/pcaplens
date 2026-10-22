"""Dissection tests: one per protocol, plus the places parsers usually lie."""

from __future__ import annotations

import struct

from pcaplens.dissect import dissect
from pcaplens.pcap import LINK_ETHERNET, LINK_RAW, LINK_SLL, Packet, read, write_pcap
from pcaplens.synth import (
    ETH_IP4,
    dns_answer,
    dns_query,
    eth,
    http_get,
    http_response,
    ipv4,
    tcp,
    tls_client_hello,
    udp,
)

CLIENT = "10.0.0.2"
SERVER = "93.184.216.34"


def frame(data: bytes, link_type: int = LINK_ETHERNET, number: int = 1) -> Packet:
    return Packet(number=number, timestamp=1.0, data=data,
                  original_length=len(data), link_type=link_type)


def pkt(payload: bytes, **kw):
    return frame(eth("02:00:00:00:00:02", "02:00:00:00:00:01", ETH_IP4, payload), **kw)


def test_ethernet_ipv4_udp_dns_query():
    data = pkt(ipv4(CLIENT, "10.0.0.1", 17, udp(45122, 53, dns_query("example.com"))))
    f = dissect(data)
    assert f.src == CLIENT and f.dst == "10.0.0.1"
    assert f.transport == "udp" and f.src_port == 45122 and f.dst_port == 53
    assert f.app == "dns"
    assert f.dns is not None
    assert f.dns.questions == [("example.com", "A")]
    assert f.dns.is_response is False
    assert [layer.name for layer in f.layers] == ["ethernet", "ipv4", "udp"]


def test_dns_compressed_answer_points_back_at_the_question():
    """The 0xC00C pointer must resolve to 'example.com', not '<root>'."""
    payload = udp(53, 45122, dns_answer("example.com", ["93.184.216.34"]))
    f = dissect(pkt(ipv4("10.0.0.1", CLIENT, 17, payload)))
    assert f.dns.is_response is True
    assert f.dns.answers == [("example.com", "A", "93.184.216.34")]
    assert "example.com" in f.summary


def test_tcp_handshake_flags_and_offsets():
    syn = pkt(ipv4(CLIENT, SERVER, 6, tcp(52344, 80, seq=1, flags=0x02, src=CLIENT, dst=SERVER)))
    f = dissect(syn)
    assert f.tcp_flags == ["SYN"]
    assert f.src_port == 52344 and f.dst_port == 80
    assert f.transport == "tcp"
    tcp_layer = next(layer for layer in f.layers if layer.name == "tcp")
    assert tcp_layer.offset == 34  # 14 ethernet + 20 ipv4
    assert tcp_layer.fields["data_offset"] == 20


def test_http_request_and_response():
    request = pkt(ipv4(CLIENT, SERVER, 6,
                       tcp(52344, 80, seq=2, ack=2, flags=0x18, src=CLIENT, dst=SERVER,
                           payload=http_get("example.com", "/index.html"))))
    f = dissect(request)
    assert f.app == "http"
    assert f.http.method == "GET"
    assert f.http.host == "example.com"
    assert f.http.headers["user-agent"].startswith("pcaplens")

    response = pkt(ipv4(SERVER, CLIENT, 6,
                        tcp(80, 52344, seq=2, ack=120, flags=0x18, src=SERVER, dst=CLIENT,
                            payload=http_response(200, "OK", "<html>hi</html>"))))
    f2 = dissect(response)
    assert f2.http.status == "200"
    assert f2.http.reason == "OK"


def test_tls_client_hello_yields_sni():
    f = dissect(pkt(ipv4(CLIENT, SERVER, 6,
                         tcp(52345, 443, seq=2, ack=2, flags=0x18, src=CLIENT, dst=SERVER,
                             payload=tls_client_hello("www.example.com")))))
    assert f.app == "tls"
    assert f.tls.handshake_type == "client_hello"
    assert f.tls.sni == "www.example.com"
    assert 0x1301 in f.tls.cipher_suites
    assert "h2" in f.tls.alpn


def test_arp_resolves_the_ip_layer_it_lacks():
    payload = struct.pack(">HHBBH", 1, ETH_IP4, 6, 4, 1)
    payload += b"\x02\x00\x00\x00\x00\x02" + bytes([10, 0, 0, 2])
    payload += b"\x00\x00\x00\x00\x00\x00" + bytes([10, 0, 0, 1])
    f = dissect(frame(eth("02:00:00:00:00:02", "ff:ff:ff:ff:ff:ff", 0x0806, payload)))
    assert f.app == "arp"
    assert f.src == "10.0.0.2" and f.dst == "10.0.0.1"
    assert "who-has" in f.summary


def test_vlan_tags_are_peeled_before_ip():
    inner = ipv4(CLIENT, SERVER, 17, udp(1000, 2000, b"hi"))
    tagged = struct.pack(">HH", 0x0020, ETH_IP4) + inner
    outer = eth("02:00:00:00:00:02", "02:00:00:00:00:01", 0x8100, tagged)
    f = dissect(frame(outer))
    assert [layer.name for layer in f.layers][:3] == ["ethernet", "vlan", "ipv4"]
    assert f.src == CLIENT


def test_ipv6_addresses_are_expanded():
    src = bytes.fromhex("20010db8000000000000000000000001")
    dst = bytes.fromhex("20010db8000000000000000000000002")
    header = struct.pack(">IHBB", 0x60000000, 8, 17, 64) + src + dst
    f = dissect(frame(eth("02:00:00:00:00:02", "02:00:00:00:00:01", 0x86DD,
                          header + udp(5000, 6000, b"x"))))
    assert f.src == "2001:db8::1"
    assert f.dst == "2001:db8::2"
    assert f.transport == "udp"


def test_ipv4_fragment_is_noted_not_misread():
    """A non-first fragment has no ports; pretending otherwise would be a lie."""
    payload = b"\x00" * 40
    header = struct.pack(">BBHHHBBH", 0x45, 0, 60, 1, 0x2000 | 25, 64, 6, 0)
    header += bytes([10, 0, 0, 2]) + bytes([10, 0, 0, 1])
    f = dissect(pkt(header + payload))
    assert any("fragment" in note for note in f.notes)


def test_truncated_headers_produce_notes_not_guesses():
    f = dissect(frame(eth("02:00:00:00:00:02", "02:00:00:00:00:01", ETH_IP4, b"\x45\x00")))
    assert any("truncated" in note for note in f.notes)
    assert not f.layers[-1].name == "tcp"


def test_short_ethernet_frame_is_reported():
    f = dissect(frame(b"\x00" * 8))
    assert any("truncated" in note for note in f.notes)


def test_linux_sll_link_layer():
    ip = ipv4(CLIENT, SERVER, 17, udp(1, 2, b"hi"))
    sll = struct.pack(">HHH", 0, 1, 6) + b"\x02\x00\x00\x00\x00\x02\x00\x00"
    sll += struct.pack(">H", ETH_IP4) + ip
    f = dissect(frame(sll, link_type=LINK_SLL))
    assert f.src == CLIENT
    assert f.layers[0].name == "linux-sll"


def test_raw_ip_link_layer_has_no_ethernet_header():
    ip = ipv4(CLIENT, SERVER, 17, udp(1, 2, b"hi"))
    f = dissect(frame(ip, link_type=LINK_RAW))
    assert f.layers[0].name == "ipv4"
    assert f.src == CLIENT


def test_unknown_link_layer_says_so(tmp_path):
    f = dissect(frame(b"\x00" * 40, link_type=999))
    assert any("not dissected" in note for note in f.notes)


def test_undissected_frame_from_real_file(tmp_path):
    """End-to-end: write frames we cannot parse and make sure nothing explodes."""
    path = tmp_path / "odd.pcap"
    write_pcap(str(path), [(1.0, b"\xde\xad\xbe\xef")])
    packet = next(iter(read(str(path))))
    f = dissect(packet)
    assert f.summary  # never blank: the UI must always be able to print something
