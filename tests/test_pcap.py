"""Reader/writer round-trips.

The fixtures are built in Python rather than checked in as .pcap binaries:
a reviewer can read what the bytes are supposed to be, and a capture built
by the code under test cannot drift away from the parser.
"""

from __future__ import annotations

import struct

import pytest

from pcaplens.pcap import (
    PcapError,
    info,
    read,
    sniff_format,
    write_pcap,
    write_pcapng,
)
from pcaplens.synth import demo_capture, eth

ETH_IP4 = 0x0800


def _sample() -> list[tuple[float, bytes]]:
    return [(1.5, b"\x01" * 54), (2.25, b"\x02" * 60), (3.0, b"\x03" * 13)]


def test_write_then_read_roundtrip(tmp_path):
    path = tmp_path / "rt.pcap"
    write_pcap(str(path), _sample())
    packets = list(read(str(path)))
    assert [p.number for p in packets] == [1, 2, 3]
    assert [p.data for p in packets] == [b"\x01" * 54, b"\x02" * 60, b"\x03" * 13]
    assert [p.original_length for p in packets] == [54, 60, 13]
    assert packets[1].timestamp == pytest.approx(2.25)


def test_pcap_info_reports_linktype_and_magic(tmp_path):
    path = tmp_path / "info.pcap"
    write_pcap(str(path), _sample())
    meta = info(str(path))
    assert meta.format == "pcap"
    assert meta.link_type == 1
    assert meta.byte_order == "little"
    assert meta.snaplen == 65535


def test_big_endian_and_nanosecond_magics_are_understood(tmp_path):
    """The magic alone decides endianness and timestamp resolution."""
    frames = _sample()
    # the magic is a NUMBER: pack it in the target endianness and the on-disk
    # bytes come out right (0xA1B2C3D4 packed little-endian is d4 c3 b2 a1).
    for magic, endian, div in (
        (0xA1B2C3D4, ">", 1_000_000),
        (0xA1B2CD34, ">", 1_000_000_000),
        (0xA1B2C3D4, "<", 1_000_000),
        (0xA1B2CD34, "<", 1_000_000_000),
    ):
        label = "be" if endian == ">" else "le"
        path = tmp_path / f"m{magic:x}-{label}.pcap"
        with open(path, "wb") as fh:
            fh.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
            for ts, data in frames:
                sec = int(ts)
                frac = int(round((ts - sec) * div)) % div
                fh.write(struct.pack(endian + "IIII", sec, frac, len(data), len(data)))
                fh.write(data)
        packets = list(read(str(path)))
        assert len(packets) == 3
        assert packets[0].timestamp == pytest.approx(1.5)


def test_pcapng_roundtrip_keeps_payload(tmp_path):
    path = tmp_path / "rt.pcapng"
    write_pcapng(str(path), _sample())
    packets = list(read(str(path)))
    assert [p.data for p in packets] == [b"\x01" * 54, b"\x02" * 60, b"\x03" * 13]
    assert info(str(path)).format == "pcapng"


def test_pcapng_padding_is_not_returned_as_payload(tmp_path):
    """EPB pads to 4 bytes; the pad must not leak into the packet."""
    path = tmp_path / "pad.pcapng"
    write_pcapng(str(path), [(1.0, b"\xaa\xbb\xcc")])  # 3 bytes -> 1 pad byte
    packet = next(iter(read(str(path))))
    assert packet.data == b"\xaa\xbb\xcc"
    assert packet.original_length == 3


def test_unknown_pcapng_blocks_are_skipped(tmp_path):
    path = tmp_path / "unknown.pcapng"
    write_pcapng(str(path), _sample())
    with open(path, "rb") as fh:
        blob = fh.read()
    # splice a nonsense block (type 0xbadc0de) in front of the first EPB
    header_end = (12 + 16) + (12 + 8)  # SHB block, then IDB block
    body = struct.pack(">II", 0xDEADBEEF, 0xCAFEBABE)
    block = struct.pack(">II", 0x0BADC0DE, 12 + len(body)) + body + struct.pack(">I", 12 + len(body))
    with open(path, "wb") as fh:
        fh.write(blob[:header_end] + block + blob[header_end:])
    assert len(list(read(str(path)))) == 3


def test_sniff_format_rejects_garbage():
    with pytest.raises(PcapError, match="not a recognised capture file"):
        sniff_format(b"%PDF")
    with pytest.raises(PcapError):
        sniff_format(b"ab")


def test_empty_file_is_rejected(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    with pytest.raises(PcapError):
        list(read(str(path)))


def test_captured_smaller_than_wire_length_is_flagged(tmp_path):
    """A frame clipped by snaplen is incomplete, not missing."""
    path = tmp_path / "clipped.pcap"
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        fh.write(struct.pack("<IIII", 1, 0, 20, 1500))
        fh.write(b"\x00" * 20)
    packet = next(iter(read(str(path))))
    assert packet.truncated is True
    assert packet.captured_length == 20
    assert packet.original_length == 1500


def test_reader_is_lazy_over_a_large_file(tmp_path):
    """The generator must not load the whole file into memory."""
    path = tmp_path / "many.pcap"
    frames = [(i * 0.001, eth("02:00:00:00:00:01", "02:00:00:00:00:02", ETH_IP4, b"\x00" * 40))
              for i in range(500)]
    write_pcap(str(path), frames)
    seen = 0
    for packet in read(str(path)):
        seen += 1
        if seen == 10:
            break
    assert seen == 10


def test_demo_capture_writes_a_usable_file(tmp_path):
    path = tmp_path / "demo.pcap"
    write_pcap(str(path), demo_capture())
    packets = list(read(str(path)))
    assert len(packets) == 12
    assert all(p.link_type == 1 for p in packets)
