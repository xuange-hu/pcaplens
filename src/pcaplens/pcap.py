"""Capture-file reader: classic pcap (libpcap) and pcapng.

Everything here is stdlib-only and works on a frozen Windows Python with no
Wireshark, no tshark, no libpcap and no Npcap installed. That constraint is
the point of the project, so it is worth stating how the formats differ:

**classic pcap**
    One 24-byte file header, then a flat sequence of records. Big and
    little endian variants are distinguished by the magic itself, and a
    second magic pair means timestamps are nanoseconds rather than
    microseconds. Link-layer type is global for the whole file.

**pcapng**
    A TLV-ish block stream. Each block is ``type, length, body, length`` so
    unknown blocks can be skipped by their length, which is what lets this
    reader tolerate future block types instead of refusing the file. Link
    type is per interface (IDB), so one pcapng can mix Ethernet and
    Linux-cooked captures.

Readers are generators: a multi-gigabyte capture never has to be resident.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator

# link-layer types we can dissect (pcap LINKTYPE_* / pcapng LinkType codes)
LINK_ETHERNET = 1
LINK_RAW = 101        # raw IP, no link header
LINK_SLL = 113        # Linux cooked capture v1
LINK_SLL2 = 276       # Linux cooked capture v2

LINK_NAMES = {
    0: "null/loopback",
    1: "ethernet",
    9: "ppp",
    101: "raw-ip",
    105: "ieee802.11",
    113: "linux-sll",
    143: "docsis",
    147: "user/ppp",
    192: "nfllog",
    276: "linux-sll2",
}

# --- classic pcap magics --------------------------------------------------- #
_MAGIC_USEC_BE = b"\xa1\xb2\xc3\xd4"
_MAGIC_USEC_LE = b"\xd4\xc3\xb2\xa1"
_MAGIC_NSEC_BE = b"\xa1\xb2\xcd\x34"
_MAGIC_NSEC_LE = b"\x34\xcd\xb2\xa1"

# --- pcapng block types ---------------------------------------------------- #
_BT_SHB = 0x0A0D0D0A
_BT_IDB = 0x00000001
_BT_PB = 0x00000002       # Packet Block (obsolete)
_BT_SPB = 0x00000003      # Simple Packet Block (obsolete)
_BT_NRB = 0x00000004      # Name Resolution Block
_BT_ISB = 0x00000005      # Interface Statistics Block
_BT_EPB = 0x00000006      # Enhanced Packet Block
_BT_DSB = 0x0000000A      # Decryption Secrets Block

_MAX_RECORD = 0x7FFFFFFF


@dataclass
class Packet:
    """One captured frame plus the metadata needed to *prove* where it came from.

    ``file_offset`` is the byte offset of the record inside the file. That is
    what makes every downstream claim checkable: instead of taking our word
    for it, an analyst — or an LLM receiving our output — can re-read the
    exact record and the exact bytes it came from.
    """

    number: int
    timestamp: float          # seconds since the Unix epoch, UTC
    data: bytes               # captured bytes (may be truncated to snaplen)
    original_length: int      # length on the wire before truncation
    link_type: int
    interface_index: int = 0
    file_offset: int = 0

    @property
    def captured_length(self) -> int:
        return len(self.data)

    @property
    def truncated(self) -> bool:
        return len(self.data) < self.original_length

    @property
    def time_iso(self) -> str:
        return datetime.fromtimestamp(self.timestamp, timezone.utc).isoformat(
            timespec="microseconds"
        )

    @property
    def link_name(self) -> str:
        return LINK_NAMES.get(self.link_type, f"linktype-{self.link_type}")


@dataclass
class CaptureInfo:
    """File-level facts."""

    path: str
    format: str                                        # "pcap" | "pcapng"
    link_types: dict[int, int] = field(default_factory=dict)  # iface -> linktype
    byte_order: str = "native"
    snaplen: int | None = None

    @property
    def link_type(self) -> int:
        return next(iter(self.link_types.values()), LINK_ETHERNET)

    @property
    def link_name(self) -> str:
        return LINK_NAMES.get(self.link_type, f"linktype-{self.link_type}")


class PcapError(Exception):
    """Raised when a capture file cannot be parsed."""


# --- format detection ------------------------------------------------------ #

def sniff_format(head: bytes) -> str:
    """Return ``"pcap"`` or ``"pcapng"`` from the first bytes of a file."""
    if len(head) < 4:
        raise PcapError("file is too short to be a capture (<4 bytes)")
    if head[:4] in (_MAGIC_USEC_BE, _MAGIC_USEC_LE, _MAGIC_NSEC_BE, _MAGIC_NSEC_LE):
        return "pcap"
    if struct.unpack(">I", head[:4])[0] == _BT_SHB:
        return "pcapng"
    raise PcapError(
        "not a recognised capture file: expected a pcap magic "
        f"(a1b2c3d4 or its byte-swapped variants) or the pcapng SHB, got {head[:4].hex()}"
    )


def _fmt_of(path: str) -> str:
    with open(path, "rb") as fh:
        return sniff_format(fh.read(4))


# --- classic pcap ---------------------------------------------------------- #

def _read_pcap(path: str) -> Iterator[Packet]:
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            raise PcapError("truncated pcap file header")

        magic = header[:4]
        if magic == _MAGIC_USEC_BE:
            endian, div = ">", 1_000_000
        elif magic == _MAGIC_USEC_LE:
            endian, div = "<", 1_000_000
        elif magic == _MAGIC_NSEC_BE:
            endian, div = ">", 1_000_000_000
        elif magic == _MAGIC_NSEC_LE:
            endian, div = "<", 1_000_000_000
        else:  # pragma: no cover - sniff_format already rejected this
            raise PcapError("unknown pcap magic")

        _, _, _, _, _snaplen, network = struct.unpack(endian + "HHiIII", header[4:])
        number = 0
        while True:
            offset = fh.tell()
            rec = fh.read(16)
            if len(rec) < 16:
                break
            ts_sec, ts_frac, incl, orig = struct.unpack(endian + "IIII", rec)
            if incl > _MAX_RECORD or orig > _MAX_RECORD:
                raise PcapError(
                    f"record {number + 1} claims an impossible length "
                    f"(incl={incl}, orig={orig}) at offset {offset}: the file is "
                    "corrupt, or its endianness was misdetected"
                )
            data = fh.read(incl)
            number += 1
            yield Packet(
                number=number,
                timestamp=ts_sec + ts_frac / div,
                data=data,
                original_length=orig,
                link_type=network,
                file_offset=offset,
            )
            if len(data) < incl:
                break  # truncated tail: report what we have, then stop


def _pcap_info(path: str) -> CaptureInfo:
    with open(path, "rb") as fh:
        header = fh.read(24)
    if len(header) < 24:
        raise PcapError("truncated pcap file header")
    magic = header[:4]
    endian = ">" if magic in (_MAGIC_USEC_BE, _MAGIC_NSEC_BE) else "<"
    _, _, _, _, snaplen, network = struct.unpack(endian + "HHiIII", header[4:])
    return CaptureInfo(
        path=path,
        format="pcap",
        link_types={0: network},
        byte_order="big" if endian == ">" else "little",
        snaplen=snaplen,
    )


# --- pcapng ---------------------------------------------------------------- #

@dataclass
class _Block:
    type: int
    body: bytes
    offset: int
    length: int


def _iter_blocks(path: str) -> Iterator[_Block]:
    """Walk pcapng blocks, skipping anything we do not understand."""
    with open(path, "rb") as fh:
        first = fh.read(4)
        if len(first) < 4:
            return
        if struct.unpack(">I", first)[0] != _BT_SHB:
            raise PcapError("pcapng file does not start with a section header block")
        pos = 0
        while True:
            fh.seek(pos)
            head = fh.read(8)
            if len(head) < 8:
                return
            btype, blen = struct.unpack(">II", head)
            if blen < 12 or blen % 4:
                raise PcapError(f"block at offset {pos} declares an invalid length {blen}")
            body_len = blen - 12
            body = fh.read(body_len)
            if len(body) < body_len:
                return  # truncated tail
            if len(fh.read(4)) < 4:
                return
            yield _Block(type=btype, body=body, offset=pos, length=blen)
            pos += blen


def _parse_tsresol(value: bytes) -> int:
    """IDB option 9: if_tsresol. Low 7 bits are a power of ten."""
    if not value:
        return 1_000_000
    unit = value[0] & 0x7F
    if unit > 9:
        return 1_000_000
    return 10 ** unit


def _idb_facts(body: bytes) -> tuple[int, int | None, int]:
    """Return ``(linktype, snaplen, ts_divisor)`` from an IDB body."""
    if len(body) < 8:
        return LINK_ETHERNET, None, 1_000_000
    linktype, _, snaplen = struct.unpack(">HHI", body[:8])
    div = 1_000_000
    opos = 8
    opts = body
    while opos + 4 <= len(opts):
        ocode, olen = struct.unpack(">HH", opts[opos:opos + 4])
        if ocode == 0:  # opt_endofopt
            break
        if ocode == 9:
            div = _parse_tsresol(opts[opos + 4:opos + 4 + olen])
        opos += 4 + ((olen + 3) // 4) * 4
    return linktype, (snaplen or None), div


def _read_pcapng(path: str) -> Iterator[Packet]:
    interfaces: dict[int, int] = {}
    divisors: dict[int, int] = {}
    number = 0
    for block in _iter_blocks(path):
        if block.type == _BT_IDB:
            linktype, snap, div = _idb_facts(block.body)
            iface = len(interfaces)
            interfaces[iface] = linktype
            divisors[iface] = div
            del snap  # snaplen is a soft limit; we do not enforce it
        elif block.type in (_BT_EPB, _BT_PB, _BT_SPB):
            if block.type == _BT_EPB:
                if len(block.body) < 20:
                    continue
                iface, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(">IIIII", block.body[:20])
                div = divisors.get(iface, 1_000_000)
                ts = ((ts_hi << 32) | ts_lo) / div
                data = block.body[20:20 + cap_len]
            elif block.type == _BT_SPB:
                if len(block.body) < 4:
                    continue
                orig_len = struct.unpack(">I", block.body[:4])[0]
                iface, ts, data = 0, 0.0, block.body[4:orig_len]
            else:  # _BT_PB, the very old single-interface variant
                if len(block.body) < 20:
                    continue
                iface, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(">IIIII", block.body[:20])
                div = divisors.get(0, 1_000_000)
                ts = ((ts_hi << 32) | ts_lo) / div
                data = block.body[20:20 + cap_len]
            if iface not in interfaces:
                # an IDB-less file is malformed; assume Ethernet rather than
                # silently dropping every frame over a housekeeping defect
                interfaces[iface] = LINK_ETHERNET
                divisors.setdefault(iface, 1_000_000)
            number += 1
            yield Packet(
                number=number,
                timestamp=ts,
                data=data,
                original_length=orig_len if block.type != _BT_SPB else orig_len,
                link_type=interfaces[iface],
                interface_index=iface,
                file_offset=block.offset,
            )


def _pcapng_info(path: str) -> CaptureInfo:
    links: dict[int, int] = {}
    snaplen: int | None = None
    for block in _iter_blocks(path):
        if block.type == _BT_IDB:
            linktype, snap, _ = _idb_facts(block.body)
            links[len(links)] = linktype
            if snaplen is None and snap:
                snaplen = snap
        if len(links) >= 1 and snaplen:
            break
    return CaptureInfo(path=path, format="pcapng", link_types=links, byte_order="big", snaplen=snaplen)


# --- public readers -------------------------------------------------------- #

def read(path: str) -> Iterator[Packet]:
    """Yield every packet in a pcap or pcapng file, lazily."""
    fmt = _fmt_of(path)
    if fmt == "pcap":
        yield from _read_pcap(path)
    else:
        yield from _read_pcapng(path)


def info(path: str) -> CaptureInfo:
    """Return file-level facts without walking every packet."""
    fmt = _fmt_of(path)
    return _pcap_info(path) if fmt == "pcap" else _pcapng_info(path)


# --- writer ---------------------------------------------------------------- #

def _pcapng_block(btype: int, body: bytes) -> bytes:
    """Wrap a body in a pcapng block, padding to a 4-byte boundary."""
    padded = body + b"\x00" * ((4 - len(body) % 4) % 4)
    length = 12 + len(padded)
    return struct.pack(">II", btype, length) + padded + struct.pack(">I", length)


def write_pcapng(path: str, frames: list[tuple[float, bytes]], link_type: int = LINK_ETHERNET) -> int:
    """Write a pcapng file (SHB + IDB + one EPB per frame).

    Lets the tests round-trip both formats and lets users convert without
    installing anything.
    """
    shb = struct.pack(">IHHq", _BT_SHB, 1, 0, -1)
    idb = struct.pack(">HHI", link_type, 0, 65535)
    with open(path, "wb") as fh:
        fh.write(_pcapng_block(_BT_SHB, shb))
        fh.write(_pcapng_block(_BT_IDB, idb))
        for ts, data in frames:
            sec = int(ts)
            frac = int(round((ts - sec) * 1_000_000)) % 1_000_000
            padded = data + b"\x00" * ((4 - len(data) % 4) % 4)
            body = struct.pack(">IIIII", 0, sec, frac, len(data), len(data)) + padded
            fh.write(_pcapng_block(_BT_EPB, body))
    return len(frames)


def write_pcap(
    path: str, frames: list[tuple[float, bytes]], link_type: int = LINK_ETHERNET
) -> int:
    """Write a classic little-endian microsecond pcap.

    Exists so the tests and the examples can build real capture files from
    nothing, which keeps the repository free of binary fixtures.
    """
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type))
        for ts, data in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000)) % 1_000_000
            fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            fh.write(data)
    return len(frames)
