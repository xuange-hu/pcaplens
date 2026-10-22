"""Aggregation: turn packets into statements that fit in a context window.

This module is where pcaplens differs from "run tshark and paste the output".

A 10 MB capture expanded by ``tshark -V`` is tens of megabytes of text. Piped
into an LLM it either blows the context window or crowds out everything else
the model was told. So nothing here returns a dump. The interface is a
**map first, then a targeted drill-down**:

    summary        30 lines: shape of the capture and what is interesting
    conversations  one line per flow, sorted by what matters
    packet N       one frame, fully dissected, with byte offsets

Two rules make that safe:

* Every aggregate carries the packet numbers it came from, so any claim can
  be opened and checked instead of trusted.
* Every list is **capped**, and says so. `top=10, total_flows=412` is honest;
  silently returning 10 of 412 as if that were all of them is how an agent
  ends up writing "the capture contains no DNS traffic".
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from .dissect import Frame, dissect
from .pcap import CaptureInfo, info, read


@dataclass
class Flow:
    """One bidirectional conversation."""

    key: str
    endpoints: tuple[str, str]
    ports: tuple[int | None, int | None]
    transport: str
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    apps: Counter = field(default_factory=Counter)
    packet_numbers: list[int] = field(default_factory=list)
    syn_count: int = 0
    syn_ack_seen: bool = False
    rst_seen: bool = False
    fin_count: int = 0
    retransmits: int = 0
    evidence_packet: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def main_app(self) -> str:
        apps = {a for a in self.apps if a and a != "tcp" and a != "udp"}
        return apps.pop() if len(apps) == 1 else (",".join(sorted(apps)) if apps else self.transport)

    @property
    def unresolved_handshake(self) -> bool:
        """SYN unanswered: the host at the other end never replied."""
        return self.transport == "tcp" and self.syn_count > 0 and not self.syn_ack_seen


@dataclass
class CaptureSummary:
    """A whole-capture digest."""

    path: str
    format: str = ""
    link_name: str = ""
    snaplen: int | None = None
    packet_count: int = 0
    byte_total: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    truncated_packets: int = 0
    protocols: list[tuple[str, int, int]] = field(default_factory=list)   # (name, packets, bytes)
    talkers: list[tuple[str, int, int]] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    dns_queries: list[tuple[str, int]] = field(default_factory=list)      # (name, count)
    http_requests: list[tuple[str, int]] = field(default_factory=list)    # ("GET host/uri", count)
    tls_sni: list[tuple[str, int]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)
    parse_errors: int = 0
    noted_frames: int = 0
    flow_count_total: int = 0
    scanned: int = 0
    limit_hit: bool = False

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def packets_per_second(self) -> float:
        return self.packet_count / self.duration if self.duration else 0.0

    @staticmethod
    def _suspicious_from(flows: Iterable[Flow]) -> list[str]:
        """Cheap, clearly-labelled heuristics, computed over *every* flow.

        These are hints, not verdicts, and each one names the packet that
        supports it so a reader can disagree with the classification.
        """
        out: list[str] = []
        for flow in flows:
            if flow.unresolved_handshake:
                out.append(
                    f"{flow.key}: {flow.syn_count} SYN sent, no SYN/ACK seen "
                    f"(evidence: packet {flow.evidence_packet})"
                )
            if flow.retransmits:
                out.append(
                    f"{flow.key}: {flow.retransmits} retransmitted segment(s) "
                    f"(evidence: packet {flow.evidence_packet})"
                )
            if flow.rst_seen and flow.fin_count == 0:
                out.append(
                    f"{flow.key}: reset without FIN "
                    f"(evidence: packet {flow.evidence_packet})"
                )
        return out


def _iter_frames(path: str, limit: int | None) -> Iterator[Frame]:
    for i, packet in enumerate(read(path), start=1):
        if limit is not None and i > limit:
            return
        try:
            yield dissect(packet)
        except Exception as exc:  # keep going: one bad frame must not lose the file
            frame = Frame(packet=packet)
            frame.notes.append(f"dissection failed: {type(exc).__name__}: {exc}")
            yield frame


def summarize(path: str, limit: int | None = None, top: int = 10) -> CaptureSummary:
    """Build the whole-capture digest, reading the file exactly once."""
    try:
        meta: CaptureInfo = info(path)
    except Exception as exc:
        out = CaptureSummary(path=path)
        out.notes.append(f"file could not be read: {exc}")
        return out

    out = CaptureSummary(
        path=path, format=meta.format, link_name=meta.link_name, snaplen=meta.snaplen
    )
    proto_pkts: Counter = Counter()
    proto_bytes: Counter = Counter()
    talker_pkts: Counter = Counter()
    talker_bytes: Counter = Counter()
    dns: Counter = Counter()
    http: Counter = Counter()
    sni: Counter = Counter()
    note_counter: Counter = Counter()
    flows: dict[str, Flow] = {}
    retransmit_keys: set[tuple] = set()

    first = True
    for frame in _iter_frames(path, limit):
        out.scanned += 1
        if frame.notes and frame.notes[0].startswith("dissection failed"):
            out.parse_errors += 1
        if frame.packet.truncated:
            out.truncated_packets += 1
        out.packet_count += 1
        out.byte_total += frame.length
        if first:
            out.first_ts = frame.timestamp
            first = False
        out.last_ts = frame.timestamp

        # the most specific thing we recognised wins the protocol slot
        name = frame.app or frame.transport or frame.packet.link_name
        proto_pkts[name] += 1
        proto_bytes[name] += frame.length

        for endpoint in (frame.src, frame.dst):
            if endpoint:
                talker_pkts[endpoint] += 1
                talker_bytes[endpoint] += frame.length

        if frame.src or frame.dst:
            flow = flows.get(frame.conversation)
            if flow is None:
                flow = Flow(
                    key=frame.conversation,
                    endpoints=frame.endpoint_pair(),
                    ports=(frame.src_port, frame.dst_port),
                    transport=frame.transport or "other",
                    first_ts=frame.timestamp,
                    evidence_packet=frame.number,
                )
                flows[frame.conversation] = flow
            flow.packets += 1
            flow.bytes += frame.length
            flow.last_ts = frame.timestamp
            if frame.app:
                flow.apps[frame.app] += 1
            if len(flow.packet_numbers) < 5:
                flow.packet_numbers.append(frame.number)
            if "SYN" in frame.tcp_flags and "ACK" not in frame.tcp_flags:
                flow.syn_count += 1
            if {"SYN", "ACK"} <= set(frame.tcp_flags):
                flow.syn_ack_seen = True
            if "RST" in frame.tcp_flags:
                flow.rst_seen = True
            if "FIN" in frame.tcp_flags:
                flow.fin_count += 1
            if frame.transport == "tcp" and len(frame.packet.data) > 0:
                layers = {layer.name: layer for layer in frame.layers}
                tcp = layers.get("tcp")
                if tcp and "seq" in tcp.fields:
                    key = (frame.src, frame.dst, frame.src_port, frame.dst_port,
                           tcp.fields["seq"], frame.length)
                    if key in retransmit_keys:
                        flow.retransmits += 1
                    retransmit_keys.add(key)

        if frame.dns:
            for qname, _qtype in frame.dns.questions:
                dns[qname] += 1
        if frame.http:
            label = (
                f"{frame.http.method} {frame.http.host}{frame.http.uri}"
                if frame.http.kind == "request"
                else f"{frame.http.status} {frame.http.reason}"
            )
            http[label] += 1
        if frame.tls and frame.tls.sni:
            sni[frame.tls.sni] += 1
        if frame.notes:
            out.noted_frames += 1
            for note in frame.notes:
                note_counter[note.split(":")[0]] += 1

    all_flows = sorted(flows.values(), key=lambda f: (-f.bytes, f.key))
    out.suspicious = CaptureSummary._suspicious_from(all_flows)
    out.protocols = [(n, proto_pkts[n], proto_bytes[n]) for n, _ in proto_pkts.most_common(top)]
    out.talkers = [(t, talker_pkts[t], talker_bytes[t]) for t, _ in talker_pkts.most_common(top)]
    out.flows = all_flows[:top]
    out.flow_count_total = len(all_flows)
    out.dns_queries = dns.most_common(top)
    out.http_requests = http.most_common(top)
    out.tls_sni = sni.most_common(top)
    if out.truncated_packets:
        out.notes.append(
            f"{out.truncated_packets} packet(s) were clipped by snaplen "
            f"({meta.snaplen}): payloads are incomplete, not missing features"
        )
    if limit and out.packet_count >= limit:
        out.limit_hit = True
        out.notes.append(f"only the first {limit} packets were read; totals are partial")
    if out.parse_errors:
        out.notes.append(f"{out.parse_errors} packet(s) could not be dissected")
    for label, count in note_counter.most_common(3):
        out.notes.append(f"{count} packet(s) reported: {label}")
    return out


def conversation_keys(path: str) -> list[str]:
    """Just the flow keys, cheapest possible listing."""
    seen: list[str] = []
    for frame in _iter_frames(path, None):
        key = frame.conversation
        if key not in seen:
            seen.append(key)
    return seen


def find(
    path: str,
    expression: str = "",
    *,
    ip: str = "",
    port: int | None = None,
    protocol: str = "",
    max_results: int = 20,
) -> list[Frame]:
    """Return frames matching the given filters.

    ``expression`` is a case-insensitive substring matched against the frame's
    ASCII text, so searching for a hostname finds it whether it appeared in a
    DNS question, an HTTP Host header or a TLS SNI.
    """
    needle = expression.lower()
    results: list[Frame] = []
    for frame in _iter_frames(path, None):
        if protocol and frame.app != protocol and frame.transport != protocol:
            continue
        if ip and ip not in (frame.src, frame.dst):
            continue
        if port is not None and port not in (frame.src_port, frame.dst_port):
            continue
        if needle:
            hay = (
                frame.summary + " "
                + " ".join(str(v) for layer in frame.layers for v in layer.fields.values())
                + " "
                + frame.packet.data.decode("latin-1", "replace")
            ).lower()
            if needle not in hay:
                continue
        results.append(frame)
        if len(results) >= max_results:
            break
    return results


def as_dict(summary: CaptureSummary, max_chars: int = 6000) -> dict:
    """Serialise for an MCP response, honouring a hard character budget."""
    payload: dict = {
        "path": summary.path,
        "format": summary.format,
        "link_layer": summary.link_name,
        "packets": summary.packet_count,
        "bytes": summary.byte_total,
        "duration_seconds": round(summary.duration, 6),
        "packets_per_second": round(summary.packets_per_second, 1),
        "truncated_by_snaplen": summary.truncated_packets,
        "protocols": [
            {"protocol": n, "packets": p, "bytes": b} for n, p, b in summary.protocols
        ],
        "top_talkers": [
            {"endpoint": t, "packets": p, "bytes": b} for t, p, b in summary.talkers
        ],
        "flows_total": summary.flow_count_total,
        "conversations": [
            {
                "flow": f.key,
                "transport": f.transport,
                "app": f.main_app,
                "packets": f.packets,
                "bytes": f.bytes,
                "duration_seconds": round(f.duration, 6),
                "evidence_packet": f.evidence_packet,
                "retransmits": f.retransmits,
                "reset": f.rst_seen,
            }
            for f in summary.flows
        ],
        "dns_queries": [{"name": n, "count": c} for n, c in summary.dns_queries],
        "http_requests": [{"request": h, "count": c} for h, c in summary.http_requests],
        "tls_sni": [{"sni": s, "count": c} for s, c in summary.tls_sni],
        "suspicious": summary.suspicious,
        "notes": summary.notes,
    }
    if summary.limit_hit:
        payload["partial"] = True
    text = repr(payload)
    if len(text) > max_chars and payload["conversations"]:
        # shrink honest-by-labelling: drop the bulkiest list, say we did
        payload["conversations"] = payload["conversations"][: max(1, len(payload["conversations"]) // 2)]
        payload["notes"] = payload["notes"] + [
            f"conversations truncated to fit a {max_chars}-char budget; ask with a filter to see the rest"
        ]
    return payload
