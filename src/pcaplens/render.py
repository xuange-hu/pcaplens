"""Plain-text rendering.

No rich, no tabulate, no colour: the core of pcaplens has **zero
dependencies**, so it can be dropped into a Windows box with no compiler and
no network. Output is plain ASCII, which also means it survives being piped
into a file or a language model unchanged.
"""

from __future__ import annotations

from typing import Iterable

from .aggregate import CaptureSummary, Flow
from .dissect import Frame

_KB = 1024


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < _KB or unit == "GB":
            return f"{n}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= _KB
    return f"{n:.1f}GB"  # pragma: no cover


def human_seconds(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, rest = divmod(seconds, 60)
    return f"{int(minutes)}m{rest:.1f}s"


def _table(headers: tuple[str, ...], rows: Iterable[tuple[str, ...]]) -> str:
    rows = list(rows)
    if not rows:
        return ""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "  ".join("-" * widths[i] for i in range(len(headers)))
    body = "\n".join(
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)) for row in rows
    )
    return f"{line}\n{sep}\n{body}"


def render_summary(s: CaptureSummary) -> str:
    out: list[str] = []
    out.append(f"file        : {s.path}")
    out.append(f"format      : {s.format}  link-layer: {s.link_name}")
    if s.snaplen:
        out.append(f"snaplen     : {s.snaplen}")
    out.append(
        f"packets     : {s.packet_count}   bytes: {human_bytes(s.byte_total)}   "
        f"duration: {human_seconds(s.duration)}   ({s.packets_per_second:.1f} pkt/s)"
    )
    if s.format != "unknown":
        out.append("")
        out.append("protocols (packets, bytes):")
        out.append(_table(("protocol", "packets", "bytes"),
                          [(n, str(p), human_bytes(b)) for n, p, b in s.protocols]) or "  (none)")
        out.append("")
        out.append("top talkers:")
        out.append(_table(("endpoint", "packets", "bytes"),
                          [(t, str(p), human_bytes(b)) for t, p, b in s.talkers]) or "  (none)")
    if s.dns_queries:
        out.append("")
        out.append("DNS queries:")
        out.append(_table(("name", "count"), [(n, str(c)) for n, c in s.dns_queries]))
    if s.http_requests:
        out.append("")
        out.append("HTTP:")
        out.append(_table(("request", "count"), [(h, str(c)) for h, c in s.http_requests]))
    if s.tls_sni:
        out.append("")
        out.append("TLS SNI:")
        out.append(_table(("sni", "count"), [(n, str(c)) for n, c in s.tls_sni]))
    if s.suspicious:
        out.append("")
        out.append("worth a look:")
        for item in s.suspicious:
            out.append(f"  - {item}")
    if s.notes:
        out.append("")
        out.append("notes:")
        for note in s.notes:
            out.append(f"  - {note}")
    return "\n".join(out)


def render_flows(flows: list[Flow], total: int) -> str:
    rows = [
        (
            f.key,
            f.main_app,
            str(f.packets),
            human_bytes(f.bytes),
            human_seconds(f.duration),
            ("yes" if f.retransmits else "-") + "/" + ("R" if f.rst_seen else "-"),
        )
        for f in flows
    ]
    body = _table(("conversation", "app", "packets", "bytes", "duration", "retrans/rst"), rows)
    if not body:
        return "  (no conversations found)"
    if total > len(flows):
        body += f"\n\n({len(flows)} of {total} conversations shown; raise --top to see more)"
    return body


def render_dns(s: CaptureSummary) -> str:
    if not s.dns_queries:
        return "  (no DNS traffic)"
    return _table(("query", "count"), [(n, str(c)) for n, c in s.dns_queries])


def render_http(s: CaptureSummary) -> str:
    if not s.http_requests:
        return "  (no HTTP traffic)"
    return _table(("request", "count"), [(h, str(c)) for h, c in s.http_requests])


def render_tls(s: CaptureSummary) -> str:
    if not s.tls_sni:
        return "  (no TLS ClientHello with SNI)"
    return _table(("sni", "count"), [(n, str(c)) for n, c in s.tls_sni])


def hexdump(data: bytes, base_offset: int = 0, limit: int = 256) -> str:
    shown = data[:limit]
    out = []
    for i in range(0, len(shown), 16):
        chunk = shown[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"  {base_offset + i:06x}  {hexpart:<47}  {ascpart}")
    if len(data) > limit:
        out.append(f"  ... {len(data) - limit} more bytes")
    return "\n".join(out)


def render_frame(frame: Frame) -> str:
    out = [
        f"packet {frame.number}  {human_bytes(frame.length)}  {frame.timestamp:.6f}",
        f"  link      : {frame.packet.link_name} (file offset 0x{frame.packet.file_offset:x})",
        f"  summary   : {frame.summary}",
    ]
    if frame.src or frame.dst:
        pair = f"{frame.src or '?'}"
        if frame.src_port is not None:
            pair += f":{frame.src_port}"
        pair += f" -> {frame.dst or '?'}"
        if frame.dst_port is not None:
            pair += f":{frame.dst_port}"
        out.append(f"  endpoints : {pair}")
    out.append("")
    out.append("  layers (offset, length):")
    for layer in frame.layers:
        fields = ", ".join(f"{k}={v}" for k, v in layer.fields.items())
        out.append(f"    {layer.name:<18} @{layer.offset:<5} len={layer.length:<5} {fields}")
    if frame.dns:
        out.append("")
        out.append(f"  DNS id=0x{frame.dns.transaction_id:04x} "
                   f"{'response' if frame.dns.is_response else 'query'} rcode={frame.dns.rcode}")
        for name, qtype in frame.dns.questions:
            out.append(f"    question: {name} {qtype}")
        for name, rtype, value in frame.dns.answers:
            out.append(f"    answer  : {name} {rtype} {value}")
    if frame.http:
        out.append("")
        if frame.http.kind == "request":
            out.append(f"  HTTP request: {frame.http.method} {frame.http.uri}")
        else:
            out.append(f"  HTTP response: {frame.http.status} {frame.http.reason}")
        for key, value in list(frame.http.headers.items())[:8]:
            out.append(f"    {key}: {value}")
    if frame.tls:
        out.append("")
        out.append(f"  TLS {frame.tls.handshake_type} version={frame.tls.version}")
        if frame.tls.sni:
            out.append(f"    SNI: {frame.tls.sni}")
        if frame.tls.cipher_suites:
            out.append("    suites: " + ", ".join(f"0x{c:04x}" for c in frame.tls.cipher_suites[:6]))
        if frame.tls.alpn:
            out.append("    ALPN: " + ", ".join(frame.tls.alpn))
    out.append("")
    out.append("  bytes:")
    out.append(hexdump(frame.packet.data))
    if frame.notes:
        out.append("")
        out.append("  notes:")
        for note in frame.notes:
            out.append(f"    - {note}")
    return "\n".join(out)


def render_search(frames: list[Frame], expression: str) -> str:
    if not frames:
        return f"  no frames matched {expression!r}"
    rows = [(str(f.number), f"{f.timestamp:.6f}", f.app or f.transport or "-", f.summary[:60])
            for f in frames]
    body = _table(("#", "time", "proto", "summary"), rows)
    return body + f"\n\n({len(frames)} match(es) for {expression!r}; raise --max to see more)"
