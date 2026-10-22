"""MCP server: the same reader, exposed to AI coding agents.

Nine tools, and each one follows the discipline the rest of the project is
built on:

* it never dumps the capture — it hands back a digest and a way to drill in;
* every list is capped and states how many items it dropped;
* every claim names the packet number that supports it, so the agent can
  open that packet instead of repeating our assertion.

That last point matters more than it looks. An agent that cannot check a
claim will confabulate, and a confabulated packet analysis is worse than no
analysis.
"""

from __future__ import annotations

import json
from typing import Any

try:  # mcp 1.x (pinned in pyproject); 2.x renames this class
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    from mcp.server.mcpserver import MCPServer as FastMCP  # type: ignore

from . import __version__
from .aggregate import as_dict, find, summarize
from .dissect import dissect
from .pcap import read as read_packets
from .render import render_frame, render_summary

mcp = FastMCP("pcaplens")

MAX_CHARS = 6000


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def _text(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


@mcp.tool()
async def pcap_summary(path: str, top: int = 10, limit: int | None = None) -> str:
    """Digest a pcap/pcapng file: shape, protocols, top talkers, conversations.

    Call this FIRST — it is the map, and every other tool is a drill-down.
    Returns DNS/HTTP/TLS findings and anything suspicious, each with the
    packet number that proves it.
    """
    summary = summarize(path, limit=limit, top=_clamp(top, 1, 50))
    return _text(as_dict(summary, max_chars=MAX_CHARS))


@mcp.tool()
async def pcap_conversations(path: str, top: int = 15) -> str:
    """List the flows in a capture, sorted by bytes, with retransmit/RST flags."""
    summary = summarize(path, top=_clamp(top, 1, 50))
    return _text({
        "flows_total": summary.flow_count_total,
        "shown": len(summary.flows),
        "conversations": [
            {
                "flow": f.key, "transport": f.transport, "app": f.main_app,
                "packets": f.packets, "bytes": f.bytes,
                "duration_seconds": round(f.duration, 6),
                "retransmits": f.retransmits, "reset": f.rst_seen,
                "unanswered_syn": f.unresolved_handshake,
                "evidence_packet": f.evidence_packet,
            }
            for f in summary.flows
        ],
    })


@mcp.tool()
async def pcap_talkers(path: str, top: int = 15) -> str:
    """Rank endpoints by packets and bytes. Use it to find who dominates a capture."""
    summary = summarize(path, top=_clamp(top, 1, 50))
    return _text({
        "shown": len(summary.talkers),
        "talkers": [
            {"endpoint": t, "packets": p, "bytes": b} for t, p, b in summary.talkers
        ],
    })


@mcp.tool()
async def pcap_protocols(path: str) -> str:
    """Protocol breakdown (packets and bytes per protocol) for a capture."""
    summary = summarize(path)
    return _text({
        "protocols": [
            {"protocol": n, "packets": p, "bytes": b} for n, p, b in summary.protocols
        ],
        "notes": summary.notes,
    })


@mcp.tool()
async def pcap_packet(path: str, number: int) -> str:
    """Fully dissect ONE packet: layers with byte offsets, fields, and a hexdump.

    This is how you verify a claim made by any other tool — the output names
    the offset and the bytes, so the finding is checkable rather than trusted.
    """
    for packet in read_packets(path):
        if packet.number == number:
            return render_frame(dissect(packet))
    return json.dumps({"error": f"packet {number} is not present in {path}"})


@mcp.tool()
async def pcap_search(
    path: str,
    text: str = "",
    ip: str = "",
    port: int | None = None,
    protocol: str = "",
    max_results: int = 20,
) -> str:
    """Find frames by substring, IP, port or protocol (dns/http/tls/tcp/udp).

    `text` matches anywhere in the frame, so a hostname is found whether it
    appears in a DNS question, an HTTP Host header or a TLS SNI.
    """
    frames = find(path, text, ip=ip, port=port, protocol=protocol,
                  max_results=_clamp(max_results, 1, 100))
    return _text({
        "matches": [
            {"packet": f.number, "time": round(f.timestamp, 6),
             "protocol": f.app or f.transport or "-", "summary": f.summary}
            for f in frames
        ],
        "returned": len(frames),
        "capped_at": _clamp(max_results, 1, 100),
    })


@mcp.tool()
async def pcap_dns(path: str, top: int = 25) -> str:
    """List DNS queries with how often each was asked, plus the answers seen."""
    summary = summarize(path, top=_clamp(top, 1, 100))
    answers: list[dict] = []
    for packet in read_packets(path):
        frame = dissect(packet)
        if frame.dns:
            for name, rtype, value in frame.dns.answers:
                answers.append({"packet": frame.number, "name": name, "type": rtype, "value": value})
        if len(answers) >= _clamp(top, 1, 100):
            break
    return _text({
        "queries": [{"name": n, "count": c} for n, c in summary.dns_queries],
        "answers": answers,
    })


@mcp.tool()
async def pcap_http(path: str, top: int = 25) -> str:
    """List HTTP requests (method, host, URI) and response statuses."""
    summary = summarize(path, top=_clamp(top, 1, 100))
    return _text({
        "requests": [{"request": h, "count": c} for h, c in summary.http_requests],
        "note": "HTTP/1.x only; no reassembly across TCP segments is attempted.",
    })


@mcp.tool()
async def pcap_tls(path: str, top: int = 25) -> str:
    """List TLS Server Name Indication values and the versions offered."""
    summary = summarize(path, top=_clamp(top, 1, 100))
    return _text({
        "sni": [{"sni": s, "count": c} for s, c in summary.tls_sni],
        "note": "from ClientHello only; encrypted traffic is not decrypted.",
    })


def run() -> None:
    """Console-script entry point (`pcaplens-mcp`, or `uvx --from pcaplens[mcp]`)."""
    mcp.run()


def tool_manifest() -> list[dict[str, str]]:
    """Synchronous listing, used by `pcaplens mcp --check` and by CI."""
    import asyncio

    async def _collect() -> list[dict[str, str]]:
        tools = await mcp.list_tools()
        return [
            {
                "name": getattr(t, "name", "?"),
                "description": (getattr(t, "description", "") or "").splitlines()[0][:110],
            }
            for t in tools
        ]

    return asyncio.run(_collect())


if __name__ == "__main__":  # pragma: no cover
    run()


__all__ = ["mcp", "run", "tool_manifest", "__version__", "render_summary"]
