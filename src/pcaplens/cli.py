"""Command line interface.

Built on **argparse so the CLI has no dependencies at all** — `python -m
pcaplens summary capture.pcap` works on a stock Python with nothing
installed. The MCP surface (the optional extra) is the same code with a
different front door.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .aggregate import as_dict, find, summarize
from .dissect import Frame, dissect
from .pcap import read as read_packets
from .pcap import write_pcap
from .render import (
    render_dns,
    render_flows,
    render_frame,
    render_http,
    render_search,
    render_summary,
    render_tls,
)
from .synth import demo_capture

def _frames_by_number(path: str, numbers: list[int]) -> list[Frame]:
    wanted = set(numbers)
    found: list[Frame] = []
    for packet in read_packets(path):
        if packet.number in wanted:
            found.append(dissect(packet))
            if len(found) == len(wanted):
                break
    return found


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcaplens",
        description=(
            "Read a pcap the way a language model should: summary first, evidence always. "
            "No tshark, no dependencies."
        ),
    )
    parser.add_argument("--version", action="version", version=f"pcaplens {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("demo", help="write a synthetic capture so you can try it right now")
    p.add_argument("output", nargs="?", default="demo.pcap")
    p.add_argument("--packets", action="store_true", help="print the frames that were written")

    p = sub.add_parser("summary", help="one-page digest of the whole capture")
    p.add_argument("path")
    p.add_argument("--top", type=int, default=10, help="how many rows per section (default 10)")
    p.add_argument("--limit", type=int, default=None, help="read only the first N packets")
    p.add_argument("--json", action="store_true", help="machine-readable output for an agent")

    p = sub.add_parser("flows", help="conversations, sorted by volume")
    p.add_argument("path")
    p.add_argument("--top", type=int, default=15)

    p = sub.add_parser("dns", help="DNS queries seen")
    p.add_argument("path")
    p = sub.add_parser("http", help="HTTP requests and responses seen")
    p.add_argument("path")
    p = sub.add_parser("tls", help="TLS Server Name Indication values seen")
    p.add_argument("path")

    p = sub.add_parser("packet", help="fully dissect one packet, with byte offsets")
    p.add_argument("path")
    p.add_argument("numbers", nargs="+", type=int)

    p = sub.add_parser("mcp", help="MCP server for AI agents (needs the [mcp] extra)")
    p.add_argument("--check", action="store_true",
                   help="list the tools an agent would get, then exit")

    p = sub.add_parser("search", help="find frames by text, ip, port or protocol")
    p.add_argument("path")
    p.add_argument("--text", default="", help="substring of the frame text or bytes")
    p.add_argument("--ip", default="")
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--proto", default="", help="e.g. dns, http, tls, tcp, udp")
    p.add_argument("--max", type=int, default=20)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "demo":
        frames = demo_capture()
        write_pcap(args.output, frames)
        print(f"wrote {len(frames)} frames to {args.output}")
        print(f"next:  pcaplens summary {args.output}")
        if args.packets:
            for i, (_ts, data) in enumerate(frames, start=1):
                print(f"  {i:>2}  {len(data):>4} bytes  {data[:16].hex()}")
        return 0

    if args.command == "summary":
        summary = summarize(args.path, limit=args.limit, top=args.top)
        if args.json:
            print(json.dumps(as_dict(summary), indent=2, ensure_ascii=False))
        else:
            print(render_summary(summary))
        return 0

    if args.command == "flows":
        summary = summarize(args.path, top=args.top)
        print(render_flows(summary.flows, summary.flow_count_total))
        return 0

    if args.command in ("dns", "http", "tls"):
        summary = summarize(args.path)
        print({"dns": render_dns, "http": render_http, "tls": render_tls}[args.command](summary))
        return 0

    if args.command == "packet":
        frames = _frames_by_number(args.path, args.numbers)
        if not frames:
            print(f"no such packet in {args.path}", file=sys.stderr)
            return 1
        for frame in frames:
            print(render_frame(frame))
            print()
        return 0

    if args.command == "mcp":
        try:
            from .mcp_server import run as run_mcp, tool_manifest
        except ImportError as exc:
            print(
                f"the MCP extra is not installed ({exc})\n"
                'install it with:  pip install "pcaplens[mcp]"',
                file=sys.stderr,
            )
            return 1
        if args.check:
            tools = tool_manifest()
            for i, tool in enumerate(tools, start=1):
                print(f"  {i:>2}. {tool['name']:<20} {tool['description']}")
            print(f"\n{len(tools)} tools. Add to your agent's MCP config:")
            print('  { "command": "pcaplens", "args": ["mcp"] }')
            return 0
        run_mcp()
        return 0

    if args.command == "search":
        frames = find(args.path, args.text, ip=args.ip, port=args.port,
                      protocol=args.proto, max_results=args.max)
        print(render_search(frames, args.text or args.proto or args.ip or str(args.port)))
        return 0

    return 1  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
