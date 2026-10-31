# pcaplens — read a pcap the way an LLM should

> **Summary first, evidence always. No tshark anywhere in sight.**

[![CI](https://github.com/xuange-hu/pcaplens/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/pcaplens/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-68%20passing-brightgreen.svg)](tests/)
[![Dependencies](https://img.shields.io/badge/dependencies-0-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-9%20tools-green.svg)](https://modelcontextprotocol.io)

[中文说明](README_CN.md)

A packet-capture reader written for the two ways people actually consume a
pcap today: **a human triaging an incident**, and **a coding agent that has
to fit the answer in a context window**.

The core is **standard-library only**. No Wireshark, no tshark, no libpcap,
no Npcap, no compiler. `pip install pcaplens` works on a locked-down Windows
laptop with no network share and no admin rights.

## Why this exists

Every popular "let your LLM read a pcap" project shells out to `tshark`.
That is two problems wearing one coat:

1. **It is not portable.** tshark is a ~100 MB install and a `PATH` entry. On
   Windows that is where most readers stop.
2. **It floods the context window.** `tshark -r x.pcap -V` on a 10 MB capture
   produces tens of megabytes of text. Piped into an agent it either blows
   the limit or crowds out everything else the model was told.

So pcaplens does not dump. It hands back a **map**, then lets you drill in:

```
summary       ~30 lines: shape of the capture and what is worth looking at
conversations one line per flow, sorted by volume, with retransmit/RST flags
packet N      one frame, fully dissected, with byte offsets and a hexdump
```

## Quick start

```bash
pip install pcaplens

pcaplens demo traffic.pcap          # no capture handy? synthesise one
pcaplens summary traffic.pcap
pcaplens flows traffic.pcap
pcaplens packet traffic.pcap 10
pcaplens search traffic.pcap --text example.com
```

Nothing else to install. `pcaplens demo` writes a real pcap containing a TCP
handshake, DNS, HTTP and a TLS ClientHello, so the whole feature set is
reachable in one command from an empty directory.

## What the output looks like

```
$ pcaplens summary traffic.pcap
file        : traffic.pcap
format      : pcap  link-layer: ethernet
packets     : 12   bytes: 1.1KB   duration: 2.00s   (6.0 pkt/s)

protocols (packets, bytes):
protocol  packets  bytes
--------  -------  -----
tcp       6        324B
http      3        442B
dns       2        158B
tls       1        152B

worth a look:
  - 10.0.0.2:52344 <-> 93.184.216.34:80: 1 retransmitted segment(s) (evidence: packet 3)
  - 10.0.0.2:52345 <-> 93.184.216.34:443: 1 SYN sent, no SYN/ACK seen (evidence: packet 9)
  - 10.0.0.2:52346 <-> 10.0.0.77:22: 1 SYN sent, no SYN/ACK seen (evidence: packet 11)
```

Every finding names the packet that supports it, so you can open that packet
instead of trusting the summary:

```
$ pcaplens packet traffic.pcap 10
packet 10  152B  2.010000
  link      : ethernet (file offset 0x3d8)
  summary   : TLS ClientHello SNI=www.example.com TLS1.2

  layers (offset, length):
    ethernet           @0     len=14    ethertype=0x800
    ipv4               @14    len=20    src=10.0.0.2, dst=93.184.216.34, ttl=64, proto=tcp
    tcp                @34    len=20    src_port=52345, dst_port=443, flags=PSH,ACK
    tls-handshake      @54    len=98

  TLS client_hello version=TLS1.2
    SNI: www.example.com
    suites: 0x1301, 0x1302, 0xc02f
```

## Let an AI agent drive it

```bash
pip install "pcaplens[mcp]"
```

```json
{
  "mcpServers": {
    "pcaplens": {
      "command": "pcaplens",
      "args": ["mcp"]
    }
  }
}
```

Nine tools: `pcap_summary`, `pcap_conversations`, `pcap_talkers`,
`pcap_protocols`, `pcap_packet`, `pcap_search`, `pcap_dns`, `pcap_http`,
`pcap_tls`.

Each one follows the same discipline as the CLI: **no raw dumps**, every list
is capped and says how many items it dropped, and every claim carries the
packet number that proves it. An agent that cannot verify a claim will
confabulate, and a confabulated packet analysis is worse than none.

Check what your agent would get without starting the server:

```bash
pcaplens mcp --check
```

## What it parses

| Layer | Coverage |
|---|---|
| Files | classic pcap (µs and ns, big and little endian) and **pcapng** (SHB/IDB/EPB/SPB/PB; unknown blocks skipped by length) |
| Link | Ethernet, 802.1Q/QinQ VLAN, Linux cooked v1 and v2, raw IP |
| Network | IPv4 (options-aware, fragment-flagged), IPv6 (extension-header chain, RFC 5952 text form), ARP |
| Transport | TCP (flags, seq/ack, offsets), UDP, ICMP/ICMPv6 |
| Application | DNS (compressed names, questions and answers), HTTP/1.x request and response, TLS ClientHello/ServerHello (SNI, suites, ALPN) |

Parsing is deliberately conservative: a field that cannot be parsed becomes a
note ("IPv4 fragment: ports below it may be absent") rather than a plausible
guess.

## Comparison

| | tshark-backed MCP servers | pcaplens |
|---|---|---|
| External binary needed | yes (Wireshark/tshark, ~100 MB) | **no** |
| Works on Windows without admin | often not | **yes** |
| Output shape | full text dump | **digest + targeted drill-down** |
| Context budget | caller's problem | **capped lists, truncation declared** |
| Findings cite evidence | no | **packet number + byte offset** |
| Core dependencies | several | **zero** |

## Install from source

```bash
git clone https://github.com/xuange-hu/pcaplens && cd pcaplens
pip install -e ".[mcp]"
pytest -q                       # 68 tests
PYTHONPATH=src python -m pcaplens.cli demo demo.pcap
```

## Limitations

Stated plainly, because guessing costs more:

* No TCP reassembly — HTTP is parsed per segment, so a large response split
  across segments shows up as "TCP" rather than "HTTP".
* No IP fragment reassembly; fragments are flagged, not glued.
* TLS is metadata only (SNI, versions, suites). Encrypted traffic is not and
  will not be decrypted.
* The heuristics are hints. `unresolved_handshake` means "no SYN/ACK was seen
  in *this* capture", which is not the same as "the host is down".

## License

MIT — see [LICENSE](LICENSE). Traffic in `demo` is synthesised locally by
`synth.py`; no third-party capture is redistributed.
