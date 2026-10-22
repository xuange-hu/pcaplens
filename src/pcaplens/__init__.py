"""pcaplens — read a capture the way a language model should.

Summary first, evidence always, and no tshark anywhere in sight.

The core is deliberately **standard-library only**: no Wireshark, no tshark,
no libpcap, no Npcap, no compiler. The MCP server is an optional extra, so
`pip install pcaplens` gives you a working CLI on a locked-down Windows box
and `pip install "pcaplens[mcp]"` additionally gives your coding agent nine
tools.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
