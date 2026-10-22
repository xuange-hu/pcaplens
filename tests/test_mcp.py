"""MCP surface: registration and one real tool round-trip."""

from __future__ import annotations

import asyncio
import json

import pytest

from pcaplens.pcap import write_pcap
from pcaplens.synth import demo_capture

mcp_server = pytest.importorskip("pcaplens.mcp_server")


@pytest.fixture()
def demo_file(tmp_path) -> str:
    path = tmp_path / "demo.pcap"
    write_pcap(str(path), demo_capture())
    return str(path)


def test_manifest_matches_decorated_tool_count():
    manifest = mcp_server.tool_manifest()
    assert len(manifest) == 9, f"expected 9 tools, got {[t['name'] for t in manifest]}"
    assert all(t["description"] for t in manifest), "every tool needs a description"


def test_tool_names_are_stable():
    """Agents are configured against these names; renaming breaks them silently."""
    names = {t["name"] for t in mcp_server.tool_manifest()}
    assert names == {
        "pcap_summary", "pcap_conversations", "pcap_talkers", "pcap_protocols",
        "pcap_packet", "pcap_search", "pcap_dns", "pcap_http", "pcap_tls",
    }


def test_pcap_summary_returns_parseable_json(demo_file):
    result = asyncio.run(mcp_server.pcap_summary(demo_file))
    if isinstance(result, tuple):  # mcp returns (content, meta) on some versions
        result = result[0]
    text = result[0].text if hasattr(result, "__getitem__") and not isinstance(result, str) else result
    if not isinstance(text, str):
        text = text.text
    payload = json.loads(text)
    assert payload["packets"] == 12
    assert payload["conversations"]


def test_pcap_packet_reports_evidence(demo_file):
    result = asyncio.run(mcp_server.pcap_packet(demo_file, 10))
    text = result if isinstance(result, str) else str(result)
    assert "packet 10" in text
    assert "layers" in text


def test_pcap_search_finds_hostname(demo_file):
    result = asyncio.run(mcp_server.pcap_search(demo_file, text="example.com"))
    text = result if isinstance(result, str) else str(result)
    payload = json.loads(text)
    assert payload["returned"] >= 3
