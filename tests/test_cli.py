"""CLI tests: run every subcommand for real, no mocking of the happy path."""

from __future__ import annotations

import json

import pytest

from pcaplens.cli import main
from pcaplens.pcap import write_pcap
from pcaplens.synth import demo_capture


@pytest.fixture()
def demo_file(tmp_path) -> str:
    path = tmp_path / "demo.pcap"
    write_pcap(str(path), demo_capture())
    return str(path)


def run(capsys, *argv: str) -> str:
    code = main(list(argv))
    assert code == 0, f"exit {code} for {argv}"
    return capsys.readouterr().out


def test_demo_writes_a_file(capsys, tmp_path):
    out = tmp_path / "out.pcap"
    printed = run(capsys, "demo", str(out))
    assert out.exists() and out.stat().st_size > 0
    assert "next:" in printed


def test_summary_is_human_readable(capsys, demo_file):
    out = run(capsys, "summary", demo_file)
    assert "packets     : 12" in out
    assert "protocols" in out
    assert "worth a look" in out


def test_summary_json_parses(capsys, demo_file):
    out = run(capsys, "summary", demo_file, "--json")
    payload = json.loads(out)
    assert payload["packets"] == 12
    assert payload["conversations"]


def test_flows_lists_conversations(capsys, demo_file):
    out = run(capsys, "flows", demo_file)
    assert "conversation" in out
    assert "10.0.0.1:53" in out


def test_dns_http_tls_views(capsys, demo_file):
    assert "example.com" in run(capsys, "dns", demo_file)
    assert "GET example.com/index.html" in run(capsys, "http", demo_file)
    assert "www.example.com" in run(capsys, "tls", demo_file)


def test_packet_shows_offsets_and_hexdump(capsys, demo_file):
    out = run(capsys, "packet", demo_file, "10")
    assert "packet 10" in out
    assert "layers" in out
    assert "000000" in out  # hexdump offset column


def test_packet_missing_number_exits_nonzero(capsys, demo_file):
    assert main(["packet", demo_file, "9999"]) == 1  # main() returns, never raises


def test_search_command(capsys, demo_file):
    out = run(capsys, "search", demo_file, "--text", "example")
    assert "match(es)" in out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_no_subcommand_exits_with_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2
