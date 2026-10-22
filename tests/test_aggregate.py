"""Aggregation: the part an agent actually consumes.

These tests pin the two promises the project makes — *nothing is silently
truncated* and *every finding names its evidence* — because both are easy to
break with a well-meaning refactor and impossible to notice afterwards.
"""

from __future__ import annotations

import json

from pcaplens.aggregate import as_dict, find, summarize
from pcaplens.pcap import write_pcap
from pcaplens.synth import demo_capture


def demo(tmp_path) -> str:
    path = tmp_path / "demo.pcap"
    write_pcap(str(path), demo_capture())
    return str(path)


def test_summary_counts_and_shape(tmp_path):
    s = summarize(demo(tmp_path))
    assert s.packet_count == 12
    assert s.format == "pcap"
    assert s.duration > 0
    assert s.byte_total > 0
    assert not s.limit_hit


def test_protocol_mix_is_recognised(tmp_path):
    s = summarize(demo(tmp_path))
    names = {name for name, _, _ in s.protocols}
    assert {"dns", "http", "tls"} <= names


def test_dns_http_and_tls_findings(tmp_path):
    s = summarize(demo(tmp_path))
    # the question section appears in both the query and the response
    assert ("example.com", 2) in s.dns_queries
    assert any("GET example.com/index.html" == h for h, _ in s.http_requests)
    assert ("www.example.com", 1) in s.tls_sni


def test_unanswered_syn_is_called_out_with_evidence(tmp_path):
    """Two SYNs in the demo never get a SYN/ACK; say so, and cite the packet."""
    s = summarize(demo(tmp_path))
    # three SYNs never get an answer: :22, :3389, and the bare SYN to :443
    scan = [line for line in s.suspicious if "no SYN/ACK seen" in line]
    assert len(scan) == 3
    assert all("evidence: packet" in line for line in scan)


def test_retransmission_is_detected(tmp_path):
    s = summarize(demo(tmp_path))
    assert any("retransmitted" in line for line in s.suspicious)


def test_flows_are_sorted_by_volume_and_counted_honestly(tmp_path):
    s = summarize(demo(tmp_path), top=2)
    assert len(s.flows) == 2
    assert s.flow_count_total >= 5
    assert s.flows[0].bytes >= s.flows[1].bytes


def test_top_limit_is_reported_not_hidden(tmp_path):
    s = summarize(demo(tmp_path), top=1)
    assert len(s.protocols) == 1
    assert any("only the first" in n for n in s.notes) is False  # no packet limit set
    assert s.flow_count_total > len(s.flows)


def test_packet_limit_marks_the_result_partial(tmp_path):
    s = summarize(demo(tmp_path), limit=3)
    assert s.packet_count == 3
    assert s.limit_hit is True
    assert any("partial" in n or "only the first" in n for n in s.notes)


def test_search_by_text_finds_across_layers(tmp_path):
    path = demo(tmp_path)
    hits = find(path, "example.com")
    assert hits, "a plain hostname search must find DNS, HTTP and TLS frames"
    assert any(f.number == 1 for f in hits)
    assert any(f.app == "tls" and f.tls.sni == "www.example.com" for f in hits)


def test_search_by_port_and_protocol(tmp_path):
    path = demo(tmp_path)
    assert all(f.dst_port == 443 or f.src_port == 443 for f in find(path, port=443))
    assert all(f.app == "dns" for f in find(path, protocol="dns"))


def test_search_result_cap_is_respected(tmp_path):
    assert len(find(demo(tmp_path), "example", max_results=2)) <= 2


def test_as_dict_is_json_serialisable_and_budgeted(tmp_path):
    s = summarize(demo(tmp_path))
    payload = as_dict(s)
    json.dumps(payload, ensure_ascii=False)  # must not raise
    assert payload["packets"] == 12
    assert payload["flows_total"] >= 5
    assert isinstance(payload["suspicious"], list)


def test_as_dict_says_when_it_truncates(tmp_path):
    s = summarize(demo(tmp_path))
    payload = as_dict(s, max_chars=300)
    assert any("budget" in n for n in payload["notes"])


def test_missing_file_is_reported_not_raised():
    s = summarize("does-not-exist.pcap")
    assert s.packet_count == 0
    assert any("could not be read" in n for n in s.notes)


def test_evidence_packet_numbers_can_be_reopened(tmp_path):
    """Every flow must carry a packet number that really exists in the file."""
    from pcaplens.pcap import read

    path = demo(tmp_path)
    s = summarize(path)
    numbers = {p.number for p in read(path)}
    for flow in s.flows:
        assert flow.evidence_packet in numbers
