import pytest
from netguard.detection.base import Finding
from netguard.evidence.wireshark import generate_wireshark_filter


def test_frame_numbers_preserved_in_wireshark_filter():
    f = Finding(
        alert_type="port_scan",
        detector="rule",
        rule_name="port_scan_vertical",
        severity="medium",
        confidence=0.9,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        dst_port=None,
        start_ts=100.0,
        end_ts=120.0,
        stage="Reconnaissance",
        summary="Test summary",
        details={"first_frame": 15, "last_frame": 42},
        evidence_refs=[],
    )
    ws_filter = generate_wireshark_filter(f)
    assert "frame.number >= 15 && frame.number <= 42" in ws_filter
    assert "ip.src == 192.168.1.10" in ws_filter
    assert "ip.dst == 10.0.0.5" in ws_filter


def test_specific_evidence_frames_in_filter():
    f = Finding(
        alert_type="brute_force",
        detector="rule",
        rule_name="repeated_short_connections",
        severity="high",
        confidence=0.8,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        dst_port=22,
        start_ts=100.0,
        end_ts=120.0,
        stage="Access Attempt",
        summary="Test summary",
        details={"first_frame": 1, "last_frame": 100},
        evidence_refs=[
            {"frame_no": 5},
            {"frame_no": 12},
            {"frame_no": 25},
        ],
    )
    ws_filter = generate_wireshark_filter(f)
    assert "frame.number == 5" in ws_filter
    assert "frame.number == 12" in ws_filter
    assert "frame.number == 25" in ws_filter
    assert "tcp.dstport == 22" in ws_filter


def test_deterministic_filter_generation():
    f = Finding(
        alert_type="dns_anomaly",
        detector="rule",
        rule_name="dns_high_volume",
        severity="medium",
        confidence=0.7,
        src_ip="192.168.1.10",
        dst_ip=None,
        dst_port=None,
        start_ts=100.0,
        end_ts=120.0,
        stage="Possible Exploitation",
        summary="Test summary",
        details={"first_frame": 10, "last_frame": 20},
        evidence_refs=[],
    )
    f1 = generate_wireshark_filter(f)
    f2 = generate_wireshark_filter(f)
    assert f1 == f2
    assert "dns" in f1
