import pytest
from netguard.detection.base import Finding
from netguard.evidence.timeline import build_incident_timeline


def test_chronological_and_stage_ordering():
    f_recon = Finding(
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
        summary="Recon alert",
        details={"first_frame": 1, "last_frame": 10},
        evidence_refs=[],
    )
    f_access = Finding(
        alert_type="brute_force",
        detector="rule",
        rule_name="repeated_short_connections",
        severity="high",
        confidence=0.8,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        dst_port=22,
        start_ts=150.0,
        end_ts=170.0,
        stage="Access Attempt",
        summary="Access alert",
        details={"first_frame": 15, "last_frame": 25},
        evidence_refs=[],
    )
    f_exfil = Finding(
        alert_type="abnormal_outbound",
        detector="rule",
        rule_name="outbound_volume",
        severity="critical",
        confidence=0.9,
        src_ip="192.168.1.10",
        dst_ip="203.0.113.5",
        dst_port=443,
        start_ts=200.0,
        end_ts=220.0,
        stage="Possible Exfiltration",
        summary="Exfil alert",
        details={"first_frame": 30, "last_frame": 50},
        evidence_refs=[],
    )

    # Input alerts unordered
    alerts = [f_exfil, f_recon, f_access]
    timeline = build_incident_timeline(alerts)

    assert len(timeline) == 3
    assert timeline[0]["stage"] == "Reconnaissance"
    assert timeline[1]["stage"] == "Access Attempt"
    assert timeline[2]["stage"] == "Possible Exfiltration"


def test_missing_stages_are_not_invented():
    f_recon = Finding(
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
        summary="Recon alert",
        details={"first_frame": 1, "last_frame": 10},
        evidence_refs=[],
    )
    timeline = build_incident_timeline([f_recon])

    assert len(timeline) == 1
    assert timeline[0]["stage"] == "Reconnaissance"
    stages_in_tl = [node["stage"] for node in timeline]
    assert "Access Attempt" not in stages_in_tl
    assert "Possible Exploitation" not in stages_in_tl
    assert "Possible Exfiltration" not in stages_in_tl
