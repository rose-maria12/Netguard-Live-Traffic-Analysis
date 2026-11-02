import pytest
from netguard.config import load_config
from netguard.detection.base import Finding
from netguard.correlation.dedup import build_dedup_key, deduplicate_findings


def make_test_finding(
    alert_type: str = "port_scan",
    rule_name: str = "port_scan_threshold",
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    dst_port: int = 80,
    start_ts: float = 100.0,
    end_ts: float = 120.0,
    severity: str = "medium",
    confidence: float = 0.9,
    stage: str = "Reconnaissance",
    first_frame: int = 1,
    last_frame: int = 10,
    evidence_count: int = 2,
) -> Finding:
    evidence = [
        {"ref_type": "packet", "ref_id": i, "frame_no": first_frame + i, "note": f"Frame {first_frame + i}"}
        for i in range(evidence_count)
    ]
    return Finding(
        alert_type=alert_type,
        detector="rule",
        rule_name=rule_name,
        severity=severity,
        confidence=confidence,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        start_ts=start_ts,
        end_ts=end_ts,
        stage=stage,
        summary=f"{alert_type} finding from {src_ip} to {dst_ip}",
        details={"first_frame": first_frame, "last_frame": last_frame},
        evidence_refs=evidence,
    )


def test_duplicate_alerts_merge():
    config = load_config()
    f1 = make_test_finding(start_ts=100.0, end_ts=120.0, severity="medium", first_frame=1, last_frame=10)
    f2 = make_test_finding(start_ts=120.0, end_ts=140.0, severity="high", first_frame=11, last_frame=20)

    deduped = deduplicate_findings([f1, f2], config=config)

    assert len(deduped) == 1
    merged = deduped[0]
    assert merged.details["merged_count"] == 2
    assert merged.start_ts == 100.0
    assert merged.end_ts == 140.0
    assert merged.severity == "high"  # Picked higher severity
    assert merged.details["first_frame"] == 1
    assert merged.details["last_frame"] == 20
    assert len(merged.evidence_refs) == 4
    assert merged.details["wireshark_filter"] == "ip.src == 192.168.1.10 && ip.dst == 10.0.0.1 && (tcp.dstport == 80 || udp.dstport == 80)"


def test_different_targets_remain_separate():
    config = load_config()
    f1 = make_test_finding(dst_ip="10.0.0.1")
    f2 = make_test_finding(dst_ip="10.0.0.2")

    deduped = deduplicate_findings([f1, f2], config=config)

    assert len(deduped) == 2
    dst_ips = [f.dst_ip for f in deduped]
    assert "10.0.0.1" in dst_ips
    assert "10.0.0.2" in dst_ips


def test_different_alert_types_remain_separate():
    config = load_config()
    f1 = make_test_finding(alert_type="port_scan", rule_name="port_scan_threshold")
    f2 = make_test_finding(alert_type="brute_force", rule_name="brute_force_threshold", stage="Access Attempt")

    deduped = deduplicate_findings([f1, f2], config=config)

    assert len(deduped) == 2
    alert_types = [f.alert_type for f in deduped]
    assert "port_scan" in alert_types
    assert "brute_force" in alert_types


def test_evidence_is_preserved():
    config = load_config()
    f1 = make_test_finding(first_frame=1, evidence_count=3)
    f2 = make_test_finding(first_frame=10, evidence_count=3)

    deduped = deduplicate_findings([f1, f2], config=config)

    assert len(deduped) == 1
    merged = deduped[0]
    assert len(merged.evidence_refs) == 6
    # Frame numbers preserved in order
    frame_nos = [e["frame_no"] for e in merged.evidence_refs]
    assert frame_nos == sorted(frame_nos)


def test_dedup_determinism():
    config = load_config()
    f1 = make_test_finding(start_ts=100.0, dst_ip="10.0.0.1")
    f2 = make_test_finding(start_ts=100.0, dst_ip="10.0.0.1")
    f3 = make_test_finding(start_ts=200.0, dst_ip="10.0.0.2")

    res1 = deduplicate_findings([f1, f2, f3], config=config)
    res2 = deduplicate_findings([f1, f2, f3], config=config)

    assert len(res1) == 2
    assert len(res2) == 2
    assert res1 == res2
