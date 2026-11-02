import pytest
from netguard.config import load_config
from netguard.detection.base import Finding
from netguard.correlation.engine import correlate_alerts, Incident, save_alerts_to_db, save_incidents_to_db


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
    detector: str = "rule",
    first_frame: int = 1,
    last_frame: int = 10,
) -> Finding:
    return Finding(
        alert_type=alert_type,
        detector=detector,
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
        evidence_refs=[
            {"ref_type": "packet", "ref_id": 1, "frame_no": first_frame, "note": f"Frame {first_frame}"}
        ],
    )


def test_same_source_correlation():
    config = load_config()
    # Alert 1: Reconnaissance at ts=100.0
    f1 = make_test_finding(src_ip="192.168.1.10", dst_ip="10.0.0.1", start_ts=100.0, end_ts=120.0, stage="Reconnaissance")
    # Alert 2: Access Attempt at ts=200.0 (within default 600s gap)
    f2 = make_test_finding(src_ip="192.168.1.10", dst_ip="10.0.0.2", start_ts=200.0, end_ts=220.0, stage="Access Attempt", alert_type="brute_force")

    incidents = correlate_alerts([f1, f2], config=config)

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.primary_ip == "192.168.1.10"
    assert len(inc.alerts) == 2
    assert inc.is_multistage is True
    assert inc.stage_count == 2
    assert "Reconnaissance" in inc.stages
    assert "Access Attempt" in inc.stages


def test_time_gap_boundary():
    config = load_config()
    # same_actor_gap_seconds is default 600s
    f1 = make_test_finding(src_ip="192.168.1.10", alert_type="port_scan", start_ts=100.0, end_ts=120.0)
    # f2 is at 1000.0 (gap = 1000 - 120 = 880s > 600s gap)
    f2 = make_test_finding(src_ip="192.168.1.10", alert_type="brute_force", start_ts=1000.0, end_ts=1020.0)

    incidents = correlate_alerts([f1, f2], config=config)

    assert len(incidents) == 2


def test_victim_to_source_pivot():
    config = load_config()
    # Alert 1: 192.168.1.10 attacks 10.0.0.5 (victim) at ts=100.0
    f1 = make_test_finding(src_ip="192.168.1.10", dst_ip="10.0.0.5", start_ts=100.0, end_ts=120.0, stage="Possible Exploitation")
    # Alert 2: 10.0.0.5 (now attacker) attacks 10.0.0.20 at ts=300.0 (within 900s pivot gap)
    f2 = make_test_finding(src_ip="10.0.0.5", dst_ip="10.0.0.20", start_ts=300.0, end_ts=320.0, stage="Possible Exfiltration", alert_type="abnormal_outbound")

    incidents = correlate_alerts([f1, f2], config=config)

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.primary_ip == "192.168.1.10"
    assert "10.0.0.5" in inc.involved_ips
    assert "10.0.0.20" in inc.involved_ips
    assert len(inc.alerts) == 2


def test_different_unrelated_sources():
    config = load_config()
    f1 = make_test_finding(src_ip="192.168.1.10", dst_ip="10.0.0.1")
    f2 = make_test_finding(src_ip="192.168.1.50", dst_ip="10.0.0.99")

    incidents = correlate_alerts([f1, f2], config=config)

    assert len(incidents) == 2
    primary_ips = [inc.primary_ip for inc in incidents]
    assert "192.168.1.10" in primary_ips
    assert "192.168.1.50" in primary_ips


def test_multi_stage_incident():
    config = load_config()
    f1 = make_test_finding(src_ip="192.168.1.10", stage="Reconnaissance", start_ts=100.0)
    f2 = make_test_finding(src_ip="192.168.1.10", stage="Access Attempt", start_ts=150.0, alert_type="brute_force")
    f3 = make_test_finding(src_ip="192.168.1.10", stage="Possible Exfiltration", start_ts=200.0, alert_type="abnormal_outbound")

    incidents = correlate_alerts([f1, f2, f3], config=config)

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.is_multistage is True
    assert inc.stage_count == 3
    assert inc.stages == ["Reconnaissance", "Access Attempt", "Possible Exfiltration"]


def test_incident_alert_links():
    config = load_config()
    f1 = make_test_finding(src_ip="192.168.1.10", alert_type="port_scan")
    f2 = make_test_finding(src_ip="192.168.1.10", alert_type="brute_force")

    incidents = correlate_alerts([f1, f2], config=config)

    assert len(incidents) == 1
    inc = incidents[0]
    assert len(inc.alerts) == 2
    alert_types = [a.alert_type for a in inc.alerts]
    assert "port_scan" in alert_types
    assert "brute_force" in alert_types


def test_evidence_preservation():
    config = load_config()
    f1 = make_test_finding(src_ip="192.168.1.10")

    incidents = correlate_alerts([f1], config=config)

    assert len(incidents) == 1
    inc = incidents[0]
    alert = inc.alerts[0]
    assert len(alert.evidence_refs) == 1
    assert alert.evidence_refs[0]["ref_type"] == "packet"


def test_deterministic_correlation_results():
    config = load_config()
    f1 = make_test_finding(src_ip="192.168.1.10", alert_type="port_scan", start_ts=100.0)
    f2 = make_test_finding(src_ip="192.168.1.10", alert_type="brute_force", start_ts=150.0)
    f3 = make_test_finding(src_ip="192.168.1.50", start_ts=200.0)

    res1 = correlate_alerts([f1, f2, f3], config=config)
    res2 = correlate_alerts([f1, f2, f3], config=config)

    assert len(res1) == 2
    assert len(res2) == 2
    assert res1 == res2


def test_db_persistence_incidents(tmp_path):
    from netguard.db import init_db, get_db
    config = load_config()
    db_path = tmp_path / "test_corr.db"

    # Seed DB with capture and run record to satisfy foreign key constraints
    init_db(db_path)
    conn = get_db(db_path)
    conn.execute(
        "INSERT INTO captures (filename, stored_path, sha256, size_bytes, file_format, link_type, imported_at, netguard_version, scapy_version) VALUES ('test', 'test', 'hash123', 100, 'pcap', 'Ethernet', 0.0, '1.0', '1.0');"
    )
    cap_id = conn.execute("SELECT id FROM captures WHERE sha256='hash123';").fetchone()[0]
    conn.execute(
        "INSERT INTO runs (id, capture_id, config_json, config_sha256, seed, started_at, python_version, sklearn_version, scapy_version, netguard_version) VALUES (1, ?, '{}', 'cfg123', 42, 0.0, '3.14', '1.0', '1.0', '1.0');",
        (cap_id,)
    )
    conn.commit()
    conn.close()

    f1 = make_test_finding(src_ip="192.168.1.10", start_ts=100.0, stage="Reconnaissance")
    f2 = make_test_finding(src_ip="192.168.1.10", start_ts=150.0, stage="Access Attempt", alert_type="brute_force")

    incidents = correlate_alerts([f1, f2], config=config)
    # Save alerts first
    alert_ids = save_alerts_to_db(incidents[0].alerts, run_id=1, db_path=db_path)
    assert len(alert_ids) == 2

    # Save incident
    inc_ids = save_incidents_to_db(incidents, run_id=1, db_path=db_path)
    assert len(inc_ids) == 1
    assert inc_ids[0] > 0
