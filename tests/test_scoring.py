import json
import pytest
from netguard.config import load_config
from netguard.db import init_db, get_db
from netguard.detection.base import Finding
from netguard.scoring.scorer import (
    score_incident,
    calculate_strongest_alert_score,
    calculate_stage_diversity_score,
    calculate_logical_order_score,
    calculate_corroboration_score,
    map_score_to_severity_level,
)
from netguard.correlation.engine import correlate_alerts, save_alerts_to_db, save_incidents_to_db


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


def test_exact_score_components():
    config = load_config()
    # High severity (26.25) + 2 stages (15.0) + ordered (15.0) + ML (10.0) = 66.25
    f1 = make_test_finding(src_ip="192.168.1.10", stage="Reconnaissance", severity="high", start_ts=100.0)
    f2 = make_test_finding(src_ip="192.168.1.10", stage="Access Attempt", detector="iforest", alert_type="ml_anomaly", severity="medium", start_ts=200.0)

    total_score, level, breakdown = score_incident([f1, f2], config=config)

    assert breakdown["strongest_alert_score"] == 26.25  # High = 0.75 * 35
    assert breakdown["stage_diversity_score"] == 15.0   # 2 stages = 0.5 * 30
    assert breakdown["logical_order_score"] == 15.0     # Chronological Recon -> Access = 15.0
    assert breakdown["corroboration_score"] == 10.0     # ML only = 10.0
    assert total_score == 66.25
    assert level == "high"


def test_minimum_score():
    config = load_config()
    # 1 alert, low severity, 1 stage, no ML, no outbound
    f1 = make_test_finding(severity="low", stage="Reconnaissance", detector="rule", alert_type="port_scan")

    total_score, level, breakdown = score_incident([f1], config=config)

    assert breakdown["strongest_alert_score"] == 8.75   # Low = 0.25 * 35
    assert breakdown["stage_diversity_score"] == 7.5    # 1 stage = 0.25 * 30
    assert breakdown["logical_order_score"] == 0.0      # Single stage = 0.0
    assert breakdown["corroboration_score"] == 0.0      # No ML / outbound = 0.0
    assert total_score == 16.25
    assert level == "low"


def test_maximum_100_score():
    config = load_config()
    # Critical alert (35) + 4 stages (30) + Ordered (15) + ML & Outbound (20) = 100
    f1 = make_test_finding(stage="Reconnaissance", severity="critical", start_ts=100.0)
    f2 = make_test_finding(stage="Access Attempt", alert_type="brute_force", start_ts=200.0)
    f3 = make_test_finding(stage="Possible Exploitation", detector="iforest", alert_type="ml_anomaly", start_ts=300.0)
    f4 = make_test_finding(stage="Possible Exfiltration", alert_type="abnormal_outbound", start_ts=400.0)

    total_score, level, breakdown = score_incident([f1, f2, f3, f4], config=config)

    assert breakdown["strongest_alert_score"] == 35.0
    assert breakdown["stage_diversity_score"] == 30.0
    assert breakdown["logical_order_score"] == 15.0
    assert breakdown["corroboration_score"] == 20.0
    assert total_score == 100.0
    assert level == "critical"


def test_stage_diversity_behavior():
    stages_1 = ["Reconnaissance"]
    stages_2 = ["Reconnaissance", "Access Attempt"]
    stages_3 = ["Reconnaissance", "Access Attempt", "Possible Exploitation"]
    stages_4 = ["Reconnaissance", "Access Attempt", "Possible Exploitation", "Possible Exfiltration"]

    assert calculate_stage_diversity_score(stages_1, 30.0) == 7.5
    assert calculate_stage_diversity_score(stages_2, 30.0) == 15.0
    assert calculate_stage_diversity_score(stages_3, 30.0) == 22.5
    assert calculate_stage_diversity_score(stages_4, 30.0) == 30.0


def test_logical_ordering_behavior():
    # Single stage: 0.0
    f1 = make_test_finding(stage="Reconnaissance", start_ts=100.0)
    assert calculate_logical_order_score([f1], 15.0) == 0.0

    # Ordered: Recon at 100 -> Access at 200 -> 15.0
    f2 = make_test_finding(stage="Access Attempt", start_ts=200.0, alert_type="brute_force")
    assert calculate_logical_order_score([f1, f2], 15.0) == 15.0

    # Inverted: Access at 100 -> Recon at 200 -> 7.5 (partial)
    f1_inv = make_test_finding(stage="Access Attempt", start_ts=100.0, alert_type="brute_force")
    f2_inv = make_test_finding(stage="Reconnaissance", start_ts=200.0)
    assert calculate_logical_order_score([f1_inv, f2_inv], 15.0) == 7.5


def test_ml_corroboration():
    # Rule alert only -> 0 ML corroboration
    f1 = make_test_finding(detector="rule", alert_type="port_scan")
    assert calculate_corroboration_score([f1], 20.0) == 0.0

    # ML alert present -> 10.0 pts ML corroboration
    f2 = make_test_finding(detector="iforest", alert_type="ml_anomaly")
    assert calculate_corroboration_score([f2], 20.0) == 10.0


def test_abnormal_outbound_corroboration():
    # Rule alert only (port_scan) -> 0 outbound corroboration
    f1 = make_test_finding(alert_type="port_scan", stage="Reconnaissance")
    assert calculate_corroboration_score([f1], 20.0) == 0.0

    # Outbound alert present -> 10.0 pts outbound corroboration
    f2 = make_test_finding(alert_type="abnormal_outbound", stage="Possible Exfiltration")
    assert calculate_corroboration_score([f2], 20.0) == 10.0


def test_severity_band_mapping():
    config = load_config()

    assert map_score_to_severity_level(85.0, config=config) == "critical"
    assert map_score_to_severity_level(60.0, config=config) == "high"
    assert map_score_to_severity_level(30.0, config=config) == "medium"
    assert map_score_to_severity_level(15.0, config=config) == "low"


def test_deterministic_scoring():
    config = load_config()
    f1 = make_test_finding(stage="Reconnaissance", severity="medium", start_ts=100.0)
    f2 = make_test_finding(stage="Access Attempt", alert_type="brute_force", severity="high", start_ts=150.0)

    score1, level1, b1 = score_incident([f1, f2], config=config)
    score2, level2, b2 = score_incident([f1, f2], config=config)

    assert score1 == score2
    assert level1 == level2
    assert b1 == b2


def test_persistence_reload_of_score(tmp_path):
    config = load_config()
    db_path = tmp_path / "test_score_db.db"

    # Seed DB with capture and run
    init_db(db_path)
    conn = get_db(db_path)
    conn.execute(
        "INSERT INTO captures (filename, stored_path, sha256, size_bytes, file_format, link_type, imported_at, netguard_version, scapy_version) VALUES ('test', 'test', 'hash_sc_123', 100, 'pcap', 'Ethernet', 0.0, '1.0', '1.0');"
    )
    cap_id = conn.execute("SELECT id FROM captures WHERE sha256='hash_sc_123';").fetchone()[0]
    conn.execute(
        "INSERT INTO runs (id, capture_id, config_json, config_sha256, seed, started_at, python_version, sklearn_version, scapy_version, netguard_version) VALUES (1, ?, '{}', 'cfg123', 42, 0.0, '3.14', '1.0', '1.0', '1.0');",
        (cap_id,)
    )
    conn.commit()
    conn.close()

    f1 = make_test_finding(src_ip="192.168.1.10", stage="Reconnaissance", severity="high", start_ts=100.0)
    f2 = make_test_finding(src_ip="192.168.1.10", stage="Access Attempt", alert_type="brute_force", severity="critical", start_ts=150.0)

    incidents = correlate_alerts([f1, f2], config=config)
    save_alerts_to_db(incidents[0].alerts, run_id=1, db_path=db_path)
    save_incidents_to_db(incidents, run_id=1, db_path=db_path)

    # Query DB and verify score, level, and score_breakdown_json persistence
    conn = get_db(db_path)
    row = conn.execute("SELECT * FROM incidents WHERE run_id=1;").fetchone()
    assert row is not None
    assert row["score"] == incidents[0].score
    assert row["level"] == incidents[0].level

    breakdown = json.loads(row["score_breakdown_json"])
    assert "strongest_alert_score" in breakdown
    assert "stage_diversity_score" in breakdown
    assert "logical_order_score" in breakdown
    assert "corroboration_score" in breakdown
    assert "disclaimer" in breakdown
    conn.close()


def test_heuristic_wording_disclaimer():
    config = load_config()
    f1 = make_test_finding()
    _, _, breakdown = score_incident([f1], config=config)

    disclaimer = breakdown.get("disclaimer", "")
    assert "heuristic" in disclaimer.lower()
    assert "not a probability" in disclaimer.lower()
