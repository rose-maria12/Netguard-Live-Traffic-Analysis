import json
import pytest
from netguard.db import init_db, get_db
from netguard.reports.html_report import generate_html_report
from netguard.reports.json_report import export_run_json


@pytest.fixture
def seeded_db(tmp_path):
    db_path = tmp_path / "test_report.db"
    init_db(db_path)

    conn = get_db(db_path)
    conn.execute(
        """
        INSERT INTO captures (
            filename, stored_path, sha256, size_bytes, file_format, link_type,
            frames_total, packets_stored, frames_skipped, imported_at,
            netguard_version, scapy_version, status
        ) VALUES ('report_cap.pcap', '/tmp/report_cap.pcap', 'sha256_report_123', 2048, 'pcap', 'Ethernet', 100, 100, 0, 1700000000.0, '1.0', '2.5.0', 'ok');
        """
    )
    cap_id = conn.execute("SELECT id FROM captures WHERE sha256='sha256_report_123';").fetchone()[0]

    conn.execute(
        """
        INSERT INTO runs (
            id, capture_id, config_json, config_sha256, seed, started_at, finished_at,
            status, python_version, sklearn_version, scapy_version, netguard_version
        ) VALUES (10, ?, '{}', 'cfg123', 42, 1700000000.0, 1700000005.0, 'completed', '3.14', '1.3', '2.5', '1.0');
        """,
        (cap_id,),
    )

    conn.execute(
        """
        INSERT INTO alerts (
            id, run_id, alert_type, detector, rule_name, severity, confidence,
            src_ip, dst_ip, dst_port, start_ts, end_ts, stage, summary,
            details_json, wireshark_filter, first_frame, last_frame, merged_count, dedup_key
        ) VALUES (100, 10, 'port_scan', 'rule', 'port_scan_vertical', 'medium', 0.9, '192.168.1.50', '10.0.0.1', 80, 1700000000.0, 1700000005.0, 'Reconnaissance', 'Scan alert', '{}', 'ip.src == 192.168.1.50', 1, 10, 1, 'k100');
        """
    )

    conn.execute(
        """
        INSERT INTO alert_evidence (alert_id, ref_type, ref_id, frame_no, note)
        VALUES (100, 'packet', 1, 1, 'Frame 1 evidence');
        """
    )

    conn.execute(
        """
        INSERT INTO incidents (
            id, run_id, primary_ip, involved_ips_json, start_ts, end_ts,
            stages_json, stage_count, is_multistage, rule_alert_count,
            ml_alert_count, score, level, score_breakdown_json, summary,
            status, created_at, updated_at
        ) VALUES (10, 10, '192.168.1.50', '["192.168.1.50"]', 1700000000.0, 1700000005.0, '["Reconnaissance"]', 1, 0, 1, 0, 35.0, 'medium', '{"strongest_alert_score": 35.0}', 'Inc summary', 'new', 1700000000.0, 1700000005.0);
        """
    )

    conn.commit()
    conn.close()
    return db_path


def test_html_report_generation(seeded_db):
    html = generate_html_report(10, db_path=seeded_db)
    assert "<!DOCTYPE html>" in html
    assert "NetGuard Forensic Incident Report" in html
    assert "sha256_report_123" in html
    assert "192.168.1.50" in html
    assert "Prioritization Metric Disclaimer" in html
    # Ensure offline integrity: no external http/https CDN links
    assert "http://" not in html.lower()
    assert "https://" not in html.lower()


def test_json_report_export(seeded_db):
    json_data = export_run_json(10, db_path=seeded_db)
    assert json_data["netguard_export_version"] in ("1.0", "1.1")
    assert json_data["run"]["id"] == 10
    assert json_data["capture"]["filename"] == "report_cap.pcap"
    assert len(json_data["alerts"]) == 1
    assert json_data["alerts"][0]["id"] == 100
    assert "wireshark_bi_filter" in json_data["alerts"][0]
    assert json_data["alerts"][0]["trigger_frames"] == [1]
    assert "feature_windows" in json_data
    assert "limitations" in json_data and len(json_data["limitations"]) >= 3
    assert len(json_data["incidents"]) == 1
    assert json_data["incidents"][0]["id"] == 10
