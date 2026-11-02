import io
import pytest
from netguard.db import init_db, get_db
from netguard.web.app import create_app


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "test_web.db"
    init_db(db_path)

    # Seed DB with capture, run, alert, and incident
    conn = get_db(db_path)
    conn.execute(
        """
        INSERT INTO captures (
            filename, stored_path, sha256, size_bytes, file_format, link_type,
            frames_total, packets_stored, frames_skipped, imported_at,
            netguard_version, scapy_version, status
        ) VALUES ('sample.pcap', '/tmp/sample.pcap', 'abc123sha256', 1024, 'pcap', 'Ethernet', 50, 50, 0, 1700000000.0, '1.0', '2.5.0', 'ok');
        """
    )
    cap_id = conn.execute("SELECT id FROM captures WHERE sha256='abc123sha256';").fetchone()[0]

    conn.execute(
        """
        INSERT INTO runs (
            id, capture_id, config_json, config_sha256, seed, started_at, finished_at,
            status, python_version, sklearn_version, scapy_version, netguard_version
        ) VALUES (1, ?, '{}', 'cfg123', 42, 1700000000.0, 1700000005.0, 'completed', '3.14', '1.3', '2.5', '1.0');
        """,
        (cap_id,),
    )

    conn.execute(
        """
        INSERT INTO alerts (
            id, run_id, alert_type, detector, rule_name, severity, confidence,
            src_ip, dst_ip, dst_port, start_ts, end_ts, stage, summary,
            details_json, wireshark_filter, first_frame, last_frame, merged_count, dedup_key
        ) VALUES (1, 1, 'port_scan', 'rule', 'port_scan_vertical', 'medium', 0.9, '192.168.1.10', '10.0.0.5', 80, 1700000000.0, 1700000005.0, 'Reconnaissance', 'Port scan detected', '{}', 'ip.src == 192.168.1.10', 1, 10, 1, 'key1');
        """
    )

    conn.execute(
        """
        INSERT INTO alert_evidence (alert_id, ref_type, ref_id, frame_no, note)
        VALUES (1, 'packet', 1, 1, 'Frame 1 SYN packet');
        """
    )

    conn.execute(
        """
        INSERT INTO incidents (
            id, run_id, primary_ip, involved_ips_json, start_ts, end_ts,
            stages_json, stage_count, is_multistage, rule_alert_count,
            ml_alert_count, score, level, score_breakdown_json, summary,
            status, created_at, updated_at
        ) VALUES (1, 1, '192.168.1.10', '["192.168.1.10", "10.0.0.5"]', 1700000000.0, 1700000005.0, '["Reconnaissance"]', 1, 0, 1, 0, 35.0, 'medium', '{"strongest_alert_score": 35.0}', 'Incident summary', 'new', 1700000000.0, 1700000005.0);
        """
    )

    conn.execute(
        "INSERT INTO incident_alerts (incident_id, alert_id, role, stage) VALUES (1, 1, 'primary_attacker', 'Reconnaissance');"
    )

    conn.commit()
    conn.close()

    app = create_app(db_path=db_path, test_config={"TESTING": True})
    return app.test_client()


def test_app_starts_and_dashboard_loads(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert b"Executive Threat Dashboard" in response.data
    assert b"Total Alerts" in response.data


def test_upload_page_loads(client):
    response = client.get("/upload")
    assert response.status_code == 200
    # Template uses "Import Capture File" as the card title and "PCAP Analysis" in the heading
    assert b"Import Capture File" in response.data or b"PCAP Analysis" in response.data


def test_traffic_forensics_page_loads(client):
    response = client.get("/traffic_forensics")
    assert response.status_code == 200
    assert b"Traffic Forensics" in response.data or b"Forensics" in response.data


def test_detect_port_scan_page_loads(client):
    response = client.get("/detection/port_scan")
    assert response.status_code == 200
    assert b"Port Scan" in response.data
    assert b"port_scan" in response.data  # alert type from seeded data


def test_detect_brute_force_page_loads(client):
    response = client.get("/detection/brute_force")
    assert response.status_code == 200
    assert b"Brute Force" in response.data


def test_detect_dns_anomaly_page_loads(client):
    response = client.get("/detection/dns_anomaly")
    assert response.status_code == 200
    assert b"DNS" in response.data


def test_detect_outbound_page_loads(client):
    response = client.get("/detection/outbound")
    assert response.status_code == 200
    assert b"Outbound" in response.data


def test_detect_ml_page_loads(client):
    response = client.get("/detection/ml")
    assert response.status_code == 200
    assert b"Isolation Forest" in response.data


def test_evaluation_page_loads(client):
    response = client.get("/evaluation")
    assert response.status_code == 200
    assert b"Evaluation" in response.data


def test_api_stats_returns_json(client):
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.get_json()
    assert "captures" in data
    assert "alerts" in data
    assert "incidents" in data


def test_api_run_status(client):
    response = client.get("/api/run/1")
    assert response.status_code == 200
    data = response.get_json()
    assert data["id"] == 1
    assert "alerts_count" in data


def test_invalid_upload_rejected(client):
    # Upload an invalid text file
    data = {"file": (io.BytesIO(b"Not a pcap file content"), "invalid.txt")}
    response = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert response.status_code == 200
    assert b"Failed to process capture file" in response.data or b"Invalid magic bytes" in response.data


def test_alerts_page_displays_alerts(client):
    response = client.get("/alerts")
    assert response.status_code == 200
    assert b"port_scan" in response.data
    assert b"192.168.1.10" in response.data


def test_incidents_page_displays_incidents(client):
    response = client.get("/incidents")
    assert response.status_code == 200
    assert b"192.168.1.10" in response.data
    assert b"35.0" in response.data


def test_incident_detail_loads(client):
    response = client.get("/incidents/1")
    assert response.status_code == 200
    assert b"Incident #1 Detail" in response.data
    assert b"Reconnaissance" in response.data
    assert b"Score Breakdown" in response.data


def test_evidence_page_loads(client):
    response = client.get("/evidence")
    assert response.status_code == 200
    assert b"Wireshark Display Filter" in response.data
    assert b"Frame 1 SYN packet" in response.data


def test_reports_routes(client):
    res_html = client.get("/reports/html/1")
    assert res_html.status_code == 200
    assert b"NetGuard Forensic Incident Report" in res_html.data

    res_json = client.get("/reports/json/1")
    assert res_json.status_code == 200
    json_data = res_json.get_json()
    assert json_data["run"]["id"] == 1


def test_empty_database_safety(tmp_path):
    empty_db = tmp_path / "empty.db"
    init_db(empty_db)
    app = create_app(db_path=empty_db, test_config={"TESTING": True})
    test_cli = app.test_client()

    assert test_cli.get("/dashboard").status_code == 200
    assert test_cli.get("/upload").status_code == 200
    assert test_cli.get("/alerts").status_code == 200
    assert test_cli.get("/incidents").status_code == 200
    assert test_cli.get("/evidence").status_code == 200
