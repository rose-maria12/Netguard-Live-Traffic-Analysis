import pytest
from netguard.detection.base import (
    SUGGESTED_PRECAUTIONS,
    SCENARIO_FLAGS,
    get_suggested_precautions,
)
from netguard.db import init_db, get_db
from netguard.web.app import create_app
from netguard.reports.json_report import export_run_json
from netguard.reports.html_report import generate_html_report


EXPECTED_MAPPINGS = {
    "Port scan": "Check whether this is an authorised scan. Inspect the targeted ports. If an untrusted source is probing your laptop, consider a temporary inbound block.",
    "Brute-force-like activity": "Check authentication logs for failed logins. Review successful logins from that source. Consider temporary blocking, MFA, and login rate limits.",
    "DNS anomaly": "Inspect the requested names and NXDOMAIN responses. Identify the application generating them. If unexplained, investigate the device and consider an endpoint security scan.",
    "Unusual outbound traffic": "Check for uploads, backups, or synchronisation. Identify the process and destination. If confirmed suspicious, consider restricting outbound access or isolating the device.",
    "ML anomaly": "Review the unusual features, inspect supporting packets, and check whether rule detectors also flagged the activity. Avoid blocking solely because of the ML score.",
}


def test_suggested_precautions_exact_text():
    """Verify each flag maps to the exact requested precautions string."""
    for flag, expected in EXPECTED_MAPPINGS.items():
        actual = get_suggested_precautions(flag)
        assert actual == expected, f"Mismatch for {flag}: got {actual!r}"


def test_detector_key_mappings():
    """Verify internal detector keys map properly."""
    assert get_suggested_precautions("port_scan") == EXPECTED_MAPPINGS["Port scan"]
    assert get_suggested_precautions("brute_force") == EXPECTED_MAPPINGS["Brute-force-like activity"]
    assert get_suggested_precautions("dns_anomaly") == EXPECTED_MAPPINGS["DNS anomaly"]
    assert get_suggested_precautions("abnormal_outbound") == EXPECTED_MAPPINGS["Unusual outbound traffic"]
    assert get_suggested_precautions("ml_anomaly") == EXPECTED_MAPPINGS["ML anomaly"]


def test_web_routes_render_precautions(tmp_path):
    """Verify all 5 detector web scenario pages render their respective precautions."""
    db_path = tmp_path / "web_test.db"
    init_db(db_path)
    app = create_app(db_path=db_path)
    client = app.test_client()

    routes_and_expectations = [
        ("/detection/port_scan", EXPECTED_MAPPINGS["Port scan"]),
        ("/detection/brute_force", EXPECTED_MAPPINGS["Brute-force-like activity"]),
        ("/detection/dns_anomaly", EXPECTED_MAPPINGS["DNS anomaly"]),
        ("/detection/outbound", EXPECTED_MAPPINGS["Unusual outbound traffic"]),
        ("/detection/ml", EXPECTED_MAPPINGS["ML anomaly"]),
    ]

    for route, expected_text in routes_and_expectations:
        resp = client.get(route)
        assert resp.status_code == 200
        html = resp.data.decode("utf-8")
        assert expected_text in html, f"Route {route} did not contain expected precautions"


def test_reports_include_precautions(tmp_path):
    """Verify JSON export and HTML report include suggested precautions."""
    db_path = tmp_path / "report_test.db"
    init_db(db_path)
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
        ) VALUES (1, 1, 'port_scan', 'rule', 'port_scan_vertical', 'medium', 0.9, '192.168.1.10', '10.0.0.5', 80, 1700000000.0, 1700000005.0, 'Reconnaissance', 'Port scan detected', '{"suggested_precautions": "Check whether this is an authorised scan. Inspect the targeted ports. If an untrusted source is probing your laptop, consider a temporary inbound block."}', 'ip.src == 192.168.1.10', 1, 10, 1, 'key1');
        """
    )
    conn.commit()
    conn.close()

    json_data = export_run_json(1, db_path=db_path)
    assert len(json_data["alerts"]) == 1
    assert json_data["alerts"][0]["suggested_precautions"] == EXPECTED_MAPPINGS["Port scan"]

    html_report = generate_html_report(1, db_path=db_path)
    assert EXPECTED_MAPPINGS["Port scan"] in html_report
