import pytest
from pathlib import Path
from netguard.config import load_config
from netguard.db import init_db, get_db
from netguard.pipeline import import_capture, run_analysis
from netguard.reports.html_report import generate_html_report
from netguard.reports.json_report import export_run_json
from netguard.web.app import create_app

DATA_DIR = Path(__file__).resolve().parent / "data"
PCAPS_DIR = DATA_DIR / "pcaps"


def test_full_end_to_end_pipeline(tmp_path):
    db_path = tmp_path / "e2e_netguard.db"
    init_db(db_path)
    config = load_config()

    multi_pcap = PCAPS_DIR / "multi_stage.pcap"
    assert multi_pcap.exists(), "multi_stage.pcap must exist for E2E test"

    # Step 1: Import PCAP into SQLite (Ingestion, flow building, DNS extraction)
    cap_dict = import_capture(multi_pcap, db_path=db_path, config=config)
    assert cap_dict["status"] == "ok"
    assert cap_dict["packets_stored"] > 0

    # Verify packets stored in DB
    conn = get_db(db_path)
    pkt_cnt = conn.execute("SELECT COUNT(*) FROM packets WHERE capture_id = ?;", (cap_dict["id"],)).fetchone()[0]
    assert pkt_cnt > 0

    flow_cnt = conn.execute("SELECT COUNT(*) FROM flows WHERE capture_id = ?;", (cap_dict["id"],)).fetchone()[0]
    assert flow_cnt > 0
    conn.close()

    # Step 2: Execute Analysis Pipeline (Feature extraction, 4 rule detectors, dedup, correlation, scoring, persistence)
    run_res = run_analysis(cap_dict["id"], db_path=db_path, config=config)
    assert run_res["status"] == "completed"
    assert run_res["alerts_count"] >= 3
    assert run_res["incidents_count"] >= 1

    # Verify DB persistence of alerts and incidents
    conn = get_db(db_path)
    alert_cnt = conn.execute("SELECT COUNT(*) FROM alerts WHERE run_id = ?;", (run_res["run_id"],)).fetchone()[0]
    assert alert_cnt == run_res["alerts_count"]

    inc_cnt = conn.execute("SELECT COUNT(*) FROM incidents WHERE run_id = ?;", (run_res["run_id"],)).fetchone()[0]
    assert inc_cnt == run_res["incidents_count"]

    ev_cnt = conn.execute("SELECT COUNT(*) FROM alert_evidence;").fetchone()[0]
    assert ev_cnt > 0
    conn.close()

    # Step 3: Verify Flask Web Dashboard access to results
    app = create_app(db_path=db_path, test_config={"TESTING": True})
    cli = app.test_client()

    dash_res = cli.get("/dashboard")
    assert dash_res.status_code == 200

    alerts_res = cli.get("/alerts")
    assert alerts_res.status_code == 200

    inc_res = cli.get("/incidents")
    assert inc_res.status_code == 200

    detail_res = cli.get(f"/incidents/{run_res['incidents'][0].id}")
    assert detail_res.status_code == 200
    assert b"Score Breakdown" in detail_res.data

    evidence_res = cli.get("/evidence")
    assert evidence_res.status_code == 200
    assert b"Wireshark Display Filter" in evidence_res.data

    # Step 4: HTML Report Export Generation
    html_report = generate_html_report(run_res["run_id"], db_path=db_path)
    assert "<!DOCTYPE html>" in html_report
    assert "NetGuard Forensic Incident Report" in html_report

    # Step 5: JSON Export Generation
    json_data = export_run_json(run_res["run_id"], db_path=db_path)
    assert json_data["run"]["id"] == run_res["run_id"]
    assert len(json_data["alerts"]) == run_res["alerts_count"]
