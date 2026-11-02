import pytest
from pathlib import Path
from netguard.pipeline import import_capture, run_analysis
from netguard.web.app import create_app
from netguard.db import init_db

def test_capture_run_isolation_regression(tmp_path):
    db_file = tmp_path / "test_iso.db"
    init_db(db_file)
    base = Path(__file__).resolve().parent / "data" / "pcaps"

    # Capture A: DNS Tunneling attack PCAP
    cap_a = import_capture(base / "dns_tunnel.pcap", db_path=db_file)
    run_a = run_analysis(cap_a["id"], db_path=db_file)

    # Capture B: Brute Force attack PCAP (No DNS attacks)
    cap_b = import_capture(base / "brute_force.pcap", db_path=db_file)
    run_b = run_analysis(cap_b["id"], db_path=db_file)

    app = create_app(db_path=db_file, test_config={"TESTING": True, "WTF_CSRF_ENABLED": False})
    with app.test_client() as client:
        # 1. Scoped to Capture B -> Must show 0 DNS findings
        res_b = client.get(f"/detection/dns_anomaly?capture_id={cap_b['id']}")
        assert res_b.status_code == 200
        assert b"dns_long_names" not in res_b.data

        # 2. Scoped to Capture A -> Must show the DNS attack alert
        res_a = client.get(f"/detection/dns_anomaly?capture_id={cap_a['id']}")
        assert res_a.status_code == 200
        assert b"dns_long_names" in res_a.data

        # 3. Alerts page scoped to Capture B
        res_b_alerts = client.get(f"/alerts?capture_id={cap_b['id']}")
        assert res_b_alerts.status_code == 200
        assert b"dns_long_names" not in res_b_alerts.data

        # 4. Alerts page scoped to Capture A
        res_a_alerts = client.get(f"/alerts?capture_id={cap_a['id']}")
        assert res_a_alerts.status_code == 200
        assert b"dns_long_names" in res_a_alerts.data

        # 5. Switching back to all captures
        res_all = client.get("/alerts?all=1")
        assert res_all.status_code == 200
        assert b"dns_long_names" in res_all.data

