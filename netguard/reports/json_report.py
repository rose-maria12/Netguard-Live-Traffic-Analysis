import json
from pathlib import Path
from typing import Any, Dict, List, Union
from netguard.db import DEFAULT_DB_PATH, get_db, init_db
from netguard.detection.base import get_suggested_precautions
from netguard.evidence.wireshark import (
    extract_trigger_frames,
    generate_bidirectional_wireshark_filter,
    generate_wireshark_filter,
)


def export_run_json(run_id: int, db_path: Union[str, Path] = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """
    Export complete run details, capture metadata, alerts, evidence references, and correlated incidents to JSON dictionary format.
    """
    init_db(db_path)
    conn = get_db(db_path)
    try:
        # Fetch run record
        cursor = conn.execute("SELECT * FROM runs WHERE id = ?;", (run_id,))
        run_row = cursor.fetchone()
        if not run_row:
            raise ValueError(f"Run ID {run_id} not found.")

        run_dict = dict(run_row)
        if isinstance(run_dict.get("config_json"), str):
            try:
                run_dict["config_json"] = json.loads(run_dict["config_json"])
            except Exception:
                pass
        if isinstance(run_dict.get("stats_json"), str):
            try:
                run_dict["stats_json"] = json.loads(run_dict["stats_json"])
            except Exception:
                pass

        # Fetch capture record
        cursor = conn.execute("SELECT * FROM captures WHERE id = ?;", (run_dict["capture_id"],))
        cap_row = cursor.fetchone()
        cap_dict = dict(cap_row) if cap_row else {}
        if cap_dict:
            cap_id = cap_dict["id"]
            cap_dict["flows_count"] = conn.execute("SELECT COUNT(*) FROM flows WHERE capture_id = ?;", (cap_id,)).fetchone()[0]
            cap_dict["dns_events_count"] = conn.execute("SELECT COUNT(*) FROM dns_events WHERE capture_id = ?;", (cap_id,)).fetchone()[0]

        # Fetch ML model record and scored feature windows for this run
        ml_model_dict = None
        if run_dict.get("model_id"):
            m_row = conn.execute("SELECT * FROM models WHERE id = ?;", (run_dict["model_id"],)).fetchone()
            if m_row:
                ml_model_dict = dict(m_row)
        if not ml_model_dict:
            m_row = conn.execute("SELECT * FROM models WHERE name = 'default_baseline' ORDER BY id DESC LIMIT 1;").fetchone()
            if m_row:
                ml_model_dict = dict(m_row)

        fw_rows = conn.execute(
            "SELECT * FROM feature_windows WHERE run_id = ? ORDER BY window_start ASC, host_ip ASC;",
            (run_id,),
        ).fetchall()
        feature_windows_list = [dict(r) for r in fw_rows]

        # Fetch alerts for this run
        cursor = conn.execute("SELECT * FROM alerts WHERE run_id = ? ORDER BY start_ts ASC, id ASC;", (run_id,))
        alert_rows = [dict(r) for r in cursor.fetchall()]

        alerts_list = []
        for a in alert_rows:
            if isinstance(a.get("details_json"), str):
                try:
                    a["details"] = json.loads(a["details_json"])
                except Exception:
                    a["details"] = {}
            else:
                a["details"] = a.get("details_json", {})

            # Fetch alert evidence
            cursor_ev = conn.execute(
                "SELECT ref_type, ref_id, frame_no, note FROM alert_evidence WHERE alert_id = ? ORDER BY id ASC;",
                (a["id"],),
            )
            a["evidence_refs"] = [dict(ev) for ev in cursor_ev.fetchall()]
            if not a.get("wireshark_filter"):
                a["wireshark_filter"] = generate_wireshark_filter(a)
            a["wireshark_bi_filter"] = a["details"].get("wireshark_bi_filter") or generate_bidirectional_wireshark_filter(a)
            a["trigger_frames"] = extract_trigger_frames(a)
            a["suggested_precautions"] = a["details"].get("suggested_precautions") or get_suggested_precautions(a.get("alert_type", ""))
            alerts_list.append(a)

        # Fetch incidents for this run
        cursor = conn.execute("SELECT * FROM incidents WHERE run_id = ? ORDER BY score DESC, id ASC;", (run_id,))
        inc_rows = [dict(r) for r in cursor.fetchall()]

        incidents_list = []
        for inc in inc_rows:
            if isinstance(inc.get("involved_ips_json"), str):
                try:
                    inc["involved_ips"] = json.loads(inc["involved_ips_json"])
                except Exception:
                    inc["involved_ips"] = []
            if isinstance(inc.get("stages_json"), str):
                try:
                    inc["stages"] = json.loads(inc["stages_json"])
                except Exception:
                    inc["stages"] = []
            if isinstance(inc.get("score_breakdown_json"), str):
                try:
                    inc["score_breakdown"] = json.loads(inc["score_breakdown_json"])
                except Exception:
                    inc["score_breakdown"] = {}

            # Fetch linked alert IDs
            cursor_ia = conn.execute(
                "SELECT alert_id, role, stage FROM incident_alerts WHERE incident_id = ?;",
                (inc["id"],),
            )
            inc["linked_alerts"] = [dict(r) for r in cursor_ia.fetchall()]
            incidents_list.append(inc)

        export_data = {
            "netguard_export_version": "1.1",
            "run": run_dict,
            "capture": cap_dict,
            "ml_model": ml_model_dict,
            "feature_windows": feature_windows_list,
            "alerts": alerts_list,
            "incidents": incidents_list,
            "disclaimer": "Prioritization scores (0-100 scale) are heuristic indicators, not probabilities or proof of compromise.",
            "limitations": [
                "Encrypted SSH/RDP payloads are not inspected; brute-force alerts indicate connection burst patterns only.",
                "Isolation Forest baseline is trained on 101 windows and calibrated at the 99th percentile on 49 windows from one CIC-IDS2017 Monday benign session (65 same-session held-out benign windows).",
                "A 99th-percentile calibration threshold cuts off the top 1% (1/49) of the calibration subset only; it does not guarantee a 1% false-positive rate on unseen traffic (observed held-out benign FPR was 3/65 = 4.62%) and does not mean 99% detection accuracy.",
                "Feature z-score deviations represent statistical shifts from the benign mean, not causal explanations of tree splits.",
            ],
        }
        return export_data

    finally:
        conn.close()
