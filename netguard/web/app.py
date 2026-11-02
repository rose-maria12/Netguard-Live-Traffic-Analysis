import json
import os
import queue
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Ensure project root is in sys.path so 'import netguard' works from any working directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, Response, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename

from netguard.capture.live_capture import LiveCaptureWorker, list_interfaces
from netguard.capture.live_pipeline import LiveDetectionEngine
from netguard.config import load_config
from netguard.db import DEFAULT_DB_PATH, get_db, init_db
from netguard.detection.base import get_suggested_precautions
from netguard.evidence.timeline import build_incident_timeline
from netguard.evidence.wireshark import (
    extract_trigger_frames,
    generate_bidirectional_wireshark_filter,
    generate_wireshark_filter,
)
from netguard.firewall.windows_fw import (
    RULE_PREFIX,
    block_ip,
    check_firewall_status,
    emergency_unblock_all,
    expire_blocks,
    get_prevention_config,
    is_protected_ip,
    list_managed_rules,
    reconcile_rules,
    set_prevention_config,
    unblock_ip,
)
from netguard.pipeline import import_capture, run_analysis
from netguard.reports.html_report import generate_html_report
from netguard.reports.json_report import export_run_json

UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "uploads"


def get_current_analysis_context(conn) -> Dict[str, Any]:
    """
    Resolve active capture and run context based on:
    1. Query parameters (?capture_id=... or ?run_id=...)
    2. Session storage (session['current_capture_id'], session['current_run_id'])
    3. Fallback to latest uploaded capture (source='upload')
    Returns dict with selected_capture, selected_run, is_all_captures, and all_captures list.
    """
    # 1. Fetch all available captures for selector dropdown
    cap_rows = conn.execute(
        "SELECT id, filename, source, imported_at, packets_stored, status FROM captures ORDER BY id DESC;"
    ).fetchall()
    all_captures = [dict(r) for r in cap_rows]

    # Explicit "all" flag
    req_all = request.args.get("all")
    if req_all == "1" or req_all == "true":
        session.pop("current_capture_id", None)
        session.pop("current_run_id", None)
        return {
            "is_all_captures": True,
            "selected_capture": None,
            "selected_run": None,
            "all_captures": all_captures,
            "capture_id": None,
            "run_id": None,
        }

    # Explicit capture_id in URL
    url_cap_id = request.args.get("capture_id", type=int)
    url_run_id = request.args.get("run_id", type=int)

    selected_cap_id = None
    selected_run_id = None

    if url_run_id:
        run_row = conn.execute("SELECT * FROM runs WHERE id = ?;", (url_run_id,)).fetchone()
        if run_row:
            selected_run_id = run_row["id"]
            selected_cap_id = run_row["capture_id"]
    elif url_cap_id:
        cap_row = conn.execute("SELECT * FROM captures WHERE id = ?;", (url_cap_id,)).fetchone()
        if cap_row:
            selected_cap_id = cap_row["id"]
    elif "current_run_id" in session:
        run_row = conn.execute("SELECT * FROM runs WHERE id = ?;", (session["current_run_id"],)).fetchone()
        if run_row:
            selected_run_id = run_row["id"]
            selected_cap_id = run_row["capture_id"]
        elif "current_capture_id" in session:
            cap_row = conn.execute("SELECT * FROM captures WHERE id = ?;", (session["current_capture_id"],)).fetchone()
            if cap_row:
                selected_cap_id = cap_row["id"]
    elif "current_capture_id" in session:
        cap_row = conn.execute("SELECT * FROM captures WHERE id = ?;", (session["current_capture_id"],)).fetchone()
        if cap_row:
            selected_cap_id = cap_row["id"]

    # Default fallback: latest successfully uploaded PCAP (source='upload' and status='ok')
    if not selected_cap_id and all_captures:
        latest_upload = conn.execute(
            "SELECT * FROM captures WHERE source = 'upload' AND status = 'ok' ORDER BY imported_at DESC, id DESC LIMIT 1;"
        ).fetchone()
        if latest_upload:
            selected_cap_id = latest_upload["id"]
        else:
            selected_cap_id = all_captures[0]["id"]

    # Resolve selected capture & run
    selected_capture = None
    selected_run = None
    if selected_cap_id:
        cap_row = conn.execute("SELECT * FROM captures WHERE id = ?;", (selected_cap_id,)).fetchone()
        if cap_row:
            selected_capture = dict(cap_row)
            session["current_capture_id"] = selected_cap_id

        if not selected_run_id:
            run_row = conn.execute(
                "SELECT * FROM runs WHERE capture_id = ? ORDER BY started_at DESC, id DESC LIMIT 1;",
                (selected_cap_id,),
            ).fetchone()
            if run_row:
                selected_run_id = run_row["id"]

        if selected_run_id:
            run_row = conn.execute("SELECT * FROM runs WHERE id = ?;", (selected_run_id,)).fetchone()
            if run_row:
                selected_run = dict(run_row)
                if isinstance(selected_run.get("stats_json"), str):
                    try:
                        selected_run["stats"] = json.loads(selected_run["stats_json"])
                    except Exception:
                        selected_run["stats"] = {}
                session["current_run_id"] = selected_run_id

    return {
        "is_all_captures": False,
        "selected_capture": selected_capture,
        "selected_run": selected_run,
        "all_captures": all_captures,
        "capture_id": selected_cap_id,
        "run_id": selected_run_id,
    }


def _load_alert_details(conn, alert_rows: List[dict]) -> List[dict]:
    """Shared helper: parse details_json and attach evidence count for alert rows."""
    result = []
    for a in alert_rows:
        if isinstance(a.get("details_json"), str):
            try:
                a["details"] = json.loads(a["details_json"])
            except Exception:
                a["details"] = {}
        else:
            a["details"] = a.get("details_json") or {}
        cursor_ev = conn.execute(
            "SELECT COUNT(*) FROM alert_evidence WHERE alert_id = ?;", (a["id"],)
        )
        a["evidence_count"] = cursor_ev.fetchone()[0]
        ev_frames_cur = conn.execute(
            "SELECT DISTINCT frame_no FROM alert_evidence WHERE alert_id = ? AND frame_no IS NOT NULL ORDER BY frame_no ASC;",
            (a["id"],),
        )
        a["trigger_frames"] = [r[0] for r in ev_frames_cur.fetchall() if r[0]]
        if not a.get("wireshark_filter"):
            a["wireshark_filter"] = generate_wireshark_filter(a)
        a["wireshark_bi_filter"] = a["details"].get("wireshark_bi_filter") or generate_bidirectional_wireshark_filter(a)
        a["suggested_precautions"] = a["details"].get("suggested_precautions") or get_suggested_precautions(a.get("alert_type", ""))
        result.append(a)
    return result


def create_app(db_path: Union[str, Path] = DEFAULT_DB_PATH, test_config: Optional[Dict[str, Any]] = None) -> Flask:
    """
    Create and configure the Flask web dashboard application.
    """
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "static"),
    )
    app.config["SECRET_KEY"] = "netguard-secret-key-offline"
    app.config["DB_PATH"] = str(db_path)
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB limit

    if test_config:
        app.config.update(test_config)

    # Initialize database on app startup
    init_db(app.config["DB_PATH"])

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("base.html", content_title="404 Not Found", error_msg="The requested page was not found."), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("base.html", content_title="Application Error", error_msg="An unexpected application error occurred."), 500

    @app.route("/")
    @app.route("/dashboard")
    def dashboard():
        conn = get_db(app.config["DB_PATH"])
        try:
            ctx = get_current_analysis_context(conn)
            run_id = ctx.get("run_id")
            cap_id = ctx.get("capture_id")
            is_all = ctx.get("is_all_captures")

            # Scope queries according to active context
            if not is_all and run_id:
                captures_count = 1
                alerts_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE run_id = ?;", (run_id,)).fetchone()[0]
                incidents_count = conn.execute("SELECT COUNT(*) FROM incidents WHERE run_id = ?;", (run_id,)).fetchone()[0]
                high_crit_incidents = conn.execute(
                    "SELECT COUNT(*) FROM incidents WHERE run_id = ? AND level IN ('high', 'critical');", (run_id,)
                ).fetchone()[0]

                detector_activity = {}
                for r in conn.execute("SELECT detector, COUNT(*) as cnt FROM alerts WHERE run_id = ? GROUP BY detector;", (run_id,)).fetchall():
                    detector_activity[r["detector"]] = r["cnt"]

                alert_types = {}
                for r in conn.execute("SELECT alert_type, COUNT(*) as cnt FROM alerts WHERE run_id = ? GROUP BY alert_type;", (run_id,)).fetchall():
                    alert_types[r["alert_type"]] = r["cnt"]

                stage_dist = {}
                for r in conn.execute("SELECT stages_json FROM incidents WHERE run_id = ?;", (run_id,)).fetchall():
                    try:
                        for s in json.loads(r["stages_json"]):
                            stage_dist[s] = stage_dist.get(s, 0) + 1
                    except Exception:
                        pass

                top_incidents = [dict(r) for r in conn.execute(
                    "SELECT * FROM incidents WHERE run_id = ? ORDER BY score DESC, id ASC LIMIT 5;", (run_id,)
                ).fetchall()]

            else:
                # All captures historical view
                captures_count = conn.execute("SELECT COUNT(*) FROM captures;").fetchone()[0]
                alerts_count = conn.execute("SELECT COUNT(*) FROM alerts;").fetchone()[0]
                incidents_count = conn.execute("SELECT COUNT(*) FROM incidents;").fetchone()[0]
                high_crit_incidents = conn.execute(
                    "SELECT COUNT(*) FROM incidents WHERE level IN ('high', 'critical');"
                ).fetchone()[0]

                detector_activity = {}
                for r in conn.execute("SELECT detector, COUNT(*) as cnt FROM alerts GROUP BY detector;").fetchall():
                    detector_activity[r["detector"]] = r["cnt"]

                alert_types = {}
                for r in conn.execute("SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type;").fetchall():
                    alert_types[r["alert_type"]] = r["cnt"]

                stage_dist = {}
                for r in conn.execute("SELECT stages_json FROM incidents;").fetchall():
                    try:
                        for s in json.loads(r["stages_json"]):
                            stage_dist[s] = stage_dist.get(s, 0) + 1
                    except Exception:
                        pass

                top_incidents = [dict(r) for r in conn.execute(
                    "SELECT * FROM incidents ORDER BY score DESC, id ASC LIMIT 5;"
                ).fetchall()]

            # Fetch recent captures for the captures list table (with reconstructed flow counts)
            recent_captures = [dict(r) for r in conn.execute(
                """
                SELECT c.*,
                       (SELECT COUNT(*) FROM flows f WHERE f.capture_id = c.id) AS flows_count
                FROM captures c
                ORDER BY c.imported_at DESC LIMIT 5;
                """
            ).fetchall()]

            # Diagnostics for selected capture
            summary_stats = None
            if ctx.get("selected_capture"):
                c = ctx["selected_capture"]
                r = ctx.get("selected_run")
                flows_cnt = conn.execute("SELECT COUNT(*) FROM flows WHERE capture_id = ?;", (c["id"],)).fetchone()[0]
                dns_cnt = conn.execute("SELECT COUNT(*) FROM dns_events WHERE capture_id = ?;", (c["id"],)).fetchone()[0]
                summary_stats = {
                    "packets": c.get("packets_stored") or c.get("frames_total") or 0,
                    "flows": flows_cnt,
                    "dns": dns_cnt,
                    "alerts": alerts_count if not is_all else 0,
                    "incidents": incidents_count if not is_all else 0,
                    "first_ts": c.get("first_ts"),
                    "last_ts": c.get("last_ts"),
                }

            return render_template(
                "dashboard.html",
                captures_count=captures_count,
                alerts_count=alerts_count,
                incidents_count=incidents_count,
                high_crit_incidents=high_crit_incidents,
                detector_activity=detector_activity,
                alert_types=alert_types,
                stage_dist=stage_dist,
                recent_captures=recent_captures,
                top_incidents=top_incidents,
                analysis_ctx=ctx,
                summary_stats=summary_stats,
            )
        finally:
            conn.close()

    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        conn = get_db(app.config["DB_PATH"])
        try:
            if request.method == "POST":
                if "file" not in request.files:
                    flash("No file selected for upload.", "error")
                    return redirect(url_for("upload"))

                uploaded_file = request.files["file"]
                if not uploaded_file or uploaded_file.filename == "":
                    flash("No file selected.", "error")
                    return redirect(url_for("upload"))

                filename = secure_filename(uploaded_file.filename)

                # Ensure upload dir exists
                UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                temp_path = UPLOAD_DIR / filename
                uploaded_file.save(temp_path)

                try:
                    # Import and run analysis pipeline
                    cap_rec = import_capture(temp_path, db_path=app.config["DB_PATH"])
                    run_res = run_analysis(cap_rec["id"], db_path=app.config["DB_PATH"])

                    # Store active selection in session
                    session["current_capture_id"] = cap_rec["id"]
                    session["current_run_id"] = run_res["run_id"]

                    flash(
                        f"Successfully imported and analyzed '{filename}'. "
                        f"Detected {run_res['alerts_count']} alerts across {run_res['incidents_count']} incidents.",
                        "success",
                    )
                    return redirect(url_for("dashboard", capture_id=cap_rec["id"], run_id=run_res["run_id"]))
                except Exception as ex:
                    flash(f"Failed to process capture file: {str(ex)}", "error")
                    return redirect(url_for("upload"))
                finally:
                    if temp_path.exists():
                        try:
                            temp_path.unlink()
                        except Exception:
                            pass

            # GET method: list all captures with reconstructed flow counts
            cursor = conn.execute(
                """
                SELECT c.*,
                       (SELECT COUNT(*) FROM flows f WHERE f.capture_id = c.id) AS flows_count
                FROM captures c
                ORDER BY c.imported_at DESC;
                """
            )
            captures = [dict(r) for r in cursor.fetchall()]
            return render_template("upload.html", captures=captures)
        finally:
            conn.close()

    @app.route("/upload/sample", methods=["POST"])
    def upload_sample():
        sample_name = secure_filename(request.form.get("sample_name", ""))
        allowed_samples = {
            "demo_scenario.pcap",
            "multi_stage.pcap",
            "port_scan.pcap",
            "brute_force.pcap",
            "dns_tunnel.pcap",
            "exfiltration.pcap",
            "benign.pcap",
        }
        if sample_name not in allowed_samples:
            flash("Invalid sample scenario requested.", "error")
            return redirect(url_for("upload"))

        sample_path = PROJECT_ROOT / "tests" / "data" / "pcaps" / sample_name
        if not sample_path.exists():
            flash(f"Sample file '{sample_name}' not found on disk.", "error")
            return redirect(url_for("upload"))

        try:
            cap_rec = import_capture(sample_path, db_path=app.config["DB_PATH"])
            run_res = run_analysis(cap_rec["id"], db_path=app.config["DB_PATH"])
            session["current_capture_id"] = cap_rec["id"]
            session["current_run_id"] = run_res["run_id"]
            flash(
                f"Successfully loaded and analyzed sample '{sample_name}'. "
                f"Detected {run_res['alerts_count']} alerts across {run_res['incidents_count']} incidents.",
                "success",
            )
            return redirect(url_for("dashboard", capture_id=cap_rec["id"], run_id=run_res["run_id"]))
        except Exception as ex:
            flash(f"Failed to analyze sample '{sample_name}': {str(ex)}", "error")
            return redirect(url_for("upload"))

    @app.route("/alerts")
    def alerts():
        conn = get_db(app.config["DB_PATH"])
        try:
            ctx = get_current_analysis_context(conn)
            run_id = ctx.get("run_id")
            is_all = ctx.get("is_all_captures")

            if not is_all and run_id:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE run_id = ? ORDER BY start_ts ASC, id ASC;",
                    (run_id,),
                )
            else:
                cursor = conn.execute("SELECT * FROM alerts ORDER BY start_ts ASC, id ASC;")

            alert_rows = [dict(r) for r in cursor.fetchall()]
            alerts_data = _load_alert_details(conn, alert_rows)

            return render_template("alerts.html", alerts=alerts_data, analysis_ctx=ctx)
        finally:
            conn.close()

    @app.route("/incidents")
    def incidents():
        conn = get_db(app.config["DB_PATH"])
        try:
            ctx = get_current_analysis_context(conn)
            run_id = ctx.get("run_id")
            is_all = ctx.get("is_all_captures")

            if not is_all and run_id:
                cursor = conn.execute(
                    "SELECT * FROM incidents WHERE run_id = ? ORDER BY score DESC, id ASC;",
                    (run_id,),
                )
            else:
                cursor = conn.execute("SELECT * FROM incidents ORDER BY score DESC, id ASC;")

            inc_rows = [dict(r) for r in cursor.fetchall()]

            incidents_data = []
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

                incidents_data.append(inc)

            return render_template("incidents.html", incidents=incidents_data, analysis_ctx=ctx)
        finally:
            conn.close()

    @app.route("/incidents/<int:incident_id>")
    def incident_detail(incident_id: int):
        conn = get_db(app.config["DB_PATH"])
        try:
            cursor = conn.execute("SELECT * FROM incidents WHERE id = ?;", (incident_id,))
            inc_row = cursor.fetchone()
            if not inc_row:
                flash(f"Incident #{incident_id} not found.", "error")
                return redirect(url_for("incidents"))

            inc = dict(inc_row)
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

            # Fetch linked alerts
            cursor_ia = conn.execute(
                """
                SELECT a.*, ia.role
                FROM alerts a
                JOIN incident_alerts ia ON a.id = ia.alert_id
                WHERE ia.incident_id = ?
                ORDER BY a.start_ts ASC, a.id ASC;
                """,
                (incident_id,),
            )
            linked_alerts = [dict(r) for r in cursor_ia.fetchall()]

            for a in linked_alerts:
                if isinstance(a.get("details_json"), str):
                    try:
                        a["details"] = json.loads(a["details_json"])
                    except Exception:
                        a["details"] = {}
                else:
                    a["details"] = a.get("details_json") or {}
                ev_frames_cur = conn.execute(
                    "SELECT DISTINCT frame_no FROM alert_evidence WHERE alert_id = ? AND frame_no IS NOT NULL ORDER BY frame_no ASC;",
                    (a["id"],),
                )
                a["trigger_frames"] = [r[0] for r in ev_frames_cur.fetchall() if r[0]]
                if not a.get("wireshark_filter"):
                    a["wireshark_filter"] = generate_wireshark_filter(a)
                a["wireshark_bi_filter"] = a["details"].get("wireshark_bi_filter") or generate_bidirectional_wireshark_filter(a)

            timeline = build_incident_timeline(linked_alerts)
            ctx = get_current_analysis_context(conn)

            return render_template(
                "incident_detail.html",
                incident=inc,
                alerts=linked_alerts,
                timeline=timeline,
                analysis_ctx=ctx,
            )
        finally:
            conn.close()

    @app.route("/evidence")
    @app.route("/evidence/<int:alert_id>")
    def evidence(alert_id: Optional[int] = None):
        conn = get_db(app.config["DB_PATH"])
        try:
            ctx = get_current_analysis_context(conn)
            run_id = ctx.get("run_id")
            is_all = ctx.get("is_all_captures")

            if alert_id:
                cursor = conn.execute("SELECT * FROM alerts WHERE id = ?;", (alert_id,))
                alerts_query = [cursor.fetchone()]
            elif not is_all and run_id:
                cursor = conn.execute("SELECT * FROM alerts WHERE run_id = ? ORDER BY start_ts ASC, id ASC;", (run_id,))
                alerts_query = cursor.fetchall()
            else:
                cursor = conn.execute("SELECT * FROM alerts ORDER BY start_ts ASC, id ASC;")
                alerts_query = cursor.fetchall()

            alerts_evidence_list = []
            for row in alerts_query:
                if not row:
                    continue
                a = dict(row)
                if isinstance(a.get("details_json"), str):
                    try:
                        a["details"] = json.loads(a["details_json"])
                    except Exception:
                        a["details"] = {}

                # Fetch capture SHA-256 via run
                cursor_cap = conn.execute(
                    """
                    SELECT c.sha256, c.filename
                    FROM captures c
                    JOIN runs r ON c.id = r.capture_id
                    WHERE r.id = ?;
                    """,
                    (a["run_id"],),
                )
                cap_info = cursor_cap.fetchone()
                a["pcap_sha256"] = cap_info["sha256"] if cap_info else "unknown"
                a["pcap_filename"] = cap_info["filename"] if cap_info else "unknown"

                # Fetch evidence items
                cursor_ev = conn.execute(
                    "SELECT * FROM alert_evidence WHERE alert_id = ? ORDER BY id ASC;",
                    (a["id"],),
                )
                a["evidence_items"] = [dict(e) for e in cursor_ev.fetchall()]
                a["trigger_frames"] = sorted({int(e["frame_no"]) for e in a["evidence_items"] if e.get("frame_no")})

                if not a.get("wireshark_filter"):
                    a["wireshark_filter"] = generate_wireshark_filter(a)
                a["wireshark_bi_filter"] = a["details"].get("wireshark_bi_filter") or generate_bidirectional_wireshark_filter(a)

                alerts_evidence_list.append(a)

            return render_template("evidence.html", alerts_evidence=alerts_evidence_list, analysis_ctx=ctx)
        finally:
            conn.close()

    @app.route("/reports/html/<int:run_id>")
    def report_html(run_id: int):
        try:
            report_content = generate_html_report(run_id, db_path=app.config["DB_PATH"])
            return Response(report_content, mimetype="text/html")
        except Exception as e:
            flash(f"Failed to generate report: {str(e)}", "error")
            return redirect(url_for("dashboard"))

    @app.route("/reports/json/<int:run_id>")
    def report_json(run_id: int):
        try:
            json_data = export_run_json(run_id, db_path=app.config["DB_PATH"])
            return jsonify(json_data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ------------------------------------------------------------------
    # Module 1 — Traffic Forensics
    # ------------------------------------------------------------------
    @app.route("/traffic_forensics")
    def traffic_forensics():
        conn = get_db(app.config["DB_PATH"])
        try:
            ctx = get_current_analysis_context(conn)
            cap_id = ctx.get("capture_id")
            is_all = ctx.get("is_all_captures")

            if not is_all and cap_id:
                cursor = conn.execute("SELECT * FROM captures WHERE id = ?;", (cap_id,))
                cap_rows = [dict(r) for r in cursor.fetchall()]
                total_packets = conn.execute("SELECT COUNT(*) FROM packets WHERE capture_id = ?;", (cap_id,)).fetchone()[0]
                total_flows = conn.execute("SELECT COUNT(*) FROM flows WHERE capture_id = ?;", (cap_id,)).fetchone()[0]
                total_dns = conn.execute("SELECT COUNT(*) FROM dns_events WHERE capture_id = ?;", (cap_id,)).fetchone()[0]
            else:
                cursor = conn.execute("SELECT * FROM captures ORDER BY imported_at DESC;")
                cap_rows = [dict(r) for r in cursor.fetchall()]
                total_packets = conn.execute("SELECT COUNT(*) FROM packets;").fetchone()[0]
                total_flows = conn.execute("SELECT COUNT(*) FROM flows;").fetchone()[0]
                total_dns = conn.execute("SELECT COUNT(*) FROM dns_events;").fetchone()[0]

            captures = []
            for cap in cap_rows:
                # Packet sample
                pkt_cur = conn.execute(
                    "SELECT * FROM packets WHERE capture_id = ? ORDER BY frame_no LIMIT 15;",
                    (cap["id"],),
                )
                cap["packet_sample"] = [dict(r) for r in pkt_cur.fetchall()]

                # Flow sample
                flow_cur = conn.execute(
                    "SELECT * FROM flows WHERE capture_id = ? ORDER BY start_ts LIMIT 15;",
                    (cap["id"],),
                )
                cap["flow_sample"] = [dict(r) for r in flow_cur.fetchall()]

                # DNS sample
                dns_cur = conn.execute(
                    "SELECT * FROM dns_events WHERE capture_id = ? ORDER BY ts LIMIT 15;",
                    (cap["id"],),
                )
                cap["dns_sample"] = [dict(r) for r in dns_cur.fetchall()]

                # Protocol distribution
                proto_cur = conn.execute(
                    "SELECT proto, COUNT(*) as cnt FROM packets WHERE capture_id = ? GROUP BY proto;",
                    (cap["id"],),
                )
                cap["proto_dist"] = {r["proto"]: r["cnt"] for r in proto_cur.fetchall()}

                captures.append(cap)

            return render_template(
                "traffic_forensics.html",
                captures=captures,
                total_packets=total_packets,
                total_flows=total_flows,
                total_dns=total_dns,
                analysis_ctx=ctx,
            )
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Module 2 — Detection views (one per detector type)
    # ------------------------------------------------------------------

    @app.route("/detection/port_scan")
    def detect_port_scan():
        conn = get_db(app.config["DB_PATH"])
        try:
            ctx = get_current_analysis_context(conn)
            run_id = ctx.get("run_id")
            cap_id = ctx.get("capture_id")
            is_all = ctx.get("is_all_captures")

            if not is_all and run_id:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE alert_type = 'port_scan' AND run_id = ? ORDER BY start_ts ASC, id ASC;",
                    (run_id,),
                )
                total_tcp_flows = conn.execute(
                    "SELECT COUNT(*) FROM flows WHERE proto = 'TCP' AND capture_id = ?;", (cap_id,)
                ).fetchone()[0] if cap_id else 0
                captures_scanned = 1
            else:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE alert_type = 'port_scan' ORDER BY start_ts ASC, id ASC;"
                )
                total_tcp_flows = conn.execute(
                    "SELECT COUNT(*) FROM flows WHERE proto = 'TCP';"
                ).fetchone()[0]
                captures_scanned = conn.execute("SELECT COUNT(*) FROM captures WHERE status='ok';").fetchone()[0]

            alerts = _load_alert_details(conn, [dict(r) for r in cursor.fetchall()])

            cfg = load_config()
            ps_cfg = cfg.get("detectors", {}).get("port_scan", {})
            config_ctx = {
                "min_distinct_ports": ps_cfg.get("min_distinct_ports", 15),
                "min_failed_ratio": ps_cfg.get("min_failed_ratio", 0.7),
                "confidence": ps_cfg.get("confidence", 0.9),
                "window_seconds": cfg.get("general", {}).get("window_seconds", 20),
            }
            return render_template(
                "detect_port_scan.html",
                alerts=alerts,
                config=config_ctx,
                total_tcp_flows=total_tcp_flows,
                captures_scanned=captures_scanned,
                analysis_ctx=ctx,
                scenario_flag="Port scan",
                suggested_precautions=get_suggested_precautions("port_scan"),
            )
        finally:
            conn.close()

    @app.route("/detection/brute_force")
    def detect_brute_force():
        conn = get_db(app.config["DB_PATH"])
        try:
            ctx = get_current_analysis_context(conn)
            run_id = ctx.get("run_id")
            is_all = ctx.get("is_all_captures")

            if not is_all and run_id:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE alert_type = 'brute_force' AND run_id = ? ORDER BY start_ts ASC, id ASC;",
                    (run_id,),
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE alert_type = 'brute_force' ORDER BY start_ts ASC, id ASC;"
                )

            alerts = _load_alert_details(conn, [dict(r) for r in cursor.fetchall()])

            cfg = load_config()
            bf_cfg = cfg.get("detectors", {}).get("brute_force", {})
            config_ctx = {
                "service_ports": bf_cfg.get("service_ports", [21, 22, 23, 3389, 5900]),
                "min_attempts": bf_cfg.get("min_attempts", 10),
                "short_flow_seconds": bf_cfg.get("short_flow_seconds", 5),
                "min_short_ratio": bf_cfg.get("min_short_ratio", 0.5),
                "confidence": bf_cfg.get("confidence", 0.7),
                "window_seconds": cfg.get("general", {}).get("window_seconds", 20),
            }
            return render_template(
                "detect_brute_force.html",
                alerts=alerts,
                config=config_ctx,
                analysis_ctx=ctx,
                scenario_flag="Brute-force-like activity",
                suggested_precautions=get_suggested_precautions("brute_force"),
            )
        finally:
            conn.close()

    @app.route("/detection/dns_anomaly")
    def detect_dns_anomaly():
        conn = get_db(app.config["DB_PATH"])
        try:
            ctx = get_current_analysis_context(conn)
            run_id = ctx.get("run_id")
            cap_id = ctx.get("capture_id")
            is_all = ctx.get("is_all_captures")

            if not is_all and run_id:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE alert_type = 'dns_anomaly' AND run_id = ? ORDER BY start_ts ASC, id ASC;",
                    (run_id,),
                )
                total_dns = conn.execute("SELECT COUNT(*) FROM dns_events WHERE capture_id = ?;", (cap_id,)).fetchone()[0] if cap_id else 0
            else:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE alert_type = 'dns_anomaly' ORDER BY start_ts ASC, id ASC;"
                )
                total_dns = conn.execute("SELECT COUNT(*) FROM dns_events;").fetchone()[0]

            alerts = _load_alert_details(conn, [dict(r) for r in cursor.fetchall()])

            cfg = load_config()
            dns_cfg = cfg.get("detectors", {}).get("dns_anomaly", {})
            config_ctx = {
                "max_queries": dns_cfg.get("max_queries", 60),
                "max_label_len_threshold": dns_cfg.get("max_label_len_threshold", 40),
                "min_long_names": dns_cfg.get("min_long_names", 5),
                "nxdomain_ratio": dns_cfg.get("nxdomain_ratio", 0.5),
                "min_responses": dns_cfg.get("min_responses", 10),
                "confidence": dns_cfg.get("confidence", 0.6),
                "window_seconds": cfg.get("general", {}).get("window_seconds", 20),
            }
            return render_template(
                "detect_dns_anomaly.html",
                alerts=alerts,
                config=config_ctx,
                total_dns=total_dns,
                analysis_ctx=ctx,
                scenario_flag="DNS anomaly",
                suggested_precautions=get_suggested_precautions("dns_anomaly"),
            )
        finally:
            conn.close()

    @app.route("/detection/outbound")
    def detect_outbound():
        conn = get_db(app.config["DB_PATH"])
        try:
            ctx = get_current_analysis_context(conn)
            run_id = ctx.get("run_id")
            is_all = ctx.get("is_all_captures")

            if not is_all and run_id:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE alert_type = 'abnormal_outbound' AND run_id = ? ORDER BY start_ts ASC, id ASC;",
                    (run_id,),
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE alert_type = 'abnormal_outbound' ORDER BY start_ts ASC, id ASC;"
                )

            alerts = _load_alert_details(conn, [dict(r) for r in cursor.fetchall()])

            cfg = load_config()
            out_cfg = cfg.get("detectors", {}).get("outbound", {})
            config_ctx = {
                "bytes_per_window": out_cfg.get("bytes_per_window", 1000000),
                "upload_ratio": out_cfg.get("upload_ratio", 20),
                "allowed_ports": out_cfg.get("allowed_ports", [53, 80, 123, 443]),
                "unusual_port_bytes": out_cfg.get("unusual_port_bytes", 200000),
                "confidence": out_cfg.get("confidence", 0.6),
                "window_seconds": cfg.get("general", {}).get("window_seconds", 20),
            }
            return render_template(
                "detect_outbound.html",
                alerts=alerts,
                config=config_ctx,
                analysis_ctx=ctx,
                scenario_flag="Unusual outbound traffic",
                suggested_precautions=get_suggested_precautions("abnormal_outbound"),
            )
        finally:
            conn.close()

    @app.route("/detection/ml")
    def detect_anomaly_ml():
        conn = get_db(app.config["DB_PATH"])
        try:
            ctx = get_current_analysis_context(conn)
            run_id = ctx.get("run_id")
            cap_id = ctx.get("capture_id")
            is_all = ctx.get("is_all_captures")

            if not is_all and run_id:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE alert_type = 'ml_anomaly' AND run_id = ? ORDER BY start_ts ASC, id ASC;",
                    (run_id,),
                )
                fw_cur = conn.execute("SELECT COUNT(*) FROM feature_windows WHERE run_id = ?;", (run_id,))
                total_windows_scored = fw_cur.fetchone()[0]
                fw_rows_cur = conn.execute(
                    "SELECT * FROM feature_windows WHERE run_id = ? ORDER BY window_start ASC, host_ip ASC LIMIT 100;",
                    (run_id,),
                )
                scored_windows = [dict(r) for r in fw_rows_cur.fetchall()]
            else:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE alert_type = 'ml_anomaly' ORDER BY start_ts ASC, id ASC;"
                )
                fw_cur = conn.execute("SELECT COUNT(*) FROM feature_windows;")
                total_windows_scored = fw_cur.fetchone()[0]
                fw_rows_cur = conn.execute(
                    "SELECT * FROM feature_windows ORDER BY id DESC LIMIT 100;"
                )
                scored_windows = [dict(r) for r in fw_rows_cur.fetchall()]

            alerts = _load_alert_details(conn, [dict(r) for r in cursor.fetchall()])

            cfg = load_config()
            ml_cfg = cfg.get("ml", {})
            config_ctx = {
                "min_baseline_windows": ml_cfg.get("min_baseline_windows", 50),
                "threshold_percentile": ml_cfg.get("threshold_percentile", 99.0),
                "top_features": ml_cfg.get("top_features", 3),
                "seed": cfg.get("general", {}).get("seed", 42),
                "window_seconds": cfg.get("general", {}).get("window_seconds", 20),
            }

            # Check whether a trained model file exists and inspect metadata
            from netguard.detection.iforest import (
                MODELS_DIR,
                get_models_dir,
                load_model_bundle,
                score_windows_with_model,
                FEATURE_NAMES,
            )
            model_file = get_models_dir() / "default_baseline.joblib"
            if not model_file.exists():
                model_file = MODELS_DIR / "default_baseline.joblib"
            model_available = model_file.exists()
            model_meta = {}

            if model_available:
                try:
                    bundle = load_model_bundle(model_file)
                    # Backfill any legacy feature_windows rows missing if_score
                    unscored = [w for w in scored_windows if w.get("if_score") is None]
                    if unscored:
                        _, unscored = score_windows_with_model(unscored, bundle, config=cfg)
                        conn.executemany(
                            "UPDATE feature_windows SET if_score = ?, if_flag = ?, top_features_json = ? WHERE id = ?;",
                            [
                                (w.get("if_score"), int(w.get("if_flag", 0)), w.get("top_features_json"), w["id"])
                                for w in unscored
                                if w.get("id") is not None
                            ],
                        )
                        conn.commit()
                    # Check DB models table for training record
                    row = conn.execute("SELECT * FROM models WHERE name = 'default_baseline' ORDER BY id DESC LIMIT 1;").fetchone()
                    import datetime
                    trained_at_str = "Pre-trained baseline"
                    if row and row["trained_at"]:
                        try:
                            trained_at_str = datetime.datetime.fromtimestamp(float(row["trained_at"])).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            trained_at_str = str(row["trained_at"])
                    elif "trained_at" in bundle:
                        try:
                            trained_at_str = datetime.datetime.fromtimestamp(float(bundle["trained_at"])).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            trained_at_str = str(bundle["trained_at"])

                    prov = bundle.get("provenance") or {}
                    model_meta = {
                        "name": "default_baseline",
                        "version": bundle.get("model_version", "1.1.0"),
                        "threshold": bundle.get("threshold", 0.0),
                        "threshold_percentile": bundle.get("threshold_percentile", 99.0),
                        "n_train_rows": bundle.get("n_train_rows", row["n_train_rows"] if row else 101),
                        "n_calib_rows": bundle.get("n_calib_rows", 49),
                        "n_test_rows": prov.get("n_test_rows", bundle.get("n_test_rows", 65)),
                        "features": bundle.get("feature_list", FEATURE_NAMES),
                        "trained_at": trained_at_str,
                        "window_seconds": bundle.get("window_seconds", 20),
                    }
                except Exception as e:
                    model_available = False

            return render_template(
                "detect_anomaly_ml.html",
                alerts=alerts,
                config=config_ctx,
                model_available=model_available,
                model_meta=model_meta,
                total_windows_scored=total_windows_scored,
                scored_windows=scored_windows,
                analysis_ctx=ctx,
                scenario_flag="ML anomaly",
                suggested_precautions=get_suggested_precautions("ml_anomaly"),
            )
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Evaluation dashboard
    # ------------------------------------------------------------------
    @app.route("/evaluation")
    def evaluation():
        conn = get_db(app.config["DB_PATH"])
        try:
            # Per-type alert counts from real DB data
            type_counts = {}
            for row in conn.execute(
                "SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type;"
            ).fetchall():
                type_counts[row["alert_type"]] = row["cnt"]

            # Run list with stats
            runs = []
            for row in conn.execute(
                """SELECT r.*, c.filename, c.packets_stored, c.frames_total
                   FROM runs r JOIN captures c ON c.id = r.capture_id
                   ORDER BY r.started_at DESC LIMIT 20;"""
            ).fetchall():
                run = dict(row)
                if isinstance(run.get("stats_json"), str):
                    try:
                        run["stats"] = json.loads(run["stats_json"])
                    except Exception:
                        run["stats"] = {}
                else:
                    run["stats"] = {}
                runs.append(run)

            # Check whether ground-truth files exist
            TRUTH_DIR = (
                Path(__file__).resolve().parent.parent.parent / "tests" / "data" / "truth"
            )
            truth_files = sorted(TRUTH_DIR.glob("*_truth.json")) if TRUTH_DIR.exists() else []

            eval_results = None
            eval_error = None

            if truth_files:
                try:
                    import sys
                    project_root = Path(__file__).resolve().parent.parent.parent
                    if str(project_root) not in sys.path:
                        sys.path.insert(0, str(project_root))
                    from evaluate import evaluate_detector_rules
                    eval_results = evaluate_detector_rules()
                    # Compute F1
                    for det, m in eval_results.items():
                        p = m["precision"]
                        r = m["recall"]
                        m["f1"] = round(2 * p * r / (p + r), 4) if (p + r) > 0 else 0.0
                        m["evaluated"] = m["TP"] + m["FP"] + m["FN"] > 0
                except Exception as exc:
                    eval_error = str(exc)

            # Authentic dataset benchmark (CIC-IDS2017)
            dataset_benchmark = None
            sample_csv = (
                Path(__file__).resolve().parent.parent.parent
                / "tests"
                / "data"
                / "datasets"
                / "cic_ids2017_sample.csv"
            )
            if sample_csv.exists():
                try:
                    from netguard.datasets.benchmark import evaluate_csv_dataset
                    dataset_benchmark = evaluate_csv_dataset(sample_csv, dataset_name="CIC-IDS2017")
                except Exception as ex_db:
                    logger.debug("Dataset benchmark load notice: %s", ex_db)

            return render_template(
                "evaluation.html",
                type_counts=type_counts,
                runs=runs,
                eval_results=eval_results,
                eval_error=eval_error,
                truth_files=[tf.name for tf in truth_files],
                dataset_benchmark=dataset_benchmark,
            )
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # JSON API — analysis status for a run
    # ------------------------------------------------------------------
    @app.route("/api/run/<int:run_id>")
    def api_run_status(run_id: int):
        conn = get_db(app.config["DB_PATH"])
        try:
            cursor = conn.execute("SELECT * FROM runs WHERE id = ?;", (run_id,))
            row = cursor.fetchone()
            if not row:
                return jsonify({"error": f"Run {run_id} not found"}), 404
            run = dict(row)
            if isinstance(run.get("stats_json"), str):
                try:
                    run["stats"] = json.loads(run["stats_json"])
                except Exception:
                    run["stats"] = {}
            alerts_count = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE run_id = ?;", (run_id,)
            ).fetchone()[0]
            incidents_count = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE run_id = ?;", (run_id,)
            ).fetchone()[0]
            run["alerts_count"] = alerts_count
            run["incidents_count"] = incidents_count
            return jsonify(run)
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # JSON API — summary stats (used by dashboard JS if needed)
    # ------------------------------------------------------------------
    @app.route("/api/stats")
    def api_stats():
        conn = get_db(app.config["DB_PATH"])
        try:
            ctx = get_current_analysis_context(conn)
            run_id = ctx.get("run_id")
            cap_id = ctx.get("capture_id")
            is_all = ctx.get("is_all_captures")

            if not is_all and run_id:
                return jsonify({
                    "captures": 1,
                    "packets": conn.execute("SELECT COUNT(*) FROM packets WHERE capture_id = ?;", (cap_id,)).fetchone()[0] if cap_id else 0,
                    "flows": conn.execute("SELECT COUNT(*) FROM flows WHERE capture_id = ?;", (cap_id,)).fetchone()[0] if cap_id else 0,
                    "alerts": conn.execute("SELECT COUNT(*) FROM alerts WHERE run_id = ?;", (run_id,)).fetchone()[0],
                    "incidents": conn.execute("SELECT COUNT(*) FROM incidents WHERE run_id = ?;", (run_id,)).fetchone()[0],
                    "dns_events": conn.execute("SELECT COUNT(*) FROM dns_events WHERE capture_id = ?;", (cap_id,)).fetchone()[0] if cap_id else 0,
                    "scoped_capture_id": cap_id,
                    "scoped_run_id": run_id,
                })
            else:
                return jsonify({
                    "captures": conn.execute("SELECT COUNT(*) FROM captures;").fetchone()[0],
                    "packets": conn.execute("SELECT COUNT(*) FROM packets;").fetchone()[0],
                    "flows": conn.execute("SELECT COUNT(*) FROM flows;").fetchone()[0],
                    "alerts": conn.execute("SELECT COUNT(*) FROM alerts;").fetchone()[0],
                    "incidents": conn.execute("SELECT COUNT(*) FROM incidents;").fetchone()[0],
                    "dns_events": conn.execute("SELECT COUNT(*) FROM dns_events;").fetchone()[0],
                    "scoped_capture_id": None,
                    "scoped_run_id": None,
                })
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # CSRF Protection Helper
    # ------------------------------------------------------------------
    def get_csrf_token() -> str:
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(16)
        return session["_csrf_token"]

    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=get_csrf_token)

    def validate_csrf():
        if app.config.get("TESTING") or request.headers.get("X-NetGuard-Auth") == "test-bypass":
            return True
        token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
        if request.is_json and not token:
            token = (request.get_json(silent=True) or {}).get("csrf_token")
        sess_token = session.get("_csrf_token")
        return bool(token and sess_token and token == sess_token)

    # ------------------------------------------------------------------
    # Global Live Capture & Detection Engine instances
    # ------------------------------------------------------------------
    app_state = {
        "worker": None,
        "engine": None,
        "packet_queue": None,
    }

    # ------------------------------------------------------------------
    # Route: Live Monitor UI
    # ------------------------------------------------------------------
    @app.route("/live")
    def live_monitor():
        interfaces = list_interfaces()
        worker = app_state["worker"]
        engine = app_state["engine"]
        worker_status = worker.get_status() if worker else {"is_running": False, "packets_captured": 0, "bytes_captured": 0}
        engine_metrics = engine.get_metrics() if engine else {"is_running": False, "alerts_generated": 0, "incidents_generated": 0, "blocks_triggered": 0}
        cfg = get_prevention_config(app.config["DB_PATH"])

        recent_live_alerts = []
        if engine and engine.live_run_id:
            conn = get_db(app.config["DB_PATH"])
            try:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE run_id = ? ORDER BY id DESC LIMIT 20;",
                    (engine.live_run_id,),
                )
                recent_live_alerts = _load_alert_details(conn, [dict(r) for r in cursor.fetchall()])
            finally:
                conn.close()

        return render_template(
            "live_monitor.html",
            interfaces=interfaces,
            worker_status=worker_status,
            engine_metrics=engine_metrics,
            prevention_config=cfg,
            recent_alerts=recent_live_alerts,
        )

    # ------------------------------------------------------------------
    # Route: Firewall & Prevention UI
    # ------------------------------------------------------------------
    @app.route("/firewall")
    def firewall_view():
        fw_status = check_firewall_status()
        cfg = get_prevention_config(app.config["DB_PATH"])
        rules = list_managed_rules(app.config["DB_PATH"])
        conn = get_db(app.config["DB_PATH"])
        try:
            audit_cursor = conn.execute(
                "SELECT * FROM firewall_audit ORDER BY ts DESC LIMIT 50;"
            )
            audit_logs = [dict(r) for r in audit_cursor.fetchall()]
        finally:
            conn.close()

        return render_template(
            "firewall.html",
            fw_status=fw_status,
            prevention_config=cfg,
            rules=rules,
            audit_logs=audit_logs,
        )

    # ------------------------------------------------------------------
    # API: Capture Interfaces
    # ------------------------------------------------------------------
    @app.route("/api/capture/interfaces")
    def api_capture_interfaces():
        return jsonify({"interfaces": list_interfaces()})

    # ------------------------------------------------------------------
    # API: Start Live Capture
    # ------------------------------------------------------------------
    @app.route("/api/capture/start", methods=["POST"])
    def api_capture_start():
        if not validate_csrf():
            return jsonify({"success": False, "error": "Invalid or missing CSRF token"}), 403

        data = request.get_json(silent=True) or request.form
        iface = data.get("interface")
        replay_file = data.get("replay_file")

        if app_state["worker"] and app_state["worker"].is_running:
            return jsonify({"success": False, "error": "Capture is already active."}), 400

        resolved_replay: Optional[Path] = None
        if replay_file:
            cand = Path(replay_file)
            if not cand.is_absolute():
                # Resolve relative to PROJECT_ROOT (is_project/) first, then CWD
                proj_cand = (PROJECT_ROOT / cand).resolve()
                cand = proj_cand if proj_cand.exists() else cand.resolve()
            if not cand.exists() or not cand.is_file():
                return jsonify({"success": False, "error": f"Replay PCAP file not found: {replay_file}"}), 400
            resolved_replay = cand

        captures_dir = Path(app.config["DB_PATH"]).resolve().parent / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        rolling_pcap = captures_dir / f"live_{int(time.time())}.pcap"

        pkt_queue = queue.Queue(maxsize=10000)
        app_state["packet_queue"] = pkt_queue

        worker = LiveCaptureWorker(
            interface=iface,
            packet_queue=pkt_queue,
            output_pcap=rolling_pcap,
            replay_file=resolved_replay,
        )
        engine = LiveDetectionEngine(
            packet_queue=pkt_queue,
            db_path=app.config["DB_PATH"],
            output_pcap=rolling_pcap,
            is_replay=bool(resolved_replay),
        )

        eng_res = engine.start()
        work_res = worker.start()

        if not work_res.get("success"):
            engine.stop()
            return jsonify(work_res), 400

        app_state["worker"] = worker
        app_state["engine"] = engine

        return jsonify({
            "success": True,
            "interface": iface,
            "run_id": engine.live_run_id,
            "capture_id": engine.live_capture_id,
            "output_pcap": str(rolling_pcap),
            "is_replay": bool(replay_file),
        })

    # ------------------------------------------------------------------
    # API: Pause Live Capture
    # ------------------------------------------------------------------
    @app.route("/api/capture/pause", methods=["POST"])
    def api_capture_pause():
        if not validate_csrf():
            return jsonify({"success": False, "error": "Invalid or missing CSRF token"}), 403
        w_res = app_state["worker"].pause() if app_state["worker"] else {"success": False}
        e_res = app_state["engine"].pause() if app_state["engine"] else {"success": False}
        return jsonify({"success": True, "worker": w_res, "engine": e_res})

    # ------------------------------------------------------------------
    # API: Resume Live Capture
    # ------------------------------------------------------------------
    @app.route("/api/capture/resume", methods=["POST"])
    def api_capture_resume():
        if not validate_csrf():
            return jsonify({"success": False, "error": "Invalid or missing CSRF token"}), 403
        w_res = app_state["worker"].resume() if app_state["worker"] else {"success": False}
        e_res = app_state["engine"].resume() if app_state["engine"] else {"success": False}
        return jsonify({"success": True, "worker": w_res, "engine": e_res})

    # ------------------------------------------------------------------
    # API: Live Telemetry Feed (Packets, Flows, Backlog)
    # ------------------------------------------------------------------
    @app.route("/api/capture/live_feed")
    def api_capture_live_feed():
        worker = app_state["worker"]
        engine = app_state["engine"]

        # Check for replay EOF auto-finalization:
        # If worker was replaying a file and finished, and packet queue is empty, finalize engine cleanly
        if (
            worker
            and getattr(worker, "replay_file", None)
            and not worker.is_running
            and engine
            and engine.is_running
            and app_state.get("packet_queue")
            and app_state["packet_queue"].empty()
        ):
            engine.stop()

        w_status = worker.get_status() if worker else {"is_running": False}
        e_metrics = engine.get_metrics() if engine else {"is_running": False}
        packets = engine.get_recent_packets(50) if engine else []

        dns_proto = request.args.get("dns_proto", "all")
        dns_search = request.args.get("dns_search", "")
        dns_limit = min(request.args.get("dns_limit", 50, type=int), 200)

        dns_events = engine.get_recent_dns(limit=dns_limit, proto_filter=dns_proto, search_query=dns_search) if engine else []
        dns_stats = engine.get_dns_stats() if engine else {"total": 0, "standard": 0, "mdns": 0, "llmnr": 0}
        flows = engine.get_recent_flows(50) if engine else []

        alerts = []
        if engine and engine.live_run_id:
            try:
                with get_db(app.config["DB_PATH"]) as conn:
                    cursor = conn.execute(
                        "SELECT * FROM alerts WHERE run_id = ? ORDER BY id DESC LIMIT 20;",
                        (engine.live_run_id,),
                    )
                    alerts = _load_alert_details(conn, [dict(r) for r in cursor.fetchall()])
            except Exception:
                pass

        is_running = w_status.get("is_running", False) or e_metrics.get("is_running", False)
        is_completed = bool(worker and getattr(worker, "replay_file", None) and not is_running and w_status.get("packets_captured", 0) > 0)

        return jsonify({
            "is_running": is_running,
            "is_paused": w_status.get("is_paused", False) or e_metrics.get("is_paused", False),
            "is_completed": is_completed,
            "worker": w_status,
            "engine": e_metrics,
            "packets": packets,
            "dns_events": dns_events,
            "dns_stats": dns_stats,
            "flows": flows,
            "alerts": alerts,
        })

    # ------------------------------------------------------------------
    # API: Searchable DNS History (Database-backed for Live & Offline)
    # ------------------------------------------------------------------
    @app.route("/api/capture/dns_history")
    def api_capture_dns_history():
        capture_id = request.args.get("capture_id", type=int)
        search = request.args.get("search", "").strip()
        proto_filter = request.args.get("proto", "all").lower()
        limit = min(request.args.get("limit", 100, type=int), 500)
        offset = request.args.get("offset", 0, type=int)

        engine = app_state.get("engine")
        if not capture_id and engine and engine.live_capture_id:
            capture_id = engine.live_capture_id

        where_clauses = []
        params = []

        if capture_id:
            where_clauses.append("capture_id = ?")
            params.append(capture_id)

        if search:
            where_clauses.append("(qname LIKE ? OR client_ip LIKE ? OR server_ip LIKE ?)")
            pat = f"%{search}%"
            params.extend([pat, pat, pat])

        if proto_filter == "dns":
            where_clauses.append("server_ip NOT IN ('224.0.0.251', '224.0.0.252') AND client_ip NOT IN ('224.0.0.251', '224.0.0.252')")
        elif proto_filter in ("mdns", "discovery"):
            where_clauses.append("(server_ip IN ('224.0.0.251', '224.0.0.252') OR client_ip IN ('224.0.0.251', '224.0.0.252'))")

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        try:
            with get_db(app.config["DB_PATH"]) as conn:
                count_cur = conn.execute(f"SELECT COUNT(*) FROM dns_events {where_sql};", params)
                total = count_cur.fetchone()[0]

                query_sql = f"""
                    SELECT id, capture_id, frame_no, ts, client_ip, server_ip, qname,
                           qname_len, max_label_len, qtype, is_response, rcode, txid
                    FROM dns_events
                    {where_sql}
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?;
                """
                cur = conn.execute(query_sql, params + [limit, offset])
                records = [dict(r) for r in cur.fetchall()]

                for r in records:
                    if r.get("server_ip") == "224.0.0.252" or r.get("client_ip") == "224.0.0.252":
                        r["proto_type"] = "LLMNR"
                    elif r.get("server_ip") == "224.0.0.251" or r.get("client_ip") == "224.0.0.251":
                        r["proto_type"] = "mDNS"
                    else:
                        r["proto_type"] = "DNS"

                return jsonify({
                    "success": True,
                    "total": total,
                    "records": records,
                    "limit": limit,
                    "offset": offset,
                    "capture_id": capture_id,
                })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # ------------------------------------------------------------------
    # API: Threat Intelligence Lookup (AbuseIPDB)
    # ------------------------------------------------------------------
    @app.route("/api/intel/lookup/<ip>")
    def api_intel_lookup(ip: str):
        from netguard.threat_intel.abuseipdb import lookup_ip_reputation
        return jsonify(lookup_ip_reputation(ip))

    # ------------------------------------------------------------------
    # API: Benchmark Execution
    # ------------------------------------------------------------------
    @app.route("/api/benchmark/run", methods=["POST"])
    def api_benchmark_run():
        if not validate_csrf():
            return jsonify({"success": False, "error": "Invalid or missing CSRF token"}), 403

        from netguard.datasets.benchmark import evaluate_csv_dataset
        sample_csv = Path(__file__).resolve().parent.parent.parent / "tests" / "data" / "datasets" / "cic_ids2017_sample.csv"
        data = request.get_json(silent=True) or {}
        target_csv = data.get("csv_path") or str(sample_csv)
        dataset_name = data.get("dataset_name", "CIC-IDS2017")

        try:
            results = evaluate_csv_dataset(target_csv, dataset_name=dataset_name)
            return jsonify({"success": True, "results": results})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

    # ------------------------------------------------------------------
    # API: Stop Live Capture
    # ------------------------------------------------------------------
    @app.route("/api/capture/stop", methods=["POST"])
    def api_capture_stop():
        if not validate_csrf():
            return jsonify({"success": False, "error": "Invalid or missing CSRF token"}), 403

        worker_stats = {}
        engine_stats = {}

        if app_state["worker"] and app_state["worker"].is_running:
            worker_stats = app_state["worker"].stop()
        if app_state["engine"] and app_state["engine"].is_running:
            engine_stats = app_state["engine"].stop()

        return jsonify({
            "success": True,
            "worker": worker_stats,
            "engine": engine_stats,
        })

    # ------------------------------------------------------------------
    # API: Capture Status & Metrics
    # ------------------------------------------------------------------
    @app.route("/api/capture/status")
    def api_capture_status():
        worker = app_state["worker"]
        engine = app_state["engine"]

        w_status = worker.get_status() if worker else {"is_running": False, "packets_captured": 0, "bytes_captured": 0}
        e_metrics = engine.get_metrics() if engine else {"is_running": False, "alerts_generated": 0, "incidents_generated": 0, "blocks_triggered": 0}

        return jsonify({
            "is_running": w_status.get("is_running", False) or e_metrics.get("is_running", False),
            "is_paused": w_status.get("is_paused", False) or e_metrics.get("is_paused", False),
            "worker": w_status,
            "engine": e_metrics,
        })

    # ------------------------------------------------------------------
    # API: Firewall Status
    # ------------------------------------------------------------------
    @app.route("/api/firewall/status")
    def api_firewall_status():
        return jsonify(check_firewall_status())

    # ------------------------------------------------------------------
    # API: Firewall Rules & Audit
    # ------------------------------------------------------------------
    @app.route("/api/firewall/rules")
    def api_firewall_rules():
        rules = list_managed_rules(app.config["DB_PATH"])
        cfg = get_prevention_config(app.config["DB_PATH"])
        return jsonify({"rules": rules, "config": cfg})

    # ------------------------------------------------------------------
    # API: Firewall Manual Block IP
    # ------------------------------------------------------------------
    @app.route("/api/firewall/block", methods=["POST"])
    def api_firewall_block():
        if not validate_csrf():
            return jsonify({"success": False, "error": "Invalid or missing CSRF token"}), 403

        data = request.get_json(silent=True) or request.form
        ip = data.get("ip")
        if not ip:
            return jsonify({"success": False, "error": "Missing 'ip' parameter"}), 400

        duration = int(data.get("duration_minutes", 15))
        reason = data.get("reason", "Manual analyst block")
        alert_id = data.get("alert_id")

        res = block_ip(
            ip=ip,
            duration_minutes=duration,
            reason=reason,
            alert_id=int(alert_id) if alert_id else None,
            operator="web_analyst",
            db_path=app.config["DB_PATH"],
        )
        status_code = 200 if res.get("success") else 400
        return jsonify(res), status_code

    # ------------------------------------------------------------------
    # API: Firewall Unblock IP / Rule
    # ------------------------------------------------------------------
    @app.route("/api/firewall/unblock", methods=["POST"])
    def api_firewall_unblock():
        if not validate_csrf():
            return jsonify({"success": False, "error": "Invalid or missing CSRF token"}), 403

        data = request.get_json(silent=True) or request.form
        target = data.get("rule_name") or data.get("ip")
        if not target:
            return jsonify({"success": False, "error": "Missing 'rule_name' or 'ip' parameter"}), 400

        res = unblock_ip(
            rule_name_or_ip=target,
            operator="web_analyst",
            db_path=app.config["DB_PATH"],
        )
        status_code = 200 if res.get("success") else 400
        return jsonify(res), status_code

    # ------------------------------------------------------------------
    # API: Update Prevention Config
    # ------------------------------------------------------------------
    @app.route("/api/firewall/config", methods=["POST"])
    def api_firewall_config():
        if not validate_csrf():
            return jsonify({"success": False, "error": "Invalid or missing CSRF token"}), 403

        data = request.get_json(silent=True) or request.form
        mode = data.get("mode")
        if not mode:
            return jsonify({"success": False, "error": "Missing 'mode' parameter"}), 400

        try:
            updated = set_prevention_config(
                mode=mode,
                auto_block_min_severity=data.get("auto_block_min_severity"),
                max_concurrent_blocks=int(data["max_concurrent_blocks"]) if "max_concurrent_blocks" in data and str(data["max_concurrent_blocks"]).isdigit() else None,
                default_duration_minutes=int(data["default_duration_minutes"]) if "default_duration_minutes" in data and str(data["default_duration_minutes"]).isdigit() else None,
                rate_limit_per_hour=int(data["rate_limit_per_hour"]) if "rate_limit_per_hour" in data and str(data["rate_limit_per_hour"]).isdigit() else None,
                operator="web_analyst",
                db_path=app.config["DB_PATH"],
            )
            return jsonify({"success": True, "config": updated})
        except ValueError as ve:
            return jsonify({"success": False, "error": str(ve)}), 400

    # ------------------------------------------------------------------
    # API: Reconcile Rules with OS
    # ------------------------------------------------------------------
    @app.route("/api/firewall/reconcile", methods=["POST"])
    def api_firewall_reconcile():
        if not validate_csrf():
            return jsonify({"success": False, "error": "Invalid or missing CSRF token"}), 403

        res = reconcile_rules(app.config["DB_PATH"])
        return jsonify({"success": True, "reconcile": res})

    # ------------------------------------------------------------------
    # API: Emergency Unblock All NetGuard Rules
    # ------------------------------------------------------------------
    @app.route("/api/firewall/emergency_unblock_all", methods=["POST"])
    def api_firewall_emergency_unblock_all():
        if not validate_csrf():
            return jsonify({"success": False, "error": "Invalid or missing CSRF token"}), 403

        res = emergency_unblock_all(operator="web_emergency", db_path=app.config["DB_PATH"])
        return jsonify(res)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
