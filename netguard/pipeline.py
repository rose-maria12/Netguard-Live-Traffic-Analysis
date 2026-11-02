import hashlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import scapy
from netguard.config import load_config
from netguard.correlation.dedup import deduplicate_findings
from netguard.correlation.engine import Incident, correlate_alerts, save_alerts_to_db, save_incidents_to_db
from netguard.db import DEFAULT_DB_PATH, get_db, init_db
from netguard.detection.allowlist import AllowList
from netguard.detection.brute_force import detect_brute_force
from netguard.detection.dns_anomaly import detect_dns_anomaly
from netguard.detection.iforest import find_model_id, load_model_bundle, score_windows_with_model
from netguard.detection.outbound import detect_abnormal_outbound
from netguard.detection.port_scan import detect_port_scan
from netguard.evidence.wireshark import (
    extract_trigger_frames,
    generate_bidirectional_wireshark_filter,
    generate_wireshark_filter,
)
from netguard.features.window_features import extract_window_features_for_capture
from netguard.ingest.flow_builder import build_flows_for_capture
from netguard.ingest.pcap_reader import calculate_sha256, parse_pcap_stream
from netguard.version import __version__ as NETGUARD_VERSION

CAPTURES_DIR = Path(__file__).resolve().parent.parent / "data" / "captures"


def import_capture(
    file_path: Union[str, Path],
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Import a PCAP or PCAPng file into SQLite database.
    - Validates file format and size
    - Computes SHA-256
    - Preserves 1-based Wireshark frame numbers
    - Stores packet records and DNS events in SQLite in a single transaction
    Returns the capture record dictionary.
    """
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        raise FileNotFoundError(f"Capture file not found: {file_path}")

    if config is None:
        config = load_config()

    max_pcap_mb = config.get("general", {}).get("max_pcap_mb", 50)
    max_frames = config.get("general", {}).get("max_frames", 500000)

    # Initialize DB schema if not existing
    init_db(db_path)

    # Calculate SHA-256 and size
    sha256_hex, file_size = calculate_sha256(file_path)

    # Check for existing capture with same SHA-256
    conn = get_db(db_path)
    try:
        cursor = conn.execute("SELECT * FROM captures WHERE sha256 = ?;", (sha256_hex,))
        row = cursor.fetchone()
        if row:
            existing_id = row["id"]
            if row["status"] == "ok":
                pkt_cnt = conn.execute("SELECT COUNT(*) FROM packets WHERE capture_id = ?;", (existing_id,)).fetchone()[0]
                flow_cnt = conn.execute("SELECT COUNT(*) FROM flows WHERE capture_id = ?;", (existing_id,)).fetchone()[0]
                if pkt_cnt > 0 and flow_cnt > 0:
                    return dict(row)
                if pkt_cnt > 0 and flow_cnt == 0:
                    conn.close()
                    build_flows_for_capture(existing_id, db_path=db_path, config=config)
                    conn = get_db(db_path)
                    return dict(conn.execute("SELECT * FROM captures WHERE id = ?;", (existing_id,)).fetchone())
            # If status != 'ok' or packets were never stored (e.g. legacy live record), remove stale row and re-ingest
            conn.execute("DELETE FROM captures WHERE id = ?;", (existing_id,))
            conn.commit()

        # Prepare copy in data/captures
        CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
        stored_filename = f"{sha256_hex[:16]}_{uuid.uuid4().hex[:8]}{file_path.suffix}"
        stored_path = CAPTURES_DIR / stored_filename
        shutil.copy2(file_path, stored_path)

        now_ts = time.time()
        scapy_ver = getattr(scapy, "__version__", "unknown")

        # Insert initial importing record
        cursor = conn.execute(
            """
            INSERT INTO captures (
                filename, stored_path, sha256, size_bytes, file_format, link_type,
                frames_total, packets_stored, frames_skipped, skipped_json,
                first_ts, last_ts, source, status, imported_at,
                netguard_version, scapy_version
            ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, '{}', NULL, NULL, 'upload', 'importing', ?, ?, ?);
            """,
            (
                file_path.name,
                str(stored_path),
                sha256_hex,
                file_size,
                "unknown",
                "Ethernet",
                now_ts,
                NETGUARD_VERSION,
                scapy_ver,
            ),
        )
        capture_id = cursor.lastrowid
        conn.commit()

        # Parse stream and insert packet / DNS records in batches
        packet_batch: list[
            Tuple[
                int,
                int,
                float,
                str,
                str,
                Optional[int],
                Optional[int],
                str,
                int,
                Optional[int],
                int,
            ]
        ] = []
        dns_batch: list[
            Tuple[
                int,
                int,
                float,
                str,
                str,
                str,
                int,
                int,
                int,
                int,
                Optional[int],
                int,
            ]
        ] = []

        summary_data: Optional[Dict[str, Any]] = None

        stream = parse_pcap_stream(stored_path, max_frames=max_frames, max_pcap_mb=max_pcap_mb)

        conn.execute("BEGIN TRANSACTION;")
        for item in stream:
            if item["type"] == "packet":
                packet_batch.append(
                    (
                        capture_id,
                        item["frame_no"],
                        item["ts"],
                        item["src_ip"],
                        item["dst_ip"],
                        item["src_port"],
                        item["dst_port"],
                        item["proto"],
                        item["length"],
                        item["tcp_flags"],
                        item["ttl"],
                    )
                )
                if len(packet_batch) >= 5000:
                    conn.executemany(
                        """
                        INSERT INTO packets (
                            capture_id, frame_no, ts, src_ip, dst_ip, src_port, dst_port,
                            proto, length, tcp_flags, ttl
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        packet_batch,
                    )
                    packet_batch.clear()

            elif item["type"] == "dns":
                dns_batch.append(
                    (
                        capture_id,
                        item["frame_no"],
                        item["ts"],
                        item["client_ip"],
                        item["server_ip"],
                        item["qname"],
                        item["qname_len"],
                        item["max_label_len"],
                        item["qtype"],
                        item["is_response"],
                        item["rcode"],
                        item["txid"],
                    )
                )
                if len(dns_batch) >= 5000:
                    conn.executemany(
                        """
                        INSERT INTO dns_events (
                            capture_id, frame_no, ts, client_ip, server_ip, qname,
                            qname_len, max_label_len, qtype, is_response, rcode, txid
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        dns_batch,
                    )
                    dns_batch.clear()

            elif item["type"] == "summary":
                summary_data = item

        # Insert remaining batches
        if packet_batch:
            conn.executemany(
                """
                INSERT INTO packets (
                    capture_id, frame_no, ts, src_ip, dst_ip, src_port, dst_port,
                    proto, length, tcp_flags, ttl
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                packet_batch,
            )
            packet_batch.clear()

        if dns_batch:
            conn.executemany(
                """
                INSERT INTO dns_events (
                    capture_id, frame_no, ts, client_ip, server_ip, qname,
                    qname_len, max_label_len, qtype, is_response, rcode, txid
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                dns_batch,
            )
            dns_batch.clear()

        if summary_data is None:
            raise ValueError("Failed to parse PCAP stream: no summary generated.")

        skipped_json_str = json.dumps(summary_data["skipped_counts"])
        conn.execute(
            """
            UPDATE captures SET
                file_format = ?,
                frames_total = ?,
                packets_stored = ?,
                frames_skipped = ?,
                skipped_json = ?,
                first_ts = ?,
                last_ts = ?,
                status = 'ok'
            WHERE id = ?;
            """,
            (
                summary_data["file_format"],
                summary_data["frames_total"],
                summary_data["packets_stored"],
                summary_data["frames_skipped"],
                skipped_json_str,
                summary_data["first_ts"],
                summary_data["last_ts"],
                capture_id,
            ),
        )
        conn.commit()

        # Phase 2: Build bidirectional flows for the capture
        conn.close()
        build_flows_for_capture(capture_id, db_path=db_path, config=config)

        conn = get_db(db_path)
        cursor = conn.execute("SELECT * FROM captures WHERE id = ?;", (capture_id,))
        return dict(cursor.fetchone())

    except Exception as e:
        conn.rollback()
        if "capture_id" in locals() and capture_id is not None:
            conn.execute(
                "UPDATE captures SET status = 'failed', error = ? WHERE id = ?;",
                (str(e), capture_id),
            )
            conn.commit()
        raise e
    finally:
        conn.close()


def run_analysis(
    capture_id: int,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    config: Optional[Dict[str, Any]] = None,
    model_name: str = "default_baseline",
) -> Dict[str, Any]:
    """
    Run full end-to-end detection, correlation, and scoring analysis on an imported capture.
    """
    if config is None:
        config = load_config()

    init_db(db_path)
    conn = get_db(db_path)

    try:
        # Verify capture exists
        cursor = conn.execute("SELECT * FROM captures WHERE id = ?;", (capture_id,))
        cap_row = cursor.fetchone()
        if not cap_row:
            raise ValueError(f"Capture ID {capture_id} not found.")

        if cap_row["status"] != "ok":
            raise ValueError(f"Capture ID {capture_id} status is '{cap_row['status']}', cannot analyze.")

        import sklearn

        scapy_ver = getattr(scapy, "__version__", "unknown")
        sklearn_ver = getattr(sklearn, "__version__", "unknown")

        config_json_str = json.dumps(config)
        config_sha256 = hashlib.sha256(config_json_str.encode("utf-8")).hexdigest()
        seed = int(config.get("general", {}).get("seed", 42))
        started_at = time.time()

        # Insert runs record
        cursor = conn.execute(
            """
            INSERT INTO runs (
                capture_id, model_id, config_json, config_sha256, seed,
                started_at, status, python_version, sklearn_version,
                scapy_version, netguard_version
            ) VALUES (?, NULL, ?, ?, ?, ?, 'running', '3.14', ?, ?, ?);
            """,
            (
                capture_id,
                config_json_str,
                config_sha256,
                seed,
                started_at,
                sklearn_ver,
                scapy_ver,
                NETGUARD_VERSION,
            ),
        )
        run_id = cursor.lastrowid
        conn.commit()

        # Fetch packets for detection
        cursor = conn.execute("SELECT * FROM packets WHERE capture_id = ?;", (capture_id,))
        packets = [dict(r) for r in cursor.fetchall()]

        # Fetch flows for detection
        cursor = conn.execute("SELECT * FROM flows WHERE capture_id = ?;", (capture_id,))
        flows = [dict(r) for r in cursor.fetchall()]

        # Fetch DNS events for detection
        cursor = conn.execute("SELECT * FROM dns_events WHERE capture_id = ?;", (capture_id,))
        dns_events = [dict(r) for r in cursor.fetchall()]

        conn.close()

        # Extract feature windows
        feat_rows = extract_window_features_for_capture(
            capture_id, run_id=run_id, db_path=db_path, config=config
        )

        all_findings = []

        # 1. Port scan detector
        ps_findings = detect_port_scan(flows, config=config)
        all_findings.extend(ps_findings)

        # 2. Brute force detector
        bf_findings = detect_brute_force(flows, config=config)
        all_findings.extend(bf_findings)

        # 3. DNS anomaly detector
        dns_findings = detect_dns_anomaly(dns_events, config=config)
        all_findings.extend(dns_findings)

        # 4. Abnormal outbound detector
        outbound_findings = detect_abnormal_outbound(flows, packets, config=config)
        all_findings.extend(outbound_findings)

        # 5. Isolation Forest ML detector
        ml_model_id = None
        if config.get("ml", {}).get("enabled", True):
            try:
                bundle = load_model_bundle(model_name)
                ml_model_id = find_model_id(
                    bundle.get("model_path", ""), db_path=db_path, model_name=model_name
                )
                if feat_rows and bundle:
                    ml_findings, feat_rows = score_windows_with_model(
                        feat_rows, bundle, config=config
                    )
                    all_findings.extend(ml_findings)
                    fw_updates = [
                        (
                            r.get("if_score"),
                            int(r.get("if_flag", 0)),
                            r.get("top_features_json"),
                            r["id"],
                        )
                        for r in feat_rows
                        if r.get("id") is not None
                    ]
                    if fw_updates:
                        with get_db(db_path) as fw_conn:
                            fw_conn.executemany(
                                "UPDATE feature_windows SET if_score = ?, if_flag = ?, top_features_json = ? WHERE id = ?;",
                                fw_updates,
                            )
                            fw_conn.commit()
            except (FileNotFoundError, Exception):
                pass

        # Filter allowlisted findings
        allowlist = AllowList(config.get("allowlist", {}))
        filtered_findings = allowlist.filter_findings(all_findings)

        # Deduplicate findings
        deduped_findings = deduplicate_findings(filtered_findings, config=config)

        # Generate Wireshark display filters for each deduplicated finding
        for f in deduped_findings:
            ws_filter = generate_wireshark_filter(f)
            f.details["wireshark_filter"] = ws_filter
            f.details["wireshark_bi_filter"] = generate_bidirectional_wireshark_filter(f)
            f.details["trigger_frames"] = extract_trigger_frames(f)

        # Save alerts to DB
        alert_ids = save_alerts_to_db(deduped_findings, run_id=run_id, db_path=db_path)

        # Correlate alerts into incidents
        incidents = correlate_alerts(deduped_findings, config=config)

        # Save incidents to DB
        inc_ids = save_incidents_to_db(incidents, run_id=run_id, db_path=db_path)

        finished_at = time.time()
        stats_data = {
            "alerts_count": len(deduped_findings),
            "incidents_count": len(incidents),
            "rule_alerts": sum(1 for a in deduped_findings if a.detector == "rule"),
            "ml_alerts": sum(1 for a in deduped_findings if a.detector == "iforest"),
        }

        conn = get_db(db_path)
        conn.execute(
            """
            UPDATE runs SET
                model_id = ?,
                finished_at = ?,
                status = 'completed',
                stats_json = ?
            WHERE id = ?;
            """,
            (ml_model_id, finished_at, json.dumps(stats_data), run_id),
        )
        conn.commit()

        return {
            "run_id": run_id,
            "capture_id": capture_id,
            "status": "completed",
            "alerts_count": len(deduped_findings),
            "incidents_count": len(incidents),
            "incidents": incidents,
            "stats": stats_data,
        }

    except Exception as e:
        conn = get_db(db_path)
        conn.execute(
            "UPDATE runs SET status = 'failed', error = ? WHERE id = ?;",
            (str(e), run_id if "run_id" in locals() else None),
        )
        conn.commit()
        raise e
    finally:
        conn.close()
