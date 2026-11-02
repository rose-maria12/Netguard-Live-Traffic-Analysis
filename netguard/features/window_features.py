import ipaddress
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from netguard.config import load_config
from netguard.db import DEFAULT_DB_PATH, get_db


def parse_internal_cidrs(cidrs: List[str]) -> List[ipaddress.IPv4Network]:
    """
    Parse a list of CIDR strings into ipaddress.IPv4Network objects.
    """
    networks = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


def is_internal_ip(ip_str: str, internal_nets: List[ipaddress.IPv4Network]) -> bool:
    """
    Check if an IPv4 address string falls within configured internal CIDRs.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local or ip_obj.is_unspecified:
            return False
        return any(ip_obj in net for net in internal_nets)
    except ValueError:
        return False


def is_external_ip(ip_str: str, internal_nets: List[ipaddress.IPv4Network]) -> bool:
    """
    Check if an IPv4 address string is external (unicast, non-internal, non-special).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local or ip_obj.is_unspecified or ip_obj.is_reserved:
            return False
        return not any(ip_obj in net for net in internal_nets)
    except ValueError:
        return False


def extract_window_features_for_capture(
    capture_id: int,
    run_id: Optional[int] = None,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    config: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Extract 20-second tumbling host-window feature rows for all internal hosts in a capture.
    Stores extracted rows in feature_windows table if run_id is provided.
    Returns list of feature dictionaries.
    """
    if config is None:
        config = load_config()

    window_seconds = float(config.get("general", {}).get("window_seconds", 20))
    internal_cidrs_str = config.get("networks", {}).get("internal_cidrs", ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"])
    internal_nets = parse_internal_cidrs(internal_cidrs_str)

    dns_servers = set(config.get("infrastructure", {}).get("dns_servers", []))
    gateways = set(config.get("infrastructure", {}).get("gateways", []))
    allow_src_ips = set(config.get("allowlist", {}).get("src_ips", []))
    excluded_hosts = dns_servers | gateways | allow_src_ips

    conn = get_db(db_path)
    try:
        # Fetch packet time bounds
        cursor = conn.execute(
            "SELECT MIN(ts) as min_ts, MAX(ts) as max_ts FROM packets WHERE capture_id = ?;",
            (capture_id,),
        )
        row = cursor.fetchone()
        if not row or row["min_ts"] is None or row["max_ts"] is None:
            return []

        min_ts = float(row["min_ts"])
        max_ts = float(row["max_ts"])

        start_time = math.floor(min_ts / window_seconds) * window_seconds
        end_time = math.ceil((max_ts + 0.001) / window_seconds) * window_seconds

        # Pre-fetch all packets for the capture
        cursor = conn.execute(
            """
            SELECT frame_no, ts, src_ip, dst_ip, src_port, dst_port, proto, length
            FROM packets
            WHERE capture_id = ?
            ORDER BY ts ASC, frame_no ASC;
            """,
            (capture_id,),
        )
        all_packets = [dict(r) for r in cursor.fetchall()]

        # Pre-fetch all flows for the capture
        cursor = conn.execute(
            """
            SELECT initiator_ip, responder_ip, initiator_port, responder_port, proto, start_ts, state
            FROM flows
            WHERE capture_id = ?
            ORDER BY start_ts ASC;
            """,
            (capture_id,),
        )
        all_flows = [dict(r) for r in cursor.fetchall()]

        # Pre-fetch all DNS events for the capture
        cursor = conn.execute(
            """
            SELECT frame_no, ts, client_ip, server_ip, qname, qname_len, is_response, rcode
            FROM dns_events
            WHERE capture_id = ?
            ORDER BY ts ASC;
            """,
            (capture_id,),
        )
        all_dns = [dict(r) for r in cursor.fetchall()]

        feature_rows: List[Dict[str, Any]] = []

        current_wstart = start_time
        while current_wstart < max_ts:
            current_wend = current_wstart + window_seconds

            # Filter packets in window
            w_pkts = [p for p in all_packets if current_wstart <= p["ts"] < current_wend]
            if not w_pkts:
                current_wstart = current_wend
                continue

            # Identify internal hosts that sent at least 1 packet in this window
            internal_hosts: Set[str] = set()
            for p in w_pkts:
                src_ip = p["src_ip"]
                if is_internal_ip(src_ip, internal_nets) and (src_ip not in excluded_hosts):
                    internal_hosts.add(src_ip)

            if not internal_hosts:
                current_wstart = current_wend
                continue

            # Filter flows starting in window
            w_flows = [f for f in all_flows if current_wstart <= f["start_ts"] < current_wend]

            # Filter DNS events in window
            w_dns = [d for d in all_dns if current_wstart <= d["ts"] < current_wend]

            for host in sorted(internal_hosts):
                # Packets for host in window (sent or received)
                host_sent_pkts = [p for p in w_pkts if p["src_ip"] == host]
                host_all_pkts = [p for p in w_pkts if p["src_ip"] == host or p["dst_ip"] == host]

                first_frame = min(p["frame_no"] for p in host_all_pkts)
                last_frame = max(p["frame_no"] for p in host_all_pkts)

                # Flows started by host in window
                host_flows = [f for f in w_flows if f["initiator_ip"] == host]

                # Feature 1 & 2: unique_dst_ports, unique_dst_ips
                dst_ports = set()
                dst_ips = set()
                for f in host_flows:
                    if f["responder_port"] is not None:
                        dst_ports.add(f["responder_port"])
                    dst_ips.add(f["responder_ip"])

                unique_dst_ports = len(dst_ports)
                unique_dst_ips = len(dst_ips)

                # Feature 3: failed_flow_ratio
                total_flows = len(host_flows)
                if total_flows > 0:
                    failed_count = sum(1 for f in host_flows if f["state"] in ("no_response", "reset"))
                    failed_flow_ratio = float(failed_count) / float(total_flows)
                else:
                    failed_flow_ratio = 0.0

                # Feature 4: max_flows_same_target
                if total_flows > 0:
                    target_counts: Dict[Tuple[str, Optional[int]], int] = {}
                    for f in host_flows:
                        target = (f["responder_ip"], f["responder_port"])
                        target_counts[target] = target_counts.get(target, 0) + 1
                    max_flows_same_target = max(target_counts.values()) if target_counts else 0
                else:
                    max_flows_same_target = 0

                # Feature 5, 6, 7: DNS metrics
                host_queries = [d for d in w_dns if d["client_ip"] == host and d["is_response"] == 0]
                host_responses = [d for d in w_dns if d["client_ip"] == host and d["is_response"] == 1]

                dns_query_count = len(host_queries)
                if dns_query_count > 0:
                    avg_qname_length = float(sum(d["qname_len"] for d in host_queries)) / float(dns_query_count)
                else:
                    avg_qname_length = 0.0

                total_responses = len(host_responses)
                if total_responses > 0:
                    nxdomain_count = sum(1 for d in host_responses if d["rcode"] == 3)
                    nxdomain_ratio = float(nxdomain_count) / float(total_responses)
                else:
                    nxdomain_ratio = 0.0

                # Feature 8 & 9: Outbound external bytes & ratio
                bytes_out_ext = sum(
                    p["length"] for p in host_sent_pkts if is_external_ip(p["dst_ip"], internal_nets)
                )

                host_recv_pkts = [p for p in w_pkts if p["dst_ip"] == host]
                bytes_in_ext = sum(
                    p["length"] for p in host_recv_pkts if is_external_ip(p["src_ip"], internal_nets)
                )

                out_in_ratio = float(bytes_out_ext) / (float(bytes_in_ext) + 1.0)

                feat_dict = {
                    "run_id": run_id,
                    "host_ip": host,
                    "window_start": current_wstart,
                    "window_end": current_wend,
                    "unique_dst_ports": unique_dst_ports,
                    "unique_dst_ips": unique_dst_ips,
                    "failed_flow_ratio": round(failed_flow_ratio, 6),
                    "max_flows_same_target": max_flows_same_target,
                    "dns_query_count": dns_query_count,
                    "avg_qname_length": round(avg_qname_length, 4),
                    "nxdomain_ratio": round(nxdomain_ratio, 6),
                    "bytes_out_external": bytes_out_ext,
                    "out_in_ratio": round(out_in_ratio, 6),
                    "first_frame": first_frame,
                    "last_frame": last_frame,
                    "if_score": None,
                    "if_flag": 0,
                    "top_features_json": None,
                }
                feature_rows.append(feat_dict)

            current_wstart = current_wend

        # If run_id provided, persist to feature_windows table and attach inserted row id
        if run_id is not None and feature_rows:
            conn.execute("BEGIN TRANSACTION;")
            for row in feature_rows:
                cur = conn.execute(
                    """
                    INSERT INTO feature_windows (
                        run_id, host_ip, window_start, window_end, unique_dst_ports,
                        unique_dst_ips, failed_flow_ratio, max_flows_same_target,
                        dns_query_count, avg_qname_length, nxdomain_ratio,
                        bytes_out_external, out_in_ratio, first_frame, last_frame,
                        if_score, if_flag, top_features_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        row["run_id"],
                        row["host_ip"],
                        row["window_start"],
                        row["window_end"],
                        row["unique_dst_ports"],
                        row["unique_dst_ips"],
                        row["failed_flow_ratio"],
                        row["max_flows_same_target"],
                        row["dns_query_count"],
                        row["avg_qname_length"],
                        row["nxdomain_ratio"],
                        row["bytes_out_external"],
                        row["out_in_ratio"],
                        row["first_frame"],
                        row["last_frame"],
                        row["if_score"],
                        row["if_flag"],
                        row["top_features_json"],
                    ),
                )
                row["id"] = cur.lastrowid
            conn.commit()

        return feature_rows

    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()
