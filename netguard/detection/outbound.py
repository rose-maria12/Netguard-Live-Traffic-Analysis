import math
from typing import Any, Dict, List, Optional, Tuple
from netguard.config import load_config
from netguard.detection.base import Finding, calculate_severity, get_suggested_precautions
from netguard.features.window_features import is_external_ip, is_internal_ip, parse_internal_cidrs


def detect_abnormal_outbound(
    flows: List[Dict[str, Any]],
    packets: List[Dict[str, Any]],
    config: Optional[Dict[str, Any]] = None,
) -> List[Finding]:
    """
    Detect abnormal outbound traffic patterns (large volume, high upload ratio, unusual destination ports).
    Grouped by (internal_src_ip, external_dst_ip, window).
    Returns list of Finding objects.
    """
    if config is None:
        config = load_config()

    out_config = config.get("detectors", {}).get("outbound", {})
    if not out_config.get("enabled", True):
        return []

    bytes_per_window = int(out_config.get("bytes_per_window", 1000000))
    min_bytes_for_ratio = int(out_config.get("min_bytes_for_ratio", 200000))
    upload_ratio_thresh = float(out_config.get("upload_ratio", 20.0))
    allowed_ports = set(out_config.get("allowed_ports", [53, 80, 123, 443]))
    unusual_port_bytes_thresh = int(out_config.get("unusual_port_bytes", 200000))
    confidence = float(out_config.get("confidence", 0.6))
    window_seconds = float(config.get("general", {}).get("window_seconds", 20))

    internal_cidrs_str = config.get("networks", {}).get("internal_cidrs", ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"])
    internal_nets = parse_internal_cidrs(internal_cidrs_str)

    # Group packets by (internal_src_ip, external_dst_ip, window_start)
    groups: Dict[Tuple[str, str, float], Dict[str, Any]] = {}

    for p in packets:
        src_ip = p["src_ip"]
        dst_ip = p["dst_ip"]
        ts = float(p["ts"])
        length = int(p["length"])
        w_start = math.floor(ts / window_seconds) * window_seconds

        # Internal -> External traffic
        if is_internal_ip(src_ip, internal_nets) and is_external_ip(dst_ip, internal_nets):
            key = (src_ip, dst_ip, w_start)
            if key not in groups:
                groups[key] = {
                    "bytes_out": 0,
                    "bytes_in": 0,
                    "out_packets": [],
                    "in_packets": [],
                }
            groups[key]["bytes_out"] += length
            groups[key]["out_packets"].append(p)

        # External -> Internal traffic (reverse direction in same window)
        elif is_external_ip(src_ip, internal_nets) and is_internal_ip(dst_ip, internal_nets):
            key = (dst_ip, src_ip, w_start)
            if key not in groups:
                groups[key] = {
                    "bytes_out": 0,
                    "bytes_in": 0,
                    "out_packets": [],
                    "in_packets": [],
                }
            groups[key]["bytes_in"] += length
            groups[key]["in_packets"].append(p)

    # Map flows by (initiator_ip, responder_ip, window_start) across all windows spanned by the flow
    flow_map: Dict[Tuple[str, str, float], List[Dict[str, Any]]] = {}
    for f in flows:
        start_w = math.floor(float(f["start_ts"]) / window_seconds) * window_seconds
        end_w = math.floor(float(f.get("end_ts", f["start_ts"])) / window_seconds) * window_seconds
        w_curr = start_w
        while w_curr <= end_w:
            key = (f["initiator_ip"], f["responder_ip"], w_curr)
            if key not in flow_map:
                flow_map[key] = []
            flow_map[key].append(f)
            w_curr += window_seconds

    findings: List[Finding] = []

    # Process groups deterministically
    for (src_ip, dst_ip, w_start) in sorted(groups.keys()):
        grp = groups[(src_ip, dst_ip, w_start)]
        bytes_out = grp["bytes_out"]
        bytes_in = grp["bytes_in"]

        if bytes_out == 0:
            continue

        out_in_ratio = float(bytes_out) / float(bytes_in) if bytes_in > 0 else 0.0

        # Check unusual ports byte volume
        pair_flows = flow_map.get((src_ip, dst_ip, w_start), [])
        unusual_port_bytes = sum(
            int(f["bytes_fwd"])
            for f in pair_flows
            if f.get("responder_port") is not None and f["responder_port"] not in allowed_ports
        )

        triggered_checks = []
        ratios: Dict[str, float] = {}

        # Check 1: Outbound Volume
        if bytes_per_window > 0 and bytes_out >= bytes_per_window:
            triggered_checks.append("outbound_volume")
            ratios["outbound_volume"] = float(bytes_out) / float(bytes_per_window)

        # Check 2: Upload Ratio (requires bytes_in > 0 for bidirectional ratio assessment)
        if bytes_in > 0 and bytes_out >= min_bytes_for_ratio and upload_ratio_thresh > 0 and out_in_ratio >= upload_ratio_thresh:
            triggered_checks.append("outbound_ratio")
            ratios["outbound_ratio"] = out_in_ratio / upload_ratio_thresh

        # Check 3: Unusual Destination Ports
        if unusual_port_bytes_thresh > 0 and unusual_port_bytes >= unusual_port_bytes_thresh:
            triggered_checks.append("outbound_unusual_port")
            ratios["outbound_unusual_port"] = float(unusual_port_bytes) / float(unusual_port_bytes_thresh)

        if triggered_checks:
            all_grp_pkts = grp["out_packets"] + grp["in_packets"]
            start_ts = min(float(p["ts"]) for p in all_grp_pkts)
            end_ts = max(float(p["ts"]) for p in all_grp_pkts)
            first_frame = min(int(p["frame_no"]) for p in all_grp_pkts)
            last_frame = max(int(p["frame_no"]) for p in all_grp_pkts)

            strongest_rule = max(ratios.keys(), key=lambda k: ratios[k])
            max_ratio = ratios[strongest_rule]
            severity = calculate_severity(max_ratio, 1.0)

            mb_out = bytes_out / (1024.0 * 1024.0)
            summary = (
                f"{src_ip} sent {mb_out:.2f} MB to {dst_ip} in {int(window_seconds)} s "
                f"with an upload/download ratio of {out_in_ratio:.1f} ({', '.join(triggered_checks)}). "
                f"Indicator of abnormal outbound traffic."
            )

            # Sort evidence flows / packets
            sorted_flows = sorted(pair_flows, key=lambda x: (x["start_ts"], x["first_frame"]))
            evidence_refs = []
            for f in sorted_flows[:50]:
                evidence_refs.append(
                    {
                        "ref_type": "flow",
                        "ref_id": f.get("id", 0),
                        "frame_no": f["first_frame"],
                        "note": f"Outbound flow to {dst_ip}:{f['responder_port']} ({f['bytes_fwd']} bytes)",
                    }
                )

            details = {
                "triggered_checks": triggered_checks,
                "strongest_check": strongest_rule,
                "primary_metric": strongest_rule,
                "observed_bytes_out": bytes_out,
                "observed_bytes_in": bytes_in,
                "observed_out_in_ratio": round(out_in_ratio, 4),
                "observed_unusual_port_bytes": unusual_port_bytes,
                "threshold_bytes_per_window": bytes_per_window,
                "threshold_upload_ratio": upload_ratio_thresh,
                "threshold_unusual_port_bytes": unusual_port_bytes_thresh,
                "first_frame": first_frame,
                "last_frame": last_frame,
                "suggested_precautions": get_suggested_precautions("abnormal_outbound"),
            }

            finding = Finding(
                alert_type="abnormal_outbound",
                detector="rule",
                rule_name=strongest_rule,
                severity=severity,
                confidence=confidence,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=None,
                start_ts=start_ts,
                end_ts=end_ts,
                stage="Possible Exfiltration",
                summary=summary,
                details=details,
                evidence_refs=evidence_refs,
            )
            findings.append(finding)

    return findings
