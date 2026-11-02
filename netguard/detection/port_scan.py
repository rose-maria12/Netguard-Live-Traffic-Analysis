import math
from typing import Any, Dict, List, Tuple
from netguard.config import load_config
from netguard.detection.base import Finding, calculate_severity, get_suggested_precautions


def detect_port_scan(
    flows: List[Dict[str, Any]], config: Optional[Dict[str, Any]] = None
) -> List[Finding]:
    """
    Detect vertical port scanning from TCP flows.
    Grouped by (initiator_ip, responder_ip, window).
    Triggers when distinct_dst_ports >= min_distinct_ports AND failed_ratio >= min_failed_ratio.
    Returns list of Finding objects.
    """
    if config is None:
        config = load_config()

    ps_config = config.get("detectors", {}).get("port_scan", {})
    if not ps_config.get("enabled", True):
        return []

    min_distinct_ports = int(ps_config.get("min_distinct_ports", 15))
    min_failed_ratio = float(ps_config.get("min_failed_ratio", 0.7))
    confidence = float(ps_config.get("confidence", 0.9))
    window_seconds = float(config.get("general", {}).get("window_seconds", 20))

    # Filter TCP flows
    tcp_flows = [f for f in flows if f["proto"] == "TCP"]

    # Group flows by (initiator_ip, responder_ip, window_start)
    groups: Dict[Tuple[str, str, float], List[Dict[str, Any]]] = {}
    for f in tcp_flows:
        w_start = math.floor(float(f["start_ts"]) / window_seconds) * window_seconds
        key = (f["initiator_ip"], f["responder_ip"], w_start)
        if key not in groups:
            groups[key] = []
        groups[key].append(f)

    findings: List[Finding] = []

    # Sort keys for deterministic output ordering
    for (src_ip, dst_ip, w_start) in sorted(groups.keys()):
        grp_flows = groups[(src_ip, dst_ip, w_start)]

        # Calculate metrics
        dst_ports = set(f["responder_port"] for f in grp_flows if f["responder_port"] is not None)
        distinct_dst_ports = len(dst_ports)

        total_flows = len(grp_flows)
        failed_count = sum(1 for f in grp_flows if f["state"] in ("no_response", "reset"))
        failed_ratio = float(failed_count) / float(total_flows) if total_flows > 0 else 0.0

        # Trigger check
        if (distinct_dst_ports >= min_distinct_ports) and (failed_ratio >= min_failed_ratio):
            start_ts = min(float(f["start_ts"]) for f in grp_flows)
            end_ts = max(float(f["end_ts"]) for f in grp_flows)
            first_frame = min(int(f["first_frame"]) for f in grp_flows)
            last_frame = max(int(f["last_frame"]) for f in grp_flows)

            severity = calculate_severity(distinct_dst_ports, min_distinct_ports)

            failed_pct = failed_ratio * 100.0
            thresh_pct = min_failed_ratio * 100.0
            summary = (
                f"{src_ip} probed {distinct_dst_ports} distinct ports on {dst_ip} within {int(window_seconds)} s; "
                f"{failed_pct:.0f}% of connections failed (thresholds: {min_distinct_ports} ports, {thresh_pct:.0f}% failed)."
            )

            # Sort evidence flows by start_ts and first_frame for determinism
            sorted_flows = sorted(grp_flows, key=lambda x: (x["start_ts"], x["first_frame"]))
            evidence_refs = []
            for f in sorted_flows[:50]:  # Cap at max_per_alert = 50
                evidence_refs.append(
                    {
                        "ref_type": "flow",
                        "ref_id": f.get("id", 0),
                        "frame_no": f["first_frame"],
                        "note": f"TCP SYN to :{f['responder_port']} ({f['state']})",
                    }
                )

            details = {
                "triggered_checks": ["port_scan_vertical"],
                "primary_metric": "distinct_dst_ports",
                "observed_ports": distinct_dst_ports,
                "observed_failed_ratio": round(failed_ratio, 4),
                "threshold_ports": min_distinct_ports,
                "threshold_failed_ratio": min_failed_ratio,
                "total_flows": total_flows,
                "first_frame": first_frame,
                "last_frame": last_frame,
                "suggested_precautions": get_suggested_precautions("port_scan"),
            }

            finding = Finding(
                alert_type="port_scan",
                detector="rule",
                rule_name="port_scan_vertical",
                severity=severity,
                confidence=confidence,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=None,
                start_ts=start_ts,
                end_ts=end_ts,
                stage="Reconnaissance",
                summary=summary,
                details=details,
                evidence_refs=evidence_refs,
            )
            findings.append(finding)

    return findings
