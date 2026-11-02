import math
from typing import Any, Dict, List, Optional, Tuple
from netguard.config import load_config
from netguard.detection.base import Finding, calculate_severity, get_suggested_precautions


def detect_brute_force(
    flows: List[Dict[str, Any]], config: Optional[Dict[str, Any]] = None
) -> List[Finding]:
    """
    Detect brute-force-like connection activity on authentication service ports.
    Grouped by (initiator_ip, responder_ip, responder_port, window).
    Triggers when attempts >= min_attempts AND short_ratio >= min_short_ratio.
    Returns list of Finding objects.
    """
    if config is None:
        config = load_config()

    bf_config = config.get("detectors", {}).get("brute_force", {})
    if not bf_config.get("enabled", True):
        return []

    service_ports = set(bf_config.get("service_ports", [21, 22, 23, 3389, 5900]))
    min_attempts = int(bf_config.get("min_attempts", 10))
    short_flow_seconds = float(bf_config.get("short_flow_seconds", 5))
    min_short_ratio = float(bf_config.get("min_short_ratio", 0.5))
    confidence = float(bf_config.get("confidence", 0.7))
    window_seconds = float(config.get("general", {}).get("window_seconds", 20))

    # Filter TCP flows matching authentication service ports
    tcp_flows = [
        f for f in flows if f["proto"] == "TCP" and (f["responder_port"] in service_ports)
    ]

    # Group flows by (initiator_ip, responder_ip, responder_port, window_start)
    groups: Dict[Tuple[str, str, int, float], List[Dict[str, Any]]] = {}
    for f in tcp_flows:
        w_start = math.floor(float(f["start_ts"]) / window_seconds) * window_seconds
        key = (f["initiator_ip"], f["responder_ip"], int(f["responder_port"]), w_start)
        if key not in groups:
            groups[key] = []
        groups[key].append(f)

    findings: List[Finding] = []

    # Sort keys for deterministic output ordering
    for (src_ip, dst_ip, dst_port, w_start) in sorted(groups.keys()):
        grp_flows = groups[(src_ip, dst_ip, dst_port, w_start)]

        attempts = len(grp_flows)
        short_established = sum(
            1
            for f in grp_flows
            if f["state"] == "established"
            and (float(f["end_ts"]) - float(f["start_ts"])) <= short_flow_seconds
        )
        short_ratio = float(short_established) / float(attempts) if attempts > 0 else 0.0

        if (attempts >= min_attempts) and (short_ratio >= min_short_ratio):
            start_ts = min(float(f["start_ts"]) for f in grp_flows)
            end_ts = max(float(f["end_ts"]) for f in grp_flows)
            first_frame = min(int(f["first_frame"]) for f in grp_flows)
            last_frame = max(int(f["last_frame"]) for f in grp_flows)

            severity = calculate_severity(attempts, min_attempts)
            short_pct = short_ratio * 100.0

            summary = (
                f"{src_ip} opened {attempts} short connections to {dst_ip}:{dst_port} within {int(window_seconds)} s "
                f"(threshold: {min_attempts}). Pattern indicator only; encrypted payloads not inspected."
            )

            sorted_flows = sorted(grp_flows, key=lambda x: (x["start_ts"], x["first_frame"]))
            evidence_refs = []
            for f in sorted_flows[:50]:  # Cap at 50
                evidence_refs.append(
                    {
                        "ref_type": "flow",
                        "ref_id": f.get("id", 0),
                        "frame_no": f["first_frame"],
                        "note": f"Short TCP flow to :{dst_port} (duration: {float(f['end_ts'])-float(f['start_ts']):.2f}s, state: {f['state']})",
                    }
                )

            details = {
                "triggered_checks": ["repeated_short_connections"],
                "primary_metric": "attempts",
                "observed_attempts": attempts,
                "observed_short_ratio": round(short_ratio, 4),
                "threshold_attempts": min_attempts,
                "threshold_short_ratio": min_short_ratio,
                "short_flow_seconds": short_flow_seconds,
                "service_port": dst_port,
                "first_frame": first_frame,
                "last_frame": last_frame,
                "encrypted_payloads_inspected": False,
                "suggested_precautions": get_suggested_precautions("brute_force"),
            }

            finding = Finding(
                alert_type="brute_force",
                detector="rule",
                rule_name="repeated_short_connections",
                severity=severity,
                confidence=confidence,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                start_ts=start_ts,
                end_ts=end_ts,
                stage="Access Attempt",
                summary=summary,
                details=details,
                evidence_refs=evidence_refs,
            )
            findings.append(finding)

    return findings
