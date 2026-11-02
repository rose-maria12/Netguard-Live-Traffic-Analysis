from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SUGGESTED_PRECAUTIONS: Dict[str, str] = {
    "port_scan": "Check whether this is an authorised scan. Inspect the targeted ports. If an untrusted source is probing your laptop, consider a temporary inbound block.",
    "brute_force": "Check authentication logs for failed logins. Review successful logins from that source. Consider temporary blocking, MFA, and login rate limits.",
    "dns_anomaly": "Inspect the requested names and NXDOMAIN responses. Identify the application generating them. If unexplained, investigate the device and consider an endpoint security scan.",
    "abnormal_outbound": "Check for uploads, backups, or synchronisation. Identify the process and destination. If confirmed suspicious, consider restricting outbound access or isolating the device.",
    "ml_anomaly": "Review the unusual features, inspect supporting packets, and check whether rule detectors also flagged the activity. Avoid blocking solely because of the ML score.",
}

SCENARIO_FLAGS: Dict[str, str] = {
    "port_scan": "Port scan",
    "brute_force": "Brute-force-like activity",
    "dns_anomaly": "DNS anomaly",
    "abnormal_outbound": "Unusual outbound traffic",
    "ml_anomaly": "ML anomaly",
}


def get_suggested_precautions(flag_or_type: str) -> str:
    """
    Return the suggested precautions / next steps for a given scenario flag or alert type.
    """
    key = (flag_or_type or "").strip().lower()
    if key in SUGGESTED_PRECAUTIONS:
        return SUGGESTED_PRECAUTIONS[key]

    alias_map = {
        "port scan": "port_scan",
        "brute-force-like activity": "brute_force",
        "brute-force": "brute_force",
        "brute force": "brute_force",
        "dns anomaly": "dns_anomaly",
        "dns": "dns_anomaly",
        "unusual outbound traffic": "abnormal_outbound",
        "abnormal outbound": "abnormal_outbound",
        "outbound": "abnormal_outbound",
        "ml anomaly": "ml_anomaly",
        "ml": "ml_anomaly",
        "iforest": "ml_anomaly",
    }
    canonical = alias_map.get(key)
    if canonical and canonical in SUGGESTED_PRECAUTIONS:
        return SUGGESTED_PRECAUTIONS[canonical]
    return ""


@dataclass
class Finding:
    alert_type: str
    detector: str
    rule_name: str
    severity: str
    confidence: float
    src_ip: str
    dst_ip: Optional[str]
    dst_port: Optional[int]
    start_ts: float
    end_ts: float
    stage: str
    summary: str
    details: Dict[str, Any]
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)


def calculate_severity(observed: float, threshold: float) -> str:
    """
    Calculate severity level ('low', 'medium', 'high', 'critical') based on observed/threshold ratio.
    """
    if threshold <= 0:
        return "low"

    ratio = observed / threshold

    if ratio >= 8.0:
        return "critical"
    elif ratio >= 4.0:
        return "high"
    elif ratio >= 2.0:
        return "medium"
    else:
        return "low"
