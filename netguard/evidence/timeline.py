from typing import Any, Dict, List, Union
from netguard.detection.base import Finding

STAGE_CANONICAL_ORDER = [
    "Reconnaissance",
    "Access Attempt",
    "Possible Exploitation",
    "Possible Exfiltration",
    "Unclassified",
]


def build_incident_timeline(alerts_or_incident: Union[List[Union[Finding, Dict[str, Any]]], Any]) -> List[Dict[str, Any]]:
    """
    Build a chronological timeline for an incident grouped by attack stages present.
    Omits missing stages.
    """
    if hasattr(alerts_or_incident, "alerts"):
        alerts_list = alerts_or_incident.alerts
    elif isinstance(alerts_or_incident, list):
        alerts_list = alerts_or_incident
    else:
        alerts_list = []

    # Group alerts by stage
    by_stage: Dict[str, List[Dict[str, Any]]] = {}

    for a in alerts_list:
        if isinstance(a, Finding):
            a_dict = {
                "id": getattr(a, "id", None) or a.details.get("alert_id"),
                "alert_type": a.alert_type,
                "detector": a.detector,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "confidence": a.confidence,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "dst_port": a.dst_port,
                "start_ts": a.start_ts,
                "end_ts": a.end_ts,
                "stage": a.stage,
                "summary": a.summary,
                "details": a.details,
                "wireshark_filter": a.details.get("wireshark_filter", ""),
                "first_frame": a.details.get("first_frame", 0),
                "last_frame": a.details.get("last_frame", 0),
                "evidence_refs": a.evidence_refs,
            }
        else:
            a_dict = dict(a)
            if "details" in a_dict and isinstance(a_dict["details"], str):
                import json
                try:
                    a_dict["details"] = json.loads(a_dict["details"])
                except Exception:
                    a_dict["details"] = {}

        stg = a_dict.get("stage", "Unclassified")
        if stg not in by_stage:
            by_stage[stg] = []
        by_stage[stg].append(a_dict)

    timeline: List[Dict[str, Any]] = []

    for stg in STAGE_CANONICAL_ORDER:
        if stg in by_stage and by_stage[stg]:
            stg_alerts = by_stage[stg]
            stg_alerts.sort(
                key=lambda item: (
                    item.get("start_ts", 0.0),
                    item.get("first_frame", 0),
                    item.get("src_ip", ""),
                    item.get("alert_type", ""),
                )
            )
            timeline.append({"stage": stg, "alerts": stg_alerts})

    # Catch any stage not in canonical order
    for stg, stg_alerts in by_stage.items():
        if stg not in STAGE_CANONICAL_ORDER and stg_alerts:
            stg_alerts.sort(
                key=lambda item: (
                    item.get("start_ts", 0.0),
                    item.get("first_frame", 0),
                    item.get("src_ip", ""),
                    item.get("alert_type", ""),
                )
            )
            timeline.append({"stage": stg, "alerts": stg_alerts})

    return timeline
