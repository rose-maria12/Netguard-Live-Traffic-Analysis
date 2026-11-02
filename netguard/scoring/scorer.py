import json
from typing import Any, Dict, List, Optional, Tuple

from netguard.config import load_config
from netguard.detection.base import Finding

STAGE_CANONICAL_ORDER = [
    "Reconnaissance",
    "Access Attempt",
    "Possible Exploitation",
    "Possible Exfiltration",
]

SEVERITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.25,
}


def calculate_strongest_alert_score(
    alerts: List[Finding], max_weight: float = 35.0
) -> float:
    """
    Component 1: Strongest alert severity/strength (Max weight 35.0).
    Critical = 1.0, High = 0.75, Medium = 0.5, Low = 0.25.
    """
    if not alerts:
        return 0.0

    highest_mult = 0.0
    for a in alerts:
        sev_mult = SEVERITY_WEIGHTS.get(a.severity.lower(), 0.25)
        if sev_mult > highest_mult:
            highest_mult = sev_mult

    return round(highest_mult * max_weight, 2)


def calculate_stage_diversity_score(
    stages: List[str], max_weight: float = 30.0
) -> float:
    """
    Component 2: Stage diversity (Max weight 30.0).
    Count distinct valid stages (Recon, Access, Exploitation, Exfiltration).
    4 stages = 1.0, 3 stages = 0.75, 2 stages = 0.5, 1 stage = 0.25, 0 = 0.0.
    """
    valid_stages = [s for s in stages if s in STAGE_CANONICAL_ORDER]
    distinct_count = len(set(valid_stages))

    if distinct_count >= 4:
        ratio = 1.0
    elif distinct_count == 3:
        ratio = 0.75
    elif distinct_count == 2:
        ratio = 0.50
    elif distinct_count == 1:
        ratio = 0.25
    else:
        ratio = 0.0

    return round(ratio * max_weight, 2)


def calculate_logical_order_score(
    alerts: List[Finding], max_weight: float = 15.0
) -> float:
    """
    Component 3: Logical stage order progression (Max weight 15.0).
    Checks if earliest occurrences of stages follow chronological order.
    Single-stage incidents receive 0.0 for progression order.
    Multi-stage incidents with non-decreasing chronological stage order receive 1.0 (full weight).
    Inverted/out-of-order stage progression receives 0.5 (half weight).
    """
    valid_alerts = [a for a in alerts if a.stage in STAGE_CANONICAL_ORDER]
    if len(valid_alerts) < 2:
        return 0.0

    # Track earliest timestamp for each stage present
    first_seen: Dict[str, float] = {}
    for a in valid_alerts:
        if a.stage not in first_seen or a.start_ts < first_seen[a.stage]:
            first_seen[a.stage] = a.start_ts

    stages_present = [s for s in STAGE_CANONICAL_ORDER if s in first_seen]
    if len(stages_present) < 2:
        return 0.0

    # Check if stage timestamps are in non-decreasing order along canonical sequence
    is_ordered = True
    for idx in range(len(stages_present) - 1):
        s_curr = stages_present[idx]
        s_next = stages_present[idx + 1]
        if first_seen[s_curr] > first_seen[s_next]:
            is_ordered = False
            break

    ratio = 1.0 if is_ordered else 0.5
    return round(ratio * max_weight, 2)


def calculate_corroboration_score(
    alerts: List[Finding], max_weight: float = 20.0
) -> float:
    """
    Component 4: ML and/or abnormal-egress corroboration (Max weight 20.0).
    - ML corroboration (10 pts / half weight): Present ONLY if an ML anomaly alert is present.
    - Abnormal outbound / exfiltration corroboration (10 pts / half weight): Present ONLY if abnormal_outbound or Possible Exfiltration alert is present.
    """
    if not alerts:
        return 0.0

    has_ml = any(a.detector == "iforest" or a.alert_type == "ml_anomaly" for a in alerts)
    has_outbound = any(
        a.alert_type == "abnormal_outbound" or a.stage == "Possible Exfiltration" for a in alerts
    )

    half_weight = max_weight / 2.0
    score = 0.0
    if has_ml:
        score += half_weight
    if has_outbound:
        score += half_weight

    return round(score, 2)


def map_score_to_severity_level(
    total_score: float, config: Optional[Dict[str, Any]] = None
) -> str:
    """
    Map total score (0-100) to severity band ('low', 'medium', 'high', 'critical') using configuration thresholds.
    """
    if config is None:
        config = load_config()

    bands = config.get("scoring", {}).get("severity_bands", {})
    crit_thresh = float(bands.get("critical", 75.0))
    high_thresh = float(bands.get("high", 50.0))
    med_thresh = float(bands.get("medium", 25.0))

    if total_score >= crit_thresh:
        return "critical"
    elif total_score >= high_thresh:
        return "high"
    elif total_score >= med_thresh:
        return "medium"
    else:
        return "low"


def score_incident(
    alerts: List[Finding], config: Optional[Dict[str, Any]] = None
) -> Tuple[float, str, Dict[str, Any]]:
    """
    Calculate deterministic 0-100 heuristic prioritization score, severity level, and breakdown dictionary for an incident.
    Note: Score is a heuristic prioritization metric (0-100 scale), NOT a probability and NOT proof of an attack.
    Returns (total_score, severity_level, breakdown_dict).
    """
    if config is None:
        config = load_config()

    weights = config.get("scoring", {}).get("weights", {})
    w_strongest = float(weights.get("strongest_alert", 35.0))
    w_diversity = float(weights.get("stage_diversity", 30.0))
    w_order = float(weights.get("stage_order", 15.0))
    w_corrob = float(weights.get("corroboration", 20.0))

    stages = list({a.stage for a in alerts})

    strongest_score = calculate_strongest_alert_score(alerts, max_weight=w_strongest)
    diversity_score = calculate_stage_diversity_score(stages, max_weight=w_diversity)
    order_score = calculate_logical_order_score(alerts, max_weight=w_order)
    corrob_score = calculate_corroboration_score(alerts, max_weight=w_corrob)

    total_score = round(
        min(100.0, max(0.0, strongest_score + diversity_score + order_score + corrob_score)), 2
    )

    level = map_score_to_severity_level(total_score, config=config)

    breakdown = {
        "strongest_alert_score": strongest_score,
        "stage_diversity_score": diversity_score,
        "logical_order_score": order_score,
        "corroboration_score": corrob_score,
        "total_score": total_score,
        "weights": {
            "strongest_alert": w_strongest,
            "stage_diversity": w_diversity,
            "stage_order": w_order,
            "corroboration": w_corrob,
        },
        "disclaimer": "Prioritization score is a heuristic metric (0-100 scale), not a probability and not proof of an attack.",
    }

    return total_score, level, breakdown
