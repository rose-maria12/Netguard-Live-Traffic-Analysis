import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from netguard.config import load_config
from netguard.db import DEFAULT_DB_PATH, get_db, init_db
from netguard.detection.base import Finding
from netguard.correlation.dedup import compare_severity, deduplicate_findings
from netguard.scoring.scorer import score_incident

STAGE_ORDER = [
    "Reconnaissance",
    "Access Attempt",
    "Possible Exploitation",
    "Possible Exfiltration",
    "Unclassified",
]


@dataclass
class Incident:
    id: Optional[int]
    primary_ip: str
    involved_ips: List[str]
    start_ts: float
    end_ts: float
    stages: List[str]
    stage_count: int
    is_multistage: bool
    rule_alert_count: int
    ml_alert_count: int
    score: float
    level: str
    summary: str
    alerts: List[Finding]
    score_breakdown: Dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    updated_at: float = 0.0


class DisjointSet:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        if self.parent[i] == i:
            return i
        self.parent[i] = self.find(self.parent[i])
        return self.parent[i]

    def union(self, i: int, j: int) -> None:
        root_i = self.find(i)
        root_j = self.find(j)
        if root_i != root_j:
            if root_i < root_j:
                self.parent[root_j] = root_i
            else:
                self.parent[root_i] = root_j


def correlate_alerts(
    alerts: List[Finding], config: Optional[Dict[str, Any]] = None
) -> List[Incident]:
    """
    Correlate deduplicated findings into Incidents using Union-Find.
    Supports same-source IP correlation gap and victim-to-source pivot gap.
    Returns list of Incident objects sorted deterministically.
    """
    if not alerts:
        return []

    if config is None:
        config = load_config()

    corr_config = config.get("correlation", {})
    same_actor_gap = float(corr_config.get("same_actor_gap_seconds", 600))
    victim_pivot_gap = float(corr_config.get("victim_pivot_gap_seconds", 900))

    # Deduplicate alerts first
    deduped_alerts = deduplicate_findings(alerts, config=config)
    n = len(deduped_alerts)
    if n == 0:
        return []

    dsu = DisjointSet(n)

    # Evaluate correlation rules between all alert pairs (i, j) where i < j
    for i in range(n):
        a_i = deduped_alerts[i]
        for j in range(i + 1, n):
            a_j = deduped_alerts[j]

            # Rule 1: Same Source IP correlation
            if a_i.src_ip == a_j.src_ip:
                time_diff = a_j.start_ts - a_i.end_ts
                if time_diff <= same_actor_gap:
                    dsu.union(i, j)

            # Rule 2: Victim-to-Source Pivot (A_i dst_ip == A_j src_ip)
            if a_i.dst_ip and a_i.dst_ip == a_j.src_ip:
                pivot_diff = a_j.start_ts - a_i.start_ts
                if 0 <= pivot_diff <= victim_pivot_gap:
                    dsu.union(i, j)

            # Rule 3: Reverse Pivot / Target Pivot (A_j dst_ip == A_i src_ip)
            if a_j.dst_ip and a_j.dst_ip == a_i.src_ip:
                pivot_diff = a_j.start_ts - a_i.start_ts
                if 0 <= pivot_diff <= victim_pivot_gap:
                    dsu.union(i, j)

    # Group alerts by root component
    groups: Dict[int, List[Finding]] = {}
    for idx in range(n):
        root = dsu.find(idx)
        if root not in groups:
            groups[root] = []
        groups[root].append(deduped_alerts[idx])

    incidents: List[Incident] = []

    for root_id in sorted(groups.keys()):
        grp_alerts = groups[root_id]
        grp_alerts.sort(
            key=lambda a: (a.start_ts, a.src_ip, a.alert_type, a.rule_name, a.dst_ip or "", a.dst_port or 0)
        )

        start_ts = min(a.start_ts for a in grp_alerts)
        end_ts = max(a.end_ts for a in grp_alerts)

        # Primary IP: source IP of earliest alert in group
        primary_ip = grp_alerts[0].src_ip

        # Involved IPs
        involved_set: Set[str] = set()
        for a in grp_alerts:
            involved_set.add(a.src_ip)
            if a.dst_ip:
                involved_set.add(a.dst_ip)
        involved_ips = sorted(list(involved_set))

        # Stages present
        grp_stages_set = set(a.stage for a in grp_alerts)
        stages = [s for s in STAGE_ORDER if s in grp_stages_set]
        stage_count = len(stages)
        is_multistage = stage_count > 1

        rule_count = sum(1 for a in grp_alerts if a.detector == "rule")
        ml_count = sum(1 for a in grp_alerts if a.detector == "iforest")

        # Calculate 0-100 heuristic prioritization score, severity level, and score breakdown
        total_score, level, score_breakdown = score_incident(grp_alerts, config=config)

        duration = max(0.0, end_ts - start_ts)
        summary = (
            f"Correlated {len(grp_alerts)} indicator(s) involving {primary_ip} "
            f"spanning {', '.join(stages)} across {duration:.1f} s. "
            f"Indicators of potential network activity."
        )

        inc = Incident(
            id=None,
            primary_ip=primary_ip,
            involved_ips=involved_ips,
            start_ts=start_ts,
            end_ts=end_ts,
            stages=stages,
            stage_count=stage_count,
            is_multistage=is_multistage,
            rule_alert_count=rule_count,
            ml_alert_count=ml_count,
            score=total_score,
            level=level,
            summary=summary,
            alerts=grp_alerts,
            score_breakdown=score_breakdown,
        )
        incidents.append(inc)

    # Sort incidents deterministically by start_ts, primary_ip
    incidents.sort(key=lambda inc: (inc.start_ts, inc.primary_ip))
    return incidents


def save_alerts_to_db(
    alerts: List[Finding], run_id: int, db_path: Union[str, Path] = DEFAULT_DB_PATH
) -> List[int]:
    """
    Persist list of deduplicated Finding objects into alerts and alert_evidence tables.
    Returns list of inserted alert IDs.
    """
    init_db(db_path)
    conn = get_db(db_path)
    inserted_ids: List[int] = []
    try:
        conn.execute("BEGIN TRANSACTION;")
        for a in alerts:
            cursor = conn.execute(
                """
                INSERT INTO alerts (
                    run_id, alert_type, detector, rule_name, severity, confidence,
                    src_ip, dst_ip, dst_port, start_ts, end_ts, stage, summary,
                    details_json, wireshark_filter, first_frame, last_frame,
                    merged_count, dedup_key, evidence_truncated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    run_id,
                    a.alert_type,
                    a.detector,
                    a.rule_name,
                    a.severity,
                    a.confidence,
                    a.src_ip,
                    a.dst_ip,
                    a.dst_port,
                    a.start_ts,
                    a.end_ts,
                    a.stage,
                    a.summary,
                    json.dumps(a.details),
                    a.details.get("wireshark_filter", ""),
                    a.details.get("first_frame", 0),
                    a.details.get("last_frame", 0),
                    a.details.get("merged_count", 1),
                    a.details.get("dedup_key", ""),
                    a.details.get("evidence_truncated", 0),
                ),
            )
            alert_id = cursor.lastrowid
            inserted_ids.append(alert_id)
            a.details["alert_id"] = alert_id

            # Save evidence refs
            evidence_rows = [
                (
                    alert_id,
                    e.get("ref_type", "packet"),
                    e.get("ref_id", 0),
                    e.get("frame_no"),
                    e.get("note", ""),
                )
                for e in a.evidence_refs
            ]
            if evidence_rows:
                conn.executemany(
                    """
                    INSERT INTO alert_evidence (alert_id, ref_type, ref_id, frame_no, note)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    evidence_rows,
                )
        conn.commit()
        return inserted_ids
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def save_incidents_to_db(
    incidents: List[Incident], run_id: int, db_path: Union[str, Path] = DEFAULT_DB_PATH
) -> List[int]:
    """
    Persist list of Incident objects into incidents and incident_alerts tables.
    Returns list of inserted incident IDs.
    """
    init_db(db_path)
    conn = get_db(db_path)
    inserted_ids: List[int] = []
    try:
        conn.execute("BEGIN TRANSACTION;")
        for inc in incidents:
            cursor = conn.execute(
                """
                INSERT INTO incidents (
                    run_id, primary_ip, involved_ips_json, start_ts, end_ts,
                    stages_json, stage_count, is_multistage, rule_alert_count,
                    ml_alert_count, score, level, score_breakdown_json, summary,
                    status, analyst_notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', '', ?, ?);
                """,
                (
                    run_id,
                    inc.primary_ip,
                    json.dumps(inc.involved_ips),
                    inc.start_ts,
                    inc.end_ts,
                    json.dumps(inc.stages),
                    inc.stage_count,
                    1 if inc.is_multistage else 0,
                    inc.rule_alert_count,
                    inc.ml_alert_count,
                    inc.score,
                    inc.level,
                    json.dumps(inc.score_breakdown),
                    inc.summary,
                    inc.created_at,
                    inc.updated_at,
                ),
            )
            incident_id = cursor.lastrowid
            inc.id = incident_id
            inserted_ids.append(incident_id)

            # Link incident to alerts in incident_alerts table
            ia_rows = []
            for a in inc.alerts:
                alert_id = a.details.get("alert_id")
                if alert_id:
                    role = "primary_attacker" if a.src_ip == inc.primary_ip else "pivot_attacker"
                    ia_rows.append((incident_id, alert_id, role, a.stage))

            if ia_rows:
                conn.executemany(
                    """
                    INSERT INTO incident_alerts (incident_id, alert_id, role, stage)
                    VALUES (?, ?, ?, ?);
                    """,
                    ia_rows,
                )
        conn.commit()
        return inserted_ids
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()
