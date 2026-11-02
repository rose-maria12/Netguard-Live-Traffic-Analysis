import json
from typing import Any, Dict, List, Optional
from netguard.config import load_config
from netguard.detection.base import Finding


def build_dedup_key(finding: Finding) -> str:
    """
    Generate deterministic deduplication key for a Finding.
    Format: alert_type:rule_name:src_ip:dst_ip:dst_port
    """
    dst_ip_str = finding.dst_ip or ""
    dst_port_str = str(finding.dst_port) if finding.dst_port is not None else ""
    return f"{finding.alert_type}:{finding.rule_name}:{finding.src_ip}:{dst_ip_str}:{dst_port_str}"


def build_wireshark_filter(finding: Finding) -> str:
    """
    Generate Wireshark display filter for a Finding.
    """
    src = finding.src_ip
    dst = finding.dst_ip
    port = finding.dst_port

    if src and dst and port:
        return f"ip.src == {src} && ip.dst == {dst} && (tcp.dstport == {port} || udp.dstport == {port})"
    elif src and dst:
        return f"ip.src == {src} && ip.dst == {dst}"
    elif src:
        return f"ip.addr == {src}"
    return ""


def compare_severity(sev1: str, sev2: str) -> str:
    """
    Return the higher severity string between sev1 and sev2.
    Hierarchy: critical > high > medium > low
    """
    weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    w1 = weights.get(sev1.lower(), 1)
    w2 = weights.get(sev2.lower(), 1)
    return sev1 if w1 >= w2 else sev2


def deduplicate_findings(
    findings: List[Finding], config: Optional[Dict[str, Any]] = None
) -> List[Finding]:
    """
    Deduplicate repeated findings matching the same dedup_key.
    Merges timestamps, frame bounds, counts, and preserves evidence references.
    Returns list of deduplicated Finding objects sorted deterministically.
    """
    if not findings:
        return []

    if config is None:
        config = load_config()

    # Sort input findings deterministically
    sorted_findings = sorted(
        findings,
        key=lambda f: (f.start_ts, f.src_ip, f.alert_type, f.rule_name, f.dst_ip or "", f.dst_port or 0),
    )

    merged_dict: Dict[str, Finding] = {}
    merged_counts: Dict[str, int] = {}

    for f in sorted_findings:
        key = build_dedup_key(f)

        if key not in merged_dict:
            # Create a copy of details and evidence refs
            details_copy = dict(f.details)
            details_copy["merged_count"] = details_copy.get("merged_count", 1)
            details_copy["dedup_key"] = key
            details_copy["wireshark_filter"] = build_wireshark_filter(f)

            evidence_copy = [dict(item) for item in f.evidence_refs]

            merged_finding = Finding(
                alert_type=f.alert_type,
                detector=f.detector,
                rule_name=f.rule_name,
                severity=f.severity,
                confidence=f.confidence,
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                dst_port=f.dst_port,
                start_ts=f.start_ts,
                end_ts=f.end_ts,
                stage=f.stage,
                summary=f.summary,
                details=details_copy,
                evidence_refs=evidence_copy,
            )
            merged_dict[key] = merged_finding
            merged_counts[key] = details_copy.get("merged_count", 1)
        else:
            existing = merged_dict[key]

            # Merge counts
            merged_counts[key] += f.details.get("merged_count", 1)
            existing.details["merged_count"] = merged_counts[key]

            # Update timestamps
            existing.start_ts = min(existing.start_ts, f.start_ts)
            existing.end_ts = max(existing.end_ts, f.end_ts)

            # Update frame bounds
            ex_first = existing.details.get("first_frame", float("inf"))
            f_first = f.details.get("first_frame", float("inf"))
            if ex_first != float("inf") or f_first != float("inf"):
                existing.details["first_frame"] = min(ex_first, f_first)

            ex_last = existing.details.get("last_frame", 0)
            f_last = f.details.get("last_frame", 0)
            existing.details["last_frame"] = max(ex_last, f_last)

            # Update severity & confidence
            existing.severity = compare_severity(existing.severity, f.severity)
            existing.confidence = max(existing.confidence, f.confidence)

            # Merge evidence references without duplicates
            seen_evidence = {
                (e.get("ref_type"), e.get("ref_id"), e.get("frame_no"))
                for e in existing.evidence_refs
            }
            for e in f.evidence_refs:
                e_key = (e.get("ref_type"), e.get("ref_id"), e.get("frame_no"))
                if e_key not in seen_evidence:
                    seen_evidence.add(e_key)
                    existing.evidence_refs.append(dict(e))

            # Sort evidence refs deterministically and cap at 50
            existing.evidence_refs.sort(key=lambda x: (x.get("frame_no") or 0, x.get("ref_id") or 0))
            if len(existing.evidence_refs) > 50:
                existing.details["evidence_truncated"] = 1
                existing.evidence_refs = existing.evidence_refs[:50]

    # Return deduplicated findings sorted deterministically
    deduped_list = list(merged_dict.values())
    deduped_list.sort(key=lambda f: (f.start_ts, f.src_ip, f.alert_type, f.rule_name, f.dst_ip or "", f.dst_port or 0))
    return deduped_list
