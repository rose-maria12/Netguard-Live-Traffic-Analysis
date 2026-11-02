import math
from typing import Any, Dict, List, Optional, Tuple
from netguard.config import load_config
from netguard.detection.base import Finding, calculate_severity, get_suggested_precautions


def detect_dns_anomaly(
    dns_events: List[Dict[str, Any]], config: Optional[Dict[str, Any]] = None
) -> List[Finding]:
    """
    Detect anomalous DNS traffic patterns (high rate, long labels, high NXDOMAIN ratio).
    Grouped by (client_ip, window). Resolvers in infrastructure.dns_servers are excluded.
    Returns list of Finding objects.
    """
    if config is None:
        config = load_config()

    dns_config = config.get("detectors", {}).get("dns_anomaly", {})
    if not dns_config.get("enabled", True):
        return []

    max_queries = int(dns_config.get("max_queries", 60))
    max_label_len_threshold = int(dns_config.get("max_label_len_threshold", 40))
    min_long_names = int(dns_config.get("min_long_names", 5))
    nxdomain_ratio_thresh = float(dns_config.get("nxdomain_ratio", 0.5))
    min_responses = int(dns_config.get("min_responses", 10))
    confidence = float(dns_config.get("confidence", 0.6))
    window_seconds = float(config.get("general", {}).get("window_seconds", 20))

    dns_servers = set(config.get("infrastructure", {}).get("dns_servers", []))
    raw_suffixes = config.get("allowlist", {}).get("dns_suffixes", [])
    dns_suffixes = tuple(s.lower() for s in raw_suffixes)

    # Filter out DNS servers as clients and allowlisted domain suffixes
    filtered_events = []
    for evt in dns_events:
        client_ip = evt["client_ip"]
        if client_ip in dns_servers:
            continue
        qname = evt.get("qname", "").lower()
        if dns_suffixes and any(qname.endswith(suf) for suf in dns_suffixes):
            continue
        filtered_events.append(evt)

    # Group by (client_ip, window_start)
    groups: Dict[Tuple[str, float], List[Dict[str, Any]]] = {}
    for evt in filtered_events:
        w_start = math.floor(float(evt["ts"]) / window_seconds) * window_seconds
        key = (evt["client_ip"], w_start)
        if key not in groups:
            groups[key] = []
        groups[key].append(evt)

    findings: List[Finding] = []

    # Process sorted keys for deterministic execution
    for (client_ip, w_start) in sorted(groups.keys()):
        grp_events = groups[(client_ip, w_start)]

        queries = [e for e in grp_events if e["is_response"] == 0]
        responses = [e for e in grp_events if e["is_response"] == 1]

        query_count = len(queries)
        long_name_count = sum(
            1 for q in queries if int(q.get("max_label_len", 0)) >= max_label_len_threshold
        )

        response_count = len(responses)
        nxdomain_count = sum(1 for r in responses if r.get("rcode") == 3)
        nx_ratio = float(nxdomain_count) / float(response_count) if response_count > 0 else 0.0

        triggered_checks = []
        ratios: Dict[str, float] = {}

        # Check 1: High Query Rate
        if max_queries > 0 and query_count >= max_queries:
            triggered_checks.append("dns_high_rate")
            ratios["dns_high_rate"] = float(query_count) / float(max_queries)

        # Check 2: Long Query Names
        if min_long_names > 0 and long_name_count >= min_long_names:
            triggered_checks.append("dns_long_names")
            ratios["dns_long_names"] = float(long_name_count) / float(min_long_names)

        # Check 3: NXDOMAIN Ratio
        if response_count >= min_responses and nxdomain_ratio_thresh > 0 and nx_ratio >= nxdomain_ratio_thresh:
            triggered_checks.append("dns_nxdomain_ratio")
            ratios["dns_nxdomain_ratio"] = nx_ratio / nxdomain_ratio_thresh

        if triggered_checks:
            start_ts = min(float(e["ts"]) for e in grp_events)
            end_ts = max(float(e["ts"]) for e in grp_events)
            first_frame = min(int(e["frame_no"]) for e in grp_events)
            last_frame = max(int(e["frame_no"]) for e in grp_events)

            # Determine strongest rule check
            strongest_rule = max(ratios.keys(), key=lambda k: ratios[k])
            max_ratio = ratios[strongest_rule]

            severity = calculate_severity(max_ratio, 1.0)

            # Target resolver IP (server_ip) if available
            server_ips = sorted(list(set(e["server_ip"] for e in grp_events if "server_ip" in e)))
            primary_server_ip = server_ips[0] if server_ips else None

            summary = (
                f"{client_ip} sent {query_count} DNS queries in {int(window_seconds)} s "
                f"({', '.join(triggered_checks)}). Indicator of anomalous DNS activity."
            )

            sorted_events = sorted(grp_events, key=lambda x: (x["ts"], x["frame_no"]))
            evidence_refs = []
            for e in sorted_events[:50]:  # Cap at 50
                evidence_refs.append(
                    {
                        "ref_type": "dns",
                        "ref_id": e.get("id", 0),
                        "frame_no": e["frame_no"],
                        "note": f"DNS {'resp' if e['is_response'] else 'query'} {e['qname']} (rcode: {e.get('rcode')})",
                    }
                )

            details = {
                "triggered_checks": triggered_checks,
                "strongest_check": strongest_rule,
                "primary_metric": strongest_rule,
                "observed_query_count": query_count,
                "observed_long_names": long_name_count,
                "observed_response_count": response_count,
                "observed_nxdomain_count": nxdomain_count,
                "observed_nxdomain_ratio": round(nx_ratio, 4),
                "threshold_max_queries": max_queries,
                "threshold_min_long_names": min_long_names,
                "threshold_nxdomain_ratio": nxdomain_ratio_thresh,
                "threshold_min_responses": min_responses,
                "first_frame": first_frame,
                "last_frame": last_frame,
                "suggested_precautions": get_suggested_precautions("dns_anomaly"),
            }

            finding = Finding(
                alert_type="dns_anomaly",
                detector="rule",
                rule_name=strongest_rule,
                severity=severity,
                confidence=confidence,
                src_ip=client_ip,
                dst_ip=primary_server_ip,
                dst_port=53,
                start_ts=start_ts,
                end_ts=end_ts,
                stage="Possible Exploitation",
                summary=summary,
                details=details,
                evidence_refs=evidence_refs,
            )
            findings.append(finding)

    return findings
