import pytest
from netguard.config import load_config
from netguard.detection.dns_anomaly import detect_dns_anomaly


def make_dns_event(
    evt_id: int,
    client_ip: str,
    server_ip: str,
    qname: str,
    ts: float,
    is_response: int = 0,
    rcode: int = 0,
    frame_no: int = 1,
) -> dict:
    qname_clean = qname.lower().rstrip(".")
    qname_len = len(qname_clean)
    labels = qname_clean.split(".") if qname_clean else []
    max_label_len = max([len(l) for l in labels], default=0)

    return {
        "id": evt_id,
        "frame_no": frame_no,
        "ts": ts,
        "client_ip": client_ip,
        "server_ip": server_ip,
        "qname": qname_clean,
        "qname_len": qname_len,
        "max_label_len": max_label_len,
        "qtype": 1,
        "is_response": is_response,
        "rcode": rcode if is_response else None,
        "txid": 1000 + evt_id,
    }


def test_below_query_threshold():
    config = load_config()
    # 59 queries (below max_queries = 60)
    events = [
        make_dns_event(i, "192.168.1.50", "8.8.8.8", f"sub{i}.example.com", ts=100.0 + (i * 0.1), frame_no=i)
        for i in range(1, 60)
    ]

    findings = detect_dns_anomaly(events, config)
    assert len(findings) == 0


def test_query_threshold_exceeded():
    config = load_config()
    # 60 queries (exactly max_queries = 60)
    events = [
        make_dns_event(i, "192.168.1.50", "8.8.8.8", f"sub{i}.example.com", ts=100.0 + (i * 0.1), frame_no=i)
        for i in range(1, 61)
    ]

    findings = detect_dns_anomaly(events, config)
    assert len(findings) == 1

    f = findings[0]
    assert f.alert_type == "dns_anomaly"
    assert f.detector == "rule"
    assert f.rule_name == "dns_high_rate"
    assert f.stage == "Possible Exploitation"
    assert f.confidence == 0.6
    assert f.src_ip == "192.168.1.50"
    assert f.dst_ip == "8.8.8.8"
    assert f.details["observed_query_count"] == 60
    assert "Indicator of anomalous DNS activity" in f.summary
    assert len(f.evidence_refs) == 50  # Capped at 50


def test_long_label_condition():
    config = load_config()
    # 5 queries with longest label length = 42 >= 40 (min_long_names = 5)
    long_label = "a" * 42
    qname = f"{long_label}.example.com"

    events = [
        make_dns_event(i, "192.168.1.50", "8.8.8.8", qname, ts=100.0 + i, frame_no=i)
        for i in range(1, 6)
    ]

    findings = detect_dns_anomaly(events, config)
    assert len(findings) == 1

    f = findings[0]
    assert f.rule_name == "dns_long_names"
    assert f.details["observed_long_names"] == 5


def test_nxdomain_ratio_condition():
    config = load_config()
    # 10 responses, 5 NXDOMAIN (rcode=3) -> ratio 0.5 (nxdomain_ratio = 0.5, min_responses = 10)
    events = [
        make_dns_event(i, "192.168.1.50", "8.8.8.8", f"domain{i}.com", ts=100.0 + i, is_response=1, rcode=3 if i <= 5 else 0, frame_no=i)
        for i in range(1, 11)
    ]

    findings = detect_dns_anomaly(events, config)
    assert len(findings) == 1

    f = findings[0]
    assert f.rule_name == "dns_nxdomain_ratio"
    assert f.details["observed_nxdomain_count"] == 5
    assert f.details["observed_nxdomain_ratio"] == 0.5


def test_min_nxdomain_responses_requirement():
    config = load_config()
    # 8 responses, all 8 NXDOMAIN (100% NXDOMAIN, but total responses 8 < min_responses 10)
    events = [
        make_dns_event(i, "192.168.1.50", "8.8.8.8", f"domain{i}.com", ts=100.0 + i, is_response=1, rcode=3, frame_no=i)
        for i in range(1, 9)
    ]

    findings = detect_dns_anomaly(events, config)
    assert len(findings) == 0


def test_disabled_dns_detector():
    config = load_config()
    config["detectors"]["dns_anomaly"]["enabled"] = False

    events = [
        make_dns_event(i, "192.168.1.50", "8.8.8.8", f"sub{i}.com", ts=100.0 + i, frame_no=i)
        for i in range(1, 70)
    ]

    findings = detect_dns_anomaly(events, config)
    assert len(findings) == 0


def test_zero_division_safety():
    config = load_config()
    # Empty list and events with 0 responses
    assert detect_dns_anomaly([], config) == []

    queries_only = [
        make_dns_event(1, "192.168.1.50", "8.8.8.8", "normal.com", ts=100.0, is_response=0, frame_no=1)
    ]
    assert detect_dns_anomaly(queries_only, config) == []


def test_dns_determinism():
    config = load_config()
    events = [
        make_dns_event(i, "192.168.1.50", "8.8.8.8", f"sub{i}.example.com", ts=100.0 + (i * 0.1), frame_no=i)
        for i in range(1, 65)
    ]

    f1 = detect_dns_anomaly(events, config)
    f2 = detect_dns_anomaly(events, config)

    assert len(f1) == 1
    assert len(f2) == 1
    assert f1[0] == f2[0]
