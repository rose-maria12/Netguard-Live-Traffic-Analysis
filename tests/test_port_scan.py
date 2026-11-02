import pytest
from netguard.config import load_config
from netguard.detection.port_scan import detect_port_scan


def make_tcp_flow(
    flow_id: int,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    start_ts: float,
    state: str = "reset",
    first_frame: int = 1,
) -> dict:
    return {
        "id": flow_id,
        "initiator_ip": src_ip,
        "responder_ip": dst_ip,
        "initiator_port": 50000 + flow_id,
        "responder_port": dst_port,
        "proto": "TCP",
        "start_ts": start_ts,
        "end_ts": start_ts + 0.1,
        "pkts_fwd": 1,
        "pkts_rev": 1 if state == "reset" else 0,
        "bytes_fwd": 60,
        "bytes_rev": 60 if state == "reset" else 0,
        "syn_count": 1,
        "rst_count": 1 if state == "reset" else 0,
        "state": state,
        "first_frame": first_frame,
        "last_frame": first_frame + 1,
    }


def test_below_distinct_ports_threshold():
    config = load_config()
    # 14 distinct ports (below min_distinct_ports=15)
    flows = [
        make_tcp_flow(i, "192.168.1.100", "10.0.0.5", port, start_ts=100.0, state="no_response", first_frame=i*2)
        for i, port in enumerate(range(1, 15), start=1)
    ]

    findings = detect_port_scan(flows, config)
    assert len(findings) == 0


def test_below_failed_ratio_threshold():
    config = load_config()
    # 20 distinct ports, but only 50% failed (below min_failed_ratio=0.7)
    flows = []
    for i in range(1, 21):
        state = "no_response" if i <= 10 else "established"
        flows.append(make_tcp_flow(i, "192.168.1.100", "10.0.0.5", 8000 + i, start_ts=100.0, state=state, first_frame=i*2))

    findings = detect_port_scan(flows, config)
    assert len(findings) == 0


def test_exactly_at_threshold():
    config = load_config()
    # 15 distinct ports, 11 failed out of 15 (73.3% failed >= 0.7)
    flows = []
    for i in range(1, 16):
        state = "no_response" if i <= 11 else "established"
        flows.append(make_tcp_flow(i, "192.168.1.100", "10.0.0.5", 8000 + i, start_ts=100.0, state=state, first_frame=i*2))

    findings = detect_port_scan(flows, config)
    assert len(findings) == 1

    f = findings[0]
    assert f.alert_type == "port_scan"
    assert f.detector == "rule"
    assert f.rule_name == "port_scan_vertical"
    assert f.stage == "Reconnaissance"
    assert f.confidence == 0.9
    assert f.severity == "low"  # ratio 15/15 = 1.0 -> low
    assert f.src_ip == "192.168.1.100"
    assert f.dst_ip == "10.0.0.5"
    assert f.details["observed_ports"] == 15
    assert len(f.evidence_refs) == 15


def test_above_threshold_severity():
    config = load_config()
    # 30 distinct ports (ratio 30/15 = 2.0 -> medium severity), 100% failed
    flows = [
        make_tcp_flow(i, "192.168.1.100", "10.0.0.5", 1000 + i, start_ts=100.0, state="reset", first_frame=i*2)
        for i in range(1, 31)
    ]

    findings = detect_port_scan(flows, config)
    assert len(findings) == 1

    f = findings[0]
    assert f.severity == "medium"
    assert f.details["observed_ports"] == 30
    assert "probed 30 distinct ports" in f.summary


def test_disabled_detector():
    config = load_config()
    config["detectors"]["port_scan"]["enabled"] = False

    flows = [
        make_tcp_flow(i, "192.168.1.100", "10.0.0.5", 1000 + i, start_ts=100.0, state="reset", first_frame=i*2)
        for i in range(1, 30)
    ]

    findings = detect_port_scan(flows, config)
    assert len(findings) == 0


def test_determinism():
    config = load_config()
    flows = [
        make_tcp_flow(i, "192.168.1.100", "10.0.0.5", 1000 + i, start_ts=100.0, state="reset", first_frame=i*2)
        for i in range(1, 20)
    ]

    findings1 = detect_port_scan(flows, config)
    findings2 = detect_port_scan(flows, config)

    assert len(findings1) == 1
    assert len(findings2) == 1
    assert findings1[0] == findings2[0]
