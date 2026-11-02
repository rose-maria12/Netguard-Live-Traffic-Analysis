import pytest
from netguard.config import load_config
from netguard.detection.brute_force import detect_brute_force


def make_bf_flow(
    flow_id: int,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    start_ts: float,
    duration: float = 1.0,
    state: str = "established",
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
        "end_ts": start_ts + duration,
        "pkts_fwd": 3,
        "pkts_rev": 3,
        "bytes_fwd": 180,
        "bytes_rev": 180,
        "syn_count": 1,
        "rst_count": 0,
        "state": state,
        "first_frame": first_frame,
        "last_frame": first_frame + 2,
    }


def test_below_minimum_attempts():
    config = load_config()
    # 9 attempts on port 22 (below min_attempts=10)
    flows = [
        make_bf_flow(i, "192.168.56.101", "192.168.56.10", 22, start_ts=100.0 + i, duration=1.0)
        for i in range(1, 10)
    ]

    findings = detect_brute_force(flows, config)
    assert len(findings) == 0


def test_below_short_flow_ratio_threshold():
    config = load_config()
    # 15 attempts, but only 3 short flows (3/15 = 0.2 < min_short_ratio 0.5)
    flows = []
    for i in range(1, 16):
        duration = 1.0 if i <= 3 else 10.0  # > 5s is not a short flow
        flows.append(make_bf_flow(i, "192.168.56.101", "192.168.56.10", 22, start_ts=100.0 + i, duration=duration))

    findings = detect_brute_force(flows, config)
    assert len(findings) == 0


def test_exactly_minimum_attempts():
    config = load_config()
    # 10 attempts on SSH port 22, all duration 1.0s (short ratio 1.0)
    flows = [
        make_bf_flow(i, "192.168.56.101", "192.168.56.10", 22, start_ts=100.0 + i, duration=1.0, first_frame=i*3)
        for i in range(1, 11)
    ]

    findings = detect_brute_force(flows, config)
    assert len(findings) == 1

    f = findings[0]
    assert f.alert_type == "brute_force"
    assert f.detector == "rule"
    assert f.rule_name == "repeated_short_connections"
    assert f.stage == "Access Attempt"
    assert f.confidence == 0.7
    assert f.severity == "low"
    assert f.src_ip == "192.168.56.101"
    assert f.dst_ip == "192.168.56.10"
    assert f.dst_port == 22
    assert f.details["observed_attempts"] == 10
    assert f.details["encrypted_payloads_inspected"] is False
    assert "Pattern indicator only" in f.summary
    assert len(f.evidence_refs) == 10


def test_rdp_brute_force_threshold_satisfied():
    config = load_config()
    # 20 attempts on RDP port 3389 within same 20s window (severity ratio 20/10 = 2.0 -> medium)
    flows = [
        make_bf_flow(i, "192.168.56.101", "192.168.56.10", 3389, start_ts=100.0 + (i * 0.5), duration=2.0, first_frame=i*3)
        for i in range(1, 21)
    ]

    findings = detect_brute_force(flows, config)
    assert len(findings) == 1

    f = findings[0]
    assert f.severity == "medium"
    assert f.dst_port == 3389
    assert f.details["observed_attempts"] == 20


def test_disabled_brute_force_detector():
    config = load_config()
    config["detectors"]["brute_force"]["enabled"] = False

    flows = [
        make_bf_flow(i, "192.168.56.101", "192.168.56.10", 22, start_ts=100.0 + i, duration=1.0)
        for i in range(1, 20)
    ]

    findings = detect_brute_force(flows, config)
    assert len(findings) == 0


def test_brute_force_determinism():
    config = load_config()
    flows = [
        make_bf_flow(i, "192.168.56.101", "192.168.56.10", 22, start_ts=100.0 + i, duration=1.0, first_frame=i*3)
        for i in range(1, 15)
    ]

    f1 = detect_brute_force(flows, config)
    f2 = detect_brute_force(flows, config)

    assert len(f1) == 1
    assert len(f2) == 1
    assert f1[0] == f2[0]
