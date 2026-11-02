import pytest
from netguard.config import load_config
from netguard.detection.outbound import detect_abnormal_outbound


def make_pkt(
    frame_no: int, src_ip: str, dst_ip: str, length: int, ts: float, proto: str = "TCP"
) -> dict:
    return {
        "id": frame_no,
        "frame_no": frame_no,
        "ts": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 10000 + frame_no,
        "dst_port": 80,
        "proto": proto,
        "length": length,
        "tcp_flags": 16,
        "ttl": 64,
    }


def make_out_flow(
    flow_id: int,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    bytes_fwd: int,
    ts: float = 100.0,
) -> dict:
    return {
        "id": flow_id,
        "initiator_ip": src_ip,
        "responder_ip": dst_ip,
        "initiator_port": 50000 + flow_id,
        "responder_port": dst_port,
        "proto": "TCP",
        "start_ts": ts,
        "end_ts": ts + 1.0,
        "pkts_fwd": 10,
        "pkts_rev": 10,
        "bytes_fwd": bytes_fwd,
        "bytes_rev": 100,
        "syn_count": 1,
        "rst_count": 0,
        "state": "established",
        "first_frame": 1,
        "last_frame": 2,
    }


def test_below_outbound_threshold():
    config = load_config()
    # 500 KB sent (below 1 MB threshold)
    packets = [
        make_pkt(1, "192.168.1.10", "8.8.8.8", 500000, ts=100.0)
    ]
    flows = [make_out_flow(1, "192.168.1.10", "8.8.8.8", 80, 500000)]

    findings = detect_abnormal_outbound(flows, packets, config)
    assert len(findings) == 0


def test_outbound_volume_threshold_satisfied():
    config = load_config()
    # 1.5 MB sent to external IP (exceeds 1 MB bytes_per_window threshold)
    packets = [
        make_pkt(1, "192.168.1.10", "8.8.8.8", 1500000, ts=100.0)
    ]
    flows = [make_out_flow(1, "192.168.1.10", "8.8.8.8", 80, 1500000)]

    findings = detect_abnormal_outbound(flows, packets, config)
    assert len(findings) == 1

    f = findings[0]
    assert f.alert_type == "abnormal_outbound"
    assert f.detector == "rule"
    assert f.rule_name == "outbound_volume"
    assert f.stage == "Possible Exfiltration"
    assert f.confidence == 0.6
    assert f.src_ip == "192.168.1.10"
    assert f.dst_ip == "8.8.8.8"
    assert f.details["observed_bytes_out"] == 1500000
    assert "Indicator of abnormal outbound traffic" in f.summary


def test_unusual_destination_port():
    config = load_config()
    # 250 KB sent to external port 9999 (not in 53, 80, 123, 443; exceeds 200 KB threshold)
    packets = [
        make_pkt(1, "192.168.1.10", "203.0.113.5", 250000, ts=100.0)
    ]
    flows = [make_out_flow(1, "192.168.1.10", "203.0.113.5", 9999, 250000)]

    findings = detect_abnormal_outbound(flows, packets, config)
    assert len(findings) == 1

    f = findings[0]
    assert f.rule_name == "outbound_unusual_port"
    assert f.details["observed_unusual_port_bytes"] == 250000


def test_disabled_outbound_detector():
    config = load_config()
    config["detectors"]["outbound"]["enabled"] = False

    packets = [make_pkt(1, "192.168.1.10", "8.8.8.8", 2000000, ts=100.0)]
    flows = [make_out_flow(1, "192.168.1.10", "8.8.8.8", 80, 2000000)]

    findings = detect_abnormal_outbound(flows, packets, config)
    assert len(findings) == 0


def test_outbound_determinism():
    config = load_config()
    packets = [make_pkt(1, "192.168.1.10", "8.8.8.8", 1500000, ts=100.0)]
    flows = [make_out_flow(1, "192.168.1.10", "8.8.8.8", 80, 1500000)]

    f1 = detect_abnormal_outbound(flows, packets, config)
    f2 = detect_abnormal_outbound(flows, packets, config)

    assert len(f1) == 1
    assert len(f2) == 1
    assert f1[0] == f2[0]
