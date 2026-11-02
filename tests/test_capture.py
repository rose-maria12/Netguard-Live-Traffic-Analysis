"""
Unit tests for NetGuard Live Capture and Live Pipeline.
Tests interface enumeration, capture worker lifecycle, and stream detection.
"""
import queue
import time
from unittest.mock import MagicMock, patch
import pytest

from netguard.capture.live_capture import LiveCaptureWorker, list_interfaces
from netguard.capture.live_pipeline import LiveDetectionEngine
from netguard.db import init_db


@pytest.fixture
def capture_db(tmp_path):
    db_file = tmp_path / "test_capture.db"
    init_db(db_file)
    return db_file


def test_list_interfaces():
    ifaces = list_interfaces()
    assert isinstance(ifaces, list)
    if ifaces:
        first = ifaces[0]
        assert "name" in first
        assert "ip" in first
        assert "is_active" in first


def test_capture_worker_lifecycle():
    q = queue.Queue()
    worker = LiveCaptureWorker(interface="TestInterface", packet_queue=q)

    assert worker.is_running is False
    status = worker.get_status()
    assert status["is_running"] is False
    assert status["packets_captured"] == 0

    # Start worker (with mocked sniff so it doesn't block)
    with patch("netguard.capture.live_capture.LiveCaptureWorker._run_live_sniff") as mock_sniff:
        res = worker.start()
        assert res["success"] is True
        assert worker.is_running is True

        # Second start attempt should fail
        dup = worker.start()
        assert dup["success"] is False
        assert "already running" in dup["error"]

        stop_res = worker.stop()
        assert stop_res["success"] is True
        assert worker.is_running is False


def test_live_detection_engine(capture_db):
    q = queue.Queue()
    engine = LiveDetectionEngine(packet_queue=q, db_path=capture_db, batch_interval=0.5)

    start_res = engine.start()
    assert start_res["success"] is True
    assert engine.is_running is True
    assert engine.live_run_id is not None

    # Duplicate start check
    dup = engine.start()
    assert dup["success"] is False

    metrics = engine.get_metrics()
    assert metrics["is_running"] is True
    assert metrics["prevention_mode"] == "monitor"

    # Push simulated packets
    # A mocked scapy IP packet
    mock_pkt = MagicMock()
    mock_pkt.haslayer.side_effect = lambda layer: True
    mock_pkt.time = time.time()
    mock_pkt.__len__.return_value = 60

    # Mock IP and TCP
    ip_mock = MagicMock()
    ip_mock.src = "198.51.100.77"
    ip_mock.dst = "10.0.0.1"

    tcp_mock = MagicMock()
    tcp_mock.sport = 12345
    tcp_mock.dport = 22
    tcp_mock.flags = "S"
    tcp_mock.seq = 100
    tcp_mock.ack = 0

    mock_pkt.__getitem__.side_effect = lambda l: ip_mock if "IP" in str(l) else tcp_mock

    # Put into queue
    q.put(mock_pkt)

    time.sleep(1.0)

    stop_res = engine.stop()
    assert stop_res["success"] is True
    assert engine.is_running is False


def test_replay_never_triggers_firewall_auto_block(capture_db):
    """Verify that replayed attack traffic never calls block_ip even when prevention mode is 'auto'."""
    from netguard.firewall.windows_fw import set_prevention_config
    from scapy.all import Ether, IP, TCP

    set_prevention_config(mode="auto", auto_block_min_severity="medium", db_path=capture_db)
    q = queue.Queue()
    engine = LiveDetectionEngine(packet_queue=q, db_path=capture_db, batch_interval=0.2, is_replay=True)

    with patch("netguard.capture.live_pipeline.block_ip") as mock_block:
        engine.start()
        base_ts = 1700000000.0
        for port in range(100, 125):
            pkt = Ether() / IP(src="198.51.100.99", dst="10.0.0.10") / TCP(sport=40000 + port, dport=port, flags="S")
            pkt.time = base_ts + (port - 100) * 0.05
            q.put(pkt)
        time.sleep(0.5)
        engine.stop()
        assert engine.total_alerts_generated >= 1
        mock_block.assert_not_called()


def test_uploaded_pcap_never_triggers_firewall_auto_block(capture_db, tmp_path, monkeypatch):
    """Verify that offline PCAP ingestion/analysis and POST /upload never trigger automatic firewall blocks even in 'auto' mode."""
    from pathlib import Path
    from netguard.db import get_db
    from netguard.detection.iforest import MODELS_DIR
    from netguard.firewall.windows_fw import set_prevention_config
    from netguard.pipeline import import_capture, run_analysis
    from netguard.web.app import create_app

    monkeypatch.setenv("NETGUARD_MODELS_DIR", str(MODELS_DIR))
    set_prevention_config(mode="auto", auto_block_min_severity="low", db_path=capture_db)
    pcap_path = Path(__file__).resolve().parent / "data" / "pcaps" / "multi_stage.pcap"

    with patch("netguard.firewall.windows_fw.block_ip") as mock_fw_block, \
         patch("netguard.firewall.windows_fw._run_powershell") as mock_ps:
        # 1. Direct offline pipeline (import_capture + run_analysis)
        cap = import_capture(pcap_path, db_path=capture_db)
        res = run_analysis(cap["id"], db_path=capture_db)
        assert res["alerts_count"] == 4
        assert res["incidents_count"] == 1
        mock_fw_block.assert_not_called()
        mock_ps.assert_not_called()

        # 2. Flask POST /upload route (app.test_client()) with another attack PCAP
        app = create_app(db_path=capture_db, test_config={"TESTING": True})
        client = app.test_client()
        dns_pcap = Path(__file__).resolve().parent / "data" / "pcaps" / "dns_tunnel.pcap"
        with open(dns_pcap, "rb") as f:
            resp = client.post(
                "/upload",
                data={"file": (f, "dns_tunnel.pcap")},
                content_type="multipart/form-data",
                follow_redirects=True,
            )
        assert resp.status_code == 200
        mock_fw_block.assert_not_called()
        mock_ps.assert_not_called()

    with get_db(capture_db) as conn:
        active_blocks = conn.execute("SELECT COUNT(*) FROM firewall_blocks;").fetchone()[0]
        assert active_blocks == 0


def test_bidirectional_wireshark_filter_and_trigger_frames():
    """Verify bidirectional Wireshark filter and exact trigger frame extraction."""
    from netguard.evidence.wireshark import (
        extract_trigger_frames,
        generate_bidirectional_wireshark_filter,
        generate_wireshark_filter,
    )

    alert = {
        "alert_type": "brute_force",
        "src_ip": "192.168.1.101",
        "dst_ip": "10.0.0.5",
        "dst_port": 22,
        "first_frame": 1,
        "last_frame": 60,
        "evidence_refs": [
            {"ref_type": "flow", "ref_id": 1, "frame_no": 1},
            {"ref_type": "flow", "ref_id": 2, "frame_no": 5},
            {"ref_type": "flow", "ref_id": 3, "frame_no": 9},
        ],
    }
    trig_filter = generate_wireshark_filter(alert)
    bi_filter = generate_bidirectional_wireshark_filter(alert)
    frames = extract_trigger_frames(alert)

    assert "ip.src == 192.168.1.101 && ip.dst == 10.0.0.5 && tcp.dstport == 22" in trig_filter
    assert "ip.addr == 192.168.1.101 && ip.addr == 10.0.0.5 && tcp.port == 22" in bi_filter
    assert "frame.number >= 1 && frame.number <= 60" in bi_filter
    assert frames == [1, 5, 9]
