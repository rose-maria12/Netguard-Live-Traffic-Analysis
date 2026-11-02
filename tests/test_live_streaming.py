"""
Unit and integration tests for NetGuard Live Streaming,
Queue Backpressure, Dropped Packets, and Pause/Resume.
"""
import queue
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from netguard.capture.live_capture import LiveCaptureWorker, list_interfaces
from netguard.capture.live_pipeline import LiveDetectionEngine
from netguard.db import init_db
from netguard.web.app import create_app


def test_interface_enumeration_types():
    ifaces = list_interfaces()
    assert isinstance(ifaces, list)
    for iface in ifaces:
        assert "iface_type" in iface
        assert "is_active" in iface
        assert "is_loopback" in iface
        assert iface["iface_type"] in [
            "Ethernet", "Wi-Fi", "Loopback", "Bluetooth", "VPN/Tunnel", "Virtual", "Network Adapter"
        ]


def test_worker_pause_resume_and_dropped():
    sample_pcap = Path(__file__).resolve().parent / "data" / "pcaps" / "benign.pcap"
    # Bounded queue of size 2 to trigger dropped packets
    pkt_queue = queue.Queue(maxsize=2)
    worker = LiveCaptureWorker(packet_queue=pkt_queue, replay_file=sample_pcap)

    worker.start()
    assert worker.is_running is True
    assert worker.is_paused is False

    # Pause worker
    worker.pause()
    assert worker.is_paused is True

    # Packets sent while paused must not enter queue
    worker._packet_callback(b"packet_paused_1")
    assert pkt_queue.qsize() == 0

    # Resume worker
    worker.resume()
    assert worker.is_paused is False

    # Send packets to fill queue and trigger drop
    worker._packet_callback(b"packet_active_1")
    worker._packet_callback(b"packet_active_2")
    assert pkt_queue.qsize() == 2

    # Third packet should overflow and increment packets_dropped
    worker._packet_callback(b"packet_overflow_3")
    assert worker.packets_dropped == 1

    status = worker.get_status()
    assert status["packets_dropped"] == 1
    assert status["backlog_queue"] == 2
    assert "throughput_pps" in status

    worker.stop()
    assert worker.is_running is False


def test_live_engine_pause_resume_and_drain(tmp_path):
    db_file = tmp_path / "test_engine.db"
    init_db(db_file)

    pkt_queue = queue.Queue(maxsize=100)
    engine = LiveDetectionEngine(packet_queue=pkt_queue, db_path=db_file)

    res = engine.start()
    assert res["success"] is True
    assert engine.is_running is True

    # Test pause and resume
    assert engine.pause()["is_paused"] is True
    assert engine.resume()["is_paused"] is False

    # Stop engine and verify final drain
    stop_res = engine.stop()
    assert stop_res["success"] is True
    assert engine.is_running is False


def test_web_live_feed_and_pause_resume_endpoints(tmp_path):
    db_file = tmp_path / "test_web_feed.db"
    init_db(db_file)
    app = create_app(db_path=db_file, test_config={"TESTING": True, "WTF_CSRF_ENABLED": False})

    with app.test_client() as client:
        # Check initial live feed
        res = client.get("/api/capture/live_feed")
        assert res.status_code == 200
        data = res.get_json()
        assert "is_running" in data
        assert "packets" in data
        assert "flows" in data

        # Test pause when not running
        res_pause = client.post("/api/capture/pause", headers={"X-NetGuard-Auth": "test-bypass"})
        assert res_pause.status_code == 200

        # Test resume when not running
        res_resume = client.post("/api/capture/resume", headers={"X-NetGuard-Auth": "test-bypass"})
        assert res_resume.status_code == 200
