import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from netguard.db import get_db
from netguard.ingest.flow_builder import build_flows_for_capture, canonical_flow_key
from netguard.pipeline import import_capture


def test_canonical_flow_key():
    key1 = canonical_flow_key("TCP", "192.168.1.10", 12345, "10.0.0.1", 80)
    key2 = canonical_flow_key("TCP", "10.0.0.1", 80, "192.168.1.10", 12345)
    assert key1 == key2
    assert key1 == ("TCP", "10.0.0.1", 80, "192.168.1.10", 12345)


def test_tcp_established_flow(tmp_path):
    pcap_path = tmp_path / "tcp_est.pcap"
    packets = [
        # 1. Initiator SYN
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S"),
        # 2. Responder SYN-ACK
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(src="10.0.0.1", dst="192.168.1.10") / TCP(sport=80, dport=5000, flags="SA"),
        # 3. Initiator ACK
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="A"),
        # 4. Initiator Data
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA"),
    ]
    wrpcap(str(pcap_path), packets)

    db_path = tmp_path / "test_flows.db"
    rec = import_capture(pcap_path, db_path=db_path)

    conn = get_db(db_path)
    flows = conn.execute("SELECT * FROM flows WHERE capture_id = ?;", (rec["id"],)).fetchall()
    conn.close()

    assert len(flows) == 1
    flow = flows[0]
    assert flow["initiator_ip"] == "192.168.1.10"
    assert flow["responder_ip"] == "10.0.0.1"
    assert flow["initiator_port"] == 5000
    assert flow["responder_port"] == 80
    assert flow["proto"] == "TCP"
    assert flow["pkts_fwd"] == 3
    assert flow["pkts_rev"] == 1
    assert flow["state"] == "established"
    assert flow["first_frame"] == 1
    assert flow["last_frame"] == 4


def test_tcp_no_response_flow(tmp_path):
    pcap_path = tmp_path / "tcp_no_resp.pcap"
    packets = [
        # Initiator SYN only
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=5001, dport=22, flags="S"),
    ]
    wrpcap(str(pcap_path), packets)

    db_path = tmp_path / "test_no_resp.db"
    rec = import_capture(pcap_path, db_path=db_path)

    conn = get_db(db_path)
    flows = conn.execute("SELECT * FROM flows WHERE capture_id = ?;", (rec["id"],)).fetchall()
    conn.close()

    assert len(flows) == 1
    assert flows[0]["state"] == "no_response"
    assert flows[0]["pkts_fwd"] == 1
    assert flows[0]["pkts_rev"] == 0


def test_tcp_reset_flow(tmp_path):
    pcap_path = tmp_path / "tcp_reset.pcap"
    packets = [
        # Initiator SYN
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=5002, dport=23, flags="S"),
        # Responder RST
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(src="10.0.0.1", dst="192.168.1.10") / TCP(sport=23, dport=5002, flags="RA"),
    ]
    wrpcap(str(pcap_path), packets)

    db_path = tmp_path / "test_reset.db"
    rec = import_capture(pcap_path, db_path=db_path)

    conn = get_db(db_path)
    flows = conn.execute("SELECT * FROM flows WHERE capture_id = ?;", (rec["id"],)).fetchall()
    conn.close()

    assert len(flows) == 1
    assert flows[0]["state"] == "reset"
    assert flows[0]["rst_count"] == 1


def test_mid_handshake_synack_initiator_swap(tmp_path):
    pcap_path = tmp_path / "synack_first.pcap"
    packets = [
        # Capture starts mid-handshake with SYN-ACK from 10.0.0.1:80 to 192.168.1.10:6000
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(src="10.0.0.1", dst="192.168.1.10") / TCP(sport=80, dport=6000, flags="SA"),
    ]
    wrpcap(str(pcap_path), packets)

    db_path = tmp_path / "test_mid.db"
    rec = import_capture(pcap_path, db_path=db_path)

    conn = get_db(db_path)
    flows = conn.execute("SELECT * FROM flows WHERE capture_id = ?;", (rec["id"],)).fetchall()
    conn.close()

    assert len(flows) == 1
    # Initiator should be swapped to 192.168.1.10:6000
    assert flows[0]["initiator_ip"] == "192.168.1.10"
    assert flows[0]["initiator_port"] == 6000
    assert flows[0]["responder_ip"] == "10.0.0.1"
    assert flows[0]["responder_port"] == 80


def test_flow_packets_association(tmp_path):
    pcap_path = tmp_path / "assoc.pcap"
    packets = [
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="10.0.0.1") / UDP(sport=1000, dport=2000),
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(src="10.0.0.1", dst="192.168.1.10") / UDP(sport=2000, dport=1000),
    ]
    wrpcap(str(pcap_path), packets)

    db_path = tmp_path / "test_assoc.db"
    rec = import_capture(pcap_path, db_path=db_path)

    conn = get_db(db_path)
    pkts = conn.execute("SELECT id, flow_id FROM packets WHERE capture_id = ?;", (rec["id"],)).fetchall()
    conn.close()

    assert len(pkts) == 2
    assert pkts[0]["flow_id"] is not None
    assert pkts[0]["flow_id"] == pkts[1]["flow_id"]
