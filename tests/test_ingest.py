import json
import tempfile
from pathlib import Path
import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapNgWriter, wrpcap

from netguard.db import get_db
from netguard.ingest.pcap_reader import calculate_sha256, detect_file_format
from netguard.pipeline import import_capture


@pytest.fixture
def sample_pcap(tmp_path):
    pcap_path = tmp_path / "test_sample.pcap"
    packets = [
        # Frame 1: TCP SYN (Port 80)
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="192.168.1.20", ttl=64) / TCP(sport=12345, dport=80, flags="S"),
        # Frame 2: Non-IP packet (ARP) -> skipped as non_ip
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst="192.168.1.1"),
        # Frame 3: UDP DNS Query (Port 53)
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=54321, dport=53) / DNS(id=1001, rd=1, qd=DNSQR(qname="test.example.com")),
        # Frame 4: UDP DNS Response (Port 53)
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=54321) / DNS(id=1001, qr=1, rcode=0, qd=DNSQR(qname="test.example.com")),
        # Frame 5: ICMP Echo Request
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="192.168.1.1") / ICMP(type=8),
    ]
    wrpcap(str(pcap_path), packets)
    return pcap_path


def test_calculate_sha256(sample_pcap):
    sha256_hex, size_bytes = calculate_sha256(sample_pcap)
    assert len(sha256_hex) == 64
    assert size_bytes > 0


def test_detect_file_format(sample_pcap):
    file_fmt = detect_file_format(sample_pcap)
    assert file_fmt == "pcap"


def test_detect_file_format_invalid(tmp_path):
    bad_file = tmp_path / "invalid.pcap"
    bad_file.write_bytes(b"BADMAGICBYTES")
    with pytest.raises(ValueError, match="Invalid magic bytes"):
        detect_file_format(bad_file)


def test_import_capture_end_to_end(sample_pcap, tmp_path):
    db_path = tmp_path / "test_netguard.db"

    capture_rec = import_capture(sample_pcap, db_path=db_path)

    assert capture_rec["status"] == "ok"
    assert capture_rec["frames_total"] == 5
    assert capture_rec["packets_stored"] == 4
    assert capture_rec["frames_skipped"] == 1
    assert "non_ip" in capture_rec["skipped_json"]

    conn = get_db(db_path)

    # Verify packets stored with exact 1-based Wireshark frame numbers
    pkts = conn.execute("SELECT * FROM packets WHERE capture_id = ? ORDER BY frame_no;", (capture_rec["id"],)).fetchall()
    assert len(pkts) == 4

    frame_nos = [p["frame_no"] for p in pkts]
    assert frame_nos == [1, 3, 4, 5]  # Frame 2 (ARP) was skipped

    # Verify Packet 1 fields
    p1 = pkts[0]
    assert p1["frame_no"] == 1
    assert p1["src_ip"] == "192.168.1.10"
    assert p1["dst_ip"] == "192.168.1.20"
    assert p1["proto"] == "TCP"
    assert p1["src_port"] == 12345
    assert p1["dst_port"] == 80
    assert p1["tcp_flags"] == 2  # SYN flag bit

    # Verify DNS events stored
    dns_events = conn.execute("SELECT * FROM dns_events WHERE capture_id = ? ORDER BY frame_no;", (capture_rec["id"],)).fetchall()
    assert len(dns_events) == 2

    # Query event (Frame 3)
    d1 = dns_events[0]
    assert d1["frame_no"] == 3
    assert d1["client_ip"] == "192.168.1.10"
    assert d1["server_ip"] == "8.8.8.8"
    assert d1["qname"] == "test.example.com"
    assert d1["is_response"] == 0

    # Response event (Frame 4)
    d2 = dns_events[1]
    assert d2["frame_no"] == 4
    assert d2["client_ip"] == "192.168.1.10"
    assert d2["server_ip"] == "8.8.8.8"
    assert d2["rcode"] == 0
    assert d2["is_response"] == 1

    conn.close()


def test_frame_number_preservation(tmp_path):
    pcap_path = tmp_path / "frame_test.pcap"
    packets = [
        # Frame 1: IPv4 / TCP
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80),
        # Frame 2: ARP (non-IP) -> skipped
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst="10.0.0.2"),
        # Frame 3: IPv4 / UDP
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=2000, dport=53),
        # Frame 4: IPv4 / ICMP
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8),
    ]
    wrpcap(str(pcap_path), packets)

    db_path = tmp_path / "test_frames.db"
    rec = import_capture(pcap_path, db_path=db_path)

    conn = get_db(db_path)
    pkts = conn.execute("SELECT frame_no FROM packets WHERE capture_id = ? ORDER BY frame_no;", (rec["id"],)).fetchall()
    conn.close()

    stored_frame_nos = [p["frame_no"] for p in pkts]
    assert stored_frame_nos == [1, 3, 4]


def test_skipped_frame_counts(tmp_path):
    pcap_path = tmp_path / "skipped_test.pcap"
    packets = [
        # Frame 1: IPv4 / TCP (stored)
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=1234),
        # Frame 2: ARP (skipped -> non_ip)
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst="10.0.0.2"),
        # Frame 3: IPv6 (skipped -> ipv6)
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=100, dport=200),
        # Frame 4: Unsupported IPv4 proto (proto=2 IGMP -> unsupported_proto)
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="224.0.0.1", proto=2),
        # Frame 5: IPv4 / UDP (stored)
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=53),
    ]
    wrpcap(str(pcap_path), packets)

    db_path = tmp_path / "test_skipped.db"
    rec = import_capture(pcap_path, db_path=db_path)

    assert rec["frames_total"] == 5
    assert rec["packets_stored"] == 2
    assert rec["frames_skipped"] == 3

    counts = json.loads(rec["skipped_json"])
    assert counts["non_ip"] == 1
    assert counts["ipv6"] == 1
    assert counts["unsupported_proto"] == 1


def test_pcapng_ingestion(tmp_path):
    pcapng_path = tmp_path / "test_sample.pcapng"
    writer = PcapNgWriter(str(pcapng_path))
    writer.write(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="172.16.0.5", dst="172.16.0.10") / TCP(sport=443, dport=54321, flags="SA"))
    writer.write(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="172.16.0.5", dst="8.8.4.4") / UDP(sport=53, dport=53333) / DNS(id=55, qr=1, rcode=0, qd=DNSQR(qname="pcapng.test")))
    writer.close()

    db_path = tmp_path / "test_pcapng.db"
    rec = import_capture(pcapng_path, db_path=db_path)

    assert rec["file_format"] == "pcapng"
    assert rec["status"] == "ok"
    assert rec["frames_total"] == 2
    assert rec["packets_stored"] == 2
    assert rec["frames_skipped"] == 0

    conn = get_db(db_path)
    pkts = conn.execute("SELECT * FROM packets WHERE capture_id = ? ORDER BY frame_no;", (rec["id"],)).fetchall()
    conn.close()

    assert len(pkts) == 2
    assert pkts[0]["frame_no"] == 1
    assert pkts[0]["src_ip"] == "172.16.0.5"
    assert pkts[1]["frame_no"] == 2


def test_frame_limit_enforced(sample_pcap, tmp_path):
    db_path = tmp_path / "test_limit.db"
    config = {
        "general": {
            "max_frames": 2,
            "max_pcap_mb": 50,
        }
    }
    with pytest.raises(ValueError, match="Frame count exceeded maximum limit"):
        import_capture(sample_pcap, db_path=db_path, config=config)


def test_corrupted_pcap_handling(tmp_path):
    bad_pcap = tmp_path / "corrupted_link.pcap"
    # Write valid PCAP header but with unsupported link type (linktype = 999)
    bad_pcap.write_bytes(b"\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x03\xe7")

    db_path = tmp_path / "test_corrupt.db"

    with pytest.raises(ValueError, match="Unsupported link type"):
        import_capture(bad_pcap, db_path=db_path)

    # Verify database status is set to failed and error is recorded
    conn = get_db(db_path)
    rec = conn.execute("SELECT * FROM captures WHERE filename = 'corrupted_link.pcap';").fetchone()
    conn.close()

    assert rec is not None
    assert rec["status"] == "failed"
    assert "Unsupported link type" in rec["error"]


def test_duplicate_capture_import(sample_pcap, tmp_path):
    db_path = tmp_path / "test_netguard.db"

    rec1 = import_capture(sample_pcap, db_path=db_path)
    rec2 = import_capture(sample_pcap, db_path=db_path)

    assert rec1["id"] == rec2["id"]
    assert rec1["sha256"] == rec2["sha256"]
