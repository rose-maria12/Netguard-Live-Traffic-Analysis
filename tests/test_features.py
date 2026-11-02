import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from netguard.db import get_db
from netguard.features.window_features import (
    extract_window_features_for_capture,
    is_external_ip,
    is_internal_ip,
    parse_internal_cidrs,
)
from netguard.pipeline import import_capture


def test_ip_classification():
    internal_nets = parse_internal_cidrs(["192.168.0.0/16", "10.0.0.0/8"])

    assert is_internal_ip("192.168.1.10", internal_nets) is True
    assert is_internal_ip("10.0.0.5", internal_nets) is True
    assert is_internal_ip("8.8.8.8", internal_nets) is False

    assert is_external_ip("8.8.8.8", internal_nets) is True
    assert is_external_ip("192.168.1.10", internal_nets) is False
    assert is_external_ip("127.0.0.1", internal_nets) is False  # Loopback is not external


def test_window_features_extraction_end_to_end(tmp_path):
    pcap_path = tmp_path / "feat_sample.pcap"
    packets = [
        # Frame 1: Internal host 192.168.1.10 contacts external 8.8.8.8:80 (TCP SYN)
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=10001, dport=80, flags="S"),
        # Frame 2: Internal host 192.168.1.10 contacts external 8.8.8.8:443 (TCP SYN)
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=10002, dport=443, flags="S"),
        # Frame 3: DNS Query for example.com (len 11)
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="1.1.1.1") / UDP(sport=50000, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname="example.com")),
        # Frame 4: DNS Response NXDOMAIN (rcode=3)
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(src="1.1.1.1", dst="192.168.1.10") / UDP(sport=53, dport=50000) / DNS(id=1, qr=1, rcode=3, qd=DNSQR(qname="example.com")),
    ]
    wrpcap(str(pcap_path), packets)

    db_path = tmp_path / "test_feat.db"
    rec = import_capture(pcap_path, db_path=db_path)

    # Insert dummy run to satisfy foreign key constraint
    conn = get_db(db_path)
    cursor = conn.execute(
        """
        INSERT INTO runs (capture_id, config_json, config_sha256, seed, started_at, status, python_version, sklearn_version, scapy_version, netguard_version)
        VALUES (?, '{}', 'dummy_hash', 42, 100.0, 'running', '3.14', '1.8', '2.8', '1.0');
        """,
        (rec["id"],),
    )
    run_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Extract features for capture
    feats = extract_window_features_for_capture(rec["id"], run_id=run_id, db_path=db_path)

    assert len(feats) >= 1
    h_feat = feats[0]

    assert h_feat["host_ip"] == "192.168.1.10"
    assert h_feat["unique_dst_ports"] == 3  # 80, 443, 53
    assert h_feat["unique_dst_ips"] == 2  # 8.8.8.8, 1.1.1.1
    assert h_feat["dns_query_count"] == 1
    assert h_feat["avg_qname_length"] == 11.0
    assert h_feat["nxdomain_ratio"] == 1.0
    assert h_feat["bytes_out_external"] > 0
    assert h_feat["out_in_ratio"] >= 0.0

    # Verify persistence to feature_windows table
    conn = get_db(db_path)
    db_rows = conn.execute("SELECT * FROM feature_windows WHERE run_id = ?;", (run_id,)).fetchall()
    conn.close()

    assert len(db_rows) == len(feats)
    assert db_rows[0]["host_ip"] == "192.168.1.10"
    assert db_rows[0]["dns_query_count"] == 1
