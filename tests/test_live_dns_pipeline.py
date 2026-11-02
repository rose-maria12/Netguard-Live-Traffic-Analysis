"""
Unit and integration tests for NetGuard Live DNS Pipeline:
- Distinction between Standard Unicast DNS (UDP 53), mDNS (UDP 5353), and LLMNR (UDP 5355).
- In-memory ring buffer separation (standard vs discovery traffic).
- Database persistence of live DNS events into SQLite dns_events table for parity with offline ingest.
- Protocol filtering, domain substring search, and API endpoints.
"""
import queue
import time
from pathlib import Path
import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR

from netguard.capture.live_pipeline import _extract_dns_event, LiveDetectionEngine
from netguard.db import init_db, get_db
from netguard.web.app import create_app


def test_extract_dns_event_classification():
    # 1. Standard DNS query: client -> 8.8.8.8:53 (wikipedia.org)
    pkt_std_query = IP(src="10.68.0.169", dst="8.8.8.8") / UDP(sport=54321, dport=53) / DNS(
        qr=0, id=1001, qd=DNSQR(qname="wikipedia.org")
    )
    ev_std = _extract_dns_event(pkt_std_query, frame_no=1)
    assert ev_std is not None
    assert ev_std["proto_type"] == "DNS"
    assert ev_std["qname"] == "wikipedia.org"
    assert ev_std["client_ip"] == "10.68.0.169"
    assert ev_std["server_ip"] == "8.8.8.8"
    assert ev_std["is_response"] == 0
    assert ev_std["txid"] == 1001

    # 2. Standard DNS response: 8.8.8.8:53 -> client (wikipedia.org -> 91.198.174.192)
    pkt_std_resp = IP(src="8.8.8.8", dst="10.68.0.169") / UDP(sport=53, dport=54321) / DNS(
        qr=1, id=1001, rcode=0, qd=DNSQR(qname="wikipedia.org"),
        an=DNSRR(rrname="wikipedia.org", rdata="91.198.174.192")
    )
    ev_resp = _extract_dns_event(pkt_std_resp, frame_no=2)
    assert ev_resp is not None
    assert ev_resp["proto_type"] == "DNS"
    assert ev_resp["client_ip"] == "10.68.0.169"
    assert ev_resp["server_ip"] == "8.8.8.8"
    assert ev_resp["is_response"] == 1
    assert "91.198.174.192" in ev_resp["answers"]

    # 3. mDNS discovery packet: client -> 224.0.0.251:5353 (_googlecast._tcp.local)
    pkt_mdns = IP(src="10.68.1.111", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(
        qr=0, id=0, qd=DNSQR(qname="_googlecast._tcp.local")
    )
    ev_mdns = _extract_dns_event(pkt_mdns, frame_no=3)
    assert ev_mdns is not None
    assert ev_mdns["proto_type"] == "mDNS"
    assert ev_mdns["qname"] == "_googlecast._tcp.local"

    # 4. LLMNR packet: client -> 224.0.0.252:5355
    pkt_llmnr = IP(src="10.68.0.50", dst="224.0.0.252") / UDP(sport=5355, dport=5355) / DNS(
        qr=0, id=555, qd=DNSQR(qname="DESKTOP-ABC")
    )
    ev_llmnr = _extract_dns_event(pkt_llmnr, frame_no=4)
    assert ev_llmnr is not None
    assert ev_llmnr["proto_type"] == "LLMNR"


def test_live_engine_dns_persistence_and_separation(tmp_path):
    db_file = tmp_path / "live_dns_test.db"
    init_db(db_file)

    pkt_queue = queue.Queue()
    engine = LiveDetectionEngine(packet_queue=pkt_queue, db_path=db_file)
    res = engine.start()
    assert res["success"] is True
    capture_id = res["capture_id"]

    # Push 1 standard DNS query (wikipedia.org) and 20 mDNS packets
    pkt_std = IP(src="10.68.0.169", dst="45.112.149.2") / UDP(sport=50000, dport=53) / DNS(
        qr=0, id=2001, qd=DNSQR(qname="wikipedia.org")
    )
    pkt_queue.put(pkt_std)

    for i in range(20):
        mdns_pkt = IP(src=f"10.68.1.{i+10}", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(
            qr=0, id=0, qd=DNSQR(qname=f"_service_{i}._tcp.local")
        )
        pkt_queue.put(mdns_pkt)

    time.sleep(1.0)
    stop_res = engine.stop()
    assert stop_res["success"] is True

    # 1. Check in-memory separation
    recent_std = engine.get_recent_dns(limit=50, proto_filter="dns")
    assert len(recent_std) == 1
    assert recent_std[0]["qname"] == "wikipedia.org"
    assert recent_std[0]["proto_type"] == "DNS"

    recent_all = engine.get_recent_dns(limit=50, proto_filter="all")
    assert len(recent_all) == 21

    recent_search = engine.get_recent_dns(limit=50, proto_filter="all", search_query="wikipedia")
    assert len(recent_search) == 1
    assert recent_search[0]["qname"] == "wikipedia.org"

    # 2. Check SQLite database persistence: wikipedia.org must exist in dns_events table!
    with get_db(db_file) as conn:
        cursor = conn.execute(
            "SELECT capture_id, client_ip, server_ip, qname, txid FROM dns_events WHERE capture_id = ? AND qname = 'wikipedia.org';",
            (capture_id,)
        )
        row = cursor.fetchone()
        assert row is not None
        assert row["qname"] == "wikipedia.org"
        assert row["client_ip"] == "10.68.0.169"
        assert row["server_ip"] == "45.112.149.2"
        assert row["txid"] == 2001

        # Total rows should be 21
        total_rows = conn.execute("SELECT COUNT(*) FROM dns_events WHERE capture_id = ?;", (capture_id,)).fetchone()[0]
        assert total_rows == 21


def test_api_capture_dns_endpoints(tmp_path):
    db_file = tmp_path / "test_api_dns.db"
    init_db(db_file)
    app = create_app(db_path=db_file, test_config={"TESTING": True, "WTF_CSRF_ENABLED": False})

    with app.test_client() as client:
        # Start capture
        start_res = client.post("/api/capture/start", json={"interface": "test_iface"})
        assert start_res.status_code == 200
        cap_id = start_res.get_json()["capture_id"]

        # Insert test records directly into DB to test dns_history endpoint
        with get_db(db_file) as conn:
            conn.execute(
                """
                INSERT INTO dns_events (capture_id, frame_no, ts, client_ip, server_ip, qname, qname_len, max_label_len, qtype, is_response, rcode, txid)
                VALUES (?, 1, ?, '10.68.0.169', '45.112.149.2', 'wikipedia.org', 13, 9, 1, 0, 0, 101);
                """,
                (cap_id, time.time())
            )
            conn.execute(
                """
                INSERT INTO dns_events (capture_id, frame_no, ts, client_ip, server_ip, qname, qname_len, max_label_len, qtype, is_response, rcode, txid)
                VALUES (?, 2, ?, '10.68.1.119', '224.0.0.251', '_rdlink._tcp.local', 18, 7, 1, 0, 0, 0);
                """,
                (cap_id, time.time())
            )
            conn.commit()

        # Query /api/capture/dns_history with search
        res = client.get(f"/api/capture/dns_history?capture_id={cap_id}&search=wikipedia")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["total"] == 1
        assert data["records"][0]["qname"] == "wikipedia.org"
        assert data["records"][0]["proto_type"] == "DNS"

        # Query /api/capture/dns_history with proto=mdns
        res_mdns = client.get(f"/api/capture/dns_history?capture_id={cap_id}&proto=mdns")
        assert res_mdns.status_code == 200
        data_mdns = res_mdns.get_json()
        assert data_mdns["total"] == 1
        assert "_rdlink._tcp.local" in data_mdns["records"][0]["qname"]
        assert data_mdns["records"][0]["proto_type"] == "mDNS"

        # Stop capture
        client.post("/api/capture/stop")

