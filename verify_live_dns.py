import os
import sys
import time
import subprocess
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from netguard.capture.live_capture import LiveCaptureWorker
from netguard.capture.live_pipeline import LiveDetectionEngine
from netguard.db import init_db, get_db

def run_verification():
    db_path = Path("is_project/data/netguard.db")
    print("=== LIVE DNS PIPELINE VERIFICATION ===")
    print(f"Target DB: {db_path}")

    # Interface from Scapy: Wi-Fi GUID
    iface = r"\Device\NPF_{AE7CA26B-6C34-49B8-9C98-AFF8EAF20BAE}"
    print(f"Binding to interface: {iface} (Wi-Fi 10.68.0.169)")

    import queue
    pkt_queue = queue.Queue(maxsize=10000)

    worker = LiveCaptureWorker(
        interface=iface,
        packet_queue=pkt_queue,
    )
    engine = LiveDetectionEngine(
        packet_queue=pkt_queue,
        db_path=db_path,
    )

    print("\n1. Starting Live Engine & Capture Worker...")
    eng_res = engine.start()
    work_res = worker.start()
    print(f"Engine start result: {eng_res}")
    print(f"Worker start result: {work_res}")

    if not work_res.get("success"):
        print("ERROR: Worker failed to start:", work_res)
        engine.stop()
        return

    time.sleep(1.0)
    print("\n2. Executing nslookup command:")
    nslookup_cmd = ["nslookup", "-type=A", "wikipedia.org", "45.112.149.2"]
    print(f"Command: {' '.join(nslookup_cmd)}")
    try:
        proc = subprocess.run(nslookup_cmd, capture_output=True, text=True, timeout=10)
        print("nslookup STDOUT:\n", proc.stdout)
        if proc.stderr:
            print("nslookup STDERR:\n", proc.stderr)
    except Exception as e:
        print(f"nslookup failed to execute: {e}")

    print("Waiting 3 seconds for packets to be processed through pipeline...")
    time.sleep(3.0)

    print("\n3. Stopping Worker & Engine...")
    w_stats = worker.stop()
    e_stats = engine.stop()
    print(f"Worker metrics: {w_stats}")
    print(f"Engine metrics: {e_stats}")

    print("\n4. Stage-by-Stage Verification:")
    # Stage 1: Captured packets
    pkts_captured = w_stats.get("packets_captured", 0)
    print(f"Stage 1 [Npcap Capture]: {pkts_captured} packets captured on Wi-Fi adapter.")

    # Stage 2: DNS Events extracted
    total_dns = len(engine.recent_dns_events)
    std_dns = len(engine.recent_standard_dns_events)
    print(f"Stage 2 [Parsing & In-Memory Queuing]: {total_dns} total DNS events parsed ({std_dns} Standard DNS, {total_dns - std_dns} mDNS).")

    # Stage 3: Live Feed / Recent DNS Query
    recent_std = engine.get_recent_dns(limit=50, proto_filter="dns")
    found_in_std = [d for d in recent_std if "wikipedia" in d.get("qname", "").lower()]
    print(f"Stage 3 [Standard DNS Feed]: Found {len(found_in_std)} wikipedia.org entries in recent_standard_dns.")
    for d in found_in_std:
        print(f"  -> QNAME: {d['qname']} | Client: {d['client_ip']} | Server: {d['server_ip']} | Proto: {d['proto_type']} | Answers: {d.get('answers')}")

    # Stage 4: Database Storage in SQLite dns_events table
    cap_id = eng_res.get("capture_id")
    print(f"Stage 4 [SQLite DB Persistence for Capture ID #{cap_id}]:")
    with get_db(db_path) as conn:
        cursor = conn.execute(
            "SELECT id, capture_id, frame_no, ts, client_ip, server_ip, qname, is_response, rcode, txid FROM dns_events WHERE capture_id = ? AND qname LIKE '%wikipedia%';",
            (cap_id,)
        )
        db_rows = [dict(r) for r in cursor.fetchall()]
        print(f"  -> Found {len(db_rows)} wikipedia records in SQLite dns_events table for live session #{cap_id}!")
        for r in db_rows:
            print(f"     Row #{r['id']}: QNAME={r['qname']}, Client={r['client_ip']}, Server={r['server_ip']}, Resp={r['is_response']}, RCode={r['rcode']}")

        # Also count mDNS discovery records in same session
        mdns_count = conn.execute(
            "SELECT COUNT(*) FROM dns_events WHERE capture_id = ? AND (server_ip = '224.0.0.251' OR client_ip = '224.0.0.251' OR qname LIKE '%.local');",
            (cap_id,)
        ).fetchone()[0]
        print(f"  -> Total mDNS discovery records persisted in DB: {mdns_count}")

    print("\n=== VERIFICATION FINISHED ===")

if __name__ == "__main__":
    run_verification()

