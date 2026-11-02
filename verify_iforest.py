#!/usr/bin/env python
"""
verify_iforest.py

Quick sanity‑check that the Isolation‑Forest detector works end‑to‑end:

1️⃣ Generate a DNS‑anomaly PCAP (Scenario D) using the demo traffic generator.
2️⃣ Ingest the PCAP → host‑window feature rows.
3️⃣ Load the trained baseline model.
4️⃣ Score the windows and print any alerts.
"""

import pathlib, sys

# 1️⃣ Generate the malicious PCAP
from scripts.demo_traffic import generate_scenario_d_dns_anomaly
from scapy.utils import wrpcap

SRC_IP = "10.0.0.5"
PCAP_PATH = pathlib.Path("data/uploads/dns_anomaly_demo.pcap")
PCAP_PATH.parent.mkdir(parents=True, exist_ok=True)
wrpcap(str(PCAP_PATH), generate_scenario_d_dns_anomaly(SRC_IP))
print(f"[+] PCAP written to {PCAP_PATH}")

# 2️⃣ Ingest + analysis pipeline
from netguard.db import init_db
from netguard.pipeline import import_capture, run_analysis

db_path = pathlib.Path("data/test_verify.db")
init_db(db_path)
cap = import_capture(PCAP_PATH, db_path=db_path)
res = run_analysis(cap["id"], db_path=db_path)

# 3️⃣ Load the trained baseline model
from netguard.detection.iforest import load_model_bundle
model_bundle = load_model_bundle("default_baseline")
print("[+] Model loaded - version:", model_bundle.get("model_version"))
print("[+] Calibrated threshold:", model_bundle.get("threshold"))

# 4. Display ML results
ml_alerts = [a for inc in res["incidents"] for a in inc.alerts if a.alert_type == "ml_anomaly"]

print("\n=== Isolation-Forest Results ===")
print(f"ML alerts generated  : {len(ml_alerts)}")
if ml_alerts:
    for f in ml_alerts:
        print("-" * 70)
        print(f"Host: {f.src_ip}")
        print(f"Score: {f.details.get('score', 'N/A')} (threshold {f.details.get('threshold', 'N/A')})")
        print(f"Severity: {f.severity}")
        print(f"Dominant family: {f.details.get('dominant_family')}")
        print(f"Summary: {f.summary}")
        print(f"Suggested precautions / next steps: {f.details.get('suggested_precautions')}")
else:
    print("No anomalies detected – the UI would show ‘No ML Anomalies Detected’.")

# Cleanup temp db
try:
    if db_path.exists():
        db_path.unlink()
except Exception:
    pass

