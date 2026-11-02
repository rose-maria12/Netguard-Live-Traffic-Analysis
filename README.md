# NetGuard — Network Intrusion Detection, Prevention & Forensic Correlation Platform

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-164%20%2F%20164%20passed%20(100%25)-success.svg)](tests/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%2F%2011%20x64%20(Npcap)-lightgrey.svg)]()

An end-to-end, forensic-grade network intrusion detection, active prevention, and multi-stage correlation system designed for Windows environments. NetGuard analyzes live network adapter traffic (Npcap) and offline PCAP/PCAPng packet captures through a 4-stage pipeline:

**Packet Ingestion → Flow Reconstruction → Behavioral Feature Windows → Dual-Engine Detection (Deterministic Rules + Isolation Forest ML) → Alert Deduplication → Union-Find Incident Correlation → 0–100 Prioritization Scoring → Windows Defender Firewall Active Containment → SOC Web Dashboard & Forensic Reports.**

---

## Key Highlights & Verification Status

- **Automated Test Suite:** **164 / 164 PASSED (100%)** across 30 test files (`pytest`).
- **Live Packet Capture:** Npcap + Scapy integration with interface discovery, pause/resume, bounded queue backpressure, dropped packets accounting, and rolling PCAP evidence persistence.
- **Active OS Prevention:** Genuine Windows Defender Firewall rule management via PowerShell NetSecurity (`New-NetFirewallRule`), supporting Monitor, Manual, and Automatic containment modes with safe IP exclusions and lease auto-expiration.
- **Dual Detection Engine:**
  - **Deterministic Rule Engine:** High-confidence vertical port scanning, short authentication connection bursts (brute-force patterns), DNS anomaly/tunneling detection, and abnormal egress exfiltration.
  - **Unsupervised ML Engine:** Scikit-Learn `IsolationForest` calibrated to 99th-percentile baseline threshold across 9 multivariate host-window features with standard scaler transform.
- **Incident Precautions & Next Steps:** Built-in operational playbook mapping threat flags to concrete analyst investigation and mitigation procedures.
- **Authentic Dataset Benchmarking:** Built-in evaluation pipeline for **CIC-IDS2017** and **UNSW-NB15** with schema translation, confusion matrix, precision/recall/F1 metrics, and CLI runner (`evaluate_dataset.py`).
- **Controlled Lab Attack Generator:** Programmatic Scapy generator (`scripts/demo_traffic.py`) for Scenarios A through F (Normal, Port Scan, Brute Force, DNS Anomaly, Outbound Transfer, Correlated Multi-Stage).
- **Threat Intelligence:** AbuseIPDB reputation lookups with RFC1918 private IP protection, in-memory TTL caching, and offline fallback.
- **Forensic Admissibility:** Stable 1-based frame numbers matching Wireshark, bidirectional copyable display filters, chronological attack timelines, and self-contained 100% offline HTML/JSON report exports.

---

## Architecture Overview

```
                      Physical / Virtual NIC (Npcap)  OR  Offline PCAP / PCAPng
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │  ingest/pcap_reader.py & capture/live_capture │  1-based frame numbers, SHA-256,
                      │  ingest/flow_builder.py                       │  bounded queue, bidirectional flows
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │  features/window_features.py                 │  9-dimensional behavioral vectors
                      │  (extract_window_features_for_capture)       │  across 20-second tumbling windows
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │  detection/                                  │
                      │   port_scan.py    – Vertical Reconnaissance  │  Deterministic rules (confidence 0.6–0.9)
                      │   brute_force.py  – Short Auth Bursts        │  +
                      │   dns_anomaly.py  – Burst / Tunneling / DGA  │  Isolation Forest ML Anomaly
                      │   outbound.py     – Abnormal Exfiltration    │  (99th percentile baseline threshold)
                      │   iforest.py      – Unsupervised ML Anomaly  │
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │  correlation/dedup.py                        │  Hash-key deduplication & CIDR allowlist
                      │  correlation/engine.py (Union-Find)          │  Same-Source (600s) + Lateral Pivot (900s)
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │  scoring/scorer.py                           │  0–100 heuristic prioritization score
                      │  evidence/wireshark.py & timeline.py         │  Wireshark filters, chronological timeline
                      │  firewall/windows_fw.py                      │  Windows Defender Firewall active blocking
                      │  threat_intel/abuseipdb.py                   │  AbuseIPDB reputation caching
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │  netguard/web/app.py (Flask Dashboard)       │  Live Monitor, Traffic Forensics, Alerts,
                      │  SQLite Database (14 tables, WAL mode)       │  Incidents, Firewall UI, Evaluation, Reports
                      └──────────────────────────────────────────────┘
```

---

## Operational Guidance & Suggested Precautions

Every detection scenario in NetGuard provides automated operational guidance for SOC analysts and incident responders:

| Flag | Scenario / Detection View | Suggested Precautions / Next Steps |
| :--- | :--- | :--- |
| **Port scan** | Vertical Port Scan (`/detection/port_scan`) | Check whether this is an authorised scan. Inspect the targeted ports. If an untrusted source is probing your laptop, consider a temporary inbound block. |
| **Brute-force-like activity** | Repeated Short Connections (`/detection/brute_force`) | Check authentication logs for failed logins. Review successful logins from that source. Consider temporary blocking, MFA, and login rate limits. |
| **DNS anomaly** | DNS Anomaly & Tunneling (`/detection/dns_anomaly`) | Inspect the requested names and NXDOMAIN responses. Identify the application generating them. If unexplained, investigate the device and consider an endpoint security scan. |
| **Unusual outbound traffic** | Abnormal Outbound Transfer (`/detection/outbound`) | Check for uploads, backups, or synchronisation. Identify the process and destination. If confirmed suspicious, consider restricting outbound access or isolating the device. |
| **ML anomaly** | Isolation Forest Host Anomaly (`/detection/ml`) | Review the unusual features, inspect supporting packets, and check whether rule detectors also flagged the activity. Avoid blocking solely because of the ML score. |

---

## Detection Rules & Thresholds

| Rule Name | Stage | Primary Thresholds | Default Confidence |
| :--- | :--- | :--- | :---: |
| **Vertical Port Scan** | Reconnaissance | $\ge 15$ distinct destination ports, $\ge 70\%$ failed flow ratio | `0.90` |
| **Brute-Force Bursts** | Access Attempt | Service ports (21, 22, 23, 3389, 5900), $\ge 10$ attempts, $\ge 50\%$ short flows ($\le 5\text{s}$) | `0.70` |
| **DNS Anomaly** | Possible Exploitation | $\ge 60$ queries/window OR label length $\ge 40$ chars OR $\ge 50\%$ NXDOMAIN responses | `0.60` |
| **Abnormal Outbound** | Possible Exfiltration | Volume $\ge 1\text{ MB}$ OR upload ratio $\ge 20:1$ OR non-standard port transfer $\ge 200\text{ KB}$ | `0.60` |
| **Isolation Forest ML** | Multivariate Anomaly | Anomaly score exceeding 99th-percentile baseline threshold across 9 host-window features | `0.50` |

---

## Installation & Setup

### 1. Requirements
- **Operating System:** Windows 10 / Windows 11 x64 (Primary), or Linux
- **Python:** Python 3.10 to 3.14
- **Npcap Driver:** Version 1.70+ with WinPcap API-compatible mode enabled (required for live NIC sniffing)

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Verify Npcap (For Live Sniffing)
Download and install Npcap from [npcap.com](https://npcap.com/#download).
---

## Quick Start & Usage

### 1. Launch the SOC Dashboard
Open an elevated PowerShell terminal (Administrator mode required for real Windows Defender Firewall rules and physical adapter sniffing):
```powershell
python run.py
```
Access the web dashboard in your browser:
 **`http://127.0.0.1:5000`**

### 2. Run the Full Automated Test Suite
```powershell
python -m pytest tests/ -v
```
*Expected Result:* **164 passed in ~47s (100% pass rate across 30 test files)**.

### 3. Evaluate Rule Detectors
```powershell
python evaluate.py
```
*Expected Result:* **100% Precision and 100% Recall** across all rule detectors on deterministic ground-truth scenarios.

### 4. Run Controlled Attack Traffic Generator (Scenarios A through F)
```powershell
# Scenario A: Normal Web & DNS Browsing (Benign)
python scripts/demo_traffic.py --scenario A

# Scenario B: Vertical Port Scan (Reconnaissance)
python scripts/demo_traffic.py --scenario B

# Scenario C: Repeated Authentication Connection Bursts (Access Attempt)
python scripts/demo_traffic.py --scenario C

# Scenario D: DNS High-Rate / Long Labels / NXDOMAIN (Possible Exploitation)
python scripts/demo_traffic.py --scenario D

# Scenario E: Abnormal Outbound Data Volume (Possible Exfiltration)
python scripts/demo_traffic.py --scenario E

# Scenario F: Correlated Multi-Stage Incident (Full Kill Chain)
python scripts/demo_traffic.py --scenario F
```

### 5. Run Authentic Dataset Benchmark (CIC-IDS2017)
```powershell
python evaluate_dataset.py --csv tests/data/datasets/cic_ids2017_sample.csv --dataset CIC-IDS2017
```

---

## Documentation Library

Comprehensive engineering, laboratory, and oral defense guides are maintained in the [`docs/`](docs/) directory:

| Document | Purpose |
| :--- | :--- |
| **[`docs/architecture.md`](docs/architecture.md)** | Deep architectural diagrams, flow math, and module specifications. |
| **[`docs/windows_setup_guide.md`](docs/windows_setup_guide.md)** | Step-by-step Windows, Npcap, Wireshark, and unprivileged mode setup. |
| **[`docs/demonstration_guide.md`](docs/demonstration_guide.md)** | Step-by-step laboratory guide for Scenarios A–F and active firewall containment. |
| **[`docs/dataset_guide.md`](docs/dataset_guide.md)** | Authoritative dataset profiles (CIC-IDS2017, UNSW-NB15), schema mapping, and metrics. |
| **[`docs/objective_mapping.md`](docs/objective_mapping.md)** | Traceability matrix mapping syllabus objectives to modules and verification tests. |
| **[`docs/viva_defense.md`](docs/viva_defense.md)** | Comprehensive oral examination Q&A guide covering architecture, ML, and defense. |
| **[`docs/results.md`](docs/results.md)** | Documented test suite results, confusion matrix, and throughput benchmarks. |

---



