# NetGuard Platform Implementation Status & Audit Checkpoint

**Date:** October 2026  
**Project:** NetGuard — Network Intrusion Detection, Prevention and Forensic Correlation Platform  
**Target Environment:** Windows 10/11 x64, Python 3.10–3.14, Npcap / WinPcap, Windows Defender Firewall  
**Current Test Suite Status:** **160 / 160 PASSED (100%)** across 29 test files

---

## 1. Verified Architecture & Feature Status

| Component | Target Location | Status | Verification Summary |
| :--- | :--- | :---: | :--- |
| **Test Suite** | `tests/` | **Verified (160/160 Pass)** | 29 test files spanning all unit, integration, live streaming, live DNS, dataset, ML lifecycle, reports, and firewall suites. |
| **PCAP Ingestion** | `netguard/ingest/` | **Verified** | Scapy streaming with 1-based frame numbers and magic byte validation. |
| **Flow Reconstruction** | `netguard/ingest/flow_builder.py` | **Verified** | Bidirectional TCP/UDP/ICMP flows with forward/reverse metrics and TCP flags. |
| **Behavioral Windowing** | `netguard/features/` | **Verified** | 20s tumbling host windows with 9-dimensional behavioral vectors and persisted `feature_windows` row IDs. |
| **Rule Detectors (4)** | `netguard/detection/` | **Verified** | Port scan, brute force, DNS anomaly, and abnormal outbound rules verified. |
| **ML Detector (1)** | `netguard/detection/iforest.py` | **Audited & Verified** | Fitted `IsolationForest` (`100` trees, `9` features) on CIC-IDS2017 Monday benign subset (`101` train / `49` calib / `65` same-session held-out; threshold `0.5978`); `feature_windows.if_score` & `runs.model_id` persistence verified; limitations on synthetic attack PCAPs documented in [`docs/results.md`](docs/results.md). |
| **Deduplication & Filter** | `netguard/correlation/dedup.py` | **Verified** | Hash-key deduplication and CIDR/IP/port allowlisting. |
| **Incident Correlation** | `netguard/correlation/engine.py` | **Verified** | Union-Find multi-stage attack clustering (same-source + pivot). |
| **Prioritization Scoring** | `netguard/scoring/scorer.py` | **Verified** | 0–100 heuristic scoring matrix with stage progression & corroboration. |
| **Forensic Evidence** | `netguard/evidence/` | **Verified** | Wireshark filter generation and chronological event timeline. |
| **Windows Firewall** | `netguard/firewall/windows_fw.py` | **Verified** | PowerShell NetSecurity commands, safety filters, lease expiry, and audit log. |
| **Live Capture Worker** | `netguard/capture/live_capture.py` | **Verified** | Live & replay streaming, pause/resume, bounded queue backpressure, dropped packets counter, rolling PCAP persistence. |
| **Live Detection Engine** | `netguard/capture/live_pipeline.py` | **Verified** | Sliding evaluation, pause/resume, queue drain, final window evaluation on shutdown, and live telemetry access. |
| **Live DNS & Discovery Pipeline** | `netguard/capture/live_pipeline.py`, `web/` | **Verified** | Standard DNS (port 53) vs mDNS (port 5353) separation, SQLite `dns_events` persistence parity, domain search & protocol filtering. |
| **Dataset Benchmarking** | `netguard/datasets/benchmark.py` | **Verified** | Full CIC-IDS2017 & UNSW-NB15 schema mappers, confusion matrix, precision/recall/F1 metrics, and CLI runner (`evaluate_dataset.py`). |
| **Threat Intelligence** | `netguard/threat_intel/abuseipdb.py` | **Verified** | AbuseIPDB API client with RFC1918 private IP protection, in-memory TTL caching, and offline fallback. |
| **Web SOC Dashboard (Flask)** | `netguard/web/app.py` | **Verified** | Flask (`Flask>=3.0.0`) application (`create_app() -> Flask`, launched via `python netguard/web/app.py` on `127.0.0.1:5000`); endpoints `/api/capture/live_feed`, `/pause`, `/resume`, `/api/intel/lookup`, `/api/benchmark/run`; 16 responsive Jinja2 templates. |
| **Demonstration Generator** | `scripts/demo_traffic.py` | **Verified** | Harmless, reproducible Scapy generator for Scenarios A through F (Normal, Port Scan, Brute Force, DNS, Outbound, Multi-Stage). |
| **Academic Documentation** | `docs/` | **Verified** | 7 comprehensive technical, setup, demo, dataset, mapping, and viva defense guides. |

---

## 2. Phase Execution Progress

- [x] **Phase 0: Repository Audit & Baseline Verification** (Completed)
- [x] **Phase 1: Real-Time Network Traffic Capture Upgrade** (Completed: pause/resume, queue backpressure, dropped packets, rolling PCAP persistence, adapter categorization)
- [x] **Phase 2: End-to-End Detection & Live Pipeline Hardening** (Completed: final window flush, live telemetry streaming, queue drain)
- [x] **Phase 3: Authentic Dataset Integration & Benchmarking** (Completed: CIC-IDS2017 & UNSW-NB15 metadata, schema mapping, confusion matrix, `evaluate_dataset.py`)
- [x] **Phase 4: Windows Firewall Core Hardening** (Completed: safe IP guards, lease expiry, emergency unblock)
- [x] **Phase 5: Controlled Attack Demonstration Lab** (Completed: `scripts/demo_traffic.py` with Scenarios A–F)
- [x] **Phase 6: SOC Dashboard Integration** (Completed: live feed, pause/resume, dataset evaluation card, threat intel lookup)
- [x] **Phase 7: Threat Intelligence Integration** (Completed: AbuseIPDB client with privacy safeguards & caching)
- [x] **Phase 8: Automated Test Suite Expansion** (Completed: 160 passing tests across 29 test files)
- [x] **Phase 9: Comprehensive Academic Documentation** (Completed: all 7 guides generated, aligned with B.Tech Information Security requirements)

---

## 3. Documentation Library Summary

1. **[`docs/architecture.md`](docs/architecture.md)** — Architectural data flow, subsystem components, feature vector definitions, scoring formulas.
2. **[`docs/windows_setup_guide.md`](docs/windows_setup_guide.md)** — Npcap installation, loopback adapter, administrator rights vs unprivileged replay mode, Wireshark setup.
3. **[`docs/demonstration_guide.md`](docs/demonstration_guide.md)** — Detailed laboratory instructions for Scenarios A through F, live streaming, active firewall containment, and emergency failsafe.
4. **[`docs/dataset_guide.md`](docs/dataset_guide.md)** — CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15 dataset profiles, schema translation, confusion matrix, and `evaluate_dataset.py` execution.
5. **[`docs/objective_mapping.md`](docs/objective_mapping.md)** — Syllabus and requirement traceability matrix mapping all original objectives and specifications to code modules and tests.
6. **[`docs/viva_defense.md`](docs/viva_defense.md)** — Comprehensive viva defense notes covering packet vs flow, dual rule/ML detection, Isolation Forest, Npcap, Windows Firewall, correlation, scoring, false positives, and limitations.
7. **[`docs/results.md`](docs/results.md)** — Documented test suite breakdown (160 tests across 29 test files), authentic dataset benchmark results, live streaming throughput, and firewall latency metrics.

---

## 4. Verification Commands

```powershell
# 1. Execute automated test suite (160 tests across 29 test files)
cd D:\netguard\is_project2\is_project
python -m pytest tests/ -v

# 2. Run authentic dataset evaluation
python evaluate_dataset.py --csv tests/data/datasets/cic_ids2017_sample.csv --dataset CIC-IDS2017

# 3. Generate lab demonstration traffic
python scripts/demo_traffic.py --scenario F --pcap data/captures/demo_scenario_f.pcap

# 4. Start the SOC Dashboard
python netguard/web/app.py
```

---

## 5. Live Capture & Replay Audit Fixes (October 2026)

| Component | Issue / Root Cause | Resolution | Verification Status |
|-----------|--------------------|------------|---------------------|
| **Capture & Run Context Isolation** | Navigation and detector pages mixed historical findings from all runs together. (e.g. repeated uploads created duplicate runs like Alert #2 and Alert #4). | Implemented query & session scoping (`get_current_analysis_context`) across Dashboard, Traffic Forensics, Detectors, Alerts, Evidence, and APIs with persistent header banner and capture selector. | Verified via `tests/test_capture_isolation.py`; switching captures cleanly isolates metrics and findings. |
| **Replay Stalling / EOF Auto-Drain** | Worker finished at packet 939 (full EOF) but engine stayed running with `is_running=true`, leaving the session unfinalized. | Implemented EOF auto-drain in `/api/capture/live_feed`. When the replay finishes and queue is drained, `engine.stop()` is triggered automatically to flush windows, persist DB records, and return `is_completed=true`. | Verified; UI displays `REPLAY COMPLETED` with exact packet summary. |
| **Flow Schema Discrepancy (0 Alerts Root Cause)** | `LiveDetectionEngine` maintained custom ad-hoc dicts (`ip_src`, `ip_dst`) while detection detectors (`port_scan`, `brute_force`) require canonical `ActiveFlow` fields (`initiator_ip`, `responder_ip`, `state`, `first_frame`). Exceptions were caught silently, resulting in 0 detections. | Integrated canonical `ActiveFlow` and `canonical_flow_key` into `LiveDetectionEngine`, identical to the verified offline pipeline. | Verified; `demo_scenario.pcap` produces 2 alerts (`port_scan_vertical`, `repeated_short_connections`) and 1 multi-stage incident (score: 38.75). |
| **DNS Schema Alignment** | `_extract_dns_event` omitted `client_ip`, `max_label_len`, and `is_response` expected by `detect_dns_anomaly`. | Aligned extraction schema to include full DNS attributes matching `pcap_reader.py`. | Verified against `dns_tunnel.pcap` (yields `dns_long_names`). |
| **Controls Layout** | Buttons overflowed on narrow displays, hiding the Stop button. | Separated interface sniffing and sample replay into two distinct cards with dedicated wrapping button action bar. | Verified; responsive at standard browser zoom. |
| **Packets Stored Metric** | Showed 0 packets stored in database after live capture. In-memory buffer size was being saved instead of actual cumulative processed packets. | Updated `LiveDetectionEngine.stop()` to store `self.total_packets_processed` into `captures.packets_stored`. | Verified; persists exact count of processed packets to SQLite. |
| **Replay Safety** | Replaying sample PCAP files could inadvertently trigger Windows Firewall rules in Automatic mode. | Added `is_replay` flag to `LiveDetectionEngine`. Firewall auto-containment is strictly disabled during offline PCAP playback. | Verified; alerts generated without firing OS firewall changes. |
| **Legacy Repo Cleanup** | Unused legacy prototype directory `d:\netguard\is_project2\netguard` remained from initial early prototype. | Safely deleted legacy directory, retaining only the active `is_project` architecture. | Clean repository confirmed; 160/160 pytest tests passing across 29 test files. |
| **Pre-Presentation Audit & Clarity Upgrades** | (1) Live DNS table marked all non-NXDOMAIN packets `RESOLVED` even for queries (`is_response=0`); (2) Evidence & reports lacked bidirectional Wireshark filters and exact trigger-frame counts vs window span; (3) HTML/JSON exports omitted ML model metadata, per-window `if_score`, and limitations; (4) Flow tables omitted `initiator_port` and `start_ts`. | Fixed DNS status badges (`QUERY`, `RESOLVED`, `RESPONSE (NOERROR)`, `NXDOMAIN`); added `generate_bidirectional_wireshark_filter` and `extract_trigger_frames`; enriched HTML/JSON exports with `ml_model`, `feature_windows`, and `limitations`; added `start_ts` & `initiator_port` to flow tables and clarified detector execution vs threat findings across UI. | Verified across all 7 PCAP scenarios and 160/160 automated tests across 29 test files. |
| **Outbound Multi-Window Flow Indexing & Host Self-Block Guard** | (1) `flow_map` in `netguard/detection/outbound.py` indexed flows only by `start_ts` window, dropping flow references when a long-lived connection spanned later 20s windows; (2) `get_local_management_ips()` needed comprehensive enumeration of all Scapy/OS local interface IPs so the host can never block its own IP. | Updated `outbound.py` to index flows across all overlapping 20s windows (`range(start_win, end_win + 1)`), strengthened `get_local_management_ips()` in `windows_fw.py`, and added regression tests in `tests/test_firewall.py`. | Verified via `tests/test_firewall.py` and full 160-test suite. |
| **Presentation UI Redesign (Warm Beige & Dark Sidebar)** | Previous dark/neon theme used inline dark colors (`#1e2433`, purple gradients), showed all virtual/loopback adapters by default, labelled DNS lookups as "Live Visited Websites", and labelled every alert source as an "Attacker". | Redesigned shared design system (`style.css`, `base.html`, and all 14 templates) with warm beige/off-white background (`#f5f2eb`), white cards (`#ffffff`), near-black typography (`#18181b`), dark charcoal sidebar (`#18181b`), expandable `<details class="how-it-works">` sections, primary physical Wi-Fi/Ethernet interface filtering with a "Show all interfaces" toggle, "DNS Activity" / "DNS Events" naming with `DNS` / `Discovery` / `All` filters, and neutral `Source IP` / `Destination IP` labels. | Verified across all 14 HTML routes, 5 API endpoints (`HTTP 200`), headless browser screenshots, and `160 / 160` passing pytest tests. |



