# Demonstration Guide & 8-Step Presentation Checklist for NetGuard

This guide walks through a hands-on presentation and laboratory demonstration showcasing the complete NetGuard pipeline: PCAP/PCAPNG ingestion, rule-based detectors, Isolation Forest ML anomaly scoring, multi-stage correlation, live DNS/mDNS monitoring, Wireshark filter verification, and Windows Defender Firewall containment.

---

## Quick 8-Step Presentation Demo Checklist (Viva & Live Demo)

Before starting, identify your local Wi-Fi IPv4 address (`<YOUR_WIFI_IP>`) and, if using a second laptop for the live LAN test, its IPv4 address (`<PEER_LAPTOP_IP>`):
```powershell
ipconfig
# Look under "Wireless LAN adapter Wi-Fi" -> "IPv4 Address" (e.g., <YOUR_WIFI_IP>)
```

### Step 1: Launch NetGuard Web Console
- **Standard Mode (Upload, Forensics, Replay, ML & Correlation):**
  ```powershell
  cd d:\netguard\is_project2\is_project
  python netguard/web/app.py
  ```
- **Elevated Mode (Required only for live Npcap adapter sniffing & real Windows Defender Firewall rule creation):**
  Open **PowerShell as Administrator** and run the same command above, then open `http://127.0.0.1:5000`.

### Step 2: Benign Traffic Baseline Check (`0` Alerts)
1. Navigate to **Upload & Analyze** (`/upload`) and upload `tests/data/pcaps/benign.pcap`.
2. Verify the top scope banner reads `File: benign.pcap | Ingest: PARSED OK (INGESTED)`.
3. On **Dashboard** (`/`), verify **Detector Execution Status vs. Findings** shows all 5 detectors executed (`Port Scan`, `Brute Force`, `DNS Anomaly`, `Outbound`, `Isolation Forest ML`) with **`0` Alerts** and **`0` Incidents**.

### Step 3: Individual Rule & ML Detector Verification
Upload or select each scenario in the topbar **Scope** selector and inspect its dedicated detector view. Each scenario displays operational guidance and analyst next steps:

| Flag | Suggested precautions / next steps |
| :--- | :--- |
| **Port scan** | Check whether this is an authorised scan. Inspect the targeted ports. If an untrusted source is probing your laptop, consider a temporary inbound block. |
| **Brute-force-like activity** | Check authentication logs for failed logins. Review successful logins from that source. Consider temporary blocking, MFA, and login rate limits. |
| **DNS anomaly** | Inspect the requested names and NXDOMAIN responses. Identify the application generating them. If unexplained, investigate the device and consider an endpoint security scan. |
| **Unusual outbound traffic** | Check for uploads, backups, or synchronisation. Identify the process and destination. If confirmed suspicious, consider restricting outbound access or isolating the device. |
| **ML anomaly** | Review the unusual features, inspect supporting packets, and check whether rule detectors also flagged the activity. Avoid blocking solely because of the ML score. |

- **Vertical Port Scan (`tests/data/pcaps/port_scan.pcap`, SHA-256 `05450ffc...`, `25` pkts, `25` flows):**
  - Open **Port Scan Detector** (`/detection/port_scan`) and **Isolation Forest ML** (`/detection/ml`).
  - Confirm `port_scan_vertical` triggers (`25` distinct TCP ports $\ge 15$, `100.0%` failed ratio $\ge 70\%$, severity `low`, confidence `0.90`, stage `Reconnaissance`) and Isolation Forest scores `0.629932 > 0.597751` (`ANOMALY`, incident score `26.25 / 100`).
- **Repeated Short SSH Connections (`tests/data/pcaps/brute_force.pcap`, SHA-256 `bc59747f...`, `60` pkts, `15` flows):**
  - Open **Brute Force Detector** (`/detection/brute_force`) and **Isolation Forest ML** (`/detection/ml`).
  - Confirm `repeated_short_connections` triggers (`15` attempts $\ge 10$ to port `22`, `100.0%` short flows $\le 5\text{s}$, severity `low`, confidence `0.70`, stage `Access Attempt`, incident score `16.25 / 100` — pattern indicator only; encrypted SSH payloads are not inspected).
  - In **Isolation Forest ML**, show the **Scored Host-Window Feature Vectors & Anomaly Decisions** table: attacker `192.168.1.101` (`[1, 1, 0.0, 15, 0, 0.0, 0.0, 0, 0.0]`) scores `0.440015 <= 0.597751` (`BELOW THRESHOLD`) and victim `10.0.0.5` scores `0.389642 <= 0.597751`, demonstrating why deterministic service-port rules complement unsupervised multivariate ML.
- **DNS Tunneling / Long Labels (`tests/data/pcaps/dns_tunnel.pcap`, SHA-256 `910fc96f...`, `50` pkts, `25` queries + `25` NXDOMAIN responses):**
  - Open **DNS Anomaly Detector** (`/detection/dns_anomaly`).
  - Confirm `dns_long_names, dns_nxdomain_ratio` triggers (`25` queries with avg length `72.6` chars and `100.0%` NXDOMAIN responses, severity `high`, confidence `0.60`, stage `Possible Exploitation`) and Isolation Forest scores `0.633776 > 0.597751` (`ANOMALY`, incident score `43.75 / 100`).
- **Abnormal Outbound Volume (`tests/data/pcaps/exfiltration.pcap`, SHA-256 `8a1c5dcd...`, `200` pkts, `1` flow):**
  - Open **Outbound Traffic Detector** (`/detection/outbound`).
  - Confirm `outbound_unusual_port` triggers (`290,800` bytes $\ge 200\text{ KB}$ to `203.0.113.50:4444`, severity `low`, confidence `0.60`, stage `Possible Exfiltration`, incident score `26.25 / 100`) while Isolation Forest scores `0.566809 <= 0.597751` (`BELOW THRESHOLD`).

### Step 4: Multi-Stage Correlation & 0–100 Risk Score Breakdown
1. Upload or select `tests/data/pcaps/multi_stage.pcap` (SHA-256 `83c5d1ad...`, `285` pkts, `41` flows) and open **Correlated Incidents** (`/incidents`) $\rightarrow$ **Details & Timeline**.
2. Verify Union-Find groups the stages for attacker `192.168.1.200` (`Reconnaissance` $\rightarrow$ `Access Attempt` $\rightarrow$ `Possible Exfiltration`) into a single multi-stage incident (`score = 66.25 / 100`, level `high`) and displays the exact heuristic score breakdown (`Strongest Alert: 8.75 / 35`, `Stage Diversity: 22.5 / 30`, `Logical Order: 15.0 / 15`, `Corroboration: 20.0 / 20`).

### Step 5: Forensic Evidence & Dual Wireshark Display Filters
1. Open **Forensic Evidence** (`/evidence`).
2. Show that each alert provides:
   - **Broad Window/Flow Frame Span** (`#first_frame–#last_frame`) vs. **Exact Trigger Frames** (`frame_no` list).
   - **1. Trigger-Direction Wireshark Filter** (`ip.src == ... && ip.dst == ...`) and **2. Bidirectional Investigation Filter** (`ip.addr == ... && ip.addr == ...`).
3. Click **Copy Trigger Filter**, open the corresponding `.pcap` in Wireshark, paste the filter, and verify the exact frames match.

### Step 6: Live Network Monitor & Real-Time `nslookup` DNS Verification
1. Open **Live Monitor** (`/live`), select your active Wi-Fi adapter (`<YOUR_WIFI_IP>`), and click **Start**.
2. Notice the **Live Visited Websites & DNS Queries** panel defaults to **`Standard DNS (Websites)`**, keeping UDP/TCP port 53 lookups separated from background `mDNS` (`224.0.0.251:5353`) and `LLMNR` (`224.0.0.252:5355`) noise, and distinguishing `QUERY`, `RESOLVED` (with `↳ <IP>` answer), `RESPONSE (NOERROR)`, and `NXDOMAIN`.
3. In a terminal, run a real lookup:
   ```powershell
   nslookup -type=A wikipedia.org
   # Or specify a reachable DNS resolver explicitly if local DNS is restricted:
   nslookup -type=A wikipedia.org 45.112.149.2
   ```
4. Verify `wikipedia.org` appears immediately in the Live Monitor DNS table (and can be filtered via the search box), then click **Stop** and verify the session is persisted in SQLite (`dns_events` and `/api/capture/dns_history`).
5. *(Safe Zero-Privilege Alternative)*: Select `Sample: Full Demo Scenario PCAP` under **Mode B: Deterministic Sample Replay** and click **Start**. Verify that replay processes all frames, generates live alerts/incidents, transitions to `REPLAY COMPLETED`, and **never** creates real Windows Firewall blocks.

### Step 7: Two-Laptop Live LAN Detection & Windows Firewall Containment (Optional Live Admin Check)
1. On the NetGuard host (`<YOUR_WIFI_IP>`, running as Administrator), open **Firewall & Prevention** (`/firewall`). Note the **Inbound Host Firewall Scope** banner (`Direction: Inbound` blocks incoming packets from `<RemoteAddress>` to `<YOUR_WIFI_IP>`).
2. From a peer laptop on the same Wi-Fi LAN (`<PEER_LAPTOP_IP>`), generate a harmless TCP port scan against `<YOUR_WIFI_IP>` (or manually enter `<PEER_LAPTOP_IP>` in **Manual IP Block** for 15 minutes and click **Enforce Inbound Firewall Block**).
3. Verify in PowerShell on `<YOUR_WIFI_IP>`:
   ```powershell
   Get-NetFirewallRule -DisplayName "NetGuard-Block-*" | Select-Object DisplayName, Direction, Action, Enabled
   ```
4. Verify `<PEER_LAPTOP_IP>` can no longer establish inbound connections to `<YOUR_WIFI_IP>`.
5. Click **Unblock** (or **Emergency Purge All**, which strictly removes only `NetGuard-Block-*` rules) and verify connectivity is restored and logged in the **Firewall Audit Log**.

### Step 8: Self-Contained HTML & JSON Forensic Report Export
1. On **Dashboard** (`/`), click **Export HTML** (`/reports/html/<run_id>`) and **Export JSON** (`/reports/json/<run_id>`).
2. Confirm the exported report is 100% offline/self-contained and includes capture SHA-256, packet/flow/DNS counts, correlated incident score breakdowns, trigger + bidirectional Wireshark filters, Isolation Forest model version (`default_baseline.joblib`), per-window anomaly scores, and methodological limitations.
