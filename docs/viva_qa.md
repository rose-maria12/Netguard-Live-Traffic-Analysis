# NetGuard Viva Defense & Technical Questions & Answers

---

### Q1: Why was NetGuard built? What problem does it solve?
**A:** Security Operations Center (SOC) analysts face severe alert fatigue caused by thousands of un-correlated, raw network intrusion alerts. NetGuard ingests raw packet captures (PCAP/PCAPNG) as well as live Windows network traffic, constructs bidirectional flows, applies deterministic rule detectors alongside machine learning anomaly detection, deduplicates redundant alerts, correlates multi-stage attack indicators into unified incidents, provides a 0–100 heuristic prioritization score, and triggers active Windows Defender Firewall containment.

---

### Q2: Does NetGuard support live network interface capture, or only offline PCAP files?
**A:** NetGuard supports **both**:
1. **Live Network Capture**: Via Npcap and Scapy, capturing real Ethernet frames from physical, virtual, or loopback network adapters with a bounded queue (`maxsize=10,000`), backpressure drop accounting, and rolling PCAP evidence persistence.
2. **Offline PCAP / PCAPng Ingestion**: Ingests files deterministically with 1-based frame numbers matching Wireshark, ideal for repeatable laboratory benchmarking and forensic investigations.
3. **Unprivileged Replay Simulation**: Allows live stream simulation in restricted lab environments without administrator privileges.

---

### Q3: Why Scapy for packet parsing and traffic generation?
**A:** Scapy is a standard, battle-tested Python networking library capable of deep packet inspection across PCAP and PCAPng formats. It allows exact 1-based Wireshark frame number tracking, layer-by-layer header parsing (IP, TCP, UDP, ICMP, DNS), and programmatic generation of reproducible attack traffic (`scripts/demo_traffic.py`).

---

### Q4: Why SQLite for backend storage?
**A:** SQLite is zero-configuration, self-contained, serverless, and transaction-safe. With Write-Ahead Logging (`WAL` mode) and foreign key constraints enabled, it handles concurrent web dashboard reads while background capture workers ingest flows and record alerts, without requiring heavyweight database servers like PostgreSQL.

---

### Q5: Why combine rule-based detection with Isolation Forest machine learning?
**A:** Rule-based detectors excel at identifying known, deterministic attack signatures (e.g., vertical port scans or SSH brute force) with zero training requirement. Isolation Forest excels at discovering unexpected multivariate host anomalies (such as unusual outbound volume or anomalous DNS query bursts) without requiring labeled attack samples. Using both provides defense-in-depth, and rule+ML corroboration awards bonus points in incident risk scoring.

---

### Q6: What features are extracted for Isolation Forest host windowing?
**A:** Nine host-window features extracted across 20-second tumbling windows:
1. `unique_dst_ports` (Scan indicator)
2. `unique_dst_ips` (Scan indicator)
3. `failed_flow_ratio` (Scan indicator)
4. `max_flows_same_target` (Brute-force indicator)
5. `dns_query_count` (DNS indicator)
6. `avg_qname_length` (DNS indicator)
7. `nxdomain_ratio` (DNS indicator)
8. `bytes_out_external` (Outbound exfiltration indicator)
9. `out_in_ratio` (Outbound exfiltration indicator)

---

### Q7: What is alert deduplication and how does NetGuard perform it?
**A:** Deduplication merges repeated instances of the same alert type between the same source and destination within an analysis run. NetGuard constructs a deterministic key (`alert_type:rule_name:src_ip:dst_ip:dst_port`), merges timestamps, updates frame bounds (`first_frame`, `last_frame`), increments `merged_count`, and retains up to 50 distinct packet/flow evidence references.

---

### Q8: How does incident correlation work?
**A:** NetGuard uses a Union-Find (Disjoint-Set Union) graph algorithm to group deduplicated alerts into Incidents based on two primary rules:
1. **Same-Source IP Correlation**: Alerts sharing the same source IP within a 600-second window are merged.
2. **Victim-to-Source Pivot Correlation**: If Host A attacks Host B (victim), and within 900 seconds Host B becomes the source IP attacking Host C, both alerts are merged into a single multi-stage incident under Host A as the primary attacker.

---

### Q9: How is the Incident Score calculated?
**A:** Using a deterministic 0–100 heuristic prioritization formula based on four components:
1. **Strongest Alert Severity** (Max 35 pts): Critical = 35, High = 26.25, Medium = 17.5, Low = 8.75.
2. **Stage Diversity** (Max 30 pts): 4 stages = 30 pts, 3 = 22.5 pts, 2 = 15 pts, 1 = 7.5 pts.
3. **Logical Stage Progression** (Max 15 pts): Non-decreasing chronological progression across canonical stages (`Reconnaissance` $\rightarrow$ `Access Attempt` $\rightarrow$ `Possible Exploitation` $\rightarrow$ `Possible Exfiltration`) receives 15 pts.
4. **Corroboration** (Max 20 pts): 10 pts for ML anomaly presence, 10 pts for abnormal outbound/exfiltration presence.

---

### Q10: What does the 0–100 Incident Score actually mean?
**A:** It is a **heuristic prioritization score** intended to rank incidents in an analyst's queue so high-priority incidents are investigated first. It is **NOT** a statistical probability of compromise and **NOT** mathematical proof of an attack.

---

### Q11: How does Wireshark integration work?
**A:** NetGuard deterministically constructs copyable Wireshark display filters (e.g., `(ip.src == 192.168.1.100 && ip.dst == 10.0.0.5) && frame.number >= 15 && frame.number <= 42`). NetGuard does **NOT** open Wireshark automatically. The dashboard provides the exact filter and instructions for the analyst to open the PCAP manually in Wireshark and paste the filter.

---

### Q12: How does active Windows Firewall prevention work?
**A:** NetGuard executes real PowerShell NetSecurity cmdlets (`New-NetFirewallRule`) to block malicious IPs at the OS level. It supports three operating modes: **Monitor** (default, no OS changes), **Manual** (analyst approves blocks), and **Automatic** (high/critical alerts trigger immediate blocks). Critical safeguards strictly prevent blocking loopback, default gateway, DNS servers, or allowlisted subnets. Rules automatically expire after 15 minutes, and an Emergency Unblock button restores standard connectivity.

---

### Q13: How does NetGuard handle external Threat Intelligence?
**A:** NetGuard integrates AbuseIPDB reputation lookups with privacy protection: it automatically suppresses lookups for private/local IPs (RFC 1918, loopback, link-local), caches results in-memory with a 1-hour TTL, and falls back gracefully to offline mode if no API key or internet connection is available.

---

### Q14: How was NetGuard evaluated against authentic academic datasets?
**A:** NetGuard includes an authentic dataset evaluation suite (`netguard/datasets/benchmark.py` and `evaluate_dataset.py`) supporting CIC-IDS2017 and UNSW-NB15. It explicitly maps third-party flow features to NetGuard's behavioral representations without fabricating missing data, computing Confusion Matrices, Precision, Recall, F1-scores, and throughput metrics.

---

### Q15: What limitations remain in the platform?
**A:**
1. **Encrypted Payloads**: Operates on packet headers, flow statistics, and DNS queries; does not decrypt TLS/SSL payloads.
2. **IPv6**: IPv6 frames are counted and safely skipped rather than fully reconstructed into flows.
3. **Kernel Bypass**: Uses user-space Scapy/Npcap rather than DPDK or eBPF/XDP, suitable for 100 Mbps lab lines rather than 100 Gbps carrier backbones.
