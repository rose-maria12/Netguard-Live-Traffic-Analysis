# NetGuard — Comprehensive Viva Defense & Oral Examination Guide

**Project:** NetGuard — Network Intrusion Detection, Prevention and Forensic Correlation Platform  
**Target Degree:** 3rd Year B.Tech Information Security / Computer Science Mini-Project  
**Author:** NetGuard Engineering Team  
**Evaluation Date:** October 2026  

---

## 1. Core Architectural Questions

### Q1: Why does NetGuard use both packet-level and flow-level analysis?
**Answer:**
Network intrusion detection requires visibility at multiple granularities:
- **Packet-Level Inspection**: Essential for examining protocol headers, TCP control flags (`SYN`, `RST`, `FIN`, `ACK`, `PSH`), time-to-live (`TTL`) anomalies, and DNS query names/labels (`qname`, `qtype`, `txid`). Packet metadata provides the exact forensic evidence needed for court admissibility and Wireshark verification.
- **Flow-Level Aggregation**: Evaluating individual packets in isolation causes computational bottlenecks and misses stateful behavioral patterns. By aggregating bidirectional packets into canonical 5-tuples (`initiator_ip`, `responder_ip`, `initiator_port`, `responder_port`, `proto`), NetGuard computes connection metrics: forward/reverse packet volume, byte asymmetry, flow duration, and handshake completion status.
- **Synergy**: NetGuard uses packet parsing to build flows, and flows to compute 20-second behavioral host vectors. This tiered approach allows high-throughput analysis while preserving microscopic packet frame numbers for forensic investigation.

---

### Q2: Why are both rule-based detection and machine learning anomaly detection included?
**Answer:**
Relying solely on rules or solely on machine learning creates critical security vulnerabilities:
- **Rule-Based Detectors (Signature & Heuristic)**: Excel at detecting known, well-defined attack methodologies with high precision and low computational cost. When an adversary performs a vertical port scan targeting 20 ports with RST responses, a deterministic rule fires instantly with 90% confidence and zero training overhead. However, rules cannot detect zero-day or subtle polymorphic anomalies outside configured thresholds.
- **Machine Learning (Isolation Forest Anomaly Detection)**: Excels at identifying multivariate, unpredicted deviations from baseline host behavior without requiring prior signatures. It flags anomalous combinations of egress volume, failed connections, and unusual DNS queries that slip under individual rule thresholds. However, pure ML suffers from higher false-positive rates and lacks domain explainability.
- **Defense-in-Depth**: NetGuard integrates both. When an incident is corroborated by both a deterministic rule AND an ML anomaly, NetGuard awards a +20 point corroboration bonus in its incident scoring engine, providing analysts with high-confidence triage.

---

### Q3: Why was Isolation Forest chosen over supervised algorithms (e.g., Random Forest, SVM)?
**Answer:**
1. **Unsupervised Nature**: In real-world enterprise networks, malicious intrusion samples are extremely rare (< 0.1% of traffic), creating massive class imbalance. Supervised models require extensive labeled training datasets that quickly become obsolete as attacker tactics evolve.
2. **Algorithmic Principle**: Isolation Forest is specifically built for anomaly detection. Unlike density- or distance-based algorithms (e.g., DBSCAN or k-Means) which compute computationally expensive pairwise distances, Isolation Forest isolates anomalies by randomly partitioning feature space. Because anomalies are "few and different", they require significantly fewer random splits to isolate, resulting in shorter average path lengths in the isolation trees ($c(n)$).
3. **Computational Efficiency**: Isolation Forest operates in linear time complexity $O(t \cdot \psi \log \psi)$, where $t$ is the number of trees (100) and $\psi$ is the subsampling size (256). This makes it suitable for streaming host-window feature evaluation without introducing pipeline latency.
4. **Calibrated Baseline**: NetGuard trains its model strictly on verified benign baseline traffic, setting the anomaly threshold at the 99th percentile ($F_{0.99}$) of training anomaly scores.

---

## 2. Windows Networking, Npcap & Live Capture

### Q4: How does live network capture work on Windows, and what role does Npcap play?
**Answer:**
- **The Windows Limitation**: Unlike Linux, where standard POSIX raw sockets or PF_PACKET allow user-space applications to sniff Ethernet frames directly, the Windows kernel restricts raw sockets (specifically since Windows XP SP2/Vista) for security reasons. Standard Windows socket APIs cannot capture Layer 2 Ethernet headers or promiscuous interface traffic.
- **The Npcap Solution**: Npcap is an open-source Windows packet capture library that installs an NDIS 6 Light-Weight Filter (LWF) driver directly into the Windows network stack. It intercepts packets directly between the network interface card (NIC) driver and the Windows TCP/IP protocol stack.
- **Scapy Integration**: Scapy binds to Npcap's `wpcap.dll` / `Packet.dll` API. NetGuard's `LiveCaptureWorker` uses Scapy's native interface backend over Npcap to enumerate network adapters, apply BPF filters (e.g., `ip`), and capture Layer 2 frames in real time.

---

### Q5: How does the live capture streaming architecture prevent packet loss and memory exhaustion?
**Answer:**
NetGuard uses a decoupled producer-consumer streaming architecture:
1. **Decoupled Worker**: Packet capture (`LiveCaptureWorker`) runs in a dedicated thread, immediately transferring captured Scapy frames into a thread-safe bounded queue (`queue.Queue(maxsize=10000)`).
2. **Backpressure & Drop Accounting**: If the detection engine or database is briefly saturated, the bounded queue prevents unlimited RAM consumption. When the queue is full, the worker drops excess frames and increments `packets_dropped`, exposing real backlog metrics in the dashboard.
3. **Sliding Window Processing**: The `LiveDetectionEngine` consumes packets, reconstructs flows, and maintains sliding evaluation windows.
4. **Graceful Flush**: When capture stops, NetGuard flushes all remaining queue items and forces a final window evaluation, ensuring no partial attacks are dropped.
5. **Rolling PCAP Evidence**: Packets are simultaneously streamed to a rolling PCAP recording file (`data/captures/live_<timestamp>.pcap`), ensuring live traffic is forensically retrievable.

---

## 3. Windows Defender Firewall Integration & Active Prevention

### Q6: How does NetGuard integrate with Windows Defender Firewall? Is it a simulation?
**Answer:**
NetGuard executes **genuine, OS-level firewall rules** directly within Windows Defender Firewall. It is not a simulation.
- **PowerShell NetSecurity Cmdlets**: NetGuard utilizes Windows PowerShell's native NetSecurity module:
  ```powershell
  New-NetFirewallRule -DisplayName "NetGuard_Block_<IP>_<hash>" -Direction Inbound -Action Block -RemoteAddress "<IP>" -Enabled True
  ```
- **Verification of Real Blocking**: When a rule is added:
  1. The rule appears in the Windows Firewall GUI (`wf.msc`) and via `Get-NetFirewallRule`.
  2. Inbound TCP SYN packets from that IP are immediately dropped at the Windows kernel level.
  3. `Test-NetConnection` or `ping` from the blocked IP fails with packet timeouts.
- **Safety Safeguards**: To prevent accidental self-denial of service, NetGuard hardcodes protected IP filters that reject blocking requests for:
  - Loopback (`127.0.0.1`, `::1`)
  - Local host interface IP and Default Gateway
  - Active DNS resolvers and DHCP infrastructure
  - Allowlisted administrative subnets
- **Lease Expiry & Emergency Unblock**: Managed rules carry a default 15-minute lease duration (`expires_at`). An automated cleanup thread (`expire_blocks()`) removes expired rules. An Emergency Unblock button removes all NetGuard rules (`DisplayName -like 'NetGuard_Block_*'`) while preserving all preexisting Windows firewall rules. All actions are logged to SQLite table `firewall_audit`.

---

## 4. Correlation, Incident Scoring & False Positives

### Q7: Why do security alerts require correlation? What is alert fatigue?
**Answer:**
In a typical enterprise or SOC environment, intrusion detection systems generate tens of thousands of raw alerts daily. A single port scan can generate 50 separate packet alerts; an automated vulnerability scanner generates hundreds. This causes **alert fatigue**, leading human analysts to overlook critical intrusions amidst the noise.

NetGuard solves this via a two-stage correlation pipeline:
1. **Deduplication**: Repeated identical alerts between the same source and destination within an analysis run are merged into a single alert record (`merged_count` incremented, timestamps updated, frame bounds expanded).
2. **Union-Find Graph Correlation**: Correlates alerts into a unified Incident based on:
   - **Same-Source IP**: Alerts sharing the same source IP within a 600-second window.
   - **Victim-to-Source Lateral Pivot**: If Host A attacks Host B, and Host B subsequently attacks Host C within 900 seconds, both are grouped into a single multi-stage incident tracing back to Host A.

---

### Q8: How is the 0–100 Incident Prioritization Score calculated? Does it represent probability?
**Answer:**
The 0–100 score is a **heuristic triage prioritization score**, designed to rank an analyst's investigation queue so critical multi-stage attacks are investigated first. It is **NOT** a statistical probability of compromise.

The score is calculated deterministically from four components (total 100 points):
1. **Strongest Alert Severity (Max 35 pts)**: Critical = 35.0, High = 26.25, Medium = 17.5, Low = 8.75.
2. **Stage Diversity (Max 30 pts)**: Rewards incidents that span multiple cyber kill-chain stages: 4 stages = 30 pts, 3 stages = 22.5 pts, 2 stages = 15 pts, 1 stage = 7.5 pts.
3. **Logical Stage Progression (Max 15 pts)**: Full 15 points awarded if alerts follow chronological kill-chain order:
   $$\text{Reconnaissance} \longrightarrow \text{Access Attempt} \longrightarrow \text{Possible Exploitation} \longrightarrow \text{Possible Exfiltration}$$
4. **Corroboration (Max 20 pts)**: +10 points if rule detection is corroborated by an Isolation Forest ML anomaly; +10 points if abnormal outbound traffic is observed.

---

### Q9: How are false positives handled in NetGuard?
**Answer:**
NetGuard employs several layers of false-positive mitigation:
1. **Configurable Detection Thresholds**: Detectors require significant behavioral evidence before firing (e.g., port scan requires $\ge 15$ ports AND $\ge 70\%$ failed flow ratio, preventing single port connection drops from alerting).
2. **Allowlisting Engine**: Configurable allowlists (`config/default_config.json`) filter out known authorized vulnerability scanners, trusted administrative subnets, internal DNS servers, and internal domain suffixes (`.local`, `.in-addr.arpa`).
3. **Heuristic Labeling & Explainability**: NetGuard does not falsely label repeated SSH connections as "Confirmed SSH Compromise"; it explicitly labels them "Brute-Force Connection Anomaly (Heuristic)".
4. **Wireshark Filter Synthesis**: For every alert, NetGuard generates the exact Wireshark display filter so a human analyst can inspect raw packet payloads before taking disruptive remediation actions.

---

## 5. Authentic Datasets & Real-World Evaluation

### Q10: How do authentic datasets (like CIC-IDS2017) differ from live network traffic?
**Answer:**
1. **Static vs. Streaming**: Datasets provide pre-recorded, static flow CSVs or PCAPs with fixed ground-truth labels. Live traffic is a continuous, asynchronous stream subject to packet jitter, out-of-order delivery, and interface drops.
2. **Feature Mismatch (CICFlowMeter vs. Host Windows)**: CIC-IDS2017 flow CSVs contain 80 statistical metrics computed per bidirectional flow (e.g., inter-arrival times, sub-flow packets). NetGuard's ML evaluates 9-dimensional host-window vectors aggregated across all flows of an IP in 20 seconds. NetGuard bridges this gap via explicit, documented schema translation in `netguard/datasets/benchmark.py`.
3. **Ground Truth Quality**: Academic literature (Engelen et al., 2021) has identified labeling errors and mirror port packet drops in CIC-IDS2017. Real live traffic has no ground truth labels and requires human SOC triage.

---

## 6. System Limitations & Academic Honesty

### Q11: What are the remaining limitations of NetGuard?
**Answer:**
In accordance with academic rigor, we acknowledge the following prototype boundaries:
1. **No Encrypted TLS Payload Inspection**: NetGuard operates on packet headers, flow statistics, and plaintext DNS queries. It does not perform TLS decryption / SSL inspection, meaning payloads inside encrypted HTTPS sessions cannot be inspected for SQL injection or malware signatures.
2. **IPv6 Scope**: NetGuard focuses on IPv4; IPv6 packets are detected, counted, and safely skipped rather than fully flow-reconstructed.
3. **High-Throughput Kernel Acceleration**: NetGuard uses Python Scapy and user-space Npcap, suitable for 100 Mbps laboratory and office links (~25,000 flows/sec). It does not use kernel bypass technologies (e.g., Intel DPDK or Linux eBPF/XDP) required for 10–100 Gbps enterprise carrier backbones.
4. **Single-Node Deployment**: The SQLite backend runs in WAL mode on a single forensic workstation; enterprise SIEM deployments typically require distributed database clusters (e.g., Elasticsearch or ClickHouse).

