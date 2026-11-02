import json
import os
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, wrpcap

DATA_DIR = Path(__file__).resolve().parent / "tests" / "data"
PCAPS_DIR = DATA_DIR / "pcaps"
TRUTH_DIR = DATA_DIR / "truth"


def generate_all_test_pcaps():
    """
    Generate deterministic synthetic test PCAPs with proper flow handshakes and distinct 20s windows.
    """
    PCAPS_DIR.mkdir(parents=True, exist_ok=True)
    TRUTH_DIR.mkdir(parents=True, exist_ok=True)

    base_time = 1700000000.0  # Fixed deterministic epoch timestamp

    # 1. Port Scan PCAP
    ps_pkts = []
    t = base_time
    src_ip = "192.168.1.100"
    dst_ip = "10.0.0.5"
    for port in range(1000, 1025):
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=50000 + port, dport=port, flags="S")
        pkt.time = t
        ps_pkts.append(pkt)
        t += 0.2

    ps_pcap_path = PCAPS_DIR / "port_scan.pcap"
    wrpcap(str(ps_pcap_path), ps_pkts)

    ps_truth = {
        "pcap_filename": "port_scan.pcap",
        "expected_alerts": [
            {
                "alert_type": "port_scan",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": None,
                "stage": "Reconnaissance",
            }
        ],
    }
    with open(TRUTH_DIR / "port_scan_truth.json", "w") as f:
        json.dump(ps_truth, f, indent=2)

    # 2. Brute Force PCAP
    bf_pkts = []
    t = base_time
    src_ip = "192.168.1.101"
    dst_ip = "10.0.0.5"
    for i in range(15):
        sport = 51000 + i
        p1 = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=22, flags="S", seq=100)
        p1.time = t
        p2 = Ether() / IP(src=dst_ip, dst=src_ip) / TCP(sport=22, dport=sport, flags="SA", seq=200, ack=101)
        p2.time = t + 0.01
        p3 = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=22, flags="A", seq=101, ack=201)
        p3.time = t + 0.02
        p4 = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=22, flags="FA", seq=101, ack=201)
        p4.time = t + 0.05
        bf_pkts.extend([p1, p2, p3, p4])
        t += 0.3

    bf_pcap_path = PCAPS_DIR / "brute_force.pcap"
    wrpcap(str(bf_pcap_path), bf_pkts)

    bf_truth = {
        "pcap_filename": "brute_force.pcap",
        "expected_alerts": [
            {
                "alert_type": "brute_force",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": 22,
                "stage": "Access Attempt",
            }
        ],
    }
    with open(TRUTH_DIR / "brute_force_truth.json", "w") as f:
        json.dump(bf_truth, f, indent=2)

    # 3. DNS Anomaly PCAP
    dns_pkts = []
    t = base_time
    src_ip = "192.168.1.102"
    server_ip = "10.0.0.53"
    for i in range(25):
        qname = f"subdomain-data-payload-chunk-{i}-longstringofhexdata1234567890.example.com"
        q_pkt = Ether() / IP(src=src_ip, dst=server_ip) / UDP(sport=53000 + i, dport=53) / DNS(
            id=100 + i, qr=0, qd=DNSQR(qname=qname, qtype="A")
        )
        q_pkt.time = t
        dns_pkts.append(q_pkt)

        r_pkt = Ether() / IP(src=server_ip, dst=src_ip) / UDP(sport=53, dport=53000 + i) / DNS(
            id=100 + i, qr=1, rcode=3, qd=DNSQR(qname=qname, qtype="A")
        )
        r_pkt.time = t + 0.05
        dns_pkts.append(r_pkt)
        t += 0.4

    dns_pcap_path = PCAPS_DIR / "dns_tunnel.pcap"
    wrpcap(str(dns_pcap_path), dns_pkts)

    dns_truth = {
        "pcap_filename": "dns_tunnel.pcap",
        "expected_alerts": [
            {
                "alert_type": "dns_anomaly",
                "src_ip": src_ip,
                "dst_ip": None,
                "dst_port": None,
                "stage": "Possible Exploitation",
            }
        ],
    }
    with open(TRUTH_DIR / "dns_tunnel_truth.json", "w") as f:
        json.dump(dns_truth, f, indent=2)

    # 4. Abnormal Outbound Exfiltration PCAP
    outbound_pkts = []
    t = base_time
    src_ip = "192.168.1.103"
    dst_ip = "203.0.113.50"
    for i in range(200):
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=52000, dport=8443, flags="PA") / (b"X" * 1400)
        pkt.time = t
        outbound_pkts.append(pkt)
        t += 0.05

    outbound_pcap_path = PCAPS_DIR / "exfiltration.pcap"
    wrpcap(str(outbound_pcap_path), outbound_pkts)

    outbound_truth = {
        "pcap_filename": "exfiltration.pcap",
        "expected_alerts": [
            {
                "alert_type": "abnormal_outbound",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": 8443,
                "stage": "Possible Exfiltration",
            }
        ],
    }
    with open(TRUTH_DIR / "exfiltration_truth.json", "w") as f:
        json.dump(outbound_truth, f, indent=2)

    # 5. Multi-Stage Attack PCAP
    # 192.168.1.200 conducts Port Scan (W1) -> Brute Force (W2) -> Exfiltration (W3)
    ms_pkts = []
    t = base_time
    src_ip = "192.168.1.200"

    # Stage 1: Reconnaissance (Port Scan) in window 0..20s
    for port in range(2000, 2025):
        pkt = Ether() / IP(src=src_ip, dst="10.0.0.10") / TCP(sport=55000 + port, dport=port, flags="S")
        pkt.time = t
        ms_pkts.append(pkt)
        t += 0.1

    # Advance to next 20s window (+25s)
    t = base_time + 25.0
    # Stage 2: Access Attempt (Brute Force SSH) in window 20..40s
    for i in range(15):
        sport = 56000 + i
        p1 = Ether() / IP(src=src_ip, dst="10.0.0.10") / TCP(sport=sport, dport=22, flags="S", seq=100)
        p1.time = t
        p2 = Ether() / IP(src="10.0.0.10", dst=src_ip) / TCP(sport=22, dport=sport, flags="SA", seq=200, ack=101)
        p2.time = t + 0.01
        p3 = Ether() / IP(src=src_ip, dst="10.0.0.10") / TCP(sport=sport, dport=22, flags="A", seq=101, ack=201)
        p3.time = t + 0.02
        p4 = Ether() / IP(src=src_ip, dst="10.0.0.10") / TCP(sport=sport, dport=22, flags="FA", seq=101, ack=201)
        p4.time = t + 0.05
        ms_pkts.extend([p1, p2, p3, p4])
        t += 0.2

    # Advance to next 20s window (+25s)
    t = base_time + 50.0
    # Stage 3: Exfiltration (Abnormal Outbound) in window 40..60s
    for i in range(200):
        pkt = Ether() / IP(src=src_ip, dst="203.0.113.99") / TCP(sport=57000, dport=8443, flags="PA") / (b"Y" * 1400)
        pkt.time = t
        ms_pkts.append(pkt)
        t += 0.05

    ms_pcap_path = PCAPS_DIR / "multi_stage.pcap"
    wrpcap(str(ms_pcap_path), ms_pkts)

    ms_truth = {
        "pcap_filename": "multi_stage.pcap",
        "expected_alerts": [
            {
                "alert_type": "port_scan",
                "src_ip": src_ip,
                "dst_ip": "10.0.0.10",
                "stage": "Reconnaissance",
            },
            {
                "alert_type": "brute_force",
                "src_ip": src_ip,
                "dst_ip": "10.0.0.10",
                "dst_port": 22,
                "stage": "Access Attempt",
            },
            {
                "alert_type": "abnormal_outbound",
                "src_ip": src_ip,
                "dst_ip": "203.0.113.99",
                "dst_port": 8443,
                "stage": "Possible Exfiltration",
            },
        ],
    }
    with open(TRUTH_DIR / "multi_stage_truth.json", "w") as f:
        json.dump(ms_truth, f, indent=2)

    # 6. Benign PCAP
    benign_pkts = []
    t = base_time
    for i in range(10):
        pkt = Ether() / IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=40000 + i, dport=80, flags="PA") / b"GET / HTTP/1.1\r\n\r\n"
        pkt.time = t
        benign_pkts.append(pkt)
        t += 2.0

    benign_pcap_path = PCAPS_DIR / "benign.pcap"
    wrpcap(str(benign_pcap_path), benign_pkts)

    benign_truth = {
        "pcap_filename": "benign.pcap",
        "expected_alerts": [],
    }
    with open(TRUTH_DIR / "benign_truth.json", "w") as f:
        json.dump(benign_truth, f, indent=2)

    print("Successfully generated all synthetic test PCAP files and ground truth JSON files.")


if __name__ == "__main__":
    generate_all_test_pcaps()
