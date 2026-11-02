#!/usr/bin/env python
"""
NetGuard Controlled Traffic & Attack Demonstration Generator
Produces controlled, harmless network traffic for Scenarios A through F:
- Scenario A: Normal Traffic (Web, DNS, TLS Handshakes)
- Scenario B: Vertical Port Scan (Reconnaissance)
  Flag: Port scan
  Suggested precautions / next steps: Check whether this is an authorised scan. Inspect the targeted ports. If an untrusted source is probing your laptop, consider a temporary inbound block.
- Scenario C: Repeated Short Authentication Connections (Access Attempt)
  Flag: Brute-force-like activity
  Suggested precautions / next steps: Check authentication logs for failed logins. Review successful logins from that source. Consider temporary blocking, MFA, and login rate limits.
- Scenario D: DNS Anomaly (High Rate, Long Labels, NXDOMAINs)
  Flag: DNS anomaly
  Suggested precautions / next steps: Inspect the requested names and NXDOMAIN responses. Identify the application generating them. If unexplained, investigate the device and consider an endpoint security scan.
- Scenario E: Abnormal Outbound Transfer (Possible Exfiltration)
  Flag: Unusual outbound traffic
  Suggested precautions / next steps: Check for uploads, backups, or synchronisation. Identify the process and destination. If confirmed suspicious, consider restricting outbound access or isolating the device.
- Scenario F: Correlated Multi-Stage Incident (Recon -> Access -> Exploit -> Exfil)
  Encompasses Port scan, Brute-force-like activity, DNS anomaly, Unusual outbound traffic, and ML anomaly.
- ML Anomaly Guidance:
  Flag: ML anomaly
  Suggested precautions / next steps: Review the unusual features, inspect supporting packets, and check whether rule detectors also flagged the activity. Avoid blocking solely because of the ML score.

SAFETY GUARANTEE:
All traffic is generated using Scapy directed ONLY towards loopback or specified
authorized lab IPs. Can output either live packets onto an interface or save to PCAP.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
except ImportError:
    print("Error: Scapy is required to run demo_traffic.py", file=sys.stderr)
    sys.exit(1)


def generate_scenario_a_normal(src_ip: str, dst_ip: str) -> list:
    """Scenario A: Routine web browsing and DNS resolution."""
    packets = []
    base_t = time.time()
    # 1. DNS queries
    for i, domain in enumerate(["example.com", "google.com", "github.com", "microsoft.com"]):
        pkt = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=src_ip, dst="192.168.1.1") / UDP(sport=53000 + i, dport=53) / DNS(
            rd=1, qd=DNSQR(qname=domain)
        )
        pkt.time = base_t + i * 0.5
        packets.append(pkt)

    # 2. HTTP/HTTPS client flows
    for i in range(5):
        sport = 49152 + i
        syn = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=443, flags="S", seq=1000)
        syn.time = base_t + 2.0 + i * 0.4
        ack = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=443, flags="A", seq=1001, ack=5001)
        ack.time = syn.time + 0.05
        data = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=443, flags="PA", seq=1001, ack=5001) / Raw(b"TLS Client Hello Simulated " + b"X" * 150)
        data.time = ack.time + 0.05
        packets.extend([syn, ack, data])

    return packets


def generate_scenario_b_port_scan(src_ip: str, dst_ip: str, num_ports: int = 25) -> list:
    """
    Scenario B: Vertical port scan across multiple target ports.
    Flag: Port scan
    Suggested precautions / next steps: Check whether this is an authorised scan. Inspect the targeted ports. If an untrusted source is probing your laptop, consider a temporary inbound block.
    """
    packets = []
    base_t = time.time()
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9000][:num_ports]

    for i, port in enumerate(ports):
        # Attacker SYN
        syn = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=src_ip, dst=dst_ip) / TCP(sport=50000 + i, dport=port, flags="S", seq=1000 + i)
        syn.time = base_t + (i * 0.05)
        packets.append(syn)
        # Target RST response (closed port)
        rst = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=dst_ip, dst=src_ip) / TCP(sport=port, dport=50000 + i, flags="RA", seq=0, ack=1001 + i)
        rst.time = syn.time + 0.005
        packets.append(rst)

    return packets


def generate_scenario_c_brute_force(src_ip: str, dst_ip: str, target_port: int = 22, attempts: int = 15) -> list:
    """
    Scenario C: Repeated short connection bursts against authentication port.
    Flag: Brute-force-like activity
    Suggested precautions / next steps: Check authentication logs for failed logins. Review successful logins from that source. Consider temporary blocking, MFA, and login rate limits.
    """
    packets = []
    base_t = time.time()

    for i in range(attempts):
        t = base_t + (i * 0.8)
        sport = 40000 + i
        syn = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=target_port, flags="S", seq=100)
        syn.time = t
        synack = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=dst_ip, dst=src_ip) / TCP(sport=target_port, dport=sport, flags="SA", seq=500, ack=101)
        synack.time = t + 0.01
        ack = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=target_port, flags="A", seq=101, ack=501)
        ack.time = t + 0.02
        # Short payload then reset
        fin = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=target_port, flags="FA", seq=101, ack=501)
        fin.time = t + 0.1
        packets.extend([syn, synack, ack, fin])

    return packets


def generate_scenario_d_dns_anomaly(src_ip: str, resolver_ip: str = "192.168.1.1", count: int = 25) -> list:
    """
    Scenario D: DNS burst query volume, long domain labels, and NXDOMAINs.
    Flag: DNS anomaly
    Suggested precautions / next steps: Inspect the requested names and NXDOMAIN responses. Identify the application generating them. If unexplained, investigate the device and consider an endpoint security scan.
    """
    packets = []
    base_t = time.time()

    for i in range(count):
        t = base_t + (i * 0.08)
        # Long encoded domain label simulating DNS tunneling
        long_label = f"data-chunk-{i:03d}-" + "a" * 42 + ".exfil.lab.local"
        q = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=src_ip, dst=resolver_ip) / UDP(sport=55000 + i, dport=53) / DNS(
            rd=1, qd=DNSQR(qname=long_label)
        )
        q.time = t
        packets.append(q)

        # NXDOMAIN response
        resp = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=resolver_ip, dst=src_ip) / UDP(sport=53, dport=55000 + i) / DNS(
            id=q[DNS].id, qr=1, rcode=3, qd=DNSQR(qname=long_label)
        )
        resp.time = t + 0.01
        packets.append(resp)

    return packets


def generate_scenario_e_outbound_anomaly(src_ip: str, dst_ip: str, total_kb: int = 1200) -> list:
    """
    Scenario E: Large volume outbound exfiltration on non-standard port.
    Flag: Unusual outbound traffic
    Suggested precautions / next steps: Check for uploads, backups, or synchronisation. Identify the process and destination. If confirmed suspicious, consider restricting outbound access or isolating the device.
    """
    packets = []
    base_t = time.time()
    sport = 48100
    dport = 9999  # Non-standard service port

    chunk_size = 1400
    num_packets = (total_kb * 1024) // chunk_size

    # Handshake
    syn = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=100)
    syn.time = base_t
    synack = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=500, ack=101)
    synack.time = base_t + 0.01
    ack = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A", seq=101, ack=501)
    ack.time = base_t + 0.02
    packets.extend([syn, synack, ack])

    # Outbound data stream
    for i in range(num_packets):
        t = base_t + 0.03 + (i * 0.005)
        data = Ether(src="00:50:56:c0:00:01", dst="00:50:56:c0:00:02") / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=101 + i * chunk_size, ack=501) / Raw(b"E" * chunk_size)
        data.time = t
        packets.append(data)

    return packets


def generate_scenario_f_multi_stage(attacker_ip: str, victim_ip: str) -> list:
    """
    Scenario F: Correlated 4-stage kill-chain incident:
    1. Reconnaissance (Port scan)
    2. Access Attempt (SSH brute force)
    3. Possible Exploitation (DNS anomaly)
    4. Possible Exfiltration (Large outbound transfer)
    """
    all_packets = []
    t_offset = time.time()

    print("[*] Stage 1/4: Synthesizing Reconnaissance (Port Scan)...")
    p1 = generate_scenario_b_port_scan(attacker_ip, victim_ip, num_ports=20)
    all_packets.extend(p1)

    print("[*] Stage 2/4: Synthesizing Access Attempt (SSH Brute Force)...")
    p2 = generate_scenario_c_brute_force(attacker_ip, victim_ip, target_port=22, attempts=12)
    # Stagger timestamps
    for pkt in p2:
        pkt.time += 5.0
    all_packets.extend(p2)

    print("[*] Stage 3/4: Synthesizing Possible Exploitation (DNS Tunneling)...")
    p3 = generate_scenario_d_dns_anomaly(attacker_ip, count=22)
    for pkt in p3:
        pkt.time += 10.0
    all_packets.extend(p3)

    print("[*] Stage 4/4: Synthesizing Possible Exfiltration (Abnormal Outbound)...")
    p4 = generate_scenario_e_outbound_anomaly(attacker_ip, victim_ip, total_kb=1100)
    for pkt in p4:
        pkt.time += 15.0
    all_packets.extend(p4)

    return all_packets


def main():
    parser = argparse.ArgumentParser(description="NetGuard Demonstration Traffic Generator")
    parser.add_argument(
        "--scenario",
        type=str,
        choices=["A", "B", "C", "D", "E", "F"],
        default="F",
        help="Demonstration scenario: A (Normal), B (Scan), C (Brute), D (DNS), E (Outbound), F (Full Multi-Stage)",
    )
    parser.add_argument("--src", type=str, default="192.168.56.105", help="Attacker / source IP")
    parser.add_argument("--dst", type=str, default="192.168.56.200", help="Victim / destination IP")
    parser.add_argument("--output", type=str, default="tests/data/pcaps/demo_scenario.pcap", help="Output PCAP file path")
    args = parser.parse_args()

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generating Scenario {args.scenario} traffic (Src: {args.src} -> Dst: {args.dst})...")

    if args.scenario == "A":
        packets = generate_scenario_a_normal(args.src, args.dst)
    elif args.scenario == "B":
        packets = generate_scenario_b_port_scan(args.src, args.dst)
    elif args.scenario == "C":
        packets = generate_scenario_c_brute_force(args.src, args.dst)
    elif args.scenario == "D":
        packets = generate_scenario_d_dns_anomaly(args.src)
    elif args.scenario == "E":
        packets = generate_scenario_e_outbound_anomaly(args.src, args.dst)
    elif args.scenario == "F":
        packets = generate_scenario_f_multi_stage(args.src, args.dst)
    else:
        packets = []

    scenario_precautions = {
        "B": ("Port scan", "Check whether this is an authorised scan. Inspect the targeted ports. If an untrusted source is probing your laptop, consider a temporary inbound block."),
        "C": ("Brute-force-like activity", "Check authentication logs for failed logins. Review successful logins from that source. Consider temporary blocking, MFA, and login rate limits."),
        "D": ("DNS anomaly", "Inspect the requested names and NXDOMAIN responses. Identify the application generating them. If unexplained, investigate the device and consider an endpoint security scan."),
        "E": ("Unusual outbound traffic", "Check for uploads, backups, or synchronisation. Identify the process and destination. If confirmed suspicious, consider restricting outbound access or isolating the device."),
        "F": ("Multi-Stage Incident", "Correlated kill-chain: Port scan -> Brute-force -> DNS anomaly -> Outbound exfiltration. Avoid blocking solely because of the ML score; corroborate with rule detectors."),
    }

    if args.scenario in scenario_precautions:
        flag_name, precautions = scenario_precautions[args.scenario]
        print(f"[i] Scenario Flag: {flag_name}")
        print(f"[i] Suggested precautions / next steps: {precautions}")

    wrpcap(str(out_path), packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {out_path} ({out_path.stat().st_size} bytes)")
    print(f"[i] To analyze in NetGuard: Upload via web dashboard OR run in Live Monitor as replay test.")


if __name__ == "__main__":
    main()
