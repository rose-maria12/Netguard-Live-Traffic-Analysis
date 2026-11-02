import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

import scapy
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.utils import PcapReader, PcapNgReader

PCAP_MAGIC_BYTES = [
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
]
PCAPNG_MAGIC_BYTES = [b"\x0a\x0d\x0d\x0a"]


def calculate_sha256(file_path: Path) -> Tuple[str, int]:
    """
    Compute SHA-256 hash of a file in 64KB chunks and return (sha256_hex, file_size_bytes).
    """
    hasher = hashlib.sha256()
    size_bytes = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
            size_bytes += len(chunk)
    return hasher.hexdigest(), size_bytes


def detect_file_format(file_path: Path) -> str:
    """
    Detect whether a capture file is 'pcap' or 'pcapng' based on magic bytes.
    Raises ValueError if format is unrecognized.
    """
    with open(file_path, "rb") as f:
        magic = f.read(4)

    if magic in PCAP_MAGIC_BYTES:
        return "pcap"
    elif magic in PCAPNG_MAGIC_BYTES:
        return "pcapng"
    else:
        raise ValueError(
            f"Invalid magic bytes ({magic.hex()}). File is not a valid PCAP or PCAPng capture."
        )


def _get_scapy_reader(file_path: Path, file_format: str):
    """
    Return a Scapy reader instance for PCAP or PCAPng.
    """
    if file_format == "pcap":
        reader = PcapReader(str(file_path))
    else:
        reader = PcapNgReader(str(file_path))

    # Verify link type (Ethernet = 1 / DLT_EN10MB)
    linktype = getattr(reader, "linktype", 1)
    if linktype is None:
        linktype = 1
    if linktype != 1:
        reader.close()
        raise ValueError("Unsupported link type. Capture on a specific Ethernet interface.")

    return reader


def parse_pcap_stream(
    file_path: Path,
    max_frames: int = 500000,
    max_pcap_mb: int = 50,
) -> Generator[Dict[str, Any], None, None]:
    """
    Stream packets from PCAP/PCAPng file one packet at a time.
    Yields events of type 'packet', 'dns', or 'summary'.
    Guarantees 1-based Wireshark-compatible frame_no counter for every frame yielded by Scapy.
    """
    file_path = Path(file_path)
    file_size = file_path.stat().st_size
    if file_size > max_pcap_mb * 1024 * 1024:
        raise ValueError(f"File size ({file_size / (1024*1024):.2f} MB) exceeds limit of {max_pcap_mb} MB.")

    file_format = detect_file_format(file_path)
    reader = _get_scapy_reader(file_path, file_format)

    frame_no = 0
    packets_stored = 0
    frames_skipped = 0
    skipped_counts = {
        "non_ip": 0,
        "ipv6": 0,
        "fragment": 0,
        "unsupported_proto": 0,
        "parse_error": 0,
    }
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None

    try:
        for pkt in reader:
            frame_no += 1
            if frame_no > max_frames:
                raise ValueError(f"Frame count exceeded maximum limit of {max_frames} frames.")

            try:
                # Check for IPv6 layer
                if pkt.haslayer("IPv6"):
                    skipped_counts["ipv6"] += 1
                    frames_skipped += 1
                    continue

                # Check for IPv4 layer
                if not pkt.haslayer(IP):
                    skipped_counts["non_ip"] += 1
                    frames_skipped += 1
                    continue

                ip_layer = pkt[IP]

                # Check for IP fragments (frag > 0 means fragment after the first)
                if getattr(ip_layer, "frag", 0) > 0:
                    skipped_counts["fragment"] += 1
                    frames_skipped += 1
                    continue

                # Identify protocol
                src_port: Optional[int] = None
                dst_port: Optional[int] = None
                tcp_flags: Optional[int] = None
                proto_name: str = ""

                if pkt.haslayer(TCP):
                    proto_name = "TCP"
                    tcp_layer = pkt[TCP]
                    src_port = int(tcp_layer.sport)
                    dst_port = int(tcp_layer.dport)
                    tcp_flags = int(tcp_layer.flags)
                elif pkt.haslayer(UDP):
                    proto_name = "UDP"
                    udp_layer = pkt[UDP]
                    src_port = int(udp_layer.sport)
                    dst_port = int(udp_layer.dport)
                elif pkt.haslayer(ICMP):
                    proto_name = "ICMP"
                else:
                    skipped_counts["unsupported_proto"] += 1
                    frames_skipped += 1
                    continue

                ts = float(pkt.time)
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts

                pkt_len = getattr(pkt, "wirelen", None)
                if pkt_len is None:
                    pkt_len = len(pkt)

                packet_record = {
                    "type": "packet",
                    "frame_no": frame_no,
                    "ts": ts,
                    "src_ip": str(ip_layer.src),
                    "dst_ip": str(ip_layer.dst),
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "proto": proto_name,
                    "length": int(pkt_len),
                    "tcp_flags": tcp_flags,
                    "ttl": int(ip_layer.ttl),
                }
                packets_stored += 1
                yield packet_record

                # Extract DNS event if UDP or TCP port 53 and DNS layer present
                if proto_name in ("UDP", "TCP") and (src_port == 53 or dst_port == 53) and pkt.haslayer(DNS):
                    dns_layer = pkt[DNS]
                    is_resp = 1 if getattr(dns_layer, "qr", 0) == 1 else 0
                    client_ip = str(ip_layer.dst) if is_resp else str(ip_layer.src)
                    server_ip = str(ip_layer.src) if is_resp else str(ip_layer.dst)
                    txid = int(getattr(dns_layer, "id", 0))
                    rcode = int(dns_layer.rcode) if is_resp and hasattr(dns_layer, "rcode") else None

                    qname_raw = ""
                    qtype = 0
                    if dns_layer.qd:
                        try:
                            qd_elem = dns_layer.qd[0]
                        except Exception:
                            qd_elem = dns_layer.qd
                        qname_val = getattr(qd_elem, "qname", b"")
                        if isinstance(qname_val, bytes):
                            qname_raw = qname_val.decode(errors="ignore")
                        else:
                            qname_raw = str(qname_val or "")
                        qtype = int(getattr(qd_elem, "qtype", 0))

                    qname_clean = qname_raw.lower().rstrip(".")
                    qname_len = len(qname_clean)
                    labels = qname_clean.split(".") if qname_clean else []
                    max_label_len = max([len(l) for l in labels], default=0)

                    dns_record = {
                        "type": "dns",
                        "frame_no": frame_no,
                        "ts": ts,
                        "client_ip": client_ip,
                        "server_ip": server_ip,
                        "qname": qname_clean,
                        "qname_len": qname_len,
                        "max_label_len": max_label_len,
                        "qtype": qtype,
                        "is_response": is_resp,
                        "rcode": rcode,
                        "txid": txid,
                    }
                    yield dns_record

            except Exception as e:
                skipped_counts["parse_error"] += 1
                frames_skipped += 1
                continue
    finally:
        try:
            reader.close()
        except Exception:
            pass

    yield {
        "type": "summary",
        "file_format": file_format,
        "frames_total": frame_no,
        "packets_stored": packets_stored,
        "frames_skipped": frames_skipped,
        "skipped_counts": skipped_counts,
        "first_ts": first_ts,
        "last_ts": last_ts,
    }
