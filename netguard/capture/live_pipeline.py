"""
NetGuard Live Detection and Prevention Pipeline
Consumes streaming packets, extracts flows, runs detection rules,
deduplicates, correlates incidents, and triggers automated prevention.
Supports pause/resume, queue draining on stop, and final window evaluation.
"""
from __future__ import annotations

import hashlib
import json
import logging
import queue
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure core scapy layers are loaded
import scapy.layers.l2
import scapy.layers.inet
import scapy.layers.dns

from netguard.config import load_config
from netguard.correlation.dedup import deduplicate_findings
from netguard.correlation.engine import correlate_alerts, save_alerts_to_db, save_incidents_to_db
from netguard.db import DEFAULT_DB_PATH, get_db, init_db
from netguard.detection.allowlist import AllowList
from netguard.detection.brute_force import detect_brute_force
from netguard.detection.dns_anomaly import detect_dns_anomaly
from netguard.detection.outbound import detect_abnormal_outbound
from netguard.detection.port_scan import detect_port_scan
from netguard.evidence.wireshark import generate_wireshark_filter
from netguard.firewall.windows_fw import (
    block_ip,
    expire_blocks,
    get_prevention_config,
    is_protected_ip,
    reconcile_rules,
)
from netguard.ingest.flow_builder import ActiveFlow, canonical_flow_key

logger = logging.getLogger(__name__)


def _extract_packet_dict(pkt: Any, frame_no: int) -> Optional[Dict[str, Any]]:
    """
    Extract structured packet dictionary from a raw Scapy packet.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except ImportError:
        return None

    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    ts = float(getattr(pkt, "time", time.time()))
    length = int(len(pkt))

    proto_name = "OTHER"
    sport = None
    dport = None
    flags = None
    tcp_seq = None
    tcp_ack = None
    flag_val = 0

    if pkt.haslayer(TCP):
        proto_name = "TCP"
        tcp_layer = pkt[TCP]
        sport = int(tcp_layer.sport)
        dport = int(tcp_layer.dport)
        flags = str(tcp_layer.flags)
        tcp_seq = int(tcp_layer.seq)
        tcp_ack = int(tcp_layer.ack)
        try:
            flag_val = int(tcp_layer.flags)
        except (ValueError, TypeError):
            # Parse flag string (e.g., 'S', 'SA', 'PA', 'F', 'R') to bitmask
            flag_val = 0
            flag_str = str(tcp_layer.flags).upper()
            if "F" in flag_str: flag_val |= 1
            if "S" in flag_str: flag_val |= 2
            if "R" in flag_str: flag_val |= 4
            if "P" in flag_str: flag_val |= 8
            if "A" in flag_str: flag_val |= 16
            if "U" in flag_str: flag_val |= 32
    elif pkt.haslayer(UDP):
        proto_name = "UDP"
        udp_layer = pkt[UDP]
        sport = int(udp_layer.sport)
        dport = int(udp_layer.dport)
    elif pkt.haslayer(ICMP):
        proto_name = "ICMP"

    return {
        "id": frame_no,
        "frame_no": frame_no,
        "ts": ts,
        "ip_src": str(ip_layer.src),
        "ip_dst": str(ip_layer.dst),
        "src_ip": str(ip_layer.src),
        "dst_ip": str(ip_layer.dst),
        "proto": proto_name,
        "sport": sport,
        "dport": dport,
        "src_port": sport,
        "dst_port": dport,
        "length": length,
        "flags": flags,
        "tcp_flags": flag_val,
        "ttl": int(getattr(ip_layer, "ttl", 64)),
        "tcp_seq": tcp_seq,
        "tcp_ack": tcp_ack,
        "payload_len": len(bytes(pkt.payload)) if hasattr(pkt, "payload") else 0,
    }


def _extract_dns_event(pkt: Any, frame_no: int) -> Optional[Dict[str, Any]]:
    """
    Extract structured DNS event from a Scapy packet if present conforming
    to the detection/dns_anomaly.py schema, accurately differentiating
    Standard Unicast DNS (UDP/TCP 53) from mDNS (UDP 5353) and LLMNR (UDP 5355).
    """
    try:
        from scapy.layers.dns import DNS, DNSQR
        if not pkt.haslayer(DNS):
            return None

        # Resolve IP addresses supporting both IPv4 and IPv6
        src_ip = None
        dst_ip = None
        if pkt.haslayer("IP"):
            src_ip = str(pkt["IP"].src)
            dst_ip = str(pkt["IP"].dst)
        elif pkt.haslayer("IPv6"):
            src_ip = str(pkt["IPv6"].src)
            dst_ip = str(pkt["IPv6"].dst)
        else:
            return None

        # Inspect transport layer for sport / dport
        sport = 0
        dport = 0
        transport_proto = "UDP"
        if pkt.haslayer("UDP"):
            sport = int(pkt["UDP"].sport)
            dport = int(pkt["UDP"].dport)
            transport_proto = "UDP"
        elif pkt.haslayer("TCP"):
            sport = int(pkt["TCP"].sport)
            dport = int(pkt["TCP"].dport)
            transport_proto = "TCP"

        # Protocol classification: DNS vs mDNS vs LLMNR
        if sport == 5353 or dport == 5353 or dst_ip in ("224.0.0.251", "ff02::fb"):
            proto_type = "mDNS"
        elif sport == 5355 or dport == 5355 or dst_ip in ("224.0.0.252", "ff02::1:3"):
            proto_type = "LLMNR"
        elif sport == 53 or dport == 53:
            proto_type = "DNS"
        else:
            proto_type = "DNS"

        dns_layer = pkt[DNS]
        qr = int(getattr(dns_layer, "qr", 0))
        txid = int(getattr(dns_layer, "id", 0))
        client_ip = src_ip if qr == 0 else dst_ip
        server_ip = dst_ip if qr == 0 else src_ip

        qname = ""
        qtype = 1
        if dns_layer.haslayer(DNSQR):
            qr_rec = dns_layer[DNSQR]
            if hasattr(qr_rec, "qname") and qr_rec.qname:
                qname = qr_rec.qname.decode("utf-8", errors="replace").rstrip(".")
            qtype = int(getattr(qr_rec, "qtype", 1))

        # Extract resolved answer IPs or hostnames if response record
        answers = []
        if qr == 1 and hasattr(dns_layer, "an") and dns_layer.an:
            try:
                from scapy.layers.dns import DNSRR
                # Support both iterable PacketListField (modern Scapy) and linked payload
                records = dns_layer.an if hasattr(dns_layer.an, "__iter__") else [dns_layer.an]
                for item in records:
                    curr = item
                    while curr:
                        if hasattr(curr, "haslayer") and curr.haslayer(DNSRR):
                            rr = curr[DNSRR]
                            rdata = getattr(rr, "rdata", None)
                            if rdata:
                                if isinstance(rdata, bytes):
                                    answers.append(rdata.decode("utf-8", errors="replace"))
                                else:
                                    answers.append(str(rdata))
                        curr = getattr(curr, "payload", None)
                        if not curr or not hasattr(curr, "haslayer"):
                            break
            except Exception:
                pass

        labels = qname.split(".") if qname else []
        max_label_len = max([len(l) for l in labels], default=0)
        rcode = int(getattr(dns_layer, "rcode", 0))

        return {
            "id": frame_no,
            "frame_no": frame_no,
            "ts": float(getattr(pkt, "time", time.time())),
            "client_ip": client_ip,
            "server_ip": server_ip,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": sport,
            "dst_port": dport,
            "proto_type": proto_type,
            "transport": transport_proto,
            "qname": qname,
            "qname_len": len(qname),
            "max_label_len": max_label_len,
            "qtype": qtype,
            "rcode": rcode,
            "is_response": qr,
            "txid": txid,
            "answers": answers,
        }
    except Exception:
        pass
    return None


class LiveDetectionEngine:
    """
    Processes incoming packets from a live queue, runs detection,
    updates database, and triggers automated prevention actions.
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        db_path: Any = DEFAULT_DB_PATH,
        config: Optional[Dict[str, Any]] = None,
        batch_interval: float = 3.0,
        output_pcap: Optional[Path] = None,
        is_replay: bool = False,
    ):
        self.packet_queue = packet_queue
        self.db_path = db_path
        self.config = config or load_config()
        self.batch_interval = batch_interval
        self.output_pcap = output_pcap
        self.is_replay = is_replay

        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Engine state
        self.is_running = False
        self.is_paused = False
        self.live_capture_id: Optional[int] = None
        self.live_run_id: Optional[int] = None
        self.total_packets_processed = 0
        self.total_alerts_generated = 0
        self.total_incidents_generated = 0
        self.total_blocks_triggered = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None

        # Memory buffer for sliding detection and live UI view
        self.recent_packets: List[Dict[str, Any]] = []
        self.recent_dns_events: List[Dict[str, Any]] = []
        self.recent_standard_dns_events: List[Dict[str, Any]] = []
        self._packet_db_batch: List[tuple] = []
        self._dns_db_batch: List[tuple] = []
        self._dns_stats: Dict[str, int] = {"total": 0, "standard": 0, "mdns": 0, "llmnr": 0}
        self.active_flows: Dict[Any, ActiveFlow] = {}
        self.seen_alert_keys: set = set()
        self._last_maintenance_time = 0.0

    def start(self) -> Dict[str, Any]:
        """
        Start detection and correlation engine.
        """
        with self._lock:
            if self.is_running:
                return {"success": False, "error": "Detection engine is already running."}

            init_db(self.db_path)
            self._init_live_run()

            self._stop_event.clear()
            self._pause_event.clear()
            self.is_running = True
            self.is_paused = False
            self.total_packets_processed = 0
            self.total_alerts_generated = 0
            self.total_incidents_generated = 0
            self.total_blocks_triggered = 0
            self.recent_packets.clear()
            self.recent_dns_events.clear()
            self.recent_standard_dns_events.clear()
            self._packet_db_batch.clear()
            self._dns_db_batch.clear()
            self._dns_stats = {"total": 0, "standard": 0, "mdns": 0, "llmnr": 0}
            self.active_flows.clear()
            self.seen_alert_keys.clear()

            self._thread = threading.Thread(
                target=self._run_loop, daemon=True, name="NetGuardLiveDetectionEngine"
            )
            self._thread.start()
            return {"success": True, "run_id": self.live_run_id, "capture_id": self.live_capture_id}

    def _flush_packet_batch(self) -> None:
        """
        Persist queued packets to the SQLite packets table for parity with offline ingest.
        """
        if not self.live_capture_id:
            return

        with self._lock:
            if not self._packet_db_batch:
                return
            batch = self._packet_db_batch[:]
            self._packet_db_batch.clear()

        try:
            with get_db(self.db_path) as conn:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO packets (
                        capture_id, frame_no, ts, src_ip, dst_ip, src_port, dst_port,
                        proto, length, tcp_flags, ttl
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    batch,
                )
                conn.commit()
        except Exception as e:
            logger.error("Failed to insert live packets batch: %s", e)

    def _flush_dns_batch(self) -> None:
        """
        Persist queued DNS events to the SQLite dns_events table for parity with offline ingest.
        """
        if not self.live_capture_id:
            return

        with self._lock:
            if not self._dns_db_batch:
                return
            batch = self._dns_db_batch[:]
            self._dns_db_batch.clear()

        try:
            with get_db(self.db_path) as conn:
                conn.executemany(
                    """
                    INSERT INTO dns_events (
                        capture_id, frame_no, ts, client_ip, server_ip, qname,
                        qname_len, max_label_len, qtype, is_response, rcode, txid
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    batch,
                )
                conn.commit()
        except Exception as e:
            logger.error("Failed to insert live dns_events batch: %s", e)

    def pause(self) -> Dict[str, Any]:
        """
        Pause detection processing.
        """
        with self._lock:
            if not self.is_running:
                return {"success": False, "error": "Detection engine is not running."}
            self.is_paused = True
            self._pause_event.set()
            return {"success": True, "is_paused": True}

    def resume(self) -> Dict[str, Any]:
        """
        Resume detection processing after a pause.
        """
        with self._lock:
            if not self.is_running:
                return {"success": False, "error": "Detection engine is not running."}
            self.is_paused = False
            self._pause_event.clear()
            return {"success": True, "is_paused": False}

    def stop(self) -> Dict[str, Any]:
        """
        Stop the detection engine, drain remaining queue, and run final window evaluation.
        """
        with self._lock:
            if not self.is_running:
                return {"success": False, "error": "Detection engine is not running."}

            self._stop_event.set()
            self._pause_event.clear()
            self.is_running = False
            self.is_paused = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=4.0)

        # Final drain of any leftover packets in the queue
        frame_counter = self.total_packets_processed
        drained_count = 0
        while not self.packet_queue.empty() and drained_count < 2000:
            try:
                pkt = self.packet_queue.get_nowait()
                frame_counter += 1
                self.total_packets_processed += 1
                drained_count += 1
                pdict = _extract_packet_dict(pkt, frame_counter)
                if pdict:
                    self.recent_packets.append(pdict)
                    self._update_flow(pdict)
                    if self.live_capture_id:
                        self._packet_db_batch.append((
                            self.live_capture_id,
                            pdict["frame_no"],
                            pdict["ts"],
                            pdict["src_ip"],
                            pdict["dst_ip"],
                            pdict["src_port"],
                            pdict["dst_port"],
                            pdict["proto"],
                            pdict["length"],
                            pdict["tcp_flags"],
                            pdict.get("ttl", 64),
                        ))
                dns_ev = _extract_dns_event(pkt, frame_counter)
                if dns_ev:
                    self.recent_dns_events.append(dns_ev)
                    proto = dns_ev.get("proto_type", "DNS")
                    if proto == "DNS":
                        self.recent_standard_dns_events.append(dns_ev)
                        self._dns_stats["standard"] += 1
                    elif proto == "mDNS":
                        self._dns_stats["mdns"] += 1
                    elif proto == "LLMNR":
                        self._dns_stats["llmnr"] += 1
                    self._dns_stats["total"] += 1

                    if self.live_capture_id:
                        self._dns_db_batch.append((
                            self.live_capture_id,
                            dns_ev["frame_no"],
                            dns_ev["ts"],
                            dns_ev["client_ip"],
                            dns_ev["server_ip"],
                            dns_ev["qname"],
                            dns_ev["qname_len"],
                            dns_ev["max_label_len"],
                            dns_ev["qtype"],
                            dns_ev["is_response"],
                            dns_ev["rcode"],
                            dns_ev.get("txid", 0),
                        ))
            except queue.Empty:
                break

        # Flush final window evaluation & persist any remaining packet/DNS/flow records
        self._flush_packet_batch()
        self._flush_dns_batch()
        if self.live_capture_id:
            try:
                from netguard.ingest.flow_builder import build_flows_for_capture
                build_flows_for_capture(self.live_capture_id, db_path=self.db_path, config=self.config)
            except Exception as ex_fl:
                logger.error("Failed to build flows for live capture %s: %s", self.live_capture_id, ex_fl)
        self._evaluate_current_window()

        # Update run & capture metadata in DB
        now = time.time()
        stored_path = str(self.output_pcap) if (self.output_pcap and self.output_pcap.exists()) else "live_memory"
        pcap_size = self.output_pcap.stat().st_size if (self.output_pcap and self.output_pcap.exists()) else 0

        try:
            with get_db(self.db_path) as conn:
                if self.live_run_id:
                    stats = {
                        "packets_processed": self.total_packets_processed,
                        "alerts_count": self.total_alerts_generated,
                        "incidents_count": self.total_incidents_generated,
                        "blocks_count": self.total_blocks_triggered,
                        "flows_count": len(self.active_flows),
                    }
                    conn.execute(
                        "UPDATE runs SET status = 'completed', finished_at = ?, stats_json = ? WHERE id = ?;",
                        (now, json.dumps(stats), self.live_run_id),
                    )
                if self.live_capture_id:
                    conn.execute(
                        """
                        UPDATE captures
                        SET frames_total = ?, packets_stored = ?, first_ts = ?, last_ts = ?,
                            stored_path = ?, size_bytes = ?, status = 'ok'
                        WHERE id = ?;
                        """,
                        (
                            self.total_packets_processed,
                            self.total_packets_processed,
                            self.first_ts or now,
                            self.last_ts or now,
                            stored_path,
                            pcap_size,
                            self.live_capture_id,
                        ),
                    )
                conn.commit()
        except Exception as e:
            logger.error("Failed to finalize live capture DB records: %s", e)

        return {
            "success": True,
            "packets_processed": self.total_packets_processed,
            "alerts": self.total_alerts_generated,
            "incidents": self.total_incidents_generated,
            "blocks": self.total_blocks_triggered,
            "flows": len(self.active_flows),
        }

    def get_metrics(self) -> Dict[str, Any]:
        """
        Return operational status, queue size, and counters.
        """
        cfg = get_prevention_config(self.db_path)
        return {
            "is_running": self.is_running,
            "is_paused": self.is_paused,
            "run_id": self.live_run_id,
            "capture_id": self.live_capture_id,
            "packets_processed": self.total_packets_processed,
            "alerts_generated": self.total_alerts_generated,
            "incidents_generated": self.total_incidents_generated,
            "blocks_triggered": self.total_blocks_triggered,
            "active_flows": len(self.active_flows),
            "prevention_mode": cfg.get("mode", "monitor"),
            "queue_size": self.packet_queue.qsize() if self.packet_queue else 0,
            "dns_stats": dict(self._dns_stats),
        }

    def get_dns_stats(self) -> Dict[str, int]:
        """
        Return DNS telemetry statistics count (total, standard, mDNS, LLMNR).
        """
        return dict(self._dns_stats)

    def get_recent_packets(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Return the most recently processed packets for live table display.
        """
        return list(reversed(self.recent_packets[-limit:]))

    def get_recent_dns(
        self,
        limit: int = 50,
        proto_filter: str = "all",
        search_query: str = "",
    ) -> List[Dict[str, Any]]:
        """
        Return the most recently processed DNS queries (visited domains / sites) for live table display.
        proto_filter: 'all' | 'dns' (standard UDP/TCP 53) | 'mdns' (UDP 5353)
        search_query: case-insensitive query string to match domain or IP.
        """
        with self._lock:
            filter_mode = (proto_filter or "all").lower()
            if filter_mode == "dns":
                source = list(self.recent_standard_dns_events)
            elif filter_mode in ("mdns", "discovery"):
                source = [e for e in self.recent_dns_events if e.get("proto_type") in ("mDNS", "LLMNR")]
            else:
                source = list(self.recent_dns_events)

            if search_query:
                sq = search_query.strip().lower()
                source = [
                    e for e in source
                    if sq in e.get("qname", "").lower()
                    or sq in e.get("client_ip", "").lower()
                    or sq in e.get("server_ip", "").lower()
                ]

            return list(reversed(source[-limit:]))

    def get_recent_flows(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Return current active flows for live table display.
        """
        flows = [fl.to_dict() for fl in self.active_flows.values()]
        flows.sort(key=lambda f: f.get("end_ts", 0), reverse=True)
        return [
            {
                **fl,
                "ip_src": fl.get("initiator_ip"),
                "ip_dst": fl.get("responder_ip"),
                "sport": fl.get("initiator_port"),
                "dport": fl.get("responder_port"),
                "packets_total": fl.get("pkts_fwd", 0) + fl.get("pkts_rev", 0),
                "bytes_total": fl.get("bytes_fwd", 0) + fl.get("bytes_rev", 0),
            }
            for fl in flows[:limit]
        ]

    def _init_live_run(self) -> None:
        """
        Register a capture and run record for the current live session.
        """
        now = time.time()
        with get_db(self.db_path) as conn:
            # 1. Create live capture record
            sha_placeholder = f"live_{uuid.uuid4().hex}"
            cap_cursor = conn.execute(
                """
                INSERT INTO captures (
                    filename, stored_path, sha256, size_bytes, file_format, link_type,
                    frames_total, packets_stored, source, status, imported_at,
                    netguard_version, scapy_version
                ) VALUES (?, 'live_memory', ?, 0, 'live', 'Ethernet', 0, 0, 'live', 'ok', ?, '1.0.0', '2.8.0');
                """,
                (f"live_session_{int(now)}", sha_placeholder, now),
            )
            self.live_capture_id = cap_cursor.lastrowid

            # 2. Create run record referencing live capture
            cursor = conn.execute(
                """
                INSERT INTO runs (
                    capture_id, config_json, config_sha256, seed,
                    started_at, status, python_version, sklearn_version,
                    scapy_version, netguard_version
                ) VALUES (?, ?, 'live-config', 42, ?, 'running', '3.14', '1.6.1', '2.8.0', '1.0.0');
                """,
                (self.live_capture_id, json.dumps(self.config), now),
            )
            self.live_run_id = cursor.lastrowid
            conn.commit()

    def _run_loop(self) -> None:
        """
        Continuous packet ingestion and detection loop.
        """
        last_eval_time = time.time()
        frame_counter = 0

        while not self._stop_event.is_set():
            if self._pause_event.is_set():
                time.sleep(0.2)
                continue

            batch_count = 0
            while batch_count < 100:
                try:
                    pkt = self.packet_queue.get(timeout=0.2)
                    frame_counter += 1
                    self.total_packets_processed += 1
                    batch_count += 1

                    pdict = _extract_packet_dict(pkt, frame_counter)
                    if pdict:
                        if self.first_ts is None:
                            self.first_ts = pdict["ts"]
                        self.last_ts = pdict["ts"]
                        self.recent_packets.append(pdict)
                        self._update_flow(pdict)
                        if self.live_capture_id:
                            self._packet_db_batch.append((
                                self.live_capture_id,
                                pdict["frame_no"],
                                pdict["ts"],
                                pdict["src_ip"],
                                pdict["dst_ip"],
                                pdict["src_port"],
                                pdict["dst_port"],
                                pdict["proto"],
                                pdict["length"],
                                pdict["tcp_flags"],
                                pdict.get("ttl", 64),
                            ))
                            if len(self._packet_db_batch) >= 200:
                                self._flush_packet_batch()

                    dns_ev = _extract_dns_event(pkt, frame_counter)
                    if dns_ev:
                        self.recent_dns_events.append(dns_ev)
                        proto = dns_ev.get("proto_type", "DNS")
                        if proto == "DNS":
                            self.recent_standard_dns_events.append(dns_ev)
                            self._dns_stats["standard"] += 1
                        elif proto == "mDNS":
                            self._dns_stats["mdns"] += 1
                        elif proto == "LLMNR":
                            self._dns_stats["llmnr"] += 1
                        self._dns_stats["total"] += 1

                        if self.live_capture_id:
                            self._dns_db_batch.append((
                                self.live_capture_id,
                                dns_ev["frame_no"],
                                dns_ev["ts"],
                                dns_ev["client_ip"],
                                dns_ev["server_ip"],
                                dns_ev["qname"],
                                dns_ev["qname_len"],
                                dns_ev["max_label_len"],
                                dns_ev["qtype"],
                                dns_ev["is_response"],
                                dns_ev["rcode"],
                                dns_ev.get("txid", 0),
                            ))
                            if len(self._dns_db_batch) >= 50:
                                self._flush_dns_batch()

                except queue.Empty:
                    break

            now = time.time()

            # Trigger detection if batch interval passed or packet threshold met
            if (now - last_eval_time >= self.batch_interval) or len(self.recent_packets) >= 50:
                self._flush_packet_batch()
                self._flush_dns_batch()
                self._evaluate_current_window()
                last_eval_time = now

            # Periodic maintenance: block expiry and rule reconcile every 30s
            if now - self._last_maintenance_time >= 30.0:
                self._last_maintenance_time = now
                try:
                    expire_blocks(self.db_path)
                    reconcile_rules(self.db_path)
                except Exception as ex:
                    logger.debug("Maintenance cycle error: %s", ex)

            # Cap recent in-memory packets and DNS events
            if len(self.recent_packets) > 1000:
                self.recent_packets = self.recent_packets[-800:]
            if len(self.recent_dns_events) > 2000:
                self.recent_dns_events = self.recent_dns_events[-1500:]
            if len(self.recent_standard_dns_events) > 1000:
                self.recent_standard_dns_events = self.recent_standard_dns_events[-800:]

    def _update_flow(self, p: Dict[str, Any]) -> None:
        """
        Update bidirectional ActiveFlow state for an incoming packet.
        """
        proto = p["proto"]
        src = p["src_ip"]
        dst = p["dst_ip"]
        sport = p["src_port"]
        dport = p["dst_port"]

        ckey = canonical_flow_key(proto, src, sport, dst, dport)
        if ckey not in self.active_flows:
            self.active_flows[ckey] = ActiveFlow(self.live_capture_id or 1, p)
        else:
            self.active_flows[ckey].add_packet(p)

    def _evaluate_current_window(self) -> None:
        """
        Run detection rules on current flows/packets and trigger actions.
        """
        if not self.recent_packets:
            return

        flows_list = [fl.to_dict() for fl in self.active_flows.values()]
        findings = []
        try:
            findings.extend(detect_port_scan(flows_list, config=self.config))
        except Exception as e:
            logger.debug("Port scan eval error: %s", e)

        try:
            findings.extend(detect_brute_force(flows_list, config=self.config))
        except Exception as e:
            logger.debug("Brute force eval error: %s", e)

        try:
            dns_eval_target = self.recent_standard_dns_events if self.recent_standard_dns_events else self.recent_dns_events
            findings.extend(detect_dns_anomaly(dns_eval_target, config=self.config))
        except Exception as e:
            logger.debug("DNS eval error: %s", e)

        try:
            findings.extend(detect_abnormal_outbound(flows_list, self.recent_packets, config=self.config))
        except Exception as e:
            logger.debug("Outbound eval error: %s", e)

        if not findings:
            return

        # Allowlist & dedup
        allowlist = AllowList(self.config.get("allowlist", {}))
        filtered = allowlist.filter_findings(findings)
        deduped = deduplicate_findings(filtered, config=self.config)

        # Filter already seen alerts in this session
        new_alerts = []
        for f in deduped:
            key = (f.rule_name, f.src_ip, f.dst_ip, getattr(f, "dst_port", None))
            if key not in self.seen_alert_keys:
                self.seen_alert_keys.add(key)
                f.details["wireshark_filter"] = generate_wireshark_filter(f)
                new_alerts.append(f)

        if not new_alerts:
            return

        # Save alerts to DB
        alert_ids = save_alerts_to_db(new_alerts, run_id=self.live_run_id, db_path=self.db_path)
        self.total_alerts_generated += len(new_alerts)

        # Correlate incidents
        incidents = correlate_alerts(new_alerts, config=self.config)
        if incidents:
            save_incidents_to_db(incidents, run_id=self.live_run_id, db_path=self.db_path)
            self.total_incidents_generated += len(incidents)

        # Automated Prevention Check (Disabled in replay mode to protect system from offline simulation)
        if not self.is_replay:
            self._check_and_trigger_prevention(new_alerts, alert_ids)
        else:
            logger.info("Replay mode active: skipped firewall automated containment for %d alerts.", len(new_alerts))

    def _check_and_trigger_prevention(self, alerts: List[Any], alert_ids: List[int]) -> None:
        """
        If prevention mode is 'auto', automatically block malicious source IPs.
        """
        cfg = get_prevention_config(self.db_path)
        mode = cfg.get("mode", "monitor")

        if mode != "auto":
            return

        min_severity = cfg.get("auto_block_min_severity", "high").lower()
        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        target_rank = severity_rank.get(min_severity, 3)

        for alert, aid in zip(alerts, alert_ids):
            sev = getattr(alert, "severity", "medium").lower()
            if severity_rank.get(sev, 2) >= target_rank:
                source_ip = getattr(alert, "src_ip", None)
                if source_ip:
                    # Execute block
                    result = block_ip(
                        ip=source_ip,
                        duration_minutes=int(cfg.get("default_duration_minutes", 15)),
                        reason=f"Automated block: {alert.rule_name} (Severity: {sev})",
                        alert_id=aid,
                        operator="auto_prevention",
                        db_path=self.db_path,
                    )
                    if result.get("success"):
                        self.total_blocks_triggered += 1
                        logger.info("Auto-blocked IP %s (Rule: %s)", source_ip, alert.rule_name)
