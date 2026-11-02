"""
NetGuard Live Capture Engine
Captures network traffic on Windows network interfaces and feeds packets to the detection pipeline.
Provides bounded queuing, rolling PCAP persistence, pause/resume, and dropped packet metrics.
"""
from __future__ import annotations

import logging
import os
import queue
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure core scapy protocols (Ethernet, IP, TCP/UDP, DNS) are registered in conf.l2types
import scapy.layers.l2
import scapy.layers.inet
import scapy.layers.dns

logger = logging.getLogger(__name__)


def list_interfaces() -> List[Dict[str, Any]]:
    """
    List all available network interfaces on the system using Scapy.
    Returns interface details including name, description, IP, MAC, interface type, and device GUID.
    """
    interfaces = []
    try:
        from scapy.all import conf
        for guid, iface in conf.ifaces.items():
            name = getattr(iface, "name", str(guid))
            description = getattr(iface, "description", "")
            ip = getattr(iface, "ip", None)
            mac = getattr(iface, "mac", None)

            desc_lower = (description + " " + name).lower()
            if "loopback" in desc_lower:
                iface_type = "Loopback"
                is_loopback = True
            elif any(w in desc_lower for w in ["wi-fi", "wireless", "802.11", "wlan"]):
                iface_type = "Wi-Fi"
                is_loopback = False
            elif "bluetooth" in desc_lower:
                iface_type = "Bluetooth"
                is_loopback = False
            elif any(v in desc_lower for v in ["vpn", "tap", "tun", "wireguard"]):
                iface_type = "VPN/Tunnel"
                is_loopback = False
            elif any(vm in desc_lower for vm in ["virtual", "hyper-v", "vethernet", "vmware", "virtualbox"]):
                iface_type = "Virtual"
                is_loopback = False
            elif any(e in desc_lower for e in ["ethernet", "gigabit", "realtek", "intel", "lan"]):
                iface_type = "Ethernet"
                is_loopback = False
            else:
                iface_type = "Network Adapter"
                is_loopback = False

            is_active = bool(ip and str(ip) != "0.0.0.0" and not str(ip).startswith("169.254"))
            is_primary = bool(is_active and iface_type in ("Wi-Fi", "Ethernet") and not is_loopback)

            readable_name = description.strip() if description and description.strip() else str(name)
            if name and str(name).lower() not in readable_name.lower() and not str(name).startswith("\\Device\\"):
                readable_name = f"{readable_name} ({name})"

            interfaces.append({
                "id": str(guid),
                "name": name,
                "description": description,
                "readable_name": readable_name,
                "ip": str(ip) if ip else "0.0.0.0",
                "mac": str(mac) if mac else "",
                "is_loopback": is_loopback,
                "is_active": is_active,
                "is_primary": is_primary,
                "iface_type": iface_type,
            })
    except Exception as e:
        logger.error("Failed to enumerate network interfaces: %s", e)

    # Sort primary physical adapters first, then active interfaces, then by name
    interfaces.sort(key=lambda x: (not x["is_primary"], not x["is_active"], x["name"]))
    return interfaces


class LiveCaptureWorker:
    """
    Thread-safe worker that captures live packets from an interface
    or streams from a real PCAP file for unprivileged live testing.
    Supports bounded queuing, pause/resume, dropped packet metrics, and rolling PCAP saving.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        packet_queue: Optional[queue.Queue] = None,
        output_pcap: Optional[Path] = None,
        bpf_filter: str = "",
        replay_file: Optional[Path] = None,
    ):
        self.interface = interface
        self.packet_queue = packet_queue if packet_queue is not None else queue.Queue(maxsize=10000)
        self.output_pcap = output_pcap
        self.bpf_filter = bpf_filter
        self.replay_file = replay_file

        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Operational metrics
        self.is_running = False
        self.is_paused = False
        self.packets_captured = 0
        self.bytes_captured = 0
        self.packets_dropped = 0
        self.start_time: Optional[float] = None
        self.stop_time: Optional[float] = None
        self.error_message: Optional[str] = None
        self._pcap_writer = None

    def start(self) -> Dict[str, Any]:
        """
        Start live packet capture in a background thread.
        """
        with self._lock:
            if self.is_running:
                return {"success": False, "error": "Capture worker is already running."}

            self._stop_event.clear()
            self._pause_event.clear()
            self.is_running = True
            self.is_paused = False
            self.packets_captured = 0
            self.bytes_captured = 0
            self.packets_dropped = 0
            self.start_time = time.time()
            self.stop_time = None
            self.error_message = None

            if self.replay_file:
                target_func = self._run_replay
            else:
                target_func = self._run_live_sniff

            self._thread = threading.Thread(target=target_func, daemon=True, name="NetGuardCaptureWorker")
            self._thread.start()
            return {"success": True, "interface": self.interface, "started_at": self.start_time}

    def pause(self) -> Dict[str, Any]:
        """
        Pause capture processing. Packets arriving while paused are dropped or ignored.
        """
        with self._lock:
            if not self.is_running:
                return {"success": False, "error": "Capture worker is not running."}
            self.is_paused = True
            self._pause_event.set()
            return {"success": True, "is_paused": True}

    def resume(self) -> Dict[str, Any]:
        """
        Resume capture processing after a pause.
        """
        with self._lock:
            if not self.is_running:
                return {"success": False, "error": "Capture worker is not running."}
            self.is_paused = False
            self._pause_event.clear()
            return {"success": True, "is_paused": False}

    def stop(self) -> Dict[str, Any]:
        """
        Stop the capture worker cleanly and flush any open capture writer.
        """
        with self._lock:
            if not self.is_running:
                return {"success": False, "error": "Capture worker is not running."}

            self._stop_event.set()
            self._pause_event.clear()
            self.is_running = False
            self.is_paused = False
            self.stop_time = time.time()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

        if self._pcap_writer:
            try:
                self._pcap_writer.close()
            except Exception:
                pass
            self._pcap_writer = None

        duration = (self.stop_time or time.time()) - (self.start_time or time.time())
        return {
            "success": True,
            "packets_captured": self.packets_captured,
            "bytes_captured": self.bytes_captured,
            "packets_dropped": self.packets_dropped,
            "duration": round(duration, 2),
        }

    def get_status(self) -> Dict[str, Any]:
        """
        Return the current worker status, queue backlog, and throughput metrics.
        """
        now = time.time()
        uptime = (now - self.start_time) if self.start_time and self.is_running else 0
        backlog = self.packet_queue.qsize() if self.packet_queue else 0
        pps = round(self.packets_captured / uptime, 1) if uptime > 0 else 0.0
        kbps = round((self.bytes_captured * 8 / 1024) / uptime, 1) if uptime > 0 else 0.0

        return {
            "is_running": self.is_running,
            "is_paused": self.is_paused,
            "interface": self.interface,
            "packets_captured": self.packets_captured,
            "bytes_captured": self.bytes_captured,
            "packets_dropped": self.packets_dropped,
            "backlog_queue": backlog,
            "throughput_pps": pps,
            "throughput_kbps": kbps,
            "uptime_seconds": round(uptime, 2),
            "start_time": self.start_time,
            "error": self.error_message,
            "output_pcap": str(self.output_pcap) if self.output_pcap else None,
            "is_replay": bool(self.replay_file),
        }

    def _packet_callback(self, packet: Any) -> None:
        """
        Handle each captured packet with pause checking and queue overflow handling.
        """
        if self.is_paused or self._pause_event.is_set():
            return

        self.packets_captured += 1
        raw_len = len(packet) if hasattr(packet, "__len__") else 0
        self.bytes_captured += raw_len

        # Write to rolling PCAP file if output_pcap configured
        if self.output_pcap:
            try:
                if self._pcap_writer is None:
                    from scapy.utils import PcapWriter
                    self.output_pcap.parent.mkdir(parents=True, exist_ok=True)
                    self._pcap_writer = PcapWriter(str(self.output_pcap), append=True, sync=True)
                self._pcap_writer.write(packet)
            except Exception as e:
                logger.error("Failed to write packet to pcap: %s", e)

        # Enqueue packet for detection pipeline with backpressure handling
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            self.packets_dropped += 1
            if self.packets_dropped % 100 == 1:
                logger.warning("Packet queue full! Dropped %d packets due to pipeline backpressure.", self.packets_dropped)

    def _run_live_sniff(self) -> None:
        """
        Live sniffing loop using Scapy. Handles permissions gracefully.
        """
        try:
            from scapy.all import conf, sniff

            # Resolve interface name / guid
            iface_to_use = self.interface
            if iface_to_use:
                for guid, iface in conf.ifaces.items():
                    if iface_to_use.lower() in [getattr(iface, "name", "").lower(), str(guid).lower()]:
                        iface_to_use = guid
                        break

            while not self._stop_event.is_set():
                if self._pause_event.is_set():
                    time.sleep(0.2)
                    continue

                try:
                    sniff(
                        iface=iface_to_use,
                        filter=self.bpf_filter or None,
                        prn=self._packet_callback,
                        store=False,
                        timeout=1.0,
                        stop_filter=lambda _: self._stop_event.is_set(),
                    )
                except (PermissionError, OSError) as pe:
                    err = (
                        "Live capture requires Administrator privileges or Npcap WinPcap-compatible mode on Windows. "
                        f"Details: {pe}"
                    )
                    logger.error(err)
                    self.error_message = err
                    break
                except Exception as ex:
                    logger.error("Live sniff exception: %s", ex)
                    self.error_message = str(ex)
                    break
        except Exception as e:
            self.error_message = str(e)
            logger.error("Unhandled capture error: %s", e)
        finally:
            self.is_running = False
            self.stop_time = time.time()

    def _run_replay(self) -> None:
        """
        Stream packets from a real PCAP file at simulated real-time rate.
        Permits safe live testing without administrative privileges.
        """
        try:
            from scapy.utils import PcapReader
            reader = PcapReader(str(self.replay_file))
            for pkt in reader:
                if self._stop_event.is_set():
                    break
                while self._pause_event.is_set() and not self._stop_event.is_set():
                    time.sleep(0.2)

                self._packet_callback(pkt)
                time.sleep(0.01)  # Throttle for live processing pacing
            reader.close()
        except Exception as e:
            self.error_message = str(e)
            logger.error("Replay exception: %s", e)
        finally:
            self.is_running = False
            self.stop_time = time.time()
