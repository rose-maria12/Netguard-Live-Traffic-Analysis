from typing import Any, Dict, List, Optional, Tuple, Union
from pathlib import Path
from netguard.db import get_db, DEFAULT_DB_PATH
from netguard.config import load_config


def canonical_flow_key(
    proto: str, src_ip: str, src_port: Optional[int], dst_ip: str, dst_port: Optional[int]
) -> Tuple[str, str, Optional[int], str, Optional[int]]:
    """
    Return canonical flow key tuple (proto, ip_min, port_min, ip_max, port_max).
    Endpoints are ordered lexicographically so both traffic directions map to the same key.
    """
    endpoint_a = (src_ip, src_port if src_port is not None else -1)
    endpoint_b = (dst_ip, dst_port if dst_port is not None else -1)

    if endpoint_a <= endpoint_b:
        return (proto, src_ip, src_port, dst_ip, dst_port)
    else:
        return (proto, dst_ip, dst_port, src_ip, src_port)


class ActiveFlow:
    def __init__(self, capture_id: int, pkt: Dict[str, Any]):
        self.capture_id = capture_id
        self.proto = pkt["proto"]

        # Check for TCP mid-handshake SYN-ACK first packet
        tcp_flags = pkt["tcp_flags"] or 0
        is_synack = (self.proto == "TCP") and ((tcp_flags & 18) == 18)

        if is_synack:
            # Swap endpoints so initiator is responder of SYN-ACK
            self.initiator_ip = pkt["dst_ip"]
            self.initiator_port = pkt["dst_port"]
            self.responder_ip = pkt["src_ip"]
            self.responder_port = pkt["src_port"]
        else:
            self.initiator_ip = pkt["src_ip"]
            self.initiator_port = pkt["src_port"]
            self.responder_ip = pkt["dst_ip"]
            self.responder_port = pkt["dst_port"]

        self.start_ts = float(pkt["ts"])
        self.end_ts = float(pkt["ts"])
        self.first_frame = int(pkt["frame_no"])
        self.last_frame = int(pkt["frame_no"])

        self.pkts_fwd = 0
        self.pkts_rev = 0
        self.bytes_fwd = 0
        self.bytes_rev = 0
        self.syn_count = 0
        self.rst_count = 0

        self.seen_init_syn = False
        self.seen_resp_synack = False
        self.seen_init_ack_after_synack = False
        self.seen_rst = False
        self.has_seen_fin_or_rst = False

        self.packet_ids: List[int] = []

        self.add_packet(pkt)

    def is_forward(self, pkt: Dict[str, Any]) -> bool:
        return (pkt["src_ip"] == self.initiator_ip) and (pkt["src_port"] == self.initiator_port)

    def add_packet(self, pkt: Dict[str, Any]) -> None:
        self.end_ts = float(pkt["ts"])
        self.last_frame = int(pkt["frame_no"])
        self.packet_ids.append(pkt["id"])

        length = int(pkt["length"])
        is_fwd = self.is_forward(pkt)

        if is_fwd:
            self.pkts_fwd += 1
            self.bytes_fwd += length
        else:
            self.pkts_rev += 1
            self.bytes_rev += length

        if self.proto == "TCP":
            flags = pkt["tcp_flags"] or 0
            if flags & 2:  # SYN bit
                self.syn_count += 1
            if flags & 4:  # RST bit
                self.rst_count += 1
                self.seen_rst = True
                self.has_seen_fin_or_rst = True
            if flags & 1:  # FIN bit
                self.has_seen_fin_or_rst = True

            # Track TCP handshake progression
            if is_fwd and (flags & 2) and not (flags & 16):  # SYN from initiator
                self.seen_init_syn = True
            elif not is_fwd and (flags & 18) == 18:  # SYN-ACK from responder
                self.seen_resp_synack = True
            elif is_fwd and (flags & 16) and not (flags & 2) and self.seen_resp_synack:  # ACK from initiator after SYN-ACK
                self.seen_init_ack_after_synack = True

    def compute_state(self) -> str:
        if self.proto != "TCP":
            return "other"

        # Priority 1: established
        if self.seen_init_syn and self.seen_resp_synack and self.seen_init_ack_after_synack:
            return "established"

        # Priority 2: reset
        if self.seen_rst:
            return "reset"

        # Priority 3: no_response (initiator sent SYN and 0 packets ever received from responder)
        if self.seen_init_syn and self.pkts_rev == 0:
            return "no_response"

        # Priority 4: other
        return "other"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capture_id": self.capture_id,
            "initiator_ip": self.initiator_ip,
            "responder_ip": self.responder_ip,
            "initiator_port": self.initiator_port,
            "responder_port": self.responder_port,
            "proto": self.proto,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "pkts_fwd": self.pkts_fwd,
            "pkts_rev": self.pkts_rev,
            "bytes_fwd": self.bytes_fwd,
            "bytes_rev": self.bytes_rev,
            "syn_count": self.syn_count,
            "rst_count": self.rst_count,
            "state": self.compute_state(),
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
            "packet_ids": self.packet_ids,
        }


def build_flows_for_capture(
    capture_id: int,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    config: Optional[Dict[str, Any]] = None,
) -> int:
    """
    Build bidirectional flows for a capture in SQLite database.
    Updates packets table with assigned flow_ids and inserts flow records into flows table.
    Returns the count of flows built.
    """
    if config is None:
        config = load_config()

    flow_idle_timeout = config.get("general", {}).get("flow_idle_timeout", 60)

    conn = get_db(db_path)
    try:
        # Fetch all packets for the capture sorted by (ts, frame_no)
        cursor = conn.execute(
            """
            SELECT id, frame_no, ts, src_ip, dst_ip, src_port, dst_port, proto, length, tcp_flags
            FROM packets
            WHERE capture_id = ?
            ORDER BY ts ASC, frame_no ASC;
            """,
            (capture_id,),
        )
        packets = [dict(row) for row in cursor.fetchall()]

        if not packets:
            return 0

        active_flows: Dict[Tuple[str, str, Optional[int], str, Optional[int]], ActiveFlow] = {}
        completed_flows: List[ActiveFlow] = []

        for pkt in packets:
            ckey = canonical_flow_key(pkt["proto"], pkt["src_ip"], pkt["src_port"], pkt["dst_ip"], pkt["dst_port"])
            pkt_ts = float(pkt["ts"])
            tcp_flags = pkt["tcp_flags"] or 0

            active = active_flows.get(ckey)

            if active is not None:
                idle_gap = pkt_ts - active.end_ts
                is_new_syn = (pkt["proto"] == "TCP") and ((tcp_flags & 2) != 0) and ((tcp_flags & 16) == 0)

                # Timeout check or TCP port reuse check
                if (idle_gap > flow_idle_timeout) or (active.has_seen_fin_or_rst and is_new_syn):
                    completed_flows.append(active)
                    active_flows[ckey] = ActiveFlow(capture_id, pkt)
                else:
                    active.add_packet(pkt)
            else:
                active_flows[ckey] = ActiveFlow(capture_id, pkt)

        # Flush remaining active flows
        for flow in active_flows.values():
            completed_flows.append(flow)

        # Save flows to database in atomic transaction
        conn.execute("BEGIN TRANSACTION;")
        conn.execute("DELETE FROM flows WHERE capture_id = ?;", (capture_id,))

        flow_insert_tuples = []
        packet_flow_updates = []

        for flow in completed_flows:
            flow_dict = flow.to_dict()
            # We will insert flows and get their generated IDs
            cursor = conn.execute(
                """
                INSERT INTO flows (
                    capture_id, initiator_ip, responder_ip, initiator_port, responder_port,
                    proto, start_ts, end_ts, pkts_fwd, pkts_rev, bytes_fwd, bytes_rev,
                    syn_count, rst_count, state, first_frame, last_frame
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    flow_dict["capture_id"],
                    flow_dict["initiator_ip"],
                    flow_dict["responder_ip"],
                    flow_dict["initiator_port"],
                    flow_dict["responder_port"],
                    flow_dict["proto"],
                    flow_dict["start_ts"],
                    flow_dict["end_ts"],
                    flow_dict["pkts_fwd"],
                    flow_dict["pkts_rev"],
                    flow_dict["bytes_fwd"],
                    flow_dict["bytes_rev"],
                    flow_dict["syn_count"],
                    flow_dict["rst_count"],
                    flow_dict["state"],
                    flow_dict["first_frame"],
                    flow_dict["last_frame"],
                ),
            )
            flow_id = cursor.lastrowid

            for pkt_id in flow_dict["packet_ids"]:
                packet_flow_updates.append((flow_id, pkt_id))

        # Batch update packets table with flow_ids
        if packet_flow_updates:
            conn.executemany(
                "UPDATE packets SET flow_id = ? WHERE id = ?;",
                packet_flow_updates,
            )

        conn.commit()
        return len(completed_flows)

    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()
