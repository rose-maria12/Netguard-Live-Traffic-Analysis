from typing import Any, Dict, Union
from netguard.detection.base import Finding


def generate_wireshark_filter(finding: Union[Finding, Dict[str, Any]]) -> str:
    """
    Generate a deterministic, valid Wireshark display filter for a given alert finding or dict.
    Preserves exact 1-based frame numbers.
    """
    if isinstance(finding, Finding):
        src_ip = finding.src_ip
        dst_ip = finding.dst_ip
        dst_port = finding.dst_port
        alert_type = finding.alert_type
        details = finding.details or {}
        first_frame = details.get("first_frame", 0)
        last_frame = details.get("last_frame", 0)
        evidence_refs = finding.evidence_refs or []
    else:
        src_ip = finding.get("src_ip", "")
        dst_ip = finding.get("dst_ip")
        dst_port = finding.get("dst_port")
        alert_type = finding.get("alert_type", "")
        details = finding.get("details", {})
        if isinstance(details, str):
            import json
            try:
                details = json.loads(details)
            except Exception:
                details = {}
        first_frame = finding.get("first_frame") or details.get("first_frame", 0)
        last_frame = finding.get("last_frame") or details.get("last_frame", 0)
        evidence_refs = finding.get("evidence_refs", [])

    # Extract specific frame numbers from evidence if available
    frame_nos = sorted(list({e.get("frame_no") for e in evidence_refs if e.get("frame_no")}))

    base_filter = ""

    if alert_type == "port_scan":
        if src_ip and dst_ip:
            base_filter = f"ip.src == {src_ip} && ip.dst == {dst_ip}"
        elif src_ip:
            base_filter = f"ip.src == {src_ip}"
    elif alert_type == "brute_force":
        if src_ip and dst_ip and dst_port:
            base_filter = f"ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.dstport == {dst_port}"
        elif src_ip and dst_ip:
            base_filter = f"ip.src == {src_ip} && ip.dst == {dst_ip}"
        elif src_ip:
            base_filter = f"ip.src == {src_ip}"
    elif alert_type == "dns_anomaly":
        if src_ip:
            base_filter = f"ip.src == {src_ip} && dns"
        else:
            base_filter = "dns"
    elif alert_type == "abnormal_outbound":
        if src_ip and dst_ip:
            base_filter = f"ip.src == {src_ip} && ip.dst == {dst_ip}"
        elif src_ip:
            base_filter = f"ip.src == {src_ip}"
    elif alert_type == "ml_anomaly":
        if src_ip:
            base_filter = f"ip.src == {src_ip}"
    else:
        if src_ip and dst_ip:
            base_filter = f"ip.src == {src_ip} && ip.dst == {dst_ip}"
        elif src_ip:
            base_filter = f"ip.src == {src_ip}"

    # Append frame bounds filter
    frame_filter = ""
    if frame_nos and len(frame_nos) <= 5:
        frames_str = " || ".join(f"frame.number == {fn}" for fn in frame_nos)
        frame_filter = f"({frames_str})"
    elif first_frame > 0 and last_frame >= first_frame:
        if first_frame == last_frame:
            frame_filter = f"frame.number == {first_frame}"
        else:
            frame_filter = f"frame.number >= {first_frame} && frame.number <= {last_frame}"

    if base_filter and frame_filter:
        return f"({base_filter}) && {frame_filter}"
    elif base_filter:
        return base_filter
    elif frame_filter:
        return frame_filter
    else:
        return "frame"


def generate_bidirectional_wireshark_filter(finding: Union[Finding, Dict[str, Any]]) -> str:
    """
    Generate a bidirectional Wireshark investigation filter (using ip.addr == ... and tcp.port == ...)
    so analysts can inspect both forward trigger packets and reverse responder packets (SYN-ACK, RST, DNS replies).
    """
    if isinstance(finding, Finding):
        src_ip = finding.src_ip
        dst_ip = finding.dst_ip
        dst_port = finding.dst_port
        alert_type = finding.alert_type
        details = finding.details or {}
        first_frame = details.get("first_frame", 0)
        last_frame = details.get("last_frame", 0)
    else:
        src_ip = finding.get("src_ip", "")
        dst_ip = finding.get("dst_ip")
        dst_port = finding.get("dst_port")
        alert_type = finding.get("alert_type", "")
        details = finding.get("details", {})
        if isinstance(details, str):
            import json
            try:
                details = json.loads(details)
            except Exception:
                details = {}
        first_frame = finding.get("first_frame") or details.get("first_frame", 0)
        last_frame = finding.get("last_frame") or details.get("last_frame", 0)

    base_filter = ""
    if alert_type == "port_scan":
        if src_ip and dst_ip:
            base_filter = f"ip.addr == {src_ip} && ip.addr == {dst_ip} && tcp"
        elif src_ip:
            base_filter = f"ip.addr == {src_ip} && tcp"
    elif alert_type == "brute_force":
        if src_ip and dst_ip and dst_port:
            base_filter = f"ip.addr == {src_ip} && ip.addr == {dst_ip} && tcp.port == {dst_port}"
        elif src_ip and dst_ip:
            base_filter = f"ip.addr == {src_ip} && ip.addr == {dst_ip} && tcp"
        elif src_ip:
            base_filter = f"ip.addr == {src_ip} && tcp"
    elif alert_type == "dns_anomaly":
        if src_ip:
            base_filter = f"ip.addr == {src_ip} && dns"
        else:
            base_filter = "dns"
    elif alert_type == "abnormal_outbound":
        if src_ip and dst_ip:
            base_filter = f"ip.addr == {src_ip} && ip.addr == {dst_ip}"
        elif src_ip:
            base_filter = f"ip.addr == {src_ip}"
    elif alert_type == "ml_anomaly":
        if src_ip:
            base_filter = f"ip.addr == {src_ip}"
    else:
        if src_ip and dst_ip:
            base_filter = f"ip.addr == {src_ip} && ip.addr == {dst_ip}"
        elif src_ip:
            base_filter = f"ip.addr == {src_ip}"

    frame_filter = ""
    if first_frame > 0 and last_frame >= first_frame:
        if first_frame == last_frame:
            frame_filter = f"frame.number == {first_frame}"
        else:
            frame_filter = f"frame.number >= {first_frame} && frame.number <= {last_frame}"

    if base_filter and frame_filter:
        return f"({base_filter}) && {frame_filter}"
    elif base_filter:
        return base_filter
    elif frame_filter:
        return frame_filter
    else:
        return "frame"


def extract_trigger_frames(finding: Union[Finding, Dict[str, Any]]) -> list[int]:
    """
    Return the sorted list of exact 1-based trigger frame numbers recorded in evidence_refs.
    Distinguishes exact trigger frames from the broad window/flow [first_frame, last_frame] span.
    """
    if isinstance(finding, Finding):
        evidence_refs = finding.evidence_refs or []
        details = finding.details or {}
    else:
        evidence_refs = finding.get("evidence_refs") or finding.get("evidence_items") or []
        details = finding.get("details") or {}
        if isinstance(details, str):
            import json
            try:
                details = json.loads(details)
            except Exception:
                details = {}

    frames = sorted({int(e["frame_no"]) for e in evidence_refs if e.get("frame_no") is not None and int(e["frame_no"]) > 0})
    if not frames and isinstance(details, dict) and details.get("trigger_frames"):
        frames = sorted({int(fn) for fn in details["trigger_frames"] if fn and int(fn) > 0})
    return frames
