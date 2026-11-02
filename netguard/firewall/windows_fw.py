"""
Windows Defender Firewall Integration for NetGuard Prevention Module.
Safe, audited, temporary block management using PowerShell cmdlets.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from netguard.db import DEFAULT_DB_PATH, get_db

logger = logging.getLogger(__name__)

RULE_PREFIX = "NetGuard-Block-"

# Known local/reserved networks that must never be blocked under any circumstances
PROTECTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # IPv4 Loopback
    ipaddress.ip_network("::1/128"),          # IPv6 Loopback
    ipaddress.ip_network("0.0.0.0/32"),       # Unspecified
    ipaddress.ip_network("::/128"),           # IPv6 Unspecified
    ipaddress.ip_network("224.0.0.0/4"),      # IPv4 Multicast
    ipaddress.ip_network("ff00::/8"),         # IPv6 Multicast
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    ipaddress.ip_network("169.254.0.0/16"),   # IPv4 Link-local
    ipaddress.ip_network("fe80::/10"),        # IPv6 Link-local
]


def _run_powershell(command: str, timeout: int = 15) -> Tuple[str, str, int]:
    """
    Execute a PowerShell command safely via subprocess.
    Returns (stdout, stderr, returncode).
    """
    ps_cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        command,
    ]
    try:
        proc = subprocess.run(
            ps_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        logger.error("PowerShell command timed out after %ds: %s", timeout, command)
        return "", f"Command timed out after {timeout} seconds", -1
    except Exception as e:
        logger.error("PowerShell execution error: %s", e)
        return "", str(e), -1


def get_local_management_ips() -> set[str]:
    """
    Dynamically discover all local host IP addresses to protect management traffic.
    """
    ips = {"127.0.0.1", "::1"}
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
        _, _, host_ips = socket.gethostbyname_ex(hostname)
        ips.update(host_ips)
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0].split("%")[0]
            if addr:
                ips.add(addr)
    except Exception:
        pass

    # Try scapy if available
    try:
        from scapy.all import conf
        for iface in conf.ifaces.values():
            if hasattr(iface, "ip") and iface.ip:
                ips.add(str(iface.ip))
            iface_ips = getattr(iface, "ips", None)
            if isinstance(iface_ips, dict):
                for addr_list in iface_ips.values():
                    for addr in addr_list:
                        clean_addr = str(addr).split("%")[0]
                        if clean_addr:
                            ips.add(clean_addr)
    except Exception:
        pass

    return ips


def is_protected_ip(ip_str: str, extra_protected: Optional[List[str]] = None) -> Tuple[bool, str]:
    """
    Check if an IP address is protected and must NEVER be blocked.
    Returns (is_protected, reason).
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    # Check loopback / multicast / reserved networks
    for net in PROTECTED_NETWORKS:
        if ip in net:
            return True, f"Address belongs to reserved/system network: {net}"

    # Check local machine IPs
    local_ips = get_local_management_ips()
    if str(ip) in local_ips:
        return True, f"Address is a local management interface: {ip}"

    # Check extra protected IPs/subnets provided
    if extra_protected:
        for item in extra_protected:
            try:
                if "/" in item:
                    if ip in ipaddress.ip_network(item.strip(), strict=False):
                        return True, f"Address matches user protected network: {item}"
                else:
                    if ip == ipaddress.ip_address(item.strip()):
                        return True, f"Address matches user protected IP: {item}"
            except ValueError:
                continue

    return False, ""


def check_firewall_status() -> Dict[str, Any]:
    """
    Verify if Windows Defender Firewall cmdlets are accessible and firewall is active.
    """
    cmd = "Get-NetFirewallProfile | Select-Object -Property Name, Enabled | ConvertTo-Json"
    stdout, stderr, code = _run_powershell(cmd)

    if code != 0:
        return {
            "available": False,
            "enabled": False,
            "profiles": [],
            "error": stderr or "Failed to query firewall profile. Ensure administrative privileges if required.",
        }

    try:
        import json
        profiles_data = json.loads(stdout)
        if isinstance(profiles_data, dict):
            profiles_data = [profiles_data]
        any_enabled = any(p.get("Enabled") is True or p.get("Enabled") == 1 for p in profiles_data)
        return {
            "available": True,
            "enabled": any_enabled,
            "profiles": profiles_data,
            "error": None,
        }
    except Exception as e:
        return {
            "available": True,
            "enabled": True,
            "profiles": [],
            "error": f"Failed to parse profile JSON: {e}",
        }


def rule_exists(rule_name: str) -> bool:
    """
    Check if a specific firewall rule currently exists in Windows Defender Firewall.
    """
    # Strict validation of rule name to avoid injection
    if not re.match(r"^NetGuard-Block-[a-zA-Z0-9_\-\.:]+$", rule_name):
        return False
    cmd = f'Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count'
    stdout, _, code = _run_powershell(cmd)
    if code == 0 and stdout.strip():
        try:
            return int(stdout.strip()) > 0
        except ValueError:
            return False
    return False


def get_prevention_config(db_path: Any = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """
    Fetch the current prevention configuration from the database.
    Default mode is 'monitor'.
    """
    with get_db(db_path) as conn:
        row = conn.execute("SELECT * FROM prevention_config WHERE id = 1;").fetchone()
        if not row:
            # Initialize default
            now = time.time()
            conn.execute(
                """
                INSERT OR IGNORE INTO prevention_config (id, mode, auto_block_min_severity, max_concurrent_blocks, default_duration_minutes, rate_limit_per_hour, updated_at, updated_by)
                VALUES (1, 'monitor', 'high', 20, 15, 10, ?, 'system');
                """,
                (now,),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM prevention_config WHERE id = 1;").fetchone()
        return dict(row)


def set_prevention_config(
    mode: str,
    auto_block_min_severity: Optional[str] = None,
    max_concurrent_blocks: Optional[int] = None,
    default_duration_minutes: Optional[int] = None,
    rate_limit_per_hour: Optional[int] = None,
    operator: str = "admin",
    db_path: Any = DEFAULT_DB_PATH,
) -> Dict[str, Any]:
    """
    Update prevention configuration. Mode must be 'monitor', 'manual', or 'auto'.
    """
    mode = mode.lower().strip()
    if mode not in {"monitor", "manual", "auto"}:
        raise ValueError(f"Invalid mode '{mode}'. Must be 'monitor', 'manual', or 'auto'.")

    cfg = get_prevention_config(db_path)
    new_severity = auto_block_min_severity or cfg.get("auto_block_min_severity", "high")
    new_max = max_concurrent_blocks if max_concurrent_blocks is not None else cfg.get("max_concurrent_blocks", 20)
    new_dur = default_duration_minutes if default_duration_minutes is not None else cfg.get("default_duration_minutes", 15)
    new_rate = rate_limit_per_hour if rate_limit_per_hour is not None else cfg.get("rate_limit_per_hour", 10)

    now = time.time()
    with get_db(db_path) as conn:
        conn.execute(
            """
            UPDATE prevention_config
            SET mode = ?, auto_block_min_severity = ?, max_concurrent_blocks = ?,
                default_duration_minutes = ?, rate_limit_per_hour = ?,
                updated_at = ?, updated_by = ?
            WHERE id = 1;
            """,
            (mode, new_severity, new_max, new_dur, new_rate, now, operator),
        )
        conn.execute(
            """
            INSERT INTO firewall_audit (action, operator, result, detail, ts)
            VALUES ('config_change', ?, 'success', ?, ?);
            """,
            (operator, f"Mode changed to {mode}, severity {new_severity}", now),
        )
        conn.commit()

    return get_prevention_config(db_path)


def block_ip(
    ip: str,
    duration_minutes: Optional[int] = None,
    reason: str = "",
    alert_id: Optional[int] = None,
    incident_id: Optional[int] = None,
    operator: str = "system",
    extra_protected: Optional[List[str]] = None,
    db_path: Any = DEFAULT_DB_PATH,
) -> Dict[str, Any]:
    """
    Safely block an IP address using Windows Defender Firewall.
    - Validates IP
    - Ensures IP is not protected
    - Checks max concurrent limits & rate limits
    - Executes PowerShell New-NetFirewallRule
    - Confirms existence
    - Records in DB and audit log
    """
    now = time.time()
    ip_clean = ip.strip()

    # 1. Validation & Protection check
    protected, reason_prot = is_protected_ip(ip_clean, extra_protected)
    if protected:
        msg = f"Cannot block protected or invalid address {ip_clean}: {reason_prot}"
        logger.warning(msg)
        with get_db(db_path) as conn:
            conn.execute(
                """
                INSERT INTO firewall_audit (action, ip_address, operator, result, detail, ts)
                VALUES ('block_rejected', ?, ?, 'rejected', ?, ?);
                """,
                (ip_clean, operator, msg, now),
            )
            conn.commit()
        return {"success": False, "error": msg, "ip": ip_clean}

    # 2. Check config & limits
    cfg = get_prevention_config(db_path)
    if duration_minutes is None or duration_minutes <= 0:
        duration_minutes = int(cfg.get("default_duration_minutes", 15))

    with get_db(db_path) as conn:
        # Check active blocks count
        active_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM firewall_blocks WHERE status = 'active';"
        ).fetchone()["cnt"]
        if active_count >= cfg.get("max_concurrent_blocks", 20):
            msg = f"Maximum concurrent blocks limit ({cfg.get('max_concurrent_blocks', 20)}) reached."
            logger.warning(msg)
            conn.execute(
                """
                INSERT INTO firewall_audit (action, ip_address, operator, result, detail, ts)
                VALUES ('block_rate_limit', ?, ?, 'rejected', ?, ?);
                """,
                (ip_clean, operator, msg, now),
            )
            conn.commit()
            return {"success": False, "error": msg, "ip": ip_clean}

        # Check rate limit in last hour
        hour_ago = now - 3600
        recent_blocks = conn.execute(
            "SELECT COUNT(*) as cnt FROM firewall_blocks WHERE created_at >= ?;",
            (hour_ago,),
        ).fetchone()["cnt"]
        if recent_blocks >= cfg.get("rate_limit_per_hour", 10):
            msg = f"Hourly block rate limit ({cfg.get('rate_limit_per_hour', 10)}/hr) exceeded."
            logger.warning(msg)
            conn.execute(
                """
                INSERT INTO firewall_audit (action, ip_address, operator, result, detail, ts)
                VALUES ('block_rate_limit', ?, ?, 'rejected', ?, ?);
                """,
                (ip_clean, operator, msg, now),
            )
            conn.commit()
            return {"success": False, "error": msg, "ip": ip_clean}

        # Check if already actively blocked
        existing = conn.execute(
            "SELECT * FROM firewall_blocks WHERE ip_address = ? AND status = 'active';",
            (ip_clean,),
        ).fetchone()
        if existing:
            return {
                "success": True,
                "message": f"IP {ip_clean} is already actively blocked under rule {existing['rule_name']}",
                "rule_name": existing["rule_name"],
                "ip": ip_clean,
                "expires_at": existing["expires_at"],
            }

    # 3. Create rule via PowerShell
    safe_ip_tag = ip_clean.replace(":", "-").replace(".", "-")
    timestamp_tag = int(now)
    rule_name = f"{RULE_PREFIX}{safe_ip_tag}-{timestamp_tag}"
    escaped_reason = (reason or "NetGuard automated intrusion block").replace('"', "'")

    cmd = (
        f'New-NetFirewallRule -DisplayName "{rule_name}" '
        f'-Direction Inbound -Action Block -RemoteAddress "{ip_clean}" '
        f'-Description "NetGuard automated block: {escaped_reason}"'
    )

    stdout, stderr, code = _run_powershell(cmd)
    expires_at = now + (duration_minutes * 60)

    if code != 0:
        err_msg = f"Failed to execute firewall rule creation: {stderr}"
        logger.error(err_msg)
        with get_db(db_path) as conn:
            conn.execute(
                """
                INSERT INTO firewall_blocks (rule_name, ip_address, reason, alert_id, incident_id, created_at, expires_at, duration_minutes, status, fw_result)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'failed', ?);
                """,
                (rule_name, ip_clean, reason, alert_id, incident_id, now, expires_at, duration_minutes, stderr),
            )
            conn.execute(
                """
                INSERT INTO firewall_audit (action, ip_address, rule_name, operator, result, detail, ts)
                VALUES ('block', ?, ?, ?, 'failed', ?, ?);
                """,
                (ip_clean, rule_name, operator, stderr, now),
            )
            conn.commit()
        return {"success": False, "error": err_msg, "ip": ip_clean, "rule_name": rule_name}

    # 4. Verify rule existence in OS
    verified = rule_exists(rule_name)
    if not verified:
        # Rule command reported 0 but rule not found
        logger.warning("Rule %s created but verification query returned false", rule_name)

    # 5. Record successful block
    with get_db(db_path) as conn:
        conn.execute(
            """
            INSERT INTO firewall_blocks (rule_name, ip_address, reason, alert_id, incident_id, created_at, expires_at, duration_minutes, status, fw_result)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 'Created successfully');
            """,
            (rule_name, ip_clean, reason, alert_id, incident_id, now, expires_at, duration_minutes),
        )
        conn.execute(
            """
            INSERT INTO firewall_audit (action, ip_address, rule_name, operator, result, detail, ts)
            VALUES ('block', ?, ?, ?, 'success', ?, ?);
            """,
            (ip_clean, rule_name, operator, f"Blocked for {duration_minutes}m. Reason: {reason}", now),
        )
        conn.commit()

    return {
        "success": True,
        "rule_name": rule_name,
        "ip": ip_clean,
        "duration_minutes": duration_minutes,
        "expires_at": expires_at,
        "verified": verified,
    }


def unblock_ip(
    rule_name_or_ip: str,
    operator: str = "system",
    db_path: Any = DEFAULT_DB_PATH,
) -> Dict[str, Any]:
    """
    Safely unblock an IP or remove a NetGuard rule.
    CRITICAL: Strictly only removes rules starting with RULE_PREFIX.
    """
    now = time.time()
    target = rule_name_or_ip.strip()

    with get_db(db_path) as conn:
        # Check if target is IP or rule_name
        row = conn.execute(
            "SELECT * FROM firewall_blocks WHERE (rule_name = ? OR ip_address = ?) AND status = 'active';",
            (target, target),
        ).fetchone()

        rule_name = row["rule_name"] if row else target
        ip_addr = row["ip_address"] if row else target

        # Safety check: Rule name MUST start with RULE_PREFIX
        if not rule_name.startswith(RULE_PREFIX):
            return {
                "success": False,
                "error": f"Refusing to remove rule '{rule_name}': does not have NetGuard prefix '{RULE_PREFIX}'",
            }

        # Remove via PowerShell
        cmd = f'Remove-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue'
        stdout, stderr, code = _run_powershell(cmd)

        # Update DB record
        conn.execute(
            """
            UPDATE firewall_blocks
            SET status = 'removed', removed_at = ?, removed_by = ?
            WHERE rule_name = ?;
            """,
            (now, operator, rule_name),
        )
        conn.execute(
            """
            INSERT INTO firewall_audit (action, ip_address, rule_name, operator, result, detail, ts)
            VALUES ('unblock', ?, ?, ?, 'success', ?, ?);
            """,
            (ip_addr, rule_name, operator, f"Rule removed by {operator}", now),
        )
        conn.commit()

    return {"success": True, "rule_name": rule_name, "ip": ip_addr}


def list_managed_rules(db_path: Any = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """
    List all NetGuard managed firewall rules from the database.
    """
    with get_db(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM firewall_blocks ORDER BY created_at DESC;"
        ).fetchall()
        return [dict(r) for r in rows]


def list_os_netguard_rules() -> List[Dict[str, Any]]:
    """
    Query actual NetGuard rules currently existing in Windows Defender Firewall.
    """
    cmd = (
        f'Get-NetFirewallRule -DisplayName "{RULE_PREFIX}*" -ErrorAction SilentlyContinue | '
        'Select-Object DisplayName, Direction, Action, Enabled | ConvertTo-Json'
    )
    stdout, _, code = _run_powershell(cmd)
    if code != 0 or not stdout.strip():
        return []
    try:
        import json
        data = json.loads(stdout)
        if isinstance(data, dict):
            return [data]
        return list(data)
    except Exception:
        return []


def reconcile_rules(db_path: Any = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """
    Reconcile active records in the DB with actual Windows Defender Firewall state.
    """
    now = time.time()
    os_rules = {r.get("DisplayName") for r in list_os_netguard_rules() if r.get("DisplayName")}

    with get_db(db_path) as conn:
        active_db = conn.execute(
            "SELECT rule_name FROM firewall_blocks WHERE status = 'active';"
        ).fetchall()
        active_db_names = {r["rule_name"] for r in active_db}

        # Rules active in DB but missing from OS
        missing_from_os = active_db_names - os_rules
        for r_name in missing_from_os:
            conn.execute(
                """
                UPDATE firewall_blocks
                SET status = 'removed', removed_at = ?, removed_by = 'reconcile_sync'
                WHERE rule_name = ?;
                """,
                (now, r_name),
            )
            conn.execute(
                """
                INSERT INTO firewall_audit (action, rule_name, operator, result, detail, ts)
                VALUES ('reconcile', ?, 'system', 'synced', 'Rule missing from OS; marked removed', ?);
                """,
                (r_name, now),
            )

        conn.commit()

    return {
        "os_rules_count": len(os_rules),
        "db_active_count": len(active_db_names),
        "missing_synced": list(missing_from_os),
    }


def expire_blocks(db_path: Any = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """
    Inspect active blocks whose expiry timestamp has passed and safely unblock them.
    """
    now = time.time()
    expired_items = []

    with get_db(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM firewall_blocks WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?;",
            (now,),
        ).fetchall()

        for row in rows:
            rule_name = row["rule_name"]
            ip_addr = row["ip_address"]
            cmd = f'Remove-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue'
            _run_powershell(cmd)

            conn.execute(
                """
                UPDATE firewall_blocks
                SET status = 'expired', removed_at = ?, removed_by = 'expiry_worker'
                WHERE id = ?;
                """,
                (now, row["id"]),
            )
            conn.execute(
                """
                INSERT INTO firewall_audit (action, ip_address, rule_name, operator, result, detail, ts)
                VALUES ('expire', ?, ?, 'expiry_worker', 'success', 'Rule automatically expired', ?);
                """,
                (ip_addr, rule_name, now),
            )
            expired_items.append({"rule_name": rule_name, "ip": ip_addr, "id": row["id"]})

        conn.commit()

    return expired_items


def emergency_unblock_all(operator: str = "admin", db_path: Any = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """
    Emergency procedure: safely remove ALL NetGuard firewall rules.
    Guaranteed NEVER to remove rules created outside of NetGuard.
    """
    now = time.time()
    cmd = f'Remove-NetFirewallRule -DisplayName "{RULE_PREFIX}*" -ErrorAction SilentlyContinue'
    stdout, stderr, code = _run_powershell(cmd)

    with get_db(db_path) as conn:
        conn.execute(
            """
            UPDATE firewall_blocks
            SET status = 'removed', removed_at = ?, removed_by = ?
            WHERE status = 'active';
            """,
            (now, f"emergency_{operator}"),
        )
        conn.execute(
            """
            INSERT INTO firewall_audit (action, operator, result, detail, ts)
            VALUES ('emergency_unblock_all', ?, 'success', 'All NetGuard-Block-* rules purged', ?);
            """,
            (operator, now),
        )
        conn.commit()

    return {
        "success": code == 0,
        "message": f"All rules starting with '{RULE_PREFIX}' have been removed.",
        "error": stderr if code != 0 else None,
    }
