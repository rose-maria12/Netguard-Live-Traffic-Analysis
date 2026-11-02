"""
Unit tests for NetGuard Windows Firewall module.
Tests protected IP lists, prevention modes, rule generation, safe unblocking, and audit logging.
"""
import time
from unittest.mock import patch
import pytest

from netguard.db import init_db
from netguard.firewall.windows_fw import (
    RULE_PREFIX,
    block_ip,
    check_firewall_status,
    emergency_unblock_all,
    expire_blocks,
    get_prevention_config,
    is_protected_ip,
    list_managed_rules,
    reconcile_rules,
    set_prevention_config,
    unblock_ip,
)


@pytest.fixture
def fw_db(tmp_path):
    db_file = tmp_path / "test_fw.db"
    init_db(db_file)
    return db_file


def test_is_protected_ip():
    # Loopback
    prot, _ = is_protected_ip("127.0.0.1")
    assert prot is True
    prot, _ = is_protected_ip("127.0.0.5")
    assert prot is True

    # IPv6 Loopback
    prot, _ = is_protected_ip("::1")
    assert prot is True

    # Multicast & Broadcast
    prot, _ = is_protected_ip("224.0.0.1")
    assert prot is True
    prot, _ = is_protected_ip("255.255.255.255")
    assert prot is True

    # Unspecified
    prot, _ = is_protected_ip("0.0.0.0")
    assert prot is True

    # Link-local
    prot, _ = is_protected_ip("169.254.10.20")
    assert prot is True

    # Invalid IP string
    prot, _ = is_protected_ip("not-an-ip")
    assert prot is True

    # Custom extra protected
    prot, _ = is_protected_ip("192.168.1.50", extra_protected=["192.168.1.0/24"])
    assert prot is True

    # Valid external IP
    prot, _ = is_protected_ip("198.51.100.42")
    assert prot is False


def test_prevention_config(fw_db):
    cfg = get_prevention_config(fw_db)
    assert cfg["mode"] == "monitor"
    assert cfg["max_concurrent_blocks"] == 20

    updated = set_prevention_config("manual", auto_block_min_severity="critical", db_path=fw_db)
    assert updated["mode"] == "manual"
    assert updated["auto_block_min_severity"] == "critical"

    with pytest.raises(ValueError):
        set_prevention_config("invalid_mode", db_path=fw_db)


@patch("netguard.firewall.windows_fw._run_powershell")
def test_block_ip_success(mock_ps, fw_db):
    # Mock New-NetFirewallRule success and rule_exists check
    mock_ps.side_effect = [
        ("", "", 0),  # New-NetFirewallRule
        ("1", "", 0), # rule_exists check
    ]

    res = block_ip("203.0.113.5", duration_minutes=10, reason="Port scan", db_path=fw_db)
    assert res["success"] is True
    assert res["ip"] == "203.0.113.5"
    assert res["rule_name"].startswith(RULE_PREFIX)
    assert res["duration_minutes"] == 10

    # Verify stored in DB
    rules = list_managed_rules(fw_db)
    assert len(rules) == 1
    assert rules[0]["ip_address"] == "203.0.113.5"
    assert rules[0]["status"] == "active"


def test_block_protected_ip_rejected(fw_db):
    from netguard.firewall.windows_fw import get_local_management_ips

    res = block_ip("127.0.0.1", db_path=fw_db)
    assert res["success"] is False
    assert "protected" in res["error"].lower()

    # Verify host's own local interface IP(s) are rejected before OS execution
    local_ips = get_local_management_ips()
    non_loopback_local = [ip for ip in local_ips if ip not in ("127.0.0.1", "::1")]
    assert len(local_ips) >= 2
    for host_ip in non_loopback_local:
        prot, reason = is_protected_ip(host_ip)
        assert prot is True
        res_host = block_ip(host_ip, db_path=fw_db)
        assert res_host["success"] is False
        assert "protected" in res_host["error"].lower() or "local management interface" in res_host["error"].lower()

    # DB should have no active block
    rules = list_managed_rules(fw_db)
    assert len(rules) == 0


@patch("netguard.firewall.windows_fw._run_powershell")
def test_unblock_ip_safety(mock_ps, fw_db):
    mock_ps.return_value = ("", "", 0)

    # Refuse removing non-NetGuard rule
    res = unblock_ip("DefaultInboundBlock", db_path=fw_db)
    assert res["success"] is False
    assert "Refusing to remove rule" in res["error"]


@patch("netguard.firewall.windows_fw._run_powershell")
def test_block_and_unblock_flow(mock_ps, fw_db):
    mock_ps.side_effect = [
        ("", "", 0),  # New rule
        ("1", "", 0), # Verify exists
        ("", "", 0),  # Remove rule
    ]

    block_res = block_ip("198.51.100.99", reason="Brute force", db_path=fw_db)
    assert block_res["success"] is True
    rule_name = block_res["rule_name"]

    unblock_res = unblock_ip(rule_name, operator="analyst", db_path=fw_db)
    assert unblock_res["success"] is True

    rules = list_managed_rules(fw_db)
    assert len(rules) == 1
    assert rules[0]["status"] == "removed"
    assert rules[0]["removed_by"] == "analyst"


@patch("netguard.firewall.windows_fw._run_powershell")
def test_expiry_worker(mock_ps, fw_db):
    mock_ps.side_effect = [
        ("", "", 0),  # New rule
        ("1", "", 0), # Verify exists
        ("", "", 0),  # Remove rule on expiry
    ]

    # Block for negative duration so it is expired immediately
    res = block_ip("198.51.100.88", duration_minutes=1, db_path=fw_db)
    assert res["success"] is True

    # Manually backdate expires_at
    from netguard.db import get_db
    with get_db(fw_db) as conn:
        conn.execute("UPDATE firewall_blocks SET expires_at = ? WHERE ip_address = '198.51.100.88';", (time.time() - 10,))
        conn.commit()

    expired = expire_blocks(fw_db)
    assert len(expired) == 1
    assert expired[0]["ip"] == "198.51.100.88"

    rules = list_managed_rules(fw_db)
    assert rules[0]["status"] == "expired"


@patch("netguard.firewall.windows_fw._run_powershell")
def test_emergency_unblock_all(mock_ps, fw_db):
    mock_ps.return_value = ("", "", 0)
    res = emergency_unblock_all(operator="superadmin", db_path=fw_db)
    assert res["success"] is True
