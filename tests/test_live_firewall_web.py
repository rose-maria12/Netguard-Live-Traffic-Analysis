"""
Integration tests for NetGuard Live Monitor and Firewall Web endpoints.
"""
from unittest.mock import patch
import pytest

from netguard.db import init_db
from netguard.web.app import create_app


@pytest.fixture
def web_client(tmp_path):
    db_file = tmp_path / "test_web.db"
    init_db(db_file)
    app = create_app(
        db_path=db_file,
        test_config={"TESTING": True, "WTF_CSRF_ENABLED": False},
    )
    with app.test_client() as client:
        yield client


def test_live_monitor_page(web_client):
    res = web_client.get("/live")
    assert res.status_code == 200
    assert b"Live Network Monitor" in res.data
    assert b"Network Interface" in res.data


def test_firewall_page(web_client):
    res = web_client.get("/firewall")
    assert res.status_code == 200
    assert b"Windows Defender Firewall" in res.data
    assert b"Operational Mode" in res.data
    assert b"NetGuard Managed Firewall Rules" in res.data


def test_api_capture_interfaces(web_client):
    res = web_client.get("/api/capture/interfaces")
    assert res.status_code == 200
    data = res.get_json()
    assert "interfaces" in data
    assert isinstance(data["interfaces"], list)


def test_api_capture_status(web_client):
    res = web_client.get("/api/capture/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "is_running" in data
    assert data["is_running"] is False


def test_api_firewall_status(web_client):
    with patch("netguard.web.app.check_firewall_status") as mock_status:
        mock_status.return_value = {"available": True, "enabled": True, "profiles": []}
        res = web_client.get("/api/firewall/status")
        assert res.status_code == 200
        data = res.get_json()
        assert data["available"] is True


def test_api_firewall_config(web_client):
    res = web_client.post(
        "/api/firewall/config",
        json={"mode": "manual", "auto_block_min_severity": "critical", "default_duration_minutes": 30},
        headers={"X-NetGuard-Auth": "test-bypass"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["config"]["mode"] == "manual"
    assert data["config"]["auto_block_min_severity"] == "critical"


@patch("netguard.firewall.windows_fw._run_powershell")
def test_api_firewall_block_and_unblock(mock_ps, web_client):
    mock_ps.side_effect = [
        ("", "", 0),  # New rule
        ("1", "", 0), # Verify exists
        ("", "", 0),  # Remove rule
    ]

    # Block IP
    res = web_client.post(
        "/api/firewall/block",
        json={"ip": "198.51.100.33", "duration_minutes": 20, "reason": "Test scan"},
        headers={"X-NetGuard-Auth": "test-bypass"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "NetGuard-Block-" in data["rule_name"]
    rule_name = data["rule_name"]

    # Verify rules endpoint
    res_rules = web_client.get("/api/firewall/rules")
    assert res_rules.status_code == 200
    rules_data = res_rules.get_json()
    assert len(rules_data["rules"]) == 1
    assert rules_data["rules"][0]["ip_address"] == "198.51.100.33"

    # Unblock IP
    res_unblock = web_client.post(
        "/api/firewall/unblock",
        json={"rule_name": rule_name},
        headers={"X-NetGuard-Auth": "test-bypass"},
    )
    assert res_unblock.status_code == 200
    assert res_unblock.get_json()["success"] is True


@patch("netguard.firewall.windows_fw._run_powershell")
def test_api_emergency_unblock_all(mock_ps, web_client):
    mock_ps.return_value = ("", "", 0)
    res = web_client.post(
        "/api/firewall/emergency_unblock_all",
        headers={"X-NetGuard-Auth": "test-bypass"},
    )
    assert res.status_code == 200
    assert res.get_json()["success"] is True
