"""
Unit and integration tests for NetGuard AbuseIPDB Threat Intelligence Integration.
"""
from netguard.db import init_db
from netguard.threat_intel.abuseipdb import AbuseIPDBClient, lookup_ip_reputation
from netguard.web.app import create_app


def test_private_and_local_ip_filtering():
    client = AbuseIPDBClient(api_key="test-dummy-key")

    # RFC 1918 / Loopback / Link-Local / Multicast
    assert client.is_queryable_public_ip("127.0.0.1") is False
    assert client.is_queryable_public_ip("192.168.1.100") is False
    assert client.is_queryable_public_ip("10.0.0.1") is False
    assert client.is_queryable_public_ip("172.16.5.20") is False
    assert client.is_queryable_public_ip("169.254.10.10") is False
    assert client.is_queryable_public_ip("224.0.0.1") is False
    assert client.is_queryable_public_ip("::1") is False
    assert client.is_queryable_public_ip("invalid-ip") is False

    # Valid public IPs
    assert client.is_queryable_public_ip("8.8.8.8") is True
    assert client.is_queryable_public_ip("1.1.1.1") is True
    assert client.is_queryable_public_ip("93.184.216.34") is True


def test_offline_fallback_for_private_ip():
    res = lookup_ip_reputation("192.168.1.50")
    assert res["is_public"] is False
    assert res["source"] == "local_filter"
    assert "Private or internal" in res["note"]


def test_offline_mode_without_api_key():
    client = AbuseIPDBClient(api_key="")
    res = client.lookup("8.8.8.8")
    assert res["is_public"] is True
    assert res["source"] == "offline"
    assert res["reputation_score"] is None


def test_threat_intel_web_endpoint(tmp_path):
    db_file = tmp_path / "test_intel_web.db"
    init_db(db_file)
    app = create_app(db_path=db_file, test_config={"TESTING": True, "WTF_CSRF_ENABLED": False})

    with app.test_client() as client:
        res = client.get("/api/intel/lookup/192.168.1.1")
        assert res.status_code == 200
        data = res.get_json()
        assert data["is_public"] is False
        assert data["country_code"] == "LOCAL"
