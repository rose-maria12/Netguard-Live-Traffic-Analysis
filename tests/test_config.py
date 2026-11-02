import pytest
from netguard.config import get_config_snapshot, load_config, validate_config


def test_load_default_config():
    config = load_config()
    assert "general" in config
    assert config["general"]["window_seconds"] == 20
    assert config["general"]["seed"] == 42


def test_validate_config_missing_section():
    config = load_config()
    del config["detectors"]
    with pytest.raises(ValueError, match="Missing required configuration section"):
        validate_config(config)


def test_validate_config_bad_weights():
    config = load_config()
    config["scoring"]["weights"]["strongest_alert"] = 50
    with pytest.raises(ValueError, match="Scoring weights must sum to 100"):
        validate_config(config)


def test_config_snapshot_hash():
    config = load_config()
    json_str, sha256_hash = get_config_snapshot(config)
    assert isinstance(json_str, str)
    assert len(sha256_hash) == 64
