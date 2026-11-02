import json
import hashlib
from pathlib import Path
from typing import Any, Dict, Tuple

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "default_config.json"


def load_config(config_path: Path | str | None = None) -> Dict[str, Any]:
    """
    Load JSON configuration file. If path is None, default_config.json is loaded.
    Returns a Python dict.
    """
    if config_path is None:
        target_path = DEFAULT_CONFIG_PATH
    else:
        target_path = Path(config_path)

    if not target_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {target_path}")

    with open(target_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    validate_config(config)
    return config


def validate_config(config: Dict[str, Any]) -> None:
    """
    Validate required configuration sections and scoring weights constraint.
    Raises ValueError on validation failure.
    """
    required_sections = [
        "general",
        "networks",
        "infrastructure",
        "allowlist",
        "detectors",
        "ml",
        "correlation",
        "scoring",
    ]
    for section in required_sections:
        if section not in config:
            raise ValueError(f"Missing required configuration section: {section}")

    # Validate scoring weights sum to 100
    weights = config.get("scoring", {}).get("weights", {})
    total_weight = sum(weights.values())
    if abs(total_weight - 100) > 1e-6:
        raise ValueError(f"Scoring weights must sum to 100, got {total_weight}")


def get_config_snapshot(config: Dict[str, Any]) -> Tuple[str, str]:
    """
    Produce a deterministic JSON snapshot string and its SHA-256 hash.
    Returns (config_json, config_sha256).
    """
    config_json = json.dumps(config, sort_keys=True)
    config_sha256 = hashlib.sha256(config_json.encode("utf-8")).hexdigest()
    return config_json, config_sha256
