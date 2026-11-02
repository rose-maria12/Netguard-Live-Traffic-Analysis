"""
Detection module for NetGuard.
"""

from netguard.detection.base import Finding
from netguard.detection.allowlist import AllowList
from netguard.detection.port_scan import detect_port_scan
from netguard.detection.brute_force import detect_brute_force
from netguard.detection.dns_anomaly import detect_dns_anomaly
from netguard.detection.outbound import detect_abnormal_outbound
from netguard.detection.iforest import (
    train_baseline_model,
    load_model_bundle,
    score_windows_with_model,
)

__all__ = [
    "Finding",
    "AllowList",
    "detect_port_scan",
    "detect_brute_force",
    "detect_dns_anomaly",
    "detect_abnormal_outbound",
    "train_baseline_model",
    "load_model_bundle",
    "score_windows_with_model",
]
