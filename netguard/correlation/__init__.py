"""
Alert deduplication and correlation module for NetGuard.
"""

from netguard.correlation.dedup import build_dedup_key, deduplicate_findings
from netguard.correlation.engine import (
    Incident,
    correlate_alerts,
    save_alerts_to_db,
    save_incidents_to_db,
)

__all__ = [
    "build_dedup_key",
    "deduplicate_findings",
    "Incident",
    "correlate_alerts",
    "save_alerts_to_db",
    "save_incidents_to_db",
]
