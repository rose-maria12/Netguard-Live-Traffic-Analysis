"""
Reporting module for NetGuard.
"""

from netguard.reports.html_report import generate_html_report
from netguard.reports.json_report import export_run_json

__all__ = [
    "generate_html_report",
    "export_run_json",
]
