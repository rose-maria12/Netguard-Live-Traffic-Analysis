#!/usr/bin/env python
"""
NetGuard — Network Intrusion Detection & Forensic Correlation Platform
Convenient Root Application Launcher
"""
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from netguard.web.app import create_app

if __name__ == "__main__":
    print("=" * 70)
    print("  NETGUARD — Security Operations Center & Intrusion Prevention")
    print("  Access Web Dashboard at: http://127.0.0.1:5000")
    print("=" * 70)
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)

