from pathlib import Path
import sqlite3
import pytest
from netguard.db import get_db, get_table_names, init_db


def test_init_db_in_memory():
    conn = get_db(":memory:")
    # Initialize schema
    schema_path = Path(__file__).resolve().parent.parent / "netguard" / "schema.sql"
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
    )
    tables = [row["name"] for row in cursor.fetchall()]

    expected_tables = [
        "alert_evidence",
        "alerts",
        "captures",
        "dns_events",
        "feature_windows",
        "flows",
        "incident_alerts",
        "incidents",
        "models",
        "packets",
        "runs",
    ]
    for table in expected_tables:
        assert table in tables


def test_foreign_keys_enabled():
    conn = get_db(":memory:")
    cursor = conn.execute("PRAGMA foreign_keys;")
    row = cursor.fetchone()
    assert row[0] == 1
