import sqlite3
from pathlib import Path
from typing import Union

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "netguard.db"


def get_db(db_path: Union[str, Path] = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """
    Get a database connection with PRAGMA foreign_keys = ON and Row factory.
    Creates parent directories if missing.
    """
    path = Path(db_path)
    if str(db_path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Union[str, Path] = DEFAULT_DB_PATH) -> None:
    """
    Initialize database schema from schema.sql.
    """
    with get_db(db_path) as conn:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema_script = f.read()
        conn.executescript(schema_script)
        conn.commit()


def get_table_names(db_path: Union[str, Path] = DEFAULT_DB_PATH) -> list[str]:
    """
    Utility function to list all user table names in the database.
    """
    with get_db(db_path) as conn:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
        )
        return [row["name"] for row in cursor.fetchall()]
