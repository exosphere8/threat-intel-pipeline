"""Load stage: SQLite schema management and idempotent upserts."""
import sqlite3
from datetime import UTC, datetime

from threat_pipeline.models import ThreatIndicator

SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    malware TEXT NOT NULL,
    first_seen_utc TEXT NOT NULL,
    last_online TEXT,
    c2_status TEXT NOT NULL,
    first_ingested_at TEXT NOT NULL,
    last_updated_at TEXT NOT NULL,
    PRIMARY KEY (dst_ip, dst_port, malware)
);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    rows_fetched INTEGER,
    rows_inserted INTEGER,
    rows_updated INTEGER,
    rows_rejected INTEGER,
    status TEXT NOT NULL
);
"""


def get_connection(db_path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def upsert_indicators(conn: sqlite3.Connection, indicators: list[ThreatIndicator]) -> tuple[int, int]:
    """Insert new indicators, update existing ones. Returns (inserted, updated)."""
    now = datetime.now(UTC).isoformat()
    inserted = 0
    updated = 0

    for indicator in indicators:
        cursor = conn.execute(
            "SELECT 1 FROM indicators WHERE dst_ip = ? AND dst_port = ? AND malware = ?",
            (indicator.dst_ip, indicator.dst_port, indicator.malware),
        )
        exists = cursor.fetchone() is not None

        conn.execute(
            """
            INSERT INTO indicators (
                dst_ip, dst_port, malware, first_seen_utc, last_online,
                c2_status, first_ingested_at, last_updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (dst_ip, dst_port, malware) DO UPDATE SET
                last_online = excluded.last_online,
                c2_status = excluded.c2_status,
                last_updated_at = excluded.last_updated_at
            """,
            (
                indicator.dst_ip,
                indicator.dst_port,
                indicator.malware,
                indicator.first_seen_utc,
                indicator.last_online,
                indicator.c2_status,
                now,
                now,
            ),
        )
        if exists:
            updated += 1
        else:
            inserted += 1

    conn.commit()
    return inserted, updated


def log_run(
    conn: sqlite3.Connection,
    started_at: str,
    finished_at: str,
    rows_fetched: int,
    rows_inserted: int,
    rows_updated: int,
    rows_rejected: int,
    status: str,
) -> None:
    conn.execute(
        """
        INSERT INTO pipeline_runs (
            started_at, finished_at, rows_fetched, rows_inserted,
            rows_updated, rows_rejected, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (started_at, finished_at, rows_fetched, rows_inserted, rows_updated, rows_rejected, status),
    )
    conn.commit()
