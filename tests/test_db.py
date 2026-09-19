import sqlite3

import pytest

from threat_pipeline import db
from threat_pipeline.models import ThreatIndicator


@pytest.fixture
def conn():
    connection = sqlite3.connect(":memory:")
    db.init_db(connection)
    yield connection
    connection.close()


def make_indicator(**overrides):
    defaults = {
        "dst_ip": "1.2.3.4",
        "dst_port": 443,
        "malware": "Emotet",
        "first_seen_utc": "2026-01-01 00:00:00",
        "last_online": "2026-01-01",
        "c2_status": "online",
    }
    defaults.update(overrides)
    return ThreatIndicator(**defaults)


def test_insert_new_indicator(conn):
    inserted, updated = db.upsert_indicators(conn, [make_indicator()])
    assert (inserted, updated) == (1, 0)
    row = conn.execute("SELECT dst_ip, c2_status FROM indicators").fetchone()
    assert row == ("1.2.3.4", "online")


def test_upsert_is_idempotent_on_rerun(conn):
    db.upsert_indicators(conn, [make_indicator()])
    inserted, updated = db.upsert_indicators(conn, [make_indicator()])
    assert (inserted, updated) == (0, 1)
    count = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    assert count == 1


def test_upsert_updates_changed_status(conn):
    db.upsert_indicators(conn, [make_indicator(c2_status="online")])
    db.upsert_indicators(conn, [make_indicator(c2_status="offline", last_online="2026-01-02")])
    row = conn.execute("SELECT c2_status, last_online FROM indicators").fetchone()
    assert row == ("offline", "2026-01-02")


def test_different_port_is_a_separate_row(conn):
    db.upsert_indicators(conn, [make_indicator(dst_port=443), make_indicator(dst_port=8080)])
    count = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    assert count == 2


def test_log_run_records_summary(conn):
    db.log_run(conn, "2026-01-01T00:00:00", "2026-01-01T00:00:05", 10, 8, 2, 0, status="success")
    row = conn.execute("SELECT status, rows_inserted FROM pipeline_runs").fetchone()
    assert row == ("success", 8)
