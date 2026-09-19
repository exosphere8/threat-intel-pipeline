import sqlite3

import pytest

from threat_pipeline import db, report
from threat_pipeline.models import ThreatIndicator


@pytest.fixture
def conn():
    connection = sqlite3.connect(":memory:")
    db.init_db(connection)
    yield connection
    connection.close()


def test_report_includes_totals_and_malware_breakdown(conn):
    db.upsert_indicators(
        conn,
        [
            ThreatIndicator("1.2.3.4", 443, "Emotet", "2026-01-01", "2026-01-01", "online"),
            ThreatIndicator("5.6.7.8", 8080, "QakBot", "2026-01-01", "2026-01-01", "offline"),
        ],
    )
    text = report.build_report(conn)
    assert "Total tracked indicators:** 2" in text
    assert "Currently online:** 1" in text
    assert "Emotet" in text
    assert "QakBot" in text


def test_report_handles_empty_db(conn):
    text = report.build_report(conn)
    assert "Total tracked indicators:** 0" in text
