"""Generate a human-readable Markdown summary of the current indicator set.

Run after the pipeline so CI/scheduled runs can commit a fresh, diffable
snapshot back to the repo instead of a binary SQLite file.
"""
import argparse
from datetime import UTC, datetime
from pathlib import Path

from threat_pipeline import db
from threat_pipeline.config import DB_PATH

REPORT_PATH = Path(__file__).resolve().parents[2] / "docs" / "latest_report.md"


def build_report(conn) -> str:
    total = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    online = conn.execute(
        "SELECT COUNT(*) FROM indicators WHERE c2_status = 'online'"
    ).fetchone()[0]

    by_malware = conn.execute(
        "SELECT malware, COUNT(*) AS n FROM indicators GROUP BY malware ORDER BY n DESC LIMIT 10"
    ).fetchall()

    last_run = conn.execute(
        "SELECT started_at, status, rows_inserted, rows_updated, rows_rejected "
        "FROM pipeline_runs ORDER BY run_id DESC LIMIT 1"
    ).fetchone()

    lines = [
        "# Threat Intel Snapshot",
        "",
        f"_Generated {datetime.now(UTC).isoformat()}_",
        "",
        f"- **Total tracked indicators:** {total}",
        f"- **Currently online:** {online}",
    ]

    if last_run:
        started_at, status, inserted, updated, rejected = last_run
        lines.append(
            f"- **Last run:** {started_at} - status `{status}`, "
            f"{inserted} inserted, {updated} updated, {rejected} rejected"
        )

    lines += ["", "## Top malware families", "", "| Malware | Indicators |", "|---|---|"]
    for malware, count in by_malware:
        lines.append(f"| {malware} | {count} |")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the latest threat intel report")
    parser.add_argument("--db-path", default=str(DB_PATH))
    parser.add_argument("--out", default=str(REPORT_PATH))
    args = parser.parse_args()

    conn = db.get_connection(Path(args.db_path))
    try:
        report_text = build_report(conn)
    finally:
        conn.close()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report_text, encoding="utf-8")
    print(f"Wrote report to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
