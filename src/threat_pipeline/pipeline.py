"""Orchestrates extract -> transform -> quality gate -> load."""
import argparse
import logging
import sys
from datetime import UTC, datetime

from threat_pipeline import db, quality
from threat_pipeline.config import DB_PATH, FEED_URL
from threat_pipeline.extract import FeedFetchError, fetch_feed
from threat_pipeline.transform import parse_feed

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class PipelineError(RuntimeError):
    """Raised when the pipeline cannot complete a run safely."""


def run(feed_url: str = FEED_URL, db_path=DB_PATH) -> dict:
    started_at = datetime.now(UTC).isoformat()
    conn = db.get_connection(db_path)
    db.init_db(conn)

    try:
        logger.info("Extracting feed from %s", feed_url)
        raw_text = fetch_feed(feed_url)

        logger.info("Transforming and validating rows")
        result = parse_feed(raw_text)
        logger.info("Parsed %d valid rows, %d rejected", len(result.indicators), len(result.errors))
        for error in result.errors[:10]:
            logger.warning("Row %d rejected: %s", error.row_number, error.reason)

        report = quality.check(result)
        if not report.passed:
            for reason in report.reasons:
                logger.error("Quality check failed: %s", reason)
            finished_at = datetime.now(UTC).isoformat()
            db.log_run(
                conn, started_at, finished_at, len(result.indicators) + len(result.errors),
                0, 0, len(result.errors), status="quality_gate_failed",
            )
            raise PipelineError("data quality gate failed: " + "; ".join(report.reasons))

        logger.info("Loading into %s", db_path)
        inserted, updated = db.upsert_indicators(conn, result.indicators)
        logger.info("Inserted %d new, updated %d existing indicators", inserted, updated)

        finished_at = datetime.now(UTC).isoformat()
        db.log_run(
            conn, started_at, finished_at, len(result.indicators) + len(result.errors),
            inserted, updated, len(result.errors), status="success",
        )

        return {
            "rows_fetched": len(result.indicators) + len(result.errors),
            "rows_inserted": inserted,
            "rows_updated": updated,
            "rows_rejected": len(result.errors),
        }
    except FeedFetchError as exc:
        finished_at = datetime.now(UTC).isoformat()
        db.log_run(conn, started_at, finished_at, 0, 0, 0, 0, status="fetch_failed")
        raise PipelineError(str(exc)) from exc
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the threat intel ETL pipeline")
    parser.add_argument("--feed-url", default=FEED_URL)
    parser.add_argument("--db-path", default=str(DB_PATH))
    args = parser.parse_args()

    from pathlib import Path

    try:
        summary = run(feed_url=args.feed_url, db_path=Path(args.db_path))
    except PipelineError as exc:
        logger.error("Pipeline run failed: %s", exc)
        return 1

    logger.info("Pipeline run complete: %s", summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
