from unittest.mock import patch

import pytest

from threat_pipeline import pipeline
from threat_pipeline.extract import FeedFetchError

VALID_FEED = (
    '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\n'
    '"2026-01-01 00:00:00","1.2.3.4","443","online","2026-01-01","Emotet"\n'
    '"2026-01-01 00:00:00","5.6.7.8","8080","offline","2026-01-01","QakBot"\n'
)


@patch("threat_pipeline.pipeline.fetch_feed")
def test_run_end_to_end_inserts_rows(mock_fetch, tmp_path):
    mock_fetch.return_value = VALID_FEED
    db_path = tmp_path / "test.db"

    summary = pipeline.run(db_path=db_path)

    assert summary["rows_inserted"] == 2
    assert summary["rows_updated"] == 0
    assert db_path.exists()


@patch("threat_pipeline.pipeline.fetch_feed")
def test_run_twice_is_idempotent(mock_fetch, tmp_path):
    mock_fetch.return_value = VALID_FEED
    db_path = tmp_path / "test.db"

    pipeline.run(db_path=db_path)
    summary = pipeline.run(db_path=db_path)

    assert summary["rows_inserted"] == 0
    assert summary["rows_updated"] == 2


@patch("threat_pipeline.pipeline.fetch_feed")
def test_run_raises_pipeline_error_on_fetch_failure(mock_fetch, tmp_path):
    mock_fetch.side_effect = FeedFetchError("upstream is down")
    db_path = tmp_path / "test.db"

    with pytest.raises(pipeline.PipelineError, match="upstream is down"):
        pipeline.run(db_path=db_path)


@patch("threat_pipeline.pipeline.fetch_feed")
def test_run_raises_on_empty_feed(mock_fetch, tmp_path):
    mock_fetch.return_value = '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\n'
    db_path = tmp_path / "test.db"

    with pytest.raises(pipeline.PipelineError, match="quality gate failed"):
        pipeline.run(db_path=db_path)
