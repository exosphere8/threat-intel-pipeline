from unittest.mock import Mock, patch

import pytest
import requests

from threat_pipeline.extract import FeedFetchError, fetch_feed


@patch("threat_pipeline.extract.requests.get")
def test_fetch_feed_returns_text_on_success(mock_get):
    mock_get.return_value = Mock(status_code=200, text="csv,data")
    assert fetch_feed("https://example.test/feed.csv") == "csv,data"


@patch("threat_pipeline.extract.requests.get")
def test_fetch_feed_raises_on_non_200(mock_get):
    mock_get.return_value = Mock(status_code=503, text="")
    with pytest.raises(FeedFetchError, match="503"):
        fetch_feed("https://example.test/feed.csv")


@patch("threat_pipeline.extract.requests.get")
def test_fetch_feed_raises_on_network_error(mock_get):
    mock_get.side_effect = requests.ConnectionError("boom")
    with pytest.raises(FeedFetchError, match="could not reach feed"):
        fetch_feed("https://example.test/feed.csv")
