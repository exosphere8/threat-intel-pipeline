"""Extract stage: fetch the raw threat feed over HTTP."""
import requests

from threat_pipeline.config import FEED_REQUEST_TIMEOUT_SECONDS, FEED_URL


class FeedFetchError(RuntimeError):
    """Raised when the upstream feed cannot be retrieved."""


def fetch_feed(url: str = FEED_URL) -> str:
    """Download the raw CSV feed and return it as text.

    Raises FeedFetchError on any network failure or non-200 response so
    callers can distinguish "no threats today" from "the pipeline broke".
    """
    try:
        response = requests.get(url, timeout=FEED_REQUEST_TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        raise FeedFetchError(f"could not reach feed at {url}: {exc}") from exc

    if response.status_code != 200:
        raise FeedFetchError(
            f"feed at {url} returned HTTP {response.status_code}"
        )

    return response.text
