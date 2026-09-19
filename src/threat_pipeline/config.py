"""Central configuration for the pipeline."""
from pathlib import Path

FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
FEED_REQUEST_TIMEOUT_SECONDS = 15

REPO_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = REPO_ROOT / "data" / "threat_intel.db"

VALID_C2_STATUSES = {"online", "offline"}
