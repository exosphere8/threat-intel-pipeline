"""Transform stage: parse raw CSV text into validated ThreatIndicator rows."""
import csv
import io
import ipaddress
from dataclasses import dataclass

from threat_pipeline.config import VALID_C2_STATUSES
from threat_pipeline.models import ThreatIndicator


@dataclass(frozen=True)
class RowError:
    row_number: int
    reason: str


@dataclass(frozen=True)
class TransformResult:
    indicators: list[ThreatIndicator]
    errors: list[RowError]


def _strip_comment_lines(raw_text: str) -> str:
    """The feed prefixes its file with '#' comment lines before the header."""
    lines = [line for line in raw_text.splitlines() if not line.startswith("#")]
    return "\n".join(lines)


def _validate_row(row: dict, row_number: int) -> tuple[ThreatIndicator | None, RowError | None]:
    dst_ip = row.get("dst_ip", "").strip()
    malware = row.get("malware", "").strip()
    c2_status = row.get("c2_status", "").strip()
    first_seen_utc = row.get("first_seen_utc", "").strip()
    last_online = row.get("last_online", "").strip()

    try:
        ipaddress.ip_address(dst_ip)
    except ValueError:
        return None, RowError(row_number, f"invalid dst_ip: {dst_ip!r}")

    try:
        dst_port = int(row.get("dst_port", "").strip())
    except ValueError:
        return None, RowError(row_number, f"invalid dst_port: {row.get('dst_port')!r}")
    if not (1 <= dst_port <= 65535):
        return None, RowError(row_number, f"dst_port out of range: {dst_port}")

    if c2_status not in VALID_C2_STATUSES:
        return None, RowError(row_number, f"unexpected c2_status: {c2_status!r}")

    if not malware:
        return None, RowError(row_number, "missing malware family")

    indicator = ThreatIndicator(
        dst_ip=dst_ip,
        dst_port=dst_port,
        malware=malware,
        first_seen_utc=first_seen_utc,
        last_online=last_online,
        c2_status=c2_status,
    )
    return indicator, None


def parse_feed(raw_text: str) -> TransformResult:
    """Parse and validate the feed, deduplicating on (dst_ip, dst_port, malware)."""
    cleaned = _strip_comment_lines(raw_text)
    reader = csv.DictReader(io.StringIO(cleaned))

    seen: dict[tuple[str, int, str], ThreatIndicator] = {}
    errors: list[RowError] = []

    for row_number, row in enumerate(reader, start=1):
        indicator, error = _validate_row(row, row_number)
        if error is not None:
            errors.append(error)
            continue
        key = (indicator.dst_ip, indicator.dst_port, indicator.malware)
        seen[key] = indicator

    return TransformResult(indicators=list(seen.values()), errors=errors)
