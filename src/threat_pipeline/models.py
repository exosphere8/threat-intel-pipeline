"""Data model for a single threat indicator record."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatIndicator:
    dst_ip: str
    dst_port: int
    malware: str
    first_seen_utc: str
    last_online: str
    c2_status: str
