"""Data-quality gate: sanity checks applied after transform, before load."""
from dataclasses import dataclass

from threat_pipeline.transform import TransformResult

# If more than this fraction of rows fail validation, something upstream
# changed shape (e.g. the feed's schema changed) — treat it as a hard failure
# rather than silently loading a mostly-empty batch.
MAX_REJECTED_FRACTION = 0.20


@dataclass(frozen=True)
class QualityReport:
    passed: bool
    reasons: list[str]


def check(result: TransformResult) -> QualityReport:
    reasons = []

    total_rows = len(result.indicators) + len(result.errors)
    if total_rows == 0:
        reasons.append("feed produced zero rows (expected at least one)")

    if total_rows > 0:
        rejected_fraction = len(result.errors) / total_rows
        if rejected_fraction > MAX_REJECTED_FRACTION:
            reasons.append(
                f"{rejected_fraction:.0%} of rows failed validation "
                f"(threshold {MAX_REJECTED_FRACTION:.0%}) — feed format may have changed"
            )

    keys = [(i.dst_ip, i.dst_port, i.malware) for i in result.indicators]
    if len(keys) != len(set(keys)):
        reasons.append("duplicate (dst_ip, dst_port, malware) keys survived transform")

    return QualityReport(passed=not reasons, reasons=reasons)
