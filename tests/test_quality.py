from threat_pipeline import quality
from threat_pipeline.models import ThreatIndicator
from threat_pipeline.transform import RowError, TransformResult


def make_indicator(ip="1.2.3.4", port=443, malware="Emotet"):
    return ThreatIndicator(
        dst_ip=ip, dst_port=port, malware=malware,
        first_seen_utc="2026-01-01 00:00:00", last_online="2026-01-01", c2_status="online",
    )


def test_passes_with_clean_batch():
    result = TransformResult(indicators=[make_indicator()], errors=[])
    report = quality.check(result)
    assert report.passed


def test_fails_on_zero_rows():
    result = TransformResult(indicators=[], errors=[])
    report = quality.check(result)
    assert not report.passed
    assert any("zero rows" in r for r in report.reasons)


def test_fails_when_rejection_rate_too_high():
    indicators = [make_indicator(port=443)]
    errors = [RowError(row_number=i, reason="bad row") for i in range(10)]
    result = TransformResult(indicators=indicators, errors=errors)
    report = quality.check(result)
    assert not report.passed
    assert any("failed validation" in r for r in report.reasons)


def test_passes_with_low_rejection_rate():
    indicators = [make_indicator(port=p) for p in range(443, 443 + 19)]
    errors = [RowError(row_number=1, reason="bad row")]
    result = TransformResult(indicators=indicators, errors=errors)
    report = quality.check(result)
    assert report.passed
