from pathlib import Path

from threat_pipeline.transform import parse_feed

FIXTURE = (Path(__file__).parent / "fixtures" / "sample_feed.csv").read_text()


def test_parses_valid_rows():
    result = parse_feed(FIXTURE)
    assert len(result.indicators) == 2
    ips = {i.dst_ip for i in result.indicators}
    assert ips == {"162.243.103.246", "50.16.16.211"}


def test_rejects_invalid_ip():
    result = parse_feed(FIXTURE)
    reasons = [e.reason for e in result.errors]
    assert any("invalid dst_ip" in r for r in reasons)


def test_rejects_invalid_port():
    result = parse_feed(FIXTURE)
    reasons = [e.reason for e in result.errors]
    assert any("invalid dst_port" in r for r in reasons)


def test_rejects_unknown_status():
    result = parse_feed(FIXTURE)
    reasons = [e.reason for e in result.errors]
    assert any("unexpected c2_status" in r for r in reasons)


def test_deduplicates_on_ip_port_malware():
    raw = (
        '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\n'
        '"2026-01-01 00:00:00","1.2.3.4","443","online","2026-01-01","Emotet"\n'
        '"2026-01-02 00:00:00","1.2.3.4","443","offline","2026-01-02","Emotet"\n'
    )
    result = parse_feed(raw)
    assert len(result.indicators) == 1
    assert result.indicators[0].c2_status == "offline"


def test_empty_feed_produces_no_rows():
    result = parse_feed('"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\n')
    assert result.indicators == []
    assert result.errors == []
