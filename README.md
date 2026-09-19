# Threat Intel Pipeline

[![CI](https://github.com/exosphere8/threat-intel-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/exosphere8/threat-intel-pipeline/actions/workflows/ci.yml)
[![Scheduled pipeline](https://github.com/exosphere8/threat-intel-pipeline/actions/workflows/pipeline.yml/badge.svg)](https://github.com/exosphere8/threat-intel-pipeline/actions/workflows/pipeline.yml)

A small, production-shaped ETL pipeline that ingests a public malware
command-and-control (C2) IP blocklist, validates and normalizes it, and
loads it into a queryable database on a daily schedule.

It exists to show the mechanics of a real data pipeline — extract,
transform, validate, load, orchestrate, observe — applied to a security
data source, rather than a one-off analysis notebook.

## Why this data source

The feed is [abuse.ch's Feodo Tracker](https://feodotracker.abuse.ch/),
a public, actively-maintained blocklist of IP addresses used as C2
infrastructure by banking trojans and botnets (Emotet, QakBot, etc.).
It's free, requires no API key, and is explicitly published for
defensive/blocklisting use — a legitimate, non-destructive dataset that's
still genuinely security-relevant.

## Architecture

```
   abuse.ch Feodo         extract.py         transform.py          quality.py
   Tracker feed    ─────▶ fetch_feed()  ────▶ parse_feed()   ────▶ check()
   (CSV over HTTP)         raises on           validates IP/port/    rejects the
                           network/HTTP         status, dedupes       whole batch if
                           failure               on (ip, port,        the feed's shape
                                                  malware)             looks broken
                                                                          │
                                                                          ▼
   docs/latest_report.md ◀──────────── report.py            db.py: upsert_indicators()
   (committed each run)     build_report()                  SQLite, idempotent,
                                                              tracks every run in
                                                              pipeline_runs table
```

`pipeline.py` orchestrates all of the above and is the single entry point
(`python -m threat_pipeline.pipeline`). Every run — success or failure —
is recorded in the `pipeline_runs` table, so the pipeline's own history
is queryable, not just its output.

**Why a quality gate before load:** if the upstream feed changes shape
(column renamed, format changed) it's better to fail loudly than to
silently load garbage or wipe out a previously-healthy dataset with an
empty one. `quality.check()` rejects the batch if it's empty or if more
than 20% of rows fail validation.

**Why SQLite, not Postgres:** this runs unattended in GitHub Actions with
no infrastructure to manage. The schema (`db.py`) and upsert logic don't
assume anything SQLite-specific beyond `ON CONFLICT` — swapping in
Postgres later is a driver change, not a rewrite.

## Running it

```bash
pip install -r requirements-dev.txt
PYTHONPATH=src python -m threat_pipeline.pipeline
PYTHONPATH=src python -m threat_pipeline.report
```

Run the tests:

```bash
pytest -v
ruff check src tests
```

## Automation

- **`ci.yml`** — runs the test suite and linter on every push/PR, across
  Python 3.11 and 3.12.
- **`pipeline.yml`** — runs the pipeline itself daily, persists the
  SQLite database between runs via GitHub Actions cache (so upserts are
  meaningful run-to-run), and commits a fresh
  [`docs/latest_report.md`](docs/latest_report.md) back to the repo —
  a diffable, human-readable snapshot instead of a binary database dump.

## Project layout

```
src/threat_pipeline/
  extract.py    - HTTP fetch, raises FeedFetchError on failure
  transform.py  - CSV parsing, per-row validation, dedup
  quality.py    - batch-level sanity gate before load
  db.py         - SQLite schema, idempotent upsert, run logging
  report.py     - Markdown summary generation
  pipeline.py   - orchestration + CLI entry point
tests/          - 24 tests, no network calls (HTTP is mocked)
```
