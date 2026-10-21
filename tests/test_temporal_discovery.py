"""Offline, deterministic time-aware origin-discovery regression coverage."""
import os
import sys
from datetime import datetime, timezone

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "cfunveil"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from core.evidence import classify_target_evidence, parse_observation_time
from core.cert_intel import CertIntelligence
from discovery_temporal_lab import run_benchmark
from rich.console import Console


def test_strict_full_dates_and_epoch_timestamps():
    assert parse_observation_time("2026") is None
    assert parse_observation_time("2026-10") is None
    assert parse_observation_time("not-a-date") is None
    assert parse_observation_time("") is None
    assert parse_observation_time("0") is None
    assert parse_observation_time("2026-10-21") == datetime(2026, 10, 21, tzinfo=timezone.utc)
    assert parse_observation_time("2026-10-20T10:05:00Z").isoformat() == "2026-10-20T10:05:00+00:00"
    assert parse_observation_time("1720000000") == datetime.fromtimestamp(1720000000, timezone.utc)


def test_latest_observation_date_dominates_old_ones():
    now = datetime(2026, 10, 21, tzinfo=timezone.utc)
    evidence = classify_target_evidence("api.fixture.example", [
        {"domain": "api.fixture.example", "last_seen": "2020-01-01"},
        {"domain": "api.fixture.example", "last_seen": "2026-10-18"},
        {"domain": "not-api.fixture.example", "record_type": "A"},
    ], as_of=now)
    assert evidence["evidence_status"] == "historical_recent"
    assert evidence["evidence_last_seen"].startswith("2026-10-18")


def test_future_and_partial_times_cannot_be_fresh_evidence():
    now = datetime(2026, 10, 21, tzinfo=timezone.utc)
    evidence = classify_target_evidence("api.fixture.example", [
        {"domain": "api.fixture.example", "last_seen": "2099-12-31"},
        {"domain": "api.fixture.example", "last_seen": "2026"},
    ], as_of=now)
    assert evidence["evidence_status"] == "historical_undated"


def test_current_dns_not_conflated_with_old_historical_observation():
    now = datetime(2026, 10, 21, tzinfo=timezone.utc)
    evidence = classify_target_evidence("api.fixture.example", [
        {"domain": "api.fixture.example", "last_seen": "2021-01-01"},
        {"domain": "api.fixture.example", "record_type": "A"},
    ], as_of=now)
    assert evidence["evidence_status"] == "current_dns_observed"


def test_wildcard_certificate_never_implies_its_own_suffix():
    cert = CertIntelligence(
        "fixture.example", {}, Console(quiet=True), None,
        target="api.fixture.example",
    )
    assert cert._matched_cert_hostname("*.api.fixture.example") is None
    assert cert._matched_cert_hostname("internal.fixture.example") is None
    assert cert._matched_cert_hostname("*.fixture.example") == "api.fixture.example"
    assert cert._matched_cert_hostname("API.FIXTURE.EXAMPLE.") == "api.fixture.example"

    filtered = CertIntelligence(
        "fixture.example", {"no_wildcards": True}, Console(quiet=True), None,
        target="api.fixture.example",
    )
    assert filtered._matched_cert_hostname("*.fixture.example") is None


@pytest.mark.asyncio
async def test_offline_temporal_discovery_benchmark_acceptance():
    report = await run_benchmark()
    assert report["benchmark"] == "offline_temporal_discovery_replay"
    assert report["checks"]
    assert all(report["checks"].values()), report["checks"]
    cases = report["scenarios"]
    assert "54.20.40.11" in cases["moved_origin"]["candidate_states"]
    assert "54.20.40.11" not in cases["moved_origin"]["target_cdn_edges"]
    assert not cases["misleading_sibling_and_certificate"]["candidate_states"]
