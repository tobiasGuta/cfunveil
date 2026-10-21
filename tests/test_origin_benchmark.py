"""Acceptance tests for a real, in-process HTTPS origin-discovery lab."""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "cfunveil"))
sys.path.insert(0, str(ROOT / "tests"))

from origin_lab import (
    ORIGIN_IP, DECOY_IP, PROXY_IP, REDIRECT_IP, UNREACHABLE_IP,
    OUT_OF_SCOPE_IP, run_benchmark,
)


@pytest.mark.asyncio
async def test_loopback_tls_benchmark_known_origin_and_negative_controls():
    report = await run_benchmark()
    discovery = report["discovery"]
    verification = report["verification"]
    cases = verification["classification"]

    assert report["target"] == "api.lab.test"
    assert discovery["known_origin_seeded"] is True
    assert discovery["seeded_origin_recall"] == 1
    assert discovery["known_origin_absent_without_evidence"] is True
    assert discovery["hidden_origin_recall"] == 0
    assert discovery["related_hostname_not_a_candidate"] is True

    assert verification["baseline_https_valid"] is True
    assert verification["true_positives"] == 1
    assert verification["false_positives"] == 0
    assert verification["no_out_of_scope_probe"] is True
    assert verification["no_redirect_following"] is True

    assert cases[ORIGIN_IP]["status"] == "verified_direct_application"
    assert cases[ORIGIN_IP]["confirmed"] is True
    assert cases[ORIGIN_IP]["tls_verified"] is True
    assert cases[DECOY_IP]["status"] == "related_service"
    assert cases[DECOY_IP]["confirmed"] is False
    assert cases[PROXY_IP]["status"] == "cdn_or_proxy"
    assert cases[PROXY_IP]["confirmed"] is False
    assert cases[REDIRECT_IP]["status"] == "redirect_only"
    assert cases[REDIRECT_IP]["confirmed"] is False
    assert cases[UNREACHABLE_IP]["status"] == "unreachable"
    assert cases[UNREACHABLE_IP]["confirmed"] is False
    assert cases[OUT_OF_SCOPE_IP]["status"] == "non_public_address"
    assert cases[OUT_OF_SCOPE_IP]["confirmed"] is False


@pytest.mark.asyncio
async def test_production_guards_still_reject_benchmark_loopback_addresses():
    from unittest.mock import MagicMock, AsyncMock
    from rich.console import Console
    from core.headers_probe import HeadersProbe
    from core.validator import OriginValidator

    normal = OriginValidator(
        "api.lab.test", "lab.test", Console(quiet=True), MagicMock(),
        authorized_cidrs=["127.0.0.0/24"],
    )
    normal.probe = MagicMock(spec=HeadersProbe)
    normal.probe.probe = AsyncMock()
    normal.probe.baseline = AsyncMock()
    data = await normal.validate_all({ORIGIN_IP: {"sources": ["DNS"]}})
    assert data[ORIGIN_IP]["verification_status"] == "non_public_address"
    normal.probe.probe.assert_not_awaited()
    normal.probe.baseline.assert_not_awaited()
