"""Regression coverage for trust boundaries in direct-IP origin verification."""
import os
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest
from rich.console import Console

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "cfunveil"))

from core.headers_probe import HeadersProbe, is_public_ip
from core.validator import OriginValidator


def response(*, ip="8.8.8.8", tls=True, status=200, hash_value="sha",
             cloudflare=False, size=400, redirect=None):
    return {
        "ip": ip, "connected_ip": ip, "peer_verified": True,
        "status": status, "scheme": "https" if tls else "http",
        "tls_verified": tls, "is_cloudflare": cloudflare,
        "server": "nginx", "body_complete": True,
        "body_length": size, "body_hash": hash_value,
        "location": redirect,
    }


@pytest.fixture
def validator():
    obj = OriginValidator(
        "example.com", "example.com", Console(), MagicMock(),
        authorized_cidrs=["8.8.8.8/32"],
    )
    obj.probe = MagicMock(spec=HeadersProbe)
    obj.probe.probe = AsyncMock(return_value=response())
    obj.probe.baseline = AsyncMock(return_value=response(ip=None))
    obj.baseline = response(ip=None)
    return obj


@pytest.mark.asyncio
async def test_verified_exact_application_match(validator):
    result = await validator.validate_ip("8.8.8.8", {"sources": ["Historical-DNS"]})
    assert result["confirmed"] is True
    assert result["application_match"] is True
    assert result["verification_status"] == "verified_direct_application"
    assert 0.8 <= result["confidence"] <= 1.0


@pytest.mark.asyncio
async def test_out_of_scope_is_never_probed(validator):
    result = await validator.validate_ip("9.9.9.9", {"sources": ["Historical-DNS"]})
    assert result["verification_status"] == "out_of_scope"
    assert result["confirmed"] is False
    validator.probe.probe.assert_not_awaited()


@pytest.mark.asyncio
async def test_private_addresses_are_rejected(validator):
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("169.254.169.254") is False
    result = await validator.validate_ip("127.0.0.1", {})
    assert result["verification_status"] == "non_public_address"
    validator.probe.probe.assert_not_awaited()


@pytest.mark.asyncio
async def test_redirect_only_is_never_confirmed(validator):
    validator.probe.probe.return_value = response(status=302, redirect="https://example.com/")
    result = await validator.validate_ip("8.8.8.8", {"sources": ["DNS"]})
    assert result["verification_status"] == "redirect_only"
    assert result["confirmed"] is False
    assert "Redirect" in result["warnings"][0]


@pytest.mark.asyncio
async def test_cdn_response_not_origin(validator):
    validator.probe.probe.return_value = response(cloudflare=True)
    result = await validator.validate_ip("8.8.8.8", {})
    assert result["verification_status"] == "cdn_or_proxy"
    assert result["confirmed"] is False


@pytest.mark.asyncio
async def test_unverified_peer_cannot_confirm(validator):
    direct = response()
    direct["peer_verified"] = False
    validator.probe.probe.return_value = direct
    result = await validator.validate_ip("8.8.8.8", {})
    assert result["verification_status"] == "inconclusive"
    assert result["confirmed"] is False


@pytest.mark.asyncio
async def test_http_only_exact_body_is_not_proof(validator):
    validator.probe.probe.return_value = response(tls=False)
    result = await validator.validate_ip("8.8.8.8", {})
    assert result["application_match"] is True
    assert result["confirmed"] is False


@pytest.mark.asyncio
async def test_generic_or_dynamic_page_not_confirmed(validator):
    validator.probe.probe.return_value = response(hash_value="different")
    result = await validator.validate_ip("8.8.8.8", {"sources": ["DNS", "Historical-DNS", "Shodan"]})
    assert result["confirmed"] is False
    assert result["verification_status"] == "related_service"

    validator.probe.probe.return_value = response(size=20)
    validator.baseline = response(ip=None, size=20)
    result = await validator.validate_ip("8.8.8.8", {})
    assert result["confirmed"] is False


@pytest.mark.asyncio
async def test_no_baseline_is_not_proof(validator):
    validator.baseline = None
    result = await validator.validate_ip("8.8.8.8", {})
    assert result["confirmed"] is False
    assert result["verification_status"] == "related_service"


@pytest.mark.asyncio
async def test_no_allowlist_disables_all_direct_validation():
    val = OriginValidator("example.com", "example.com", Console(), MagicMock())
    val.probe = MagicMock(spec=HeadersProbe)
    val.probe.probe = AsyncMock()
    val.probe.baseline = AsyncMock()
    results = await val.validate_all({"8.8.8.8": {"sources": ["DNS"]}})
    assert results["8.8.8.8"]["verification_status"] == "out_of_scope"
    val.probe.probe.assert_not_awaited()
    val.probe.baseline.assert_not_awaited()


@pytest.mark.asyncio
async def test_probe_disables_redirect_and_sets_sni():
    p = HeadersProbe("example.com", Console(), MagicMock())
    direct = response()
    direct["connected_ip"] = "8.8.8.8"
    p._request = AsyncMock(return_value=direct)
    data = await p.probe("8.8.8.8", "example.com")
    assert data["peer_verified"] is True
    kwargs = p._request.await_args.kwargs
    assert kwargs["host"] == "example.com"
    assert kwargs["sni"] == "example.com"


@pytest.mark.asyncio
async def test_probe_no_nonstandard_ports_or_private_targets():
    p = HeadersProbe("example.com", Console(), MagicMock())
    p._request = AsyncMock()
    assert await p.probe("127.0.0.1") is None
    assert await p.probe("8.8.8.8", port=8080) is None
    p._request.assert_not_awaited()


@pytest.mark.asyncio
async def test_probe_http_fallback_unverified_tls():
    p = HeadersProbe("example.com", Console(), MagicMock())
    direct = response(tls=False)
    p._request = AsyncMock(side_effect=[None, direct])
    result = await p.probe("8.8.8.8")
    assert result["scheme"] == "http"
    assert result["tls_verified"] is False
    assert p._request.await_count == 2


@pytest.mark.asyncio
async def test_allowlisted_baseline_taken_once(validator):
    validator.baseline = None
    data = await validator.validate_all({
        "8.8.8.8": {"sources": ["DNS"]},
        "9.9.9.9": {"sources": ["DNS"]},
    })
    validator.probe.baseline.assert_awaited_once_with("example.com")
    assert data["8.8.8.8"]["confirmed"] is True
    assert data["9.9.9.9"]["verification_status"] == "out_of_scope"
