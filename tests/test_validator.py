import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import asyncio
from rich.console import Console

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PKG_DIR = os.path.join(ROOT, "cfunveil")
if PKG_DIR not in sys.path:
    sys.path.insert(0, PKG_DIR)

from core.validator import OriginValidator
from core.headers_probe import HeadersProbe

@pytest.fixture
def validator():
    console = Console()
    session = AsyncMock()
    val = OriginValidator("target.com", "target.com", console, session)
    val.probe = AsyncMock(spec=HeadersProbe)
    val.baseline = {}
    return val

@pytest.mark.asyncio
async def test_scoring_cloudflare_proxy(validator):
    """Scenario: Known CDN-fronted domain (should NOT resolve as origin)"""
    validator.probe.probe.return_value = {
        "status": 200,
        "server": "cloudflare",
        "headers": {"cf-ray": "xyz"},
        "is_cloudflare": True,
        "all_headers": {"cf-ray": "xyz"},
        "redirect_chain": []
    }
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={443: ["target.com"]})
    validator._reverse_dns = AsyncMock(return_value="")
    validator._grab_banners = AsyncMock(return_value={})
    
    with patch("socket.socket") as mock_socket:
        # Mock port 80 raw probe timeout
        mock_socket.return_value.recv.side_effect = asyncio.TimeoutError()
        result = await validator.validate_ip("1.1.1.1", {})
        
    assert result["confirmed"] is False
    assert result["confidence"] <= 0.01
    assert "CloudFlare headers detected" in str(result["warnings"])

@pytest.mark.asyncio
async def test_scoring_direct_origin(validator):
    """Scenario: Known direct-origin services (should resolve correctly)"""
    validator.probe.probe.return_value = {
        "status": 200,
        "server": "nginx",
        "headers": {"x-powered-by": "PHP"},
        "is_cloudflare": False,
        "domain_in_body": True,
        "all_headers": {"x-powered-by": "PHP"},
        "redirect_chain": []
    }
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={443: ["target.com"]})
    validator._reverse_dns = AsyncMock(return_value="")
    validator._grab_banners = AsyncMock(return_value={})
    
    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.recv.side_effect = asyncio.TimeoutError()
        result = await validator.validate_ip("2.2.2.2", {})
        
    assert result["confirmed"] is True
    assert result["confidence"] >= 0.8
    assert "No CloudFlare headers" in str(result["evidence"])
    assert "Target domain found in response body" in str(result["evidence"])

@pytest.mark.asyncio
async def test_scoring_differential_match(validator):
    """Scenario: Body hash match + redirect leak (Strong combinations pass)"""
    validator.baseline = {
        "body_length": 5000,
        "body_hash": "deadbeef",
        "custom_headers": {"x-target-id": "123"}
    }
    validator.probe.probe.return_value = {
        "status": 302,
        "server": "nginx",
        "is_cloudflare": False,
        "all_headers": {"x-target-id": "123"},
        "body_length": 5000,
        "body_hash": "deadbeef",
        "redirect_chain": [
            {"location": "http://3.3.3.3/"}
        ]
    }
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={})
    validator._reverse_dns = AsyncMock(return_value="")
    validator._grab_banners = AsyncMock(return_value={})
    
    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.recv.side_effect = asyncio.TimeoutError()
        result = await validator.validate_ip("3.3.3.3", {})
        
    assert result["confirmed"] is True
    assert result["confidence"] >= 0.8
    assert "Exact response body match with CDN fronted request (Differential)" in str(result["evidence"])
    assert "Host redirected to itself via bare IP (Strong Origin Identifier)" in str(result["evidence"])

@pytest.mark.asyncio
async def test_scoring_noisy_ip(validator):
    """Scenario: Noisy IPs (mass scanners/honeypots) should be heavily penalized"""
    validator.probe.probe.return_value = {
        "status": 200,
        "server": "nginx",
        "is_cloudflare": False, # Gets +35
        "all_headers": {},
        "redirect_chain": []
    }
    validator._check_greynoise = AsyncMock(return_value={"noise": True, "riot": False, "classification": "malicious"}) # Gets -40
    validator._get_cert_domains = AsyncMock(return_value={})
    validator._reverse_dns = AsyncMock(return_value="")
    validator._grab_banners = AsyncMock(return_value={})
    
    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.recv.side_effect = asyncio.TimeoutError()
        result = await validator.validate_ip("4.4.4.4", {})
        
    assert result["confirmed"] is False
    assert result["confidence"] <= 30

@pytest.mark.asyncio
async def test_single_moderate_signal_does_not_pass(validator):
    """Test: A single moderate signal (e.g. only Banner match) does not exceed threshold"""
    validator.probe.probe.return_value = None # No HTTP response
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={})
    validator._reverse_dns = AsyncMock(return_value="")
    
    # Only Banner Match (+20)
    validator._grab_banners = AsyncMock(return_value={22: "SSH-2.0-OpenSSH_target.com"})
    
    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.recv.side_effect = asyncio.TimeoutError()
        result = await validator.validate_ip("5.5.5.5", {})
        
    assert result["confirmed"] is False
    assert result["confidence"] == 0.25


@pytest.mark.asyncio
async def test_scoring_historical_records(validator):
    """Test: Legacy A records provide a lightweight score bump without exceeding threshold on their own"""
    validator.probe.probe.return_value = None # No HTTP response
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={})
    validator._reverse_dns = AsyncMock(return_value="")
    validator._grab_banners = AsyncMock(return_value={})
    
    # Needs to match the checks metadata
    meta = {
        "sources": ["Historical-DNS"],
        "oldest_seen": "2018-01-01",
        "newest_seen": "2020-01-01"
    }

    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.recv.side_effect = asyncio.TimeoutError()
        result = await validator.validate_ip("6.6.6.6", meta)
        
    assert result["confirmed"] is False
    assert result["confidence"] >= 0.05
    assert "Historical DNS record detected" in str(result["evidence"]) or "Highly legacy DNS record detected" in str(result["evidence"])


@pytest.mark.asyncio
async def test_tls_scoring_exact_match(validator):
    validator.probe.probe.return_value = {"status": 403, "server": "nginx"}
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={8443: ["target.com"]})
    validator._reverse_dns = AsyncMock(return_value="")
    validator._grab_banners = AsyncMock(return_value={})
    res = await validator.validate_ip("1.1.1.1", {})
    assert any("Exact SSL match on port 8443" in e for e in res["evidence"])

@pytest.mark.asyncio
async def test_tls_scoring_wildcard_match(validator):
    validator.probe.probe.return_value = {"status": 403, "server": "nginx"}
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={2053: ["*.target.com"]})
    validator._reverse_dns = AsyncMock(return_value="")
    validator._grab_banners = AsyncMock(return_value={})
    res = await validator.validate_ip("1.1.1.1", {})
    assert any("Wildcard SSL match on port 2053" in e for e in res["evidence"])

@pytest.mark.asyncio
async def test_tls_scoring_mismatch_penalty(validator):
    validator.probe.probe.return_value = {"status": 403, "server": "nginx"}
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={443: ["shared-host.com", "other.com"], 2053: ["another.com"]})
    validator._reverse_dns = AsyncMock(return_value="")
    validator._grab_banners = AsyncMock(return_value={})
    res = await validator.validate_ip("1.1.1.1", {})
    assert any("Mismatched SSL certificate on ports 443,2053" in e for e in res["evidence"])



@pytest.mark.asyncio
async def test_v2_score_normalization_consistency(validator):
    """Verify that final score is tightly bounded to 0.0 - 1.0"""
    validator.probe.probe.return_value = {
        "status": 200, "server": "nginx", "is_cloudflare": False,
        "domain_in_body": True, "redirect_chain": [{"location": "http://1.1.1.1/"}]
    }
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={443: ["target.com"], 8443: ["target.com"]})
    validator._reverse_dns = AsyncMock(return_value="target.com")
    validator._grab_banners = AsyncMock(return_value={22: "target.com", 21: "target.com"})
    
    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.recv.side_effect = asyncio.TimeoutError()
        result = await validator.validate_ip("1.1.1.1", {"ns_divergence": True})
        
    assert result["confidence"] <= 1.0
    assert result["confidence"] > 0.8
    assert result["confirmed"] is True
    # Verify legacy fallback
    legacy_result = await validator.validate_ip("1.1.1.1", {"ns_divergence": True}, scoring_version="v1")
    assert legacy_result["confidence"] <= 100

@pytest.mark.asyncio
async def test_v2_no_inflation_correlated_weak_signals(validator):
    """Ensure soft caps prevent a single category from dominating the score."""
    validator.probe.probe.return_value = None
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={})
    validator._reverse_dns = AsyncMock(return_value="not-matching.com")
    
    # 10 different ports showing banners
    banners = {port: "target.com" for port in range(1000, 1010)}
    validator._grab_banners = AsyncMock(return_value=banners)
    
    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.recv.side_effect = asyncio.TimeoutError()
        result = await validator.validate_ip("1.1.1.1", {})
        
    assert result["confidence"] < 0.8
    assert result["confirmed"] is False

@pytest.mark.asyncio
async def test_v2_low_medium_high_clusters(validator):
    """Validate specific scenarios cleanly place into low, medium, and high score bands."""
    
    # LOW: Generic 403 config
    validator.probe.probe.return_value = {"status": 403, "server": "nginx", "is_cloudflare": False}
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={})
    validator._reverse_dns = AsyncMock(return_value="")
    validator._grab_banners = AsyncMock(return_value={})
    
    low_res = await validator.validate_ip("1.1.1.1", {})
    assert low_res["confidence"] < 0.6
    
    # MEDIUM: Wildcard cert but nothing else
    validator.probe.probe.return_value = None
    validator._get_cert_domains = AsyncMock(return_value={443: ["*.target.com"]})
    med_res = await validator.validate_ip("1.1.1.1", {})
    assert 0.3 <= med_res["confidence"] < 0.8
    
    # HIGH: Exact TLS match + CF bypass
    validator.probe.probe.return_value = {"status": 200, "server": "nginx", "is_cloudflare": False}
    validator._get_cert_domains = AsyncMock(return_value={443: ["target.com"]})
    high_res = await validator.validate_ip("1.1.1.1", {})
    assert high_res["confidence"] >= 0.8

@pytest.mark.asyncio
async def test_v2_score_normalization_consistency(validator):
    """Verify that final score is tightly bounded to 0.0 - 1.0"""
    validator.probe.probe.return_value = {
        "status": 200, "server": "nginx", "is_cloudflare": False,
        "domain_in_body": True, "redirect_chain": [{"location": "http://1.1.1.1/"}]
    }
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={443: ["target.com"], 8443: ["target.com"]})
    validator._reverse_dns = AsyncMock(return_value="target.com")
    validator._grab_banners = AsyncMock(return_value={22: "target.com", 21: "target.com"})
    
    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.recv.side_effect = asyncio.TimeoutError()
        result = await validator.validate_ip("1.1.1.1", {"ns_divergence": True})
        
    assert result["confidence"] <= 1.0
    assert result["confidence"] > 0.8
    assert result["confirmed"] is True
    # Verify legacy fallback
    legacy_result = await validator.validate_ip("1.1.1.1", {"ns_divergence": True}, scoring_version="v1")
    assert legacy_result["confidence"] <= 100

@pytest.mark.asyncio
async def test_v2_no_inflation_correlated_weak_signals(validator):
    """Ensure soft caps prevent a single category from dominating the score."""
    validator.probe.probe.return_value = None
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={})
    validator._reverse_dns = AsyncMock(return_value="not-matching.com")
    
    # 10 different ports showing banners
    banners = {port: "target.com" for port in range(1000, 1010)}
    validator._grab_banners = AsyncMock(return_value=banners)
    
    with patch("socket.socket") as mock_socket:
        mock_socket.return_value.recv.side_effect = asyncio.TimeoutError()
        result = await validator.validate_ip("1.1.1.1", {})
        
    assert result["confidence"] < 0.8
    assert result["confirmed"] is False

@pytest.mark.asyncio
async def test_v2_low_medium_high_clusters(validator):
    """Validate specific scenarios cleanly place into low, medium, and high score bands."""
    
    # LOW: Generic 403 config
    validator.probe.probe.return_value = {"status": 403, "server": "nginx", "is_cloudflare": False}
    validator._check_greynoise = AsyncMock(return_value={"noise": False, "riot": False})
    validator._get_cert_domains = AsyncMock(return_value={})
    validator._reverse_dns = AsyncMock(return_value="")
    validator._grab_banners = AsyncMock(return_value={})
    
    low_res = await validator.validate_ip("1.1.1.1", {})
    assert low_res["confidence"] < 0.6
    
    # MEDIUM: Wildcard cert but nothing else
    validator.probe.probe.return_value = None
    validator._get_cert_domains = AsyncMock(return_value={443: ["*.target.com"]})
    med_res = await validator.validate_ip("1.1.1.1", {})
    assert 0.3 <= med_res["confidence"] < 0.8
    
    # HIGH: Exact TLS match + CF bypass
    validator.probe.probe.return_value = {"status": 200, "server": "nginx", "is_cloudflare": False}
    validator._get_cert_domains = AsyncMock(return_value={443: ["target.com"]})
    high_res = await validator.validate_ip("1.1.1.1", {})
    assert high_res["confidence"] >= 0.8
