"""Offline candidate-attribution tests based on the observed Life360 scan patterns."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from rich.console import Console

from core.asn_intel import ASNIntelligence
from core.dns_enum import DNSEnumerator, is_cloudflare_ip
from core.historical import HistoricalSources
from core.engine import ReconEngine


def test_cloudflare_cidr_membership_matches_published_ranges():
    assert is_cloudflare_ip("104.18.37.240") is True
    assert is_cloudflare_ip("108.162.193.194") is True
    assert is_cloudflare_ip("173.245.59.194") is True
    assert is_cloudflare_ip("2606:4700::1111") is True
    assert is_cloudflare_ip("8.8.8.8") is False
    assert is_cloudflare_ip("garbage") is False


@pytest.mark.asyncio
async def test_subdomain_dns_does_not_expand_to_root_spf_or_siblings(monkeypatch):
    queried = []

    class Resolver:
        def __init__(self):
            self.nameservers = []

        async def query(self, domain, kind):
            queried.append((domain, kind))
            if domain == "api-cloudfront.life360.com" and kind == "A":
                return [SimpleNamespace(host="104.18.37.240")]
            raise ValueError("no record")

    monkeypatch.setattr("core.dns_enum.aiodns.DNSResolver", Resolver)
    result = await DNSEnumerator(
        "api-cloudfront.life360.com", "life360.com", Console()
    ).run()
    assert result["ips"] == []
    assert result["cloudflare_ips"] == ["104.18.37.240"]
    assert result["records"]["104.18.37.240"] == [
        {"domain": "api-cloudfront.life360.com", "record_type": "A"}
    ]
    assert queried
    assert set(domain for domain, _ in queried) == {"api-cloudfront.life360.com"}
    assert set(kind for _, kind in queried) == {"A", "AAAA", "CNAME"}


@pytest.mark.asyncio
async def test_dns_alias_resolves_without_promoting_external_domain(monkeypatch):
    class Resolver:
        def __init__(self):
            self.nameservers = []

        async def query(self, domain, kind):
            if domain == "api-cloudfront.life360.com" and kind == "CNAME":
                return [SimpleNamespace(cname="some-edge.example.net.")]
            if domain == "some-edge.example.net" and kind == "A":
                return [SimpleNamespace(host="8.8.8.8")]
            raise ValueError("no answer")

    monkeypatch.setattr("core.dns_enum.aiodns.DNSResolver", Resolver)
    result = await DNSEnumerator(
        "api-cloudfront.life360.com", "life360.com", Console()
    ).run()
    assert result["ips"] == ["8.8.8.8"]
    assert result["records"]["8.8.8.8"][0]["domain"] == "api-cloudfront.life360.com"
    assert "some-edge.example.net" not in result["subdomains"]


def test_historical_rejects_unrelated_embedded_third_party_domains():
    historical = HistoricalSources(
        "life360.com", {}, Console(), MagicMock(), target="api-cloudfront.life360.com"
    )
    historical._add_historical_ip("2.21.20.134", "www.tiktok.com", "urlscan")
    historical._add_historical_ip("162.159.140.229", "x.com", "urlscan")
    historical._add_historical_ip("57.144.244.141", "web.facebook.com", "urlscan")
    historical._add_historical_ip("54.147.150.225", "nexus.dev.life360.com", "urlscan")
    historical._add_historical_ip(
        "104.18.37.240", "api-cloudfront.life360.com", "urlscan"
    )
    assert len(historical.found_ips) == 2
    assert "54.147.150.225" in historical.found_ips
    assert historical.found_ips["104.18.37.240"]["records"][0]["relation"] == "exact_target"
    assert historical.found_ips["54.147.150.225"]["records"][0]["relation"] == "related_hostname"


@pytest.mark.asyncio
async def test_asn_enrichment_never_generates_sibling_ips():
    asn = ASNIntelligence(["8.8.8.8"], Console(), MagicMock())
    asn._lookup_ip = AsyncMock(return_value={
        "ip": "8.8.8.8", "asn": "AS15169", "prefix": "8.8.8.0/24"
    })
    result = await asn.run()
    assert result["sibling_ips"] == []
    assert list(result["resolved"]) == ["8.8.8.8"]


@pytest.mark.asyncio
async def test_scan_outputs_exclusive_origin_related_and_cdn_buckets(tmp_path, monkeypatch):
    from core.cert_intel import CertIntelligence

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("core.dns_enum.DNSEnumerator.run", AsyncMock(return_value={
        "ips": [],
        "cloudflare_ips": ["104.18.37.240"],
        "records": {"104.18.37.240": [
            {"domain": "api-cloudfront.life360.com", "record_type": "A"}
        ]},
        "subdomains": ["api-cloudfront.life360.com"],
    }))
    monkeypatch.setattr(CertIntelligence, "run", AsyncMock(return_value={
        "ips": [], "subdomains": []
    }))
    monkeypatch.setattr(HistoricalSources, "run", AsyncMock(return_value={"ips": {
        "104.18.37.240": {
            "records": [{"domain": "api-cloudfront.life360.com", "source": "urlscan"}],
            "sources": ["urlscan"]
        },
        "54.147.150.225": {
            "records": [{"domain": "nexus.dev.life360.com", "source": "urlscan"}],
            "sources": ["urlscan"]
        },
        "52.3.4.5": {
            "records": [{"domain": "api-cloudfront.life360.com", "source": "securitytrails"}],
            "sources": ["securitytrails"]
        }
    }}))
    monkeypatch.setattr(ASNIntelligence, "run", AsyncMock(return_value={
        "resolved": {}, "sibling_ips": ["52.3.4.6"]
    }))
    engine = ReconEngine({
        "target": "api-cloudfront.life360.com",
        "threads": 5, "timeout": 5, "validate": False,
    }, Console())
    results = await engine.run()
    assert set(results["ips"]) == {"52.3.4.5"}
    assert set(results["cdn_edges"]) == {"104.18.37.240"}
    assert set(results["related_infrastructure"]) == {"54.147.150.225"}
    assert "52.3.4.6" not in results["ips"]
    assert results["summary"]["total_ips_found"] == 1
    assert results["summary"]["cdn_edge_count"] == 1
    assert results["summary"]["related_ip_count"] == 1
