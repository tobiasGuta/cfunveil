"""Offline Shodan attribution tests; no real host, provider, or API requests."""
import json
import os
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest
from rich.console import Console

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "cfunveil"))

from core.shodan_evidence import describe_shodan_match
from core.shodan_pivot import ShodanPivot


@pytest.mark.parametrize("target,root,hostnames,expected", [
    ("api.example.co.uk", "example.co.uk",
     ["API.EXAMPLE.CO.UK.", "mail.example.co.uk"], "exact_target_hostname"),
    ("api.example.co.uk", "example.co.uk",
     ["mail.example.co.uk"], "related_hostname"),
    ("api.example.co.uk", "example.co.uk",
     ["api.example.co.uk.attacker.net", "otherexample.co.uk"], "query_only"),
    ("service.customer.github.io", "customer.github.io",
     ["service.other.github.io"], "query_only"),
    ("customer.github.io", "customer.github.io",
     ["www.customer.github.io"], "related_hostname"),
    ("customer.github.io", "customer.github.io",
     ["customer.github.io"], "exact_target_hostname"),
])
def test_classification_respects_generic_hostname_and_psl_scope(
    target, root, hostnames, expected,
):
    record = describe_shodan_match(
        {"hostnames": hostnames, "domains": [root], "ip_str": "8.8.8.8"},
        target=target, root_domain=root, strategy="hostname",
        query=f'hostname:"{root}"',
    )
    assert record["relation"] == expected
    if expected == "exact_target_hostname":
        assert record["exact_hostnames"] == [target]
    if expected == "query_only":
        assert not record["exact_hostnames"]
        assert not record["related_hostnames"]


def test_fingerprint_and_cert_queries_never_imply_target_hostname():
    data = {
        "ip_str": "8.8.8.8",
        "hostnames": ["unrelated.example.org"],
        "ssl": {"cert": {
            "subject": {"CN": "api.example.net"},
            "alt_names": ["api.example.net", "*.example.net"],
        }},
    }
    favicon = describe_shodan_match(
        data, target="api.example.net", root_domain="example.net",
        strategy="favicon_hash", query="http.favicon.hash:123",
    )
    assert favicon["relation"] == "fingerprint_only"
    assert "api.example.net" in favicon["certificate_names"]
    cert = describe_shodan_match(
        data, target="api.example.net", root_domain="example.net",
        strategy="ssl_certificate", query='ssl:"example.net"',
    )
    assert cert["relation"] == "query_only"  # cert is not live hostname/DNS proof
    assert cert["observed_at"] is None


def test_shodan_accumulates_query_specific_observations_and_preserves_timestamps():
    pivot = ShodanPivot(
        "api.example.co.uk", "example.co.uk",
        {"shodan_key": "offline-placeholder"}, Console(quiet=True),
    )
    ip = "9.9.9.9"
    first = {
        "ip_str": ip, "hostnames": ["MAIL.EXAMPLE.CO.UK."],
        "domains": ["example.co.uk"], "port": 443,
        "timestamp": "2026-10-14T12:00:00Z", "org": "Example Hosting",
        "ssl": {"cert": {"subject": {"CN": "api.example.co.uk"}}},
    }
    other = {
        "ip_str": ip, "hostnames": ["api.example.co.uk", "mail.example.co.uk"],
        "domains": ["example.co.uk"], "port": 80,
        "timestamp": "2026-10-19T08:00:00Z", "org": "Example Hosting",
    }
    pivot._add_result(first, strategy="ssl_certificate", query='ssl:"example.co.uk"')
    pivot._add_result(first, strategy="ssl_certificate", query='ssl:"example.co.uk"')
    pivot._add_result(other, strategy="hostname", query='hostname:"api.example.co.uk"')
    pivot._add_result({"ip_str": ip, "hostnames": ["different.net"], "port": 8080},
                      strategy="favicon_hash", query="http.favicon.hash:42")
    saved = pivot.found_ips[ip]
    assert len(saved["shodan_evidence"]) == 3
    assert saved["shodan_observations_truncated"] == 0
    assert saved["shodan_relations"] == [
        "related_hostname", "exact_target_hostname", "fingerprint_only",
    ]
    assert set(saved["hostnames"]) == {
        "mail.example.co.uk", "api.example.co.uk", "different.net",
    }
    assert set(saved["ports"]) == {443, 80, 8080}
    assert saved["shodan_evidence"][0]["observed_at"] == "2026-10-14T12:00:00Z"
    assert saved["shodan_evidence"][1]["observed_at"] == "2026-10-19T08:00:00Z"
    assert saved["shodan_evidence"][2]["observed_at"] is None
    assert all("query" in record and "strategy" in record for record in saved["shodan_evidence"])
    assert "example.co.uk" in json.dumps(saved)


def test_shodan_strategies_record_the_exact_query_without_network(monkeypatch):
    pivot = ShodanPivot(
        "app.example.org", "example.org",
        {"shodan_key": "offline-placeholder"}, Console(quiet=True),
    )
    captured = []

    class FakeAPI:
        def search(self, query, limit=None):
            captured.append((query, limit))
            return {"matches": [{
                "ip_str": "8.8.8.8",
                "hostnames": ["portal.example.org"],
                "port": 443,
            }]}

    pivot.api = FakeAPI()
    pivot._ssl_cert_pivot()
    pivot._hostname_search()
    pivot._http_search()
    assert len(captured) == 7
    records = pivot.found_ips["8.8.8.8"]["shodan_evidence"]
    assert len(records) == 7
    assert {r["strategy"] for r in records} == {
        "ssl_certificate", "hostname", "http_content",
    }
    assert {r["query"] for r in records} == {q for q, _ in captured}
    assert all(r["relation"] == "related_hostname" for r in records)


def test_shodan_ip_evidence_is_bounded_and_truncation_visible():
    pivot = ShodanPivot(
        "app.example.org", "example.org",
        {"shodan_key": "offline-placeholder"}, Console(quiet=True),
    )
    for i in range(130):
        pivot._add_result(
            {"ip_str": "8.8.8.8", "hostnames": ["unrelated.net"]},
            strategy="hostname", query=f"offline search {i}",
        )
    data = pivot.found_ips["8.8.8.8"]
    assert len(data["shodan_evidence"]) == 128
    assert data["shodan_observations_truncated"] == 2
    assert data["shodan_relations"] == ["query_only"]


@pytest.mark.asyncio
async def test_engine_keeps_shodan_exact_hostname_in_related_bucket_and_json(
    tmp_path, monkeypatch,
):
    from core.dns_enum import DNSEnumerator
    from core.cert_intel import CertIntelligence
    from core.historical import HistoricalSources
    from core.asn_intel import ASNIntelligence
    from core.engine import ReconEngine
    from output.reporter import generate_report

    monkeypatch.chdir(tmp_path)
    pivot = ShodanPivot(
        "api.example.org", "example.org",
        {"shodan_key": "offline-placeholder"}, Console(quiet=True),
    )
    pivot._add_result({
        "ip_str": "8.8.8.8", "hostnames": ["api.example.org"],
        "timestamp": "2026-10-20T10:00:00Z", "port": 443,
    }, strategy="hostname", query='hostname:"api.example.org"')

    monkeypatch.setattr(DNSEnumerator, "run", AsyncMock(
        return_value={"ips": [], "cloudflare_ips": [], "records": {}, "subdomains": []},
    ))
    monkeypatch.setattr(CertIntelligence, "run", AsyncMock(
        return_value={"ips": [], "records": {}, "subdomains": []},
    ))
    monkeypatch.setattr(HistoricalSources, "run", AsyncMock(
        return_value={"ips": {}},
    ))
    monkeypatch.setattr(ASNIntelligence, "run", AsyncMock(
        return_value={"resolved": {}, "sibling_ips": []},
    ))
    monkeypatch.setattr(ShodanPivot, "run", AsyncMock(
        return_value={"ips": pivot.found_ips},
    ))
    engine = ReconEngine({
        "target": "api.example.org", "threads": 5, "timeout": 3,
        "validate": False, "shodan_key": "offline-placeholder",
    }, Console(quiet=True))
    report = await engine.run()
    assert report["ips"] == {}
    assert set(report["related_infrastructure"]) == {"8.8.8.8"}
    record = report["related_infrastructure"]["8.8.8.8"]
    assert record["sources"] == ["Shodan"]
    assert record["details"]["shodan_evidence"][0]["relation"] == "exact_target_hostname"

    generate_report(report, str(tmp_path / "report.json"), "api.example.org")
    serialized = json.loads((tmp_path / "report.json").read_text())
    assert serialized["related_infrastructure"]["8.8.8.8"]["details"]["shodan_evidence"][0]["query"] == 'hostname:"api.example.org"'



def test_html_shows_query_provenance_and_escapes_shodan_search_strings(tmp_path):
    from output.reporter import generate_report

    payload = {
        "target": "api.example.org",
        "ips": {},
        "summary": {"total_ips_found": 0},
        "related_infrastructure": {
            "8.8.8.8": {
                "sources": ["Shodan"], "records": [],
                "details": {
                    "hostnames": ["portal.example.org"],
                    "shodan_evidence": [{
                        "strategy": "http_content", "relation": "related_hostname",
                        "query": 'http.html:"<script>evil()</script>"',
                        "observed_at": None,
                    }],
                },
            },
        },
    }
    path = tmp_path / "evidence.html"
    generate_report(payload, str(path), "api.example.org")
    html = path.read_text()
    assert "portal.example.org" in html
    assert "Shodan query provenance (not origin proof)" in html
    assert "related_hostname" in html
    assert "http_content" in html
    assert "&lt;script&gt;" in html
    assert "<script>evil()</script>" not in html
