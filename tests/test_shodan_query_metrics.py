"""Offline Shodan query accounting; no third-party requests or real target inputs."""
import json
import os
import sys
from unittest.mock import AsyncMock

import pytest
import shodan
from rich.console import Console

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "cfunveil")))

from core.shodan_query_metrics import ShodanQueryMetrics
from core.shodan_pivot import ShodanPivot


def observation(*, hostnames, port=443, timestamp=None):
    return {
        "hostnames": hostnames, "certificate_names": [],
        "observed_at": timestamp, "port": port,
        "product": "Example", "version": None, "jarm": None,
        "query": "not part of identity", "strategy": "not part of identity",
        "relation": "related_hostname",
    }


def test_query_accounting_separates_order_dependent_and_exclusive_coverage():
    metrics = ShodanQueryMetrics()
    one = observation(hostnames=["a.example.co.uk"])
    two = observation(hostnames=["b.example.co.uk"])
    changed = observation(hostnames=["b.example.co.uk"], port=8443)
    metrics.success(
        strategy="ssl_certificate", query="q1", limit=2,
        matches=[{}, {}], accepted=[("8.8.8.8", one), ("9.9.9.9", two)],
        provider_total=123,
    )
    metrics.success(
        strategy="hostname", query="q2", limit=10,
        matches=[{}, {}, {}],
        accepted=[
            ("9.9.9.9", {**two, "query": "another query", "strategy": "hostname"}),
            ("9.9.9.9", changed),
            ("1.1.1.1", one),
        ],
        provider_total=None,
    )
    a, b = metrics.snapshot()
    assert a["limit_reached"] is True
    assert a["provider_total"] == 123
    assert a["returned_matches"] == 2
    assert a["unique_ips"] == 2
    assert a["incremental_new_ips"] == 2
    assert a["exclusive_ips"] == 1
    assert a["shared_ips"] == 1
    assert a["unique_banner_evidence"] == 2
    assert a["exclusive_banner_evidence"] == 1
    assert a["shared_banner_evidence"] == 1
    assert a["incremental_new_banner_evidence"] == 2

    assert b["unique_ips"] == 2
    assert b["accepted_matches"] == 3
    assert b["incremental_new_ips"] == 1
    assert b["exclusive_ips"] == 1
    assert b["shared_ips"] == 1
    assert b["unique_banner_evidence"] == 3
    assert b["incremental_new_banner_evidence"] == 2
    assert b["exclusive_banner_evidence"] == 2
    assert b["shared_banner_evidence"] == 1
    assert b["limit_reached"] is False
    assert b["query_credits_used"] is None
    assert json.loads(json.dumps(metrics.snapshot())) == metrics.snapshot()


def test_failed_and_skipped_queries_not_counted_as_zero_coverage():
    metrics = ShodanQueryMetrics()
    metrics.failure(
        strategy="ssl_certificate", query="ssl:example.net",
        limit=100, error_type="APIError",
    )
    metrics.skipped(strategy="favicon_hash", reason="favicon_unavailable")
    error, skipped = metrics.snapshot()
    assert error["status"] == "error"
    assert error["error_type"] == "APIError"
    assert error["unique_ips"] is None
    assert error["returned_matches"] is None
    assert error["query_credits_used"] is None
    assert skipped["status"] == "skipped"
    assert skipped["query"] is None
    assert skipped["skip_reason"] == "favicon_unavailable"
    assert skipped["incremental_new_ips"] is None


def test_real_query_execution_path_accounts_for_filtered_banners_and_failures():
    pivot = ShodanPivot(
        "api.example.net", "example.net",
        {"shodan_key": "offline-placeholder"}, Console(quiet=True),
    )

    class FakeAPI:
        def search(self, query, limit=None):
            if '"api.example.net"' in query:
                raise shodan.APIError("offline simulated unavailable")
            return {
                "total": 245,
                "matches": [
                    {
                        "ip_str": "9.9.9.9", "asn": "AS64500",
                        "hostnames": ["service.example.net"], "port": 443,
                    },
                    {
                        "ip_str": "1.1.1.1", "asn": "AS13335",
                        "hostnames": ["service.example.net"], "port": 443,
                    },
                ],
            }

    pivot.api = FakeAPI()
    pivot._hostname_search()
    rows = pivot.query_metrics.snapshot()
    assert len(rows) == 2
    good, failed = rows
    assert good["status"] == "success"
    assert good["provider_total"] == 245
    assert good["returned_matches"] == 2
    assert good["accepted_matches"] == 1
    assert good["unique_ips"] == 1
    assert good["incremental_new_ips"] == 1
    assert good["limit_reached"] is False
    assert failed["status"] == "error"
    assert failed["error_type"] == "APIError"
    assert failed["unique_ips"] is None
    assert set(pivot.found_ips) == {"9.9.9.9"}


def test_identical_bounded_ssl_queries_are_flagged_but_not_optimized():
    pivot = ShodanPivot(
        "service.customer.github.io", "customer.github.io",
        {"shodan_key": "offline-placeholder"}, Console(quiet=True),
    )
    calls = []

    class FakeAPI:
        def search(self, query, limit=None):
            calls.append((query, limit))
            return {
                "total": 999,
                "matches": [
                    {"ip_str": f"8.8.8.{i}", "hostnames": ["other.customer.github.io"]}
                    for i in range(1, 101)
                ],
            }

    pivot.api = FakeAPI()
    pivot._ssl_cert_pivot()
    rows = pivot.query_metrics.snapshot()
    assert len(calls) == 3
    assert len(rows) == 3
    assert all(row["limit_reached"] is True for row in rows)
    assert all(row["provider_total"] == 999 for row in rows)
    assert [row["incremental_new_ips"] for row in rows] == [100, 0, 0]
    assert [row["exclusive_ips"] for row in rows] == [0, 0, 0]
    assert [row["unique_banner_evidence"] for row in rows] == [100, 100, 100]
    assert all(row["exclusive_banner_evidence"] == 0 for row in rows)
    assert all(row["query_credits_used"] is None for row in rows)
    assert len(pivot.found_ips) == 100


@pytest.mark.parametrize("no_wait", [False, True])
@pytest.mark.asyncio
async def test_engine_exports_shodan_metrics_both_execution_modes(
    no_wait, tmp_path, monkeypatch,
):
    from core.engine import ReconEngine
    from core.dns_enum import DNSEnumerator
    from core.cert_intel import CertIntelligence
    from core.historical import HistoricalSources
    from core.asn_intel import ASNIntelligence
    from output.reporter import generate_report

    monkeypatch.chdir(tmp_path)
    fake_metrics = ShodanQueryMetrics()
    fake_metrics.success(
        strategy="hostname", query='hostname:"example.org"', limit=100,
        matches=[{}],
        accepted=[("8.8.8.8", observation(hostnames=["api.example.org"]))],
        provider_total=500,
    )

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
    monkeypatch.setattr(ShodanPivot, "run", AsyncMock(return_value={
        "ips": {}, "query_metrics": fake_metrics.snapshot(),
    }))

    engine = ReconEngine({
        "target": "api.example.org", "shodan_key": "offline-placeholder",
        "threads": 3, "timeout": 3, "validate": False, "no_wait": no_wait,
    }, Console(quiet=True))
    result = await engine.run()
    assert result["ips"] == {}
    assert result["shodan_query_metrics"] == fake_metrics.snapshot()
    assert result["shodan_query_metrics"][0]["query_credits_used"] is None
    filename = tmp_path / "metrics.json"
    generate_report(result, str(filename), "api.example.org")
    assert json.loads(filename.read_text())["shodan_query_metrics"] == fake_metrics.snapshot()


def test_html_query_metrics_escaped_and_explicit_about_uncertainty(tmp_path):
    from output.reporter import generate_report

    metrics = ShodanQueryMetrics()
    metrics.success(
        strategy="http_content", query='http.html:"<script>x()</script>"',
        limit=1, matches=[{}], accepted=[],
        provider_total=None,
    )
    path = tmp_path / "report.html"
    generate_report(
        {"ips": {}, "related_infrastructure": {}, "cdn_edges": {},
         "summary": {}, "shodan_query_metrics": metrics.snapshot()},
        str(path), "example.org",
    )
    html = path.read_text()
    assert "Shodan query effectiveness" in html
    assert "New IPs and evidence depend on query order" in html
    assert "Result cap hit: Yes" in html
    assert "provider credits used: not available" in html
    assert "&lt;script&gt;" in html
    assert "<script>x()</script>" not in html
