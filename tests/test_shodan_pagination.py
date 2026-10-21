"""No-network acceptance coverage for opt-in Shodan pagination.

All provider responses below are synthetic; targets are documentation domains.
"""
import json
import os
import sys
from unittest.mock import AsyncMock

import pytest
import shodan
from rich.console import Console

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "cfunveil")))
from core.shodan_pivot import ShodanPivot


def make_pivot(max_pages=1, budget=8):
    return ShodanPivot(
        "api.example.co.uk", "example.co.uk",
        {
            "shodan_key": "offline-placeholder",
            "shodan_max_pages": max_pages,
            "shodan_extra_page_budget": budget,
        },
        Console(quiet=True),
    )


def banners(page, n=100):
    return [
        {
            "ip_str": f"8.{page}.{i // 254 + 1}.{i % 254 + 1}",
            "port": 443,
            "timestamp": f"2026-10-{page:02d}T00:00:00Z",
            "hostnames": ["mail.example.co.uk"],
        }
        for i in range(n)
    ]


def test_original_single_page_queries_stay_unchanged_and_do_not_pay_extra():
    pivot = make_pivot()
    calls = []

    class Fake:
        def search(self, query, **kwargs):
            calls.append((query, kwargs))
            return {"matches": banners(1, 50), "total": 250}

    pivot.api = Fake()
    pivot._execute_query('http.html:"example.co.uk"', strategy="http_content", limit=50)
    assert calls == [('http.html:"example.co.uk"', {"limit": 50})]
    assert pivot.extra_page_requests_used == 0
    [row] = pivot.query_metrics.snapshot()
    assert row["page"] == 1
    assert row["returned_matches"] == 50
    assert row["pagination_stop_reason"] == "per_query_page_cap"
    assert row["provider_total"] == 250


def test_opt_in_queries_first_request_complete_page_before_page_two():
    pivot = make_pivot(max_pages=3, budget=2)
    calls = []

    class Fake:
        def search(self, query, **kwargs):
            calls.append(kwargs)
            page = kwargs.get("page", 1)
            return {"matches": banners(page, 5 if page == 3 else 100), "total": 205}

    pivot.api = Fake()
    pivot._execute_query("offline query", strategy="http_content", limit=50)
    assert calls == [{"limit": 100}, {"page": 2, "limit": 100}, {"page": 3, "limit": 100}]
    rows = pivot.query_metrics.snapshot()
    assert [r["page"] for r in rows] == [1, 2, 3]
    assert [r["returned_matches"] for r in rows] == [100, 100, 5]
    assert [r["incremental_new_ips"] for r in rows] == [100, 100, 5]
    assert all(r["strategy"] == "http_content" for r in rows)
    assert rows[-1]["pagination_stop_reason"] == "provider_total_reached"
    assert pivot.extra_page_requests_used == 2
    assert len(pivot.found_ips) == 205
    assert all(x["sources"] == ["Shodan"] for x in [])  # no engine-origin promotion
    assert pivot.api is not None


def test_global_budget_across_multiple_queries_and_page_cap():
    pivot = make_pivot(max_pages=3, budget=3)
    calls = []

    class Fake:
        def search(self, query, **kwargs):
            calls.append((query, kwargs))
            return {"matches": banners(kwargs.get("page", 1)), "total": 999}

    pivot.api = Fake()
    pivot._ssl_cert_pivot()
    # First query pages 1/2/3; second query pages 1/2; third page 1 only.
    assert [kwargs.get("page", 1) for _, kwargs in calls] == [1, 2, 3, 1, 2, 1]
    assert pivot.extra_page_requests_used == 3
    rows = pivot.query_metrics.snapshot()
    assert [r["pagination_stop_reason"] for r in rows if r.get("pagination_stop_reason")] == [
        "per_query_page_cap", "global_extra_page_budget", "global_extra_page_budget",
    ]
    assert len(pivot.found_ips) == 300
    assert [r["incremental_new_ips"] for r in rows] == [100, 100, 100, 0, 0, 0]
    summary = pivot.query_metrics.snapshot()
    assert all(r["query_credits_used"] is None for r in summary)


def test_per_query_cap_prevents_fetching_page_four_even_with_budget():
    pivot = make_pivot(max_pages=2, budget=20)
    calls = []

    class Fake:
        def search(self, query, **kwargs):
            calls.append(kwargs)
            return {"matches": banners(kwargs.get("page", 1)), "total": 1000}

    pivot.api = Fake()
    pivot._execute_query("offline", strategy="hostname", limit=100)
    assert calls == [{"limit": 100}, {"page": 2, "limit": 100}]
    assert pivot.query_metrics.snapshot()[-1]["pagination_stop_reason"] == "per_query_page_cap"
    assert pivot.extra_page_requests_used == 1


def test_failure_on_extra_page_consumes_one_attempt_and_no_retry():
    pivot = make_pivot(max_pages=5, budget=1)
    calls = []

    class Fake:
        def search(self, query, **kwargs):
            calls.append(kwargs)
            if kwargs.get("page") == 2:
                raise shodan.APIError("Offline synthetic failure")
            return {"matches": banners(1), "total": 999}

    pivot.api = Fake()
    with pytest.raises(shodan.APIError):
        pivot._execute_query("offline", strategy="hostname", limit=100, retry=True)
    assert calls == [{"limit": 100}, {"page": 2, "limit": 100}]
    assert pivot.extra_page_requests_used == 1
    rows = pivot.query_metrics.snapshot()
    assert [r["status"] for r in rows] == ["success", "error"]
    assert rows[1]["page"] == 2
    assert rows[1]["error_type"] == "APIError"
    assert len(pivot.found_ips) == 100
    # Even after a failed extra page the scan cannot overspend its budget.
    pivot._execute_query("offline-other", strategy="hostname", limit=100)
    assert calls[-1] == {"limit": 100}
    assert pivot.query_metrics.snapshot()[-1]["pagination_stop_reason"] == "global_extra_page_budget"


@pytest.mark.parametrize("max_pages,budget", [
    (0, 8), (6, 8), (1.0, 8), (True, 8), (2, -1), (2, 21),
    (2, "8"), (2, False),
])
def test_programmatic_engine_config_rejects_invalid_budgets(max_pages, budget):
    with pytest.raises(ValueError):
        make_pivot(max_pages, budget)


def test_shodan_reporting_includes_page_info_with_no_sensitive_credentials(tmp_path):
    from output.reporter import generate_report

    pivot = make_pivot(max_pages=2, budget=1)

    class Fake:
        def search(self, query, **kwargs):
            return {"matches": banners(kwargs.get("page", 1)), "total": 400}

    pivot.api = Fake()
    pivot._execute_query('ssl:"example.co.uk" -org:"Cloudflare"',
                         strategy="ssl_certificate", limit=100)
    payload = {
        "ips": {}, "related_infrastructure": {}, "cdn_edges": {}, "summary": {},
        "shodan_query_metrics": pivot.query_metrics.snapshot(),
        "shodan_pagination_budget": {
            "max_pages_per_query": pivot.max_pages,
            "extra_page_request_budget": pivot.extra_page_budget,
            "extra_page_requests_attempted": pivot.extra_page_requests_used,
            "actual_query_credits_used": None,
        },
    }
    json_path = tmp_path / "report.json"
    generate_report(payload, str(json_path), "api.example.co.uk")
    assert json.loads(json_path.read_text())["shodan_query_metrics"][1]["page"] == 2
    html_path = tmp_path / "report.html"
    generate_report(payload, str(html_path), "api.example.co.uk")
    markup = html_path.read_text()
    assert "Max pages/query: 2" in markup
    assert "extra-page attempts: 1" in markup
    assert "pagination stopped: per_query_page_cap" in markup
    assert "<th>Page</th>" in markup


@pytest.mark.parametrize("no_wait", [False, True])
@pytest.mark.asyncio
async def test_engine_preserves_pagination_budget_both_modes(no_wait, tmp_path, monkeypatch):
    from core.engine import ReconEngine
    from core.dns_enum import DNSEnumerator
    from core.cert_intel import CertIntelligence
    from core.historical import HistoricalSources
    from core.asn_intel import ASNIntelligence

    monkeypatch.chdir(tmp_path)
    budget = {
        "max_pages_per_query": 3, "extra_page_request_budget": 2,
        "extra_page_requests_attempted": 2, "actual_query_credits_used": None,
    }
    monkeypatch.setattr(DNSEnumerator, "run", AsyncMock(
        return_value={"ips": [], "cloudflare_ips": [], "records": {}, "subdomains": []},
    ))
    monkeypatch.setattr(CertIntelligence, "run", AsyncMock(
        return_value={"ips": [], "records": {}, "subdomains": []},
    ))
    monkeypatch.setattr(HistoricalSources, "run", AsyncMock(return_value={"ips": {}}))
    monkeypatch.setattr(ASNIntelligence, "run", AsyncMock(
        return_value={"resolved": {}, "sibling_ips": []},
    ))
    monkeypatch.setattr(ShodanPivot, "run", AsyncMock(return_value={
        "ips": {}, "query_metrics": [], "pagination_budget": budget,
    }))
    engine = ReconEngine({
        "target": "api.example.co.uk", "shodan_key": "offline-placeholder",
        "shodan_max_pages": 3, "shodan_extra_page_budget": 2,
        "threads": 3, "timeout": 3, "validate": False, "no_wait": no_wait,
    }, Console(quiet=True))
    result = await engine.run()
    assert result["shodan_pagination_budget"] == budget
    assert result["ips"] == {}
