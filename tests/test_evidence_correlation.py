"""No-network same-IP correlation regressions for target-agnostic scan outputs."""
import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from rich.console import Console

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "cfunveil"))

from core.correlation import correlate_scan_evidence
from core.shodan_evidence import describe_shodan_match


AS_OF = datetime(2026, 10, 21, tzinfo=timezone.utc)


def banner(hosts, *, target="api.example.co.uk", root="example.co.uk", query="q"):
    return describe_shodan_match(
        {
            "hostnames": hosts, "port": 443, "ip_str": "9.9.9.9",
            "timestamp": "2026-10-19T10:00:00Z",
        },
        target=target, root_domain=root, query=query, strategy="hostname",
    )


def test_exact_current_host_with_related_shodan_never_reclassifies_or_scores():
    target = "api.example.co.uk"
    candidates = {
        "9.9.9.9": {
            "sources": ["DNS"], "confidence": 0.0,
            "verification_status": "not_tested", "confirmed": False,
            "records": [{"domain": target, "record_type": "A"}],
        }
    }
    first = banner([target], query="hostname q1")
    second = {**first, "query": "hostname q2"}
    related = {
        "9.9.9.9": {
            "sources": ["Shodan", "Historical-DNS"],
            "records": [{
                "domain": "portal.example.co.uk",
                "source": "hackertarget", "last_seen": "2026-10-01",
            }],
            "details": {
                "shodan_evidence": [first, second],
                "shodan_observations_truncated": 2,
            },
        }
    }
    before = json.dumps([candidates, related], sort_keys=True)
    result = correlate_scan_evidence(
        target, "example.co.uk", candidates, related, {}, as_of=AS_OF,
    )
    assert json.dumps([candidates, related], sort_keys=True) == before
    entry = result["ips"]["9.9.9.9"]
    assert entry["category"] == "origin_lead"
    assert entry["origin_verified"] is False
    assert entry["source_labels"] == ["DNS", "Historical-DNS", "Shodan"]
    assert entry["evidence_families"] == [
        "current_dns", "related_hostname_records", "shodan_observations",
    ]
    assert entry["exact_target"]["evidence_status"] == "current_dns_observed"
    assert entry["exact_target"]["current_dns_records"] == 1
    assert entry["exact_target"]["historical_records"] == 0
    assert entry["related_host_context"]["hostnames"] == ["portal.example.co.uk"]
    assert entry["related_host_context"]["records"] == 1
    assert entry["related_host_context"]["record_source_labels"] == ["hackertarget"]
    assert entry["shodan_context"] == {
        "retained_query_observations": 2,
        "distinct_banner_observations": 1,
        "observation_relations": ["exact_target_hostname"],
        "omitted_query_observations": 2,
    }
    assert result["summary"]["exact_target_with_shodan_context"] == 1
    assert candidates["9.9.9.9"]["sources"] == ["DNS"]


def test_historical_dates_sources_stale_and_undated_are_not_current_dns():
    target = "app.example.net"
    candidates = {
        "1.1.1.1": {"sources": ["Historical-DNS"], "records": [
            {"domain": target, "source": "securitytrails",
             "last_seen": "2025-01-03T10:00:00Z"},
            {"domain": target, "source": "hackertarget"},
            {"domain": target, "record_type": "A",
             "observation_status": "previous_run"},
        ]}
    }
    result = correlate_scan_evidence(
        target, "example.net", candidates, {}, {}, as_of=AS_OF,
    )
    x = result["ips"]["1.1.1.1"]
    assert x["exact_target"]["historical_records"] == 2
    assert x["exact_target"]["dated_historical_records"] == 1
    assert x["exact_target"]["previous_run_dns_records"] == 1
    assert x["exact_target"]["historical_source_labels"] == [
        "hackertarget", "securitytrails",
    ]
    assert x["exact_target"]["evidence_status"] == "historical_stale"
    assert x["exact_target"]["evidence_last_seen"] == "2025-01-03T10:00:00+00:00"
    assert "previous_run_dns" in x["evidence_families"]
    assert "current_dns" not in x["evidence_families"]


def test_shodan_exact_hostname_without_independent_dns_remains_related():
    target = "api.example.net"
    related = {
        "9.9.9.9": {
            "sources": ["Shodan"],
            "records": [],
            "details": {"shodan_evidence": [
                banner([target], target=target, root="example.net"),
            ]},
        }
    }
    result = correlate_scan_evidence(
        target, "example.net", {}, related, {}, as_of=AS_OF,
    )
    x = result["ips"]["9.9.9.9"]
    assert x["category"] == "related_infrastructure"
    assert x["exact_target"]["evidence_status"] == "no_exact_target_evidence"
    assert x["evidence_families"] == ["shodan_observations"]
    assert result["summary"]["shodan_exact_hostname_without_dns_or_history"] == 1
    assert result["summary"]["exact_target_with_shodan_context"] == 0


def test_cdn_cannot_become_lead_when_shodan_and_historical_context_overlap():
    target = "api.example.net"
    cdn = {
        "104.18.37.240": {
            "sources": ["DNS"], "records": [
                {"domain": target, "record_type": "A"},
            ],
            "confirmed": False,
        },
    }
    related = {
        "104.18.37.240": {
            "sources": ["Shodan", "Historical-DNS"],
            "records": [{
                "domain": "portal.example.net", "source": "urlscan",
                "last_seen": "2026-10-01T00:00:00Z",
            }],
            "details": {"shodan_evidence": [
                banner([target], target=target, root="example.net"),
            ]},
        }
    }
    result = correlate_scan_evidence(
        target, "example.net", {}, related, cdn, as_of=AS_OF,
    )
    assert result["ips"]["104.18.37.240"]["category"] == "cdn_edge"
    assert result["ips"]["104.18.37.240"]["same_ip_multi_family"] is True
    assert result["summary"]["total_correlated_ips"] == 1


def test_private_suffix_lookalikes_and_unscoped_domains_not_correlated():
    target = "service.customer.github.io"
    result = correlate_scan_evidence(
        target, "customer.github.io", {}, {
            "9.9.9.9": {
                "sources": ["Historical-DNS"], "records": [
                    {"domain": "other.github.io", "source": "hackertarget"},
                    {"domain": "evilcustomer.github.io", "source": "hackertarget"},
                    {"domain": "api.customer.github.io", "source": "urlscan"},
                ],
            },
        }, {}, as_of=AS_OF,
    )
    entry = result["ips"]["9.9.9.9"]
    assert entry["category"] == "related_infrastructure"
    assert entry["related_host_context"]["hostnames"] == ["api.customer.github.io"]
    assert entry["exact_target"]["historical_records"] == 0
    assert entry["exact_target"]["evidence_status"] == "no_exact_target_evidence"


def test_input_validations_and_empty_index():
    with pytest.raises(ValueError):
        correlate_scan_evidence("foo.co.uk", "co.uk", {}, {}, {},
                                as_of=datetime(2026, 10, 21))
    with pytest.raises(ValueError):
        correlate_scan_evidence("foo.other.net", "example.net", {}, {}, {},
                                as_of=AS_OF)
    assert correlate_scan_evidence(
        "api.example.net", "example.net", {}, {}, {}, as_of=AS_OF,
    ) == {"ips": {}, "summary": {
        "total_correlated_ips": 0, "multi_family_ips": 0,
        "exact_target_with_shodan_context": 0,
        "shodan_exact_hostname_without_dns_or_history": 0,
    }}


@pytest.mark.parametrize("no_wait", [False, True])
@pytest.mark.asyncio
async def test_engine_correlations_use_hidden_related_ip_and_never_promote(
    no_wait, tmp_path, monkeypatch,
):
    from core.engine import ReconEngine
    from core.dns_enum import DNSEnumerator
    from core.cert_intel import CertIntelligence
    from core.historical import HistoricalSources
    from core.asn_intel import ASNIntelligence
    from core.shodan_pivot import ShodanPivot
    from output.reporter import generate_report

    monkeypatch.chdir(tmp_path)
    target = "api.example.net"
    monkeypatch.setattr(DNSEnumerator, "run", AsyncMock(return_value={
        "ips": ["9.9.9.9"], "cloudflare_ips": [],
        "records": {"9.9.9.9": [{"domain": target, "record_type": "A"}]},
        "subdomains": [target],
    }))
    monkeypatch.setattr(CertIntelligence, "run", AsyncMock(return_value={
        "ips": [], "records": {}, "subdomains": [],
    }))
    monkeypatch.setattr(HistoricalSources, "run", AsyncMock(return_value={
        "ips": {"9.9.9.9": {
            "records": [{
                "domain": "portal.example.net", "source": "hackertarget",
            }],
        }},
    }))
    monkeypatch.setattr(ShodanPivot, "run", AsyncMock(return_value={
        "ips": {"9.9.9.9": {
            "shodan_evidence": [
                banner([target], target=target, root="example.net"),
            ],
            "shodan_relations": ["exact_target_hostname"],
        }},
        "query_metrics": [], "pagination_budget": None,
    }))
    monkeypatch.setattr(ASNIntelligence, "run", AsyncMock(return_value={
        "resolved": {}, "sibling_ips": [],
    }))
    engine = ReconEngine({
        "target": target, "shodan_key": "offline-placeholder",
        "threads": 3, "timeout": 3, "validate": False, "no_wait": no_wait,
    }, Console(quiet=True), evidence_as_of=AS_OF)
    result = await engine.run()
    assert list(result["ips"]) == ["9.9.9.9"]
    assert result["ips"]["9.9.9.9"]["sources"] == ["DNS"]
    assert result["ips"]["9.9.9.9"]["confidence"] == 0
    assert not result["related_infrastructure"]  # same IP filtered here
    x = result["evidence_correlations"]["ips"]["9.9.9.9"]
    assert x["category"] == "origin_lead"
    assert x["exact_target"]["evidence_status"] == "current_dns_observed"
    assert x["related_host_context"]["hostnames"] == ["portal.example.net"]
    assert x["shodan_context"]["distinct_banner_observations"] == 1
    assert x["same_ip_multi_family"] is True
    json_report = tmp_path / "report.json"
    generate_report(result, str(json_report), target)
    assert json.loads(json_report.read_text())["evidence_correlations"]["ips"]["9.9.9.9"] == x


def test_html_correlation_escapes_untrusted_provider_labels(tmp_path):
    from output.reporter import generate_report

    target = "api.example.net"
    candidates = {
        "9.9.9.9": {
            "sources": ["DNS"], "records": [
                {"domain": target, "record_type": "A"},
                {"domain": target, "source": "<script>alert(1)</script>"},
            ],
        },
    }
    related = {
        "9.9.9.9": {
            "sources": ["Shodan"], "details": {
                "shodan_evidence": [banner([target], target=target, root="example.net")],
            },
        },
    }
    correlated = correlate_scan_evidence(
        target, "example.net", candidates, related, {}, as_of=AS_OF,
    )
    path = tmp_path / "report.html"
    generate_report({
        "ips": candidates, "related_infrastructure": {},
        "cdn_edges": {}, "summary": {}, "evidence_correlations": correlated,
    }, str(path), target)
    html = path.read_text()
    assert "Same-IP evidence correlation (not origin proof)" in html
    assert "current_dns_observed" in html
    assert "&lt;script&gt;" in html
    assert "<script>alert(1)</script>" not in html



def test_incomplete_exact_record_cannot_invent_historical_evidence():
    target = "api.example.net"
    result = correlate_scan_evidence(
        target, "example.net", {}, {
            "9.9.9.9": {"sources": ["Unknown"], "records": [
                {"domain": target, "arbitrary": "unattributed"},
            ]},
        }, {}, as_of=AS_OF,
    )
    entry = result["ips"]["9.9.9.9"]
    assert entry["exact_target"]["evidence_status"] == "no_exact_target_evidence"
    assert entry["exact_target"]["historical_records"] == 0
    assert entry["evidence_families"] == []
