"""Read-only, no-network evidence-utility acceptance tests."""
import json
import os
import sys
from copy import deepcopy
from datetime import datetime, timezone

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "cfunveil"))

from audit_evidence import main
from core.evidence_utility import evaluate_evidence_utility


AS_OF = datetime(2026, 10, 21, 20, 0, tzinfo=timezone.utc)


def correlation_row(category, status="no_exact_target_evidence", *,
                    families=(), relations=(), banners=0, siblings=0,
                    dated_history=0):
    return {
        "category": category,
        "same_ip_multi_family": len(families) > 1,
        "evidence_families": list(families),
        "exact_target": {
            "evidence_status": status,
            "dated_historical_records": dated_history,
        },
        "related_host_context": {"records": siblings},
        "shodan_context": {
            "retained_query_observations": banners,
            "distinct_banner_observations": banners,
            "omitted_query_observations": 0,
            "observation_relations": list(relations),
        },
    }


def embedded_report():
    return {
        "target": "api.example.net", "root_domain": "example.net",
        "ips": {},
        "related_infrastructure": {
            "8.8.8.8": {"sources": ["Shodan"]},
            "9.9.9.9": {"sources": ["Shodan"]},
        },
        "cdn_edges": {"104.18.37.240": {"sources": ["DNS"]}},
        "evidence_correlations": {"ips": {
            "8.8.8.8": correlation_row(
                "related_infrastructure",
                families=("related_hostname_records", "shodan_observations"),
                banners=2, siblings=1, relations=("related_hostname",),
            ),
            "9.9.9.9": correlation_row(
                "related_infrastructure",
                families=("shodan_observations",), banners=1,
                relations=("exact_target_hostname",),
            ),
            "104.18.37.240": correlation_row(
                "cdn_edge", "current_dns_observed",
                families=("current_dns", "related_hostname_records"),
                siblings=1,
            ),
        }},
        "shodan_query_metrics": [
            {
                "status": "success", "page": 1,
                "incremental_new_ips": 100,
                "incremental_new_banner_evidence": 100,
            },
            {
                "status": "success", "page": 2,
                "incremental_new_ips": 65,
                "incremental_new_banner_evidence": 70,
            },
            {
                "status": "error", "page": 3,
                "incremental_new_ips": None,
            },
            {"status": "skipped", "page": None},
        ],
        "shodan_pagination_budget": {
            "extra_page_requests_attempted": 2,
            "actual_query_credits_used": None,
        },
    }


def test_realistic_embedded_index_keeps_coverage_separate_from_origin_relevance():
    report = embedded_report()
    original = deepcopy(report)
    audit = evaluate_evidence_utility(report, as_of=AS_OF)
    assert report == original
    assert audit["correlation_basis"] == "embedded_scan_correlations"
    assert audit["discovery_outcomes"] == {
        "origin_leads": 0,
        "reported_confirmed_direct_matches": 0,
        "cdn_edges": 1,
        "related_infrastructure": 2,
        "distinct_ips_in_visible_buckets": 3,
        "ips_in_multiple_visible_buckets": 0,
    }
    ev = audit["correlated_evidence"]
    assert ev["ips_indexed"] == 3
    assert ev["multi_family_ips_by_category"] == {
        "origin_lead": 0, "cdn_edge": 1,
        "related_infrastructure": 1, "unclassified": 0,
    }
    assert ev["ips_with_explicit_exact_hostname_in_shodan"] == 1
    assert ev["ips_with_exact_dns_or_history_and_shodan"] == 0
    assert ev["ips_with_retained_shodan_observations"] == 2
    assert ev["distinct_retained_shodan_banners"] == 3
    assert ev["ips_with_sibling_record_context"] == 2
    assert not any("precision" in k for k in ev)
    assert "precision, recall" in " ".join(audit["interpretation_limits"])
    q = audit["shodan_sample_efficiency"]
    assert q["successful_search_pages"] == 2
    assert q["failed_search_pages"] == 1
    assert q["skipped_searches"] == 1
    assert q["extra_search_pages_returned"] == 1
    assert q["extra_page_attempts_reported"] == 2
    assert q["scan_new_ips_attributed_to_extra_pages"] == 65
    assert q["scan_new_banners_attributed_to_extra_pages"] == 70
    assert q["actual_shodan_query_credits_used"] is None


def test_legacy_report_reconstruction_is_explicit_and_never_promotes():
    target = "api.example.co.uk"
    report = {
        "target": target, "root_domain": "example.co.uk",
        "ips": {}, "cdn_edges": {},
        "related_infrastructure": {
            "8.8.8.8": {"sources": ["Shodan"], "records": [],
                        "details": {"shodan_evidence": [
                            {"query": "q1", "relation": "exact_target_hostname",
                             "port": 443, "hostnames": [target], "observed_at": None},
                            {"query": "q2", "relation": "exact_target_hostname",
                             "port": 443, "hostnames": [target], "observed_at": None},
                        ]}},
            "9.9.9.9": {"sources": ["Historical-DNS"],
                        "records": [{"domain": "portal.example.co.uk",
                                     "source": "hackertarget"}]},
        },
    }
    original = deepcopy(report)
    audit = evaluate_evidence_utility(report, as_of=AS_OF)
    assert report == original
    assert audit["correlation_basis"] == "reconstructed_visible_report_buckets"
    assert "miss" in audit["coverage_caveat"]
    assert audit["discovery_outcomes"]["origin_leads"] == 0
    ev = audit["correlated_evidence"]
    assert ev["ips_with_explicit_exact_hostname_in_shodan"] == 1
    assert ev["ips_with_exact_dns_or_history_and_shodan"] == 0
    assert ev["ips_with_retained_shodan_observations"] == 1
    assert ev["distinct_retained_shodan_banners"] == 1
    assert audit["shodan_sample_efficiency"]["extra_page_attempts_reported"] is None
    assert audit["shodan_sample_efficiency"]["query_page_metrics_present"] is False


def test_exact_historical_stale_is_not_current_or_verified():
    report = {
        "target": "api.example.net", "root_domain": "example.net",
        "ips": {"1.1.1.1": {
            "records": [{"domain": "api.example.net", "source": "securitytrails",
                         "last_seen": "2025-01-15T11:00:00Z"}],
            "sources": ["Historical-DNS"], "confirmed": False,
        }},
    }
    audit = evaluate_evidence_utility(report, as_of=AS_OF)
    ev = audit["correlated_evidence"]
    assert ev["exact_host_evidence_statuses"]["historical_stale"] == 1
    assert ev["ips_with_exact_historical_without_current_dns"] == 1
    assert ev["ips_with_dated_exact_historical_records"] == 1
    assert ev["origin_leads_with_current_dns"] == 0
    assert audit["discovery_outcomes"]["reported_confirmed_direct_matches"] == 0


def test_embedded_correlations_preserve_original_classification_context():
    report = embedded_report()
    report["ips"]["1.1.1.1"] = {
        "sources": ["DNS"], "confirmed": True, "confidence": 0.7,
    }
    report["evidence_correlations"]["ips"]["1.1.1.1"] = correlation_row(
        "origin_lead", "current_dns_observed", families=("current_dns",),
    )
    audit = evaluate_evidence_utility(report, as_of=AS_OF)
    assert audit["discovery_outcomes"]["origin_leads"] == 1
    assert audit["discovery_outcomes"]["reported_confirmed_direct_matches"] == 1
    assert audit["correlated_evidence"]["origin_leads_with_current_dns"] == 1
    assert report["ips"]["1.1.1.1"]["confidence"] == 0.7


def test_unknown_malformed_shodan_data_does_not_invent_a_relevance_signal():
    report = embedded_report()
    entry = report["evidence_correlations"]["ips"]["8.8.8.8"]
    entry["shodan_context"]["observation_relations"] = [{"relation": "exact_target_hostname"}, 42]
    entry["shodan_context"]["distinct_banner_observations"] = -50
    report["shodan_query_metrics"][1]["incremental_new_ips"] = True
    audit = evaluate_evidence_utility(report, as_of=AS_OF)
    assert audit["correlated_evidence"]["ips_with_explicit_exact_hostname_in_shodan"] == 1  # other IP
    assert audit["correlated_evidence"]["distinct_retained_shodan_banners"] == 1
    assert audit["shodan_sample_efficiency"]["scan_new_ips_attributed_to_extra_pages"] == 0


@pytest.mark.parametrize("report", [
    None, [], {}, {"target": "api.example.net"},
    {"target": "api.example.net", "root_domain": "example.net", "ips": []},
    {"target": "api.example.net", "root_domain": "example.net",
     "evidence_correlations": []},
])
def test_invalid_reports_fail_instead_of_silent_zeroes(report):
    with pytest.raises(ValueError):
        evaluate_evidence_utility(report, as_of=AS_OF)


def test_naive_timestamp_rejected_for_legacy_report():
    with pytest.raises(ValueError, match="timezone"):
        evaluate_evidence_utility({
            "target": "api.example.net", "root_domain": "example.net",
        }, as_of=datetime(2026, 10, 21))


def test_cli_json_stdout_no_network_or_report_mutation(tmp_path, capsys):
    path = tmp_path / "existing.json"
    report = embedded_report()
    path.write_text(json.dumps(report), encoding="utf-8")
    before = path.read_bytes()
    assert main([str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["discovery_outcomes"]["related_infrastructure"] == 2
    assert path.read_bytes() == before


def test_cli_legacy_time_option_deterministic(tmp_path, capsys):
    path = tmp_path / "old.json"
    path.write_text(json.dumps({
        "target": "api.example.net", "root_domain": "example.net",
    }))
    assert main([str(path), "--as-of", "2026-10-21T20:00:00Z"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["correlation_basis"] == "reconstructed_visible_report_buckets"
    assert output["discovery_outcomes"]["origin_leads"] == 0
