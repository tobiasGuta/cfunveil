"""Offline, read-only evidence utility audit for saved CFUnveil JSON reports.

An audit reports descriptive observations and *never* scores candidates,
discovers addresses, proves origin ownership, or authorizes active requests.
There are deliberately no network, Shodan, or third-party imports here.
"""
from collections import Counter
from datetime import datetime, timezone

from core.correlation import correlate_scan_evidence


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _number(value):
    # Ignore booleans and malformed/negative counts from untrusted input.
    return value if type(value) is int and value >= 0 else 0


def _rows(value):
    return value if isinstance(value, list) else []


def _safe_relations(entry):
    values = _mapping(entry.get("shodan_context", {})).get("observation_relations", [])
    return set(values) if isinstance(values, list) else set()


def evaluate_evidence_utility(report: dict, *, as_of=None) -> dict:
    """Audit an existing report without modifying it or initiating I/O.

    Embedded correlations represent the original completed scan. Legacy
    reports lack the hidden related-IP bucket, so rehydration from visible
    buckets can undercount same-IP overlaps. The fallback's time is the
    supplied audit time, not necessarily the original scan time.
    """
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")
    target = report.get("target")
    root = report.get("root_domain")
    if not isinstance(target, str) or not isinstance(root, str):
        raise ValueError("report must contain target and root_domain strings")
    buckets = {}
    for key in ("ips", "related_infrastructure", "cdn_edges"):
        value = report.get(key, {})
        if not isinstance(value, dict):
            raise ValueError(f"{key} must be a JSON object")
        buckets[key] = value

    embedded = report.get("evidence_correlations")
    if embedded is not None:
        if not isinstance(embedded, dict) or not isinstance(embedded.get("ips"), dict):
            raise ValueError("embedded evidence_correlations must have an ips object")
        correlated = embedded
        basis = "embedded_scan_correlations"
    else:
        as_of = as_of or datetime.now(timezone.utc)
        if as_of.tzinfo is None:
            raise ValueError("as_of must be timezone-aware")
        correlated = correlate_scan_evidence(
            target, root, buckets["ips"], buckets["related_infrastructure"],
            buckets["cdn_edges"], as_of=as_of,
        )
        basis = "reconstructed_visible_report_buckets"

    entries = _mapping(correlated.get("ips"))
    by_category = Counter()
    statuses = Counter()
    family_counts = Counter()
    cross_family_categories = Counter()
    with_shodan = 0
    explicit_exact_shodan = 0
    with_sibling_context = 0
    banner_observations = 0
    omitted_banners = 0
    with_exact_and_shodan = 0
    historical_only_exact = 0
    dated_historical_ips = 0
    candidates_with_current_dns = 0

    for ip, raw in entries.items():
        if not isinstance(raw, dict):
            continue
        category = raw.get("category")
        if category not in ("origin_lead", "cdn_edge", "related_infrastructure"):
            category = "unclassified"
        by_category[category] += 1

        exact = _mapping(raw.get("exact_target"))
        status = exact.get("evidence_status", "unknown")
        if not isinstance(status, str):
            status = "unknown"
        statuses[status] += 1
        if category == "origin_lead" and status == "current_dns_observed":
            candidates_with_current_dns += 1
        if status in ("historical_recent", "historical_stale", "historical_undated"):
            historical_only_exact += 1
        if _number(exact.get("dated_historical_records")):
            dated_historical_ips += 1

        families = raw.get("evidence_families", [])
        if isinstance(families, list):
            for family in set(f for f in families if isinstance(f, str)):
                family_counts[family] += 1
        if raw.get("same_ip_multi_family") is True:
            cross_family_categories[category] += 1

        siblings = _mapping(raw.get("related_host_context"))
        if _number(siblings.get("records")) > 0:
            with_sibling_context += 1

        shodan = _mapping(raw.get("shodan_context"))
        banners = _number(shodan.get("distinct_banner_observations"))
        retained = _number(shodan.get("retained_query_observations"))
        banner_observations += banners
        omitted_banners += _number(shodan.get("omitted_query_observations"))
        relations = _safe_relations(raw)
        if retained:
            with_shodan += 1
            if status != "no_exact_target_evidence" and status != "unknown":
                with_exact_and_shodan += 1
        if "exact_target_hostname" in relations:
            explicit_exact_shodan += 1

    query_rows = _rows(report.get("shodan_query_metrics"))
    succeeded = [
        x for x in query_rows if isinstance(x, dict) and x.get("status") == "success"
    ]
    additional = [x for x in succeeded
                  if type(x.get("page")) is int and x["page"] > 1]
    failures = sum(
        isinstance(x, dict) and x.get("status") == "error"
        for x in query_rows
    )
    skipped = sum(
        isinstance(x, dict) and x.get("status") == "skipped"
        for x in query_rows
    )
    budget = _mapping(report.get("shodan_pagination_budget"))

    # Read actual bucket membership, not heuristic inference from correlations.
    verified_as_reported = sum(
        isinstance(value, dict) and value.get("confirmed") is True
        for value in buckets["ips"].values()
    )
    overlapping_bucket_ips = (
        (set(buckets["ips"]) & set(buckets["related_infrastructure"]))
        | (set(buckets["ips"]) & set(buckets["cdn_edges"]))
        | (set(buckets["related_infrastructure"]) & set(buckets["cdn_edges"]))
    )
    return {
        "schema_version": 1,
        "target": target,
        "correlation_basis": basis,
        "coverage_caveat": (
            "Embedded scan correlations include hidden same-IP context."
            if basis == "embedded_scan_correlations" else
            "Legacy reconstruction can miss related evidence filtered out of "
            "the original report; historical recency uses audit time."
        ),
        "discovery_outcomes": {
            "origin_leads": len(buckets["ips"]),
            "reported_confirmed_direct_matches": verified_as_reported,
            "cdn_edges": len(buckets["cdn_edges"]),
            "related_infrastructure": len(buckets["related_infrastructure"]),
            "distinct_ips_in_visible_buckets": len(
                set(buckets["ips"]) | set(buckets["related_infrastructure"])
                | set(buckets["cdn_edges"])
            ),
            "ips_in_multiple_visible_buckets": len(overlapping_bucket_ips),
        },
        "correlated_evidence": {
            "ips_indexed": sum(by_category.values()),
            "by_existing_category": {
                name: by_category[name] for name in
                ("origin_lead", "cdn_edge", "related_infrastructure", "unclassified")
            },
            "multi_family_ips_by_category": {
                name: cross_family_categories[name] for name in
                ("origin_lead", "cdn_edge", "related_infrastructure", "unclassified")
            },
            "exact_host_evidence_statuses": dict(sorted(statuses.items())),
            "evidence_family_ip_counts": dict(sorted(family_counts.items())),
            "origin_leads_with_current_dns": candidates_with_current_dns,
            "ips_with_exact_historical_without_current_dns": historical_only_exact,
            "ips_with_dated_exact_historical_records": dated_historical_ips,
            "ips_with_sibling_record_context": with_sibling_context,
            "ips_with_retained_shodan_observations": with_shodan,
            "ips_with_explicit_exact_hostname_in_shodan": explicit_exact_shodan,
            "ips_with_exact_dns_or_history_and_shodan": with_exact_and_shodan,
            "distinct_retained_shodan_banners": banner_observations,
            "omitted_shodan_query_observations": omitted_banners,
        },
        "shodan_sample_efficiency": {
            "successful_search_pages": len(succeeded),
            "failed_search_pages": failures,
            "skipped_searches": skipped,
            "extra_search_pages_returned": len(additional),
            "extra_page_attempts_reported": (
                _number(budget["extra_page_requests_attempted"])
                if "extra_page_requests_attempted" in budget else None
            ),
            "scan_new_ips_attributed_to_extra_pages": sum(
                _number(r.get("incremental_new_ips")) for r in additional
            ),
            "scan_new_banners_attributed_to_extra_pages": sum(
                _number(r.get("incremental_new_banner_evidence"))
                for r in additional
            ),
            "actual_shodan_query_credits_used": None,
        },
        "interpretation_limits": [
            "Recorded multiple evidence families do not establish independent providers.",
            "No ground-truth labels are available: precision, recall and origin correctness cannot be inferred.",
            "Shodan banner observations lack page identity: page-level exact-host relevance is not measurable from this report.",
            "Report categories and confirmed flags are existing scan outputs, not revalidated by this audit.",
        ],
    }
