"""Read-only cross-source context for CFUnveil discovery results.

This module does not discover IPs, classify leads, calculate confidence,
authorize connections, or infer an origin from independent-looking provider
observations. Same-IP correlation is contextual, never origin proof.
"""
import json
from datetime import datetime, timezone

from core.evidence import (
    _CURRENT_DNS_TYPES, classify_target_evidence, parse_observation_time,
)
from core.shodan_query_metrics import _banner_key


_SHODAN_RELATIONS = frozenset({
    "exact_target_hostname", "related_hostname", "fingerprint_only", "query_only",
})


def _name(value):
    return value.strip().lower().rstrip(".") if isinstance(value, str) else ""


def _in_scope(name, root_domain):
    return name == root_domain or name.endswith("." + root_domain)


def _canonical(value):
    return json.dumps(value, sort_keys=True, default=str, ensure_ascii=True)


def _entries(*values):
    return (v for v in values if isinstance(v, dict))


def _sources(data):
    values = list(data.get("sources", ())) + list(data.get("context_sources", ()))
    return {s for s in values if isinstance(s, str) and s.strip()}


def correlate_scan_evidence(
    target: str, root_domain: str, candidates: dict,
    related: dict, cdn_edges: dict, *, as_of=None,
) -> dict:
    """Construct a separate, deterministic correlation index for all IP buckets.

    Reads overlapping related-bucket records even when that IP is also a
    candidate or CDN edge and therefore hidden from the final related table.
    Doesn't touch its inputs or copy correlation fields into scoring data.
    """
    as_of = as_of or datetime.now(timezone.utc)
    if as_of.tzinfo is None:
        raise ValueError("as_of must be timezone-aware")
    as_of = as_of.astimezone(timezone.utc)
    target, root_domain = _name(target), _name(root_domain)
    if not target or not root_domain or not _in_scope(target, root_domain):
        raise ValueError("target must be inside the supplied scan scope")

    correlations = {}
    ip_keys = sorted(set(candidates) | set(related) | set(cdn_edges))
    for ip in ip_keys:
        category = (
            "origin_lead" if ip in candidates
            else "cdn_edge" if ip in cdn_edges
            else "related_infrastructure"
        )
        data_sets = list(_entries(
            candidates.get(ip), related.get(ip), cdn_edges.get(ip),
        ))
        sources = set()
        records = {}
        observations = {}
        omitted_shodan = 0
        for data in data_sets:
            sources.update(_sources(data))
            for record in data.get("records", []):
                if isinstance(record, dict):
                    records[_canonical(record)] = record
            details = data.get("details", {})
            if not isinstance(details, dict):
                continue
            for item in details.get("shodan_evidence", []):
                if isinstance(item, dict):
                    observations[_canonical(item)] = item
            # A Shodan context copied to another category should not double
            # count its per-IP truncation number.
            count = details.get("shodan_observations_truncated", 0)
            if type(count) is int and count > omitted_shodan:
                omitted_shodan = count

        current_dns = set()
        previous_dns = set()
        historical = set()
        dated_historical = set()
        historical_providers = set()
        related_hostnames = set()
        exact_records = []
        for signature, record in records.items():
            name = _name(record.get("domain"))
            if not name or not _in_scope(name, root_domain):
                continue
            if name != target:
                related_hostnames.add(name)
                continue
            kind = record.get("record_type")
            exact_records.append(record)
            if kind in _CURRENT_DNS_TYPES:
                if record.get("observation_status") == "previous_run":
                    previous_dns.add(signature)
                else:
                    current_dns.add(signature)
            elif isinstance(record.get("source"), str) and record["source"].strip():
                historical.add(signature)
                historical_providers.add(record["source"])
                time = parse_observation_time(record.get("last_seen"))
                if time is not None and time <= as_of:
                    dated_historical.add(signature)

        relations = {
            item.get("relation") for item in observations.values()
            if item.get("relation") in _SHODAN_RELATIONS
        }
        banner_signatures = {
            _banner_key(ip, item) for item in observations.values()
        }
        if current_dns:
            exact_status = "current_dns_observed"
            last_seen = None
        else:
            status = classify_target_evidence(
                target, exact_records, as_of=as_of,
            )
            exact_status, last_seen = (
                status["evidence_status"], status["evidence_last_seen"],
            )

        families = []
        if current_dns:
            families.append("current_dns")
        if previous_dns:
            families.append("previous_run_dns")
        if historical:
            families.append("historical_dns")
        if observations:
            families.append("shodan_observations")
        if sources & {"FOFA", "ZoomEye", "Email-Header"}:
            families.append("other_passive_context")

        correlations[ip] = {
            "category": category,
            "source_labels": sorted(sources),
            "evidence_families": families,
            "same_ip_multi_family": len(families) > 1,
            "exact_target": {
                "evidence_status": exact_status,
                "evidence_last_seen": last_seen,
                "current_dns_records": len(current_dns),
                "previous_run_dns_records": len(previous_dns),
                "historical_records": len(historical),
                "dated_historical_records": len(dated_historical),
                "historical_source_labels": sorted(historical_providers),
            },
            "related_host_context": {
                "hostnames": sorted(related_hostnames)[:32],
                "omitted_hostnames": max(0, len(related_hostnames) - 32),
            },
            "shodan_context": {
                "retained_query_observations": len(observations),
                "distinct_banner_observations": len(banner_signatures),
                "observation_relations": sorted(relations),
                "omitted_query_observations": omitted_shodan,
                # Queries and observation counts are never treated as
                # independent evidence providers or an origin confidence.
            },
            "origin_verified": any(bool(x.get("confirmed")) for x in
                                   _entries(candidates.get(ip))),
        }

    return {
        "ips": correlations,
        "summary": {
            "total_correlated_ips": len(correlations),
            "multi_family_ips": sum(
                x["same_ip_multi_family"] for x in correlations.values()
            ),
            "exact_target_with_shodan_context": sum(
                x["shodan_context"]["retained_query_observations"] > 0 and
                x["exact_target"]["evidence_status"] != "no_exact_target_evidence"
                for x in correlations.values()
            ),
            "shodan_exact_hostname_without_dns_or_history": sum(
                "exact_target_hostname" in x["shodan_context"]["observation_relations"]
                and x["exact_target"]["evidence_status"] == "no_exact_target_evidence"
                for x in correlations.values()
            ),
        },
    }
