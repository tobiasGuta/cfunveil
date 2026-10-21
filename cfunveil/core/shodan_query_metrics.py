"""Offline, target-agnostic accounting for Shodan search effectiveness.

These are *observed, bounded query samples*, not comprehensive Shodan coverage
or measurements of actual provider credits. Query-order dependent and
order-independent contributions are explicitly separated.
"""
import json
from collections import Counter


def _banner_key(ip, observation):
    """Identify the underlying banner evidence without its search query/strategy.

    Different searches returning the same observed banner should not increase
    evidence diversity. Different hostnames, ports, timestamps, certificate
    data, or service attributes can contribute independent *observations*,
    but they never become independent proof of origin attribution.
    """
    keys = (
        "hostnames", "certificate_names", "observed_at", "port",
        "product", "version", "jarm",
    )
    return json.dumps(
        [ip, {key: observation.get(key) for key in keys}],
        sort_keys=True, ensure_ascii=True, default=str,
    )


class ShodanQueryMetrics:
    def __init__(self):
        self._rows = []
        self._ip_sets = []
        self._evidence_sets = []
        self._seen_ips = set()
        self._seen_evidence = set()

    def success(self, *, strategy, query, limit, matches, accepted, provider_total, page=1):
        """Record one completed client search invocation.

        'accepted' contains (IP, normalized observation) for matches retained
        after non-target-specific source filtering; rejected responses are
        counted separately, not silently promoted.
        """
        ips = {ip for ip, _ in accepted}
        evidence = {_banner_key(ip, observation) for ip, observation in accepted}
        self._rows.append({
            "strategy": strategy,
            "query": query,
            "page": page,
            "status": "success",
            "error_type": None,
            "result_limit": limit,
            "limit_reached": len(matches) >= limit,
            "provider_total": provider_total,
            "returned_matches": len(matches),
            "accepted_matches": len(accepted),
            "unique_ips": len(ips),
            "incremental_new_ips": len(ips - self._seen_ips),
            "exclusive_ips": 0,  # computed across all completed queries
            "shared_ips": 0,
            "unique_banner_evidence": len(evidence),
            "incremental_new_banner_evidence": len(evidence - self._seen_evidence),
            "exclusive_banner_evidence": 0,
            "shared_banner_evidence": 0,
            # Shodan search results do not report actual consumed credits.
            # Do not mistake the configured result limit for the credit cost.
            "query_credits_used": None,
        })
        self._ip_sets.append(ips)
        self._evidence_sets.append(evidence)
        self._seen_ips.update(ips)
        self._seen_evidence.update(evidence)

    def failure(self, *, strategy, query, limit, error_type, page=1):
        self._rows.append({
            "strategy": strategy, "query": query, "page": page, "status": "error",
            "error_type": error_type, "result_limit": limit,
            "limit_reached": None, "provider_total": None,
            "returned_matches": None, "accepted_matches": None,
            "unique_ips": None, "incremental_new_ips": None,
            "exclusive_ips": None, "shared_ips": None,
            "unique_banner_evidence": None,
            "incremental_new_banner_evidence": None,
            "exclusive_banner_evidence": None, "shared_banner_evidence": None,
            "query_credits_used": None,
        })
        self._ip_sets.append(set())
        self._evidence_sets.append(set())

    def skipped(self, *, strategy, reason, query=None, page=None, limit=None):
        self.failure(
            strategy=strategy, query=query, limit=limit, error_type=None,
            page=page,
        )
        self._rows[-1]["status"] = "skipped"
        self._rows[-1]["skip_reason"] = reason

    def mark_stop(self, reason):
        """Annotate the most recent page outcome with its pagination stop."""
        if self._rows:
            self._rows[-1]["pagination_stop_reason"] = reason

    def snapshot(self):
        ip_frequency = Counter(ip for ips in self._ip_sets for ip in ips)
        evidence_frequency = Counter(ev for keys in self._evidence_sets for ev in keys)
        rows = []
        for row, ips, evidence in zip(
            self._rows, self._ip_sets, self._evidence_sets,
        ):
            result = row.copy()
            if result["status"] == "success":
                result["exclusive_ips"] = sum(ip_frequency[ip] == 1 for ip in ips)
                result["shared_ips"] = sum(ip_frequency[ip] > 1 for ip in ips)
                result["exclusive_banner_evidence"] = sum(
                    evidence_frequency[key] == 1 for key in evidence
                )
                result["shared_banner_evidence"] = sum(
                    evidence_frequency[key] > 1 for key in evidence
                )
            rows.append(result)
        return rows
