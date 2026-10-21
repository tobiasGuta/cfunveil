"""Offline, time-controlled discovery replay through CFUnveil's source parsers.

No external network calls are made: DNS, urlscan, and crt.sh are replaced with
in-memory fixtures. The selected IPv4 literals are illustrative only and are
never contacted.
"""
import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from core.cert_intel import CertIntelligence
from core.dns_enum import DNSEnumerator, is_cloudflare_ip
from core.engine import ReconEngine
from core.historical import HistoricalSources

TARGET = "api.fixture.example"
ROOT = "fixture.example"
AS_OF = datetime(2026, 10, 21, tzinfo=timezone.utc)
CURRENT_IP = "54.20.40.10"
OLD_IP = "54.20.40.11"
NEW_IP = "54.20.40.12"
SIBLING_IP = "54.20.40.13"
HISTORY_IP = "54.20.40.14"
UNKNOWN_IP = "54.20.40.15"
CDN_IP = "104.18.37.240"


class _Response:
    status = 200

    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def json(self, **kwargs):
        return self.value


async def _replay(*, current=(), scans=(), certificates=()):
    class FakeResolver:
        def __init__(self, *args, **kwargs):
            self.nameservers = []

        async def query(self, domain, kind):
            if domain == TARGET and kind == "A" and current:
                return [SimpleNamespace(host=ip) for ip in current]
            raise LookupError("No answer in the offline fixture")

    class FakeSession:
        def get(self, url, **kwargs):
            assert url.startswith("https://urlscan.io/api/v1/search/")
            return _Response({
                "results": [
                    {
                        "page": {"ip": item["ip"], "domain": item["domain"]},
                        "task": {"time": item.get("seen", "")},
                    } for item in scans
                ]
            })

    async def fake_cert_request(session, url, **kwargs):
        assert url.startswith("https://crt.sh/")
        assert "api.fixture.example" in url
        return _Response([
            {"name_value": "\n".join(certificates)}
        ])

    with patch("core.dns_enum.aiodns.DNSResolver", FakeResolver), patch(
        "core.utils.http_get_with_retry", fake_cert_request,
    ):
        dns = await DNSEnumerator(TARGET, ROOT, Console(quiet=True)).run()
        historical = HistoricalSources(
            ROOT, {}, Console(quiet=True), FakeSession(), target=TARGET,
        )
        await historical._query_urlscan()
        cert = CertIntelligence(
            ROOT, {}, Console(quiet=True), None, target=TARGET,
        )
        await cert._query_crtsh()
        await cert._resolve_subdomains()

    # Reserved .example domains exist only inside our offline fixtures.
    with patch("core.scope.registrable_domain", return_value=ROOT):
        engine = ReconEngine(
            {"target": TARGET}, Console(quiet=True), evidence_as_of=AS_OF,
        )
    # Match the orchestration engine's real ingestion and categorization.
    for ip in dns.get("ips", []):
        engine._add_ip(ip, "DNS", {"records": dns["records"].get(ip, [])})
    for ip in dns.get("cloudflare_ips", []):
        engine._add_ip(ip, "DNS", {
            "records": dns["records"].get(ip, []),
        }, category="cdn")
    for ip in cert.found_ips:
        records = cert.records.get(ip, [])
        exact = any(r.get("domain") == TARGET for r in records)
        category = (
            "cdn" if is_cloudflare_ip(ip)
            else "candidate" if exact else "related"
        )
        engine._add_ip(ip, "SSL-Cert", {"records": records}, category=category)
    for ip, metadata in historical.found_ips.items():
        engine._add_historical_ip(ip, metadata)

    return {
        "candidate_states": {
            ip: data.get("evidence_status") for ip, data in sorted(engine.discovered_ips.items())
        },
        "last_seen": {
            ip: data.get("evidence_last_seen") for ip, data in sorted(engine.discovered_ips.items())
        },
        "target_cdn_edges": sorted(engine.cdn_edges),
        "related_infrastructure": sorted(engine.related_ips),
        "cert_hostnames": sorted(cert.found_subdomains),
        "records": {ip: data.get("records", []) for ip, data in engine.discovered_ips.items()},
    }


async def run_benchmark():
    # 1. A currently resolved origin candidate, with a matching cert name.
    current = await _replay(
        current=[CURRENT_IP], certificates=[TARGET, "www.fixture.example"],
        scans=[{"ip": CURRENT_IP, "domain": TARGET, "seen": "2026-10-20T05:30:00Z"}],
    )
    # 2. DNS points to a new IP; the former target IP is still visible
    # through a 2023 passive source, but must retain its stale label.
    moved = await _replay(
        current=[NEW_IP], certificates=[TARGET],
        scans=[{"ip": OLD_IP, "domain": TARGET, "seen": "2023-07-15T09:30:00Z"}],
    )
    # 3. A wildcard for children of the target is NOT evidence for the target;
    # a sibling SAN/historical hostname cannot become an exact-host lead.
    misleading = await _replay(
        current=[CDN_IP],
        certificates=["internal.fixture.example", "*.api.fixture.example"],
        scans=[
            {"ip": SIBLING_IP, "domain": "internal.fixture.example", "seen": "2026-10-20T12:00:00Z"},
            {"ip": "54.20.40.99", "domain": "third-party.example", "seen": "2026-10-20T12:00:00Z"},
        ],
    )
    # 4. Even recent passive history is only an observed lead, not current
    # DNS. Missing timestamps must not be guessed to be recent.
    recent = await _replay(
        scans=[
            {"ip": HISTORY_IP, "domain": TARGET, "seen": "2026-10-18T12:00:00Z"},
            {"ip": UNKNOWN_IP, "domain": TARGET},
        ],
    )
    report = {
        "benchmark": "offline_temporal_discovery_replay",
        "as_of_utc": AS_OF.isoformat(),
        "scope": "offline DNS, urlscan and certificate parser fixtures; zero external requests",
        "scenarios": {
            "current_dns": current,
            "moved_origin": moved,
            "misleading_sibling_and_certificate": misleading,
            "recent_and_undated_history": recent,
        },
        "checks": {
            "current_ip_current_dns": current["candidate_states"].get(CURRENT_IP) == "current_dns_observed",
            "current_ip_has_host_certificate": TARGET in current["cert_hostnames"],
            "current_ip_has_two_sources": len(current["records"].get(CURRENT_IP, [])) >= 2,
            "new_ip_current_dns": moved["candidate_states"].get(NEW_IP) == "current_dns_observed",
            "old_ip_preserved_as_stale": moved["candidate_states"].get(OLD_IP) == "historical_stale",
            "old_ip_last_seen_preserved": moved["last_seen"].get(OLD_IP) == "2023-07-15T09:30:00+00:00",
            "no_unrelated_candidate": misleading["candidate_states"] == {},
            "sibling_only_related": SIBLING_IP in misleading["related_infrastructure"],
            "third_party_rejected": "54.20.40.99" not in misleading["related_infrastructure"],
            "cdn_classified": misleading["target_cdn_edges"] == [CDN_IP],
            "misleading_cert_not_target": TARGET not in misleading["cert_hostnames"],
            "recent_history_not_current_dns": recent["candidate_states"].get(HISTORY_IP) == "historical_recent",
            "undated_history_not_current_dns": recent["candidate_states"].get(UNKNOWN_IP) == "historical_undated",
        },
        "limitations": [
            "Recorded origin knowledge and IP assignments are fixture inputs, not externally discovered facts",
            "Recent passive records do not prove current origin ownership or service reachability",
            "No origin validation is performed; use the separate HTTPS loopback benchmark",
            "The replay tests selected parsers and engine ingestion, not live DNS/provider reliability",
        ],
    }
    return report


if __name__ == "__main__":
    import json
    print(json.dumps(asyncio.run(run_benchmark()), indent=2, sort_keys=True))
