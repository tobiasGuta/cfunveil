"""
core/engine.py - Main orchestration engine
Runs all modules concurrently and aggregates results
"""

import json
import os
import re
import asyncio
from datetime import datetime, timezone
from core.evidence import (
    _CURRENT_DNS_TYPES,
    classify_target_evidence,
    invalidate_restored_dns_evidence,
)
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.table import Table

# Defer imports of heavy optional modules until runtime to improve import-time
# resilience (avoids requiring all optional deps just to import the engine).


class ReconEngine:
    def __init__(self, config: dict, console: Console, *, evidence_as_of=None):
        self.evidence_as_of = evidence_as_of or datetime.now(timezone.utc)
        self.config = config
        self.console = console
        self.target = config["target"].rstrip(".").lower()
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z0-9-]{2,63}", self.target):
            raise ValueError("target must be a valid domain name, not a URL or path")
        # Suffix-aware scope selection is essential for .co.uk and private
        # suffixes (e.g. example.github.io). An invalid root must fail closed:
        # never broaden a requested hostname into a public suffix.
        from core.scope import registrable_domain
        self.root_domain = registrable_domain(self.target)
        self.discovered_ips: dict[str, dict] = {}
        self.related_ips: dict[str, dict] = {}
        self.cdn_edges: dict[str, dict] = {}
        # Version the checkpoint filename so earlier, overinclusive scan states
        # cannot silently reintroduce unrelated origin candidates.
        self.session_file = f"cfunveil_{self.target.replace('.', '_')}_session_v6.json"
        self.completed_modules: set[str] = set()
        self.subdomains: set[str] = set()

        if self.config.get("resume") and os.path.exists(self.session_file):
            with open(self.session_file, "r", encoding="utf-8") as f:
                state = json.load(f)
            if state.get("target") != self.target or state.get("version") != 6:
                raise ValueError("Session target/version mismatch; start a new scan")
            self.discovered_ips = state.get("discovered_ips", {})
            self.related_ips = state.get("related_ips", {})
            self.cdn_edges = state.get("cdn_edges", {})
            self.completed_modules = set(state.get("completed_modules", []))
            self.subdomains = set(state.get("subdomains", []))
            # A checkpoint's DNS/cert-hostname address evidence is historical
            # by definition. Preserve it as previous-run evidence, refresh both
            # resolving modules, and avoid reusing a stale subdomain inventory.
            for registry in (self.discovered_ips, self.related_ips, self.cdn_edges):
                invalidate_restored_dns_evidence(
                    registry, self.target, as_of=self.evidence_as_of,
                )
            self.completed_modules.difference_update({"dns", "ssl"})
            self.subdomains.clear()
            self.console.print(
                "[green][+] Restored prior evidence; DNS and certificate-hostname "
                "addresses will be refreshed[/green]"
            )

    def _save_session(self):
        """Atomically checkpoint discoveries without ever clearing them."""
        import tempfile
        state = {
            "version": 6,
            "target": self.target,
            "discovered_ips": self.discovered_ips,
            "related_ips": self.related_ips,
            "cdn_edges": self.cdn_edges,
            "completed_modules": sorted(self.completed_modules),
            "subdomains": sorted(self.subdomains),
        }
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=".", prefix=".cfunveil-", delete=False
            ) as f:
                temp_path = f.name
                json.dump(state, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.session_file)
        except OSError as exc:
            self.console.print(f"[yellow][!] Could not save session: {exc}[/yellow]")
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

    def _add_ip(self, ip: str, source: str, extra: dict | None = None,
                *, category: str = "candidate"):
        """Merge source evidence, keeping provenance and candidate types separate."""
        if not ip or not self._is_valid_ip(ip):
            return
        groups = {
            "candidate": self.discovered_ips,
            "related": self.related_ips,
            "cdn": self.cdn_edges,
        }
        if category not in groups:
            raise ValueError(f"Unknown candidate category: {category}")
        registry = groups[category]
        data = registry.setdefault(ip, {"sources": [], "details": {}, "records": []})
        if source not in data["sources"]:
            data["sources"].append(source)
        for record in (extra or {}).get("records", []):
            if not isinstance(record, dict):
                continue
            if (
                record.get("record_type") in _CURRENT_DNS_TYPES
                and record.get("observation_status") != "previous_run"
            ):
                # A new observation supersedes a copy of this same exact
                # record retained from an earlier scan. Bound report size.
                data["records"] = [
                    old for old in data["records"]
                    if not (
                        isinstance(old, dict)
                        and old.get("observation_status") == "previous_run"
                        and old.get("record_type") == record.get("record_type")
                        and old.get("domain") == record.get("domain")
                    )
                ]
            if record not in data["records"]:
                data["records"].append(dict(record))
        if extra:
            details = {
                key: value for key, value in extra.items()
                if key not in ("records", "sources")
            }
            data["details"].update(details)
        if category == "candidate":
            data.update(classify_target_evidence(
                self.target, data["records"], as_of=self.evidence_as_of,
            ))

    def _add_historical_ip(self, ip: str, meta: dict):
        """Promote only historical records explicitly bound to the scan host."""
        from core.dns_enum import is_cloudflare_ip
        records = meta.get("records", [])
        exact_target = any(
            (record.get("domain") or "").lower().rstrip(".") == self.target
            for record in records
            if isinstance(record, dict)
        )
        if is_cloudflare_ip(ip):
            # An address in Cloudflare's ranges is only a *target CDN edge*
            # when its provenance names the requested host. A CDN address
            # seen only under an unrelated sibling is related infrastructure.
            category = "cdn" if exact_target or ip in self.cdn_edges else "related"
        else:
            category = "candidate" if exact_target else "related"
        self._add_ip(ip, "Historical-DNS", meta, category=category)

    def _attach_related_shodan_context(self):
        """Expose same-IP Shodan evidence without promoting its provenance.

        Related discovery may overlap a separately verified exact-host DNS/
        historical IP or a target CDN edge. Keep that context available in the
        surviving bucket while leaving the candidate's source list and
        verification score grounded only in its independent origin evidence.
        """
        for registry in (self.discovered_ips, self.cdn_edges):
            for ip, candidate in registry.items():
                related = self.related_ips.get(ip)
                if not isinstance(related, dict):
                    continue
                details = related.get("details", {})
                if not isinstance(details, dict) or "shodan_evidence" not in details:
                    continue
                target_details = candidate.setdefault("details", {})
                for key in (
                    "shodan_evidence", "shodan_relations",
                    "shodan_observations_truncated",
                ):
                    if key in details:
                        target_details[key] = details[key]
                candidate["context_sources"] = sorted(set(
                    candidate.get("context_sources", ())
                ) | set(related.get("sources", ())))

    def _is_valid_ip(self, ip: str) -> bool:
        # Accept both IPv4 and IPv6 using the stdlib `ipaddress` module
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except Exception:
            return False

    async def run(self) -> dict:
        # Never mix an unverified passive-source connector with an active
        # verification run, including when this engine is used outside CLI.
        if self.config.get("validate") and self.config.get("verify_ssl") is False:
            raise ValueError(
                "--insecure is only supported with --no-validate; "
                "TLS verification is required for origin confirmation"
            )
        results = {
            "target": self.target,
            "root_domain": self.root_domain,
            "subdomains": [],
            "ips": {},
            "related_infrastructure": {},
            "cdn_edges": {},
            "shodan_query_metrics": [],
            "validated_origins": [],
            "asn_data": {},
            "summary": {}
        }

        # Respect verify_ssl config: when False, disable SSL verification on connector
        # Import aiohttp lazily to avoid requiring it at module import time
        try:
            import aiohttp
        except Exception:
            raise RuntimeError("Required dependency `aiohttp` is not installed. Install it with `pip install aiohttp` to run scans.")

        # Respect verify_ssl config: when False, disable SSL verification on connector
        if self.config.get("verify_ssl") is False:
            connector = aiohttp.TCPConnector(
                limit=self.config["threads"],
                ssl=False,
                force_close=True
            )
        else:
            connector = aiohttp.TCPConnector(
                limit=self.config["threads"],
                force_close=True
            )
        timeout = aiohttp.ClientTimeout(total=self.config["timeout"])

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

            # If initial IPs were provided (email headers), register them first
            for ip in self.config.get("initial_ips", []):
                self._add_ip(ip, "Email-Header", category="related")

            # ── Module 1: DNS Enumeration ─────────────────────────────
            if 'dns' not in self.completed_modules:
                self.console.print("[bold green][1/6][/bold green] DNS Enumeration & Subdomain Harvest...")
                from core.dns_enum import DNSEnumerator
                dns_enum = DNSEnumerator(self.target, self.root_domain, self.console)
                dns_results = await dns_enum.run()

                # Root-domain enumeration also finds sibling hostnames. Their
                # addresses cannot become origin leads for the requested apex.
                # Missing hostname evidence is likewise insufficient.
                from core.dns_enum import is_cloudflare_ip
                for ip in set(dns_results.get("ips", [])) | set(
                    dns_results.get("cloudflare_ips", [])
                ):
                    records = dns_results.get("records", {}).get(ip, [])
                    exact = any(
                        isinstance(record, dict)
                        and str(record.get("domain", "")).lower().rstrip(".") == self.target
                        for record in records
                    )
                    category = (
                        ("cdn" if is_cloudflare_ip(ip) else "candidate")
                        if exact else "related"
                    )
                    self._add_ip(ip, "DNS", {"records": records}, category=category)
                self.subdomains.update(dns_results.get("subdomains", []))
                self.console.print(f"    [dim]Found {len(dns_results.get('ips', []))} IPs, "
                                   f"{len(dns_results.get('subdomains', []))} subdomains[/dim]")
                self.completed_modules.add('dns')
                self._save_session()
            else:
                self.console.print("[dim][1/6] DNS Enumeration (Skipped - restored from session)[/dim]")
            results["subdomains"] = list(self.subdomains)

            # ── Module 2: SSL Certificate Intelligence ───────────────
            if 'ssl' not in self.completed_modules:
                self.console.print("[bold green][2/6][/bold green] SSL Certificate Transparency (crt.sh + Censys)...")
                from core.cert_intel import CertIntelligence
                cert_intel = CertIntelligence(
                    self.root_domain, self.config, self.console, session, target=self.target
                )
                cert_results = await cert_intel.run()

                from core.dns_enum import is_cloudflare_ip
                for ip in cert_results.get("ips", []):
                    records = cert_results.get("records", {}).get(ip, [])
                    exact = any(r.get("domain") == self.target for r in records)
                    category = (
                        "cdn" if exact and is_cloudflare_ip(ip)
                        else "candidate" if exact else "related"
                    )
                    self._add_ip(ip, "SSL-Cert", {"records": records}, category=category)
                self.subdomains.update(cert_results.get("subdomains", []))
                self.console.print(f"    [dim]Found {len(cert_results.get('ips', []))} IPs from cert data[/dim]")
                self.completed_modules.add('ssl')
                self._save_session()
            else:
                self.console.print("[dim][2/6] SSL Certificate Intelligence (Skipped - restored from session)[/dim]")
            results["subdomains"] = list(self.subdomains)

            # Prepare tasks for Shodan and Historical. In --no-wait mode we'll start them
            # concurrently and print an interim summary before awaiting their completion.
            shodan = None
            shodan_task = None
            if self.config.get("shodan_key"):
                from core.shodan_pivot import ShodanPivot
                shodan = ShodanPivot(
                    self.target, self.root_domain, self.config, self.console
                )

            fofa = None
            fofa_task = None
            if self.config.get("fofa_email") and self.config.get("fofa_key"):
                from core.osint_pivot import FOFAPivot
                fofa = FOFAPivot(self.target, self.root_domain, self.config, self.console, session)

            zoomeye = None
            zoomeye_task = None
            if self.config.get("zoomeye_key"):
                from core.osint_pivot import ZoomEyePivot
                zoomeye = ZoomEyePivot(self.target, self.root_domain, self.config, self.console, session)

            self.console.print("[bold green][3/6][/bold green] Shodan & OSINT Intelligence Pivot...")

            self.console.print("[bold green][4/6][/bold green] Historical DNS & Passive Sources...")
            from core.historical import HistoricalSources
            historical = HistoricalSources(
                self.root_domain, self.config, self.console, session, target=self.target
            )

            if self.config.get("no_wait"):
                async def run_named(name, source):
                    return name, await source.run()

                tasks = [
                    asyncio.create_task(run_named(name, source))
                    for name, source in [
                        ("shodan", shodan),
                        ("fofa", fofa),
                        ("zoomeye", zoomeye),
                        ("historical", historical),
                    ] if source is not None
                ]
                for completed in asyncio.as_completed(tasks):
                    try:
                        name, payload = await completed
                    except Exception as exc:
                        self.console.print(f"[yellow][!] Intelligence module failed: {exc}[/yellow]")
                        continue
                    payload = payload or {}
                    if name == "shodan":
                        results["shodan_query_metrics"] = payload.get("query_metrics", [])
                    if name == "historical":
                        found = payload.get("ips", {})
                        iterator = found.items() if isinstance(found, dict) else ((ip, {}) for ip in found)
                        for ip, meta in iterator:
                            self._add_historical_ip(ip, meta)
                    else:
                        for ip, meta in payload.get("ips", {}).items():
                            self._add_ip(ip, {"shodan": "Shodan", "fofa": "FOFA", "zoomeye": "ZoomEye"}[name], meta, category="related")
            else:
                # Blocking (original) behavior
                if shodan:
                    shodan_results = await shodan.run()
                    results["shodan_query_metrics"] = shodan_results.get("query_metrics", [])
                    for ip, meta in shodan_results.get("ips", {}).items():
                        self._add_ip(ip, "Shodan", meta, category="related")
                    self.console.print(
                        f"    [dim]Shodan returned {len(shodan_results.get('ips', {}))} IPs[/dim]"
                    )
                else:
                    self.console.print("[bold yellow][3/6][/bold yellow] Shodan — [dim]skipped (no API key)[/dim]")

                if fofa:
                    fofa_results = await fofa.run()
                    for ip, meta in fofa_results.get("ips", {}).items():
                        self._add_ip(ip, "FOFA", meta, category="related")
                    self.console.print(f"    [dim]FOFA returned {len(fofa_results.get('ips', {}))} IPs[/dim]")

                if zoomeye:
                    zoomeye_results = await zoomeye.run()
                    for ip, meta in zoomeye_results.get("ips", {}).items():
                        self._add_ip(ip, "ZoomEye", meta, category="related")
                    self.console.print(f"    [dim]ZoomEye returned {len(zoomeye_results.get('ips', {}))} IPs[/dim]")

                hist_results = await historical.run()
                if isinstance(hist_results.get("ips"), dict):
                    for ip, meta in hist_results.get("ips", {}).items():
                        self._add_historical_ip(ip, meta)
                else:
                    for ip in hist_results.get("ips", []):
                        self._add_ip(ip, "Historical-DNS", category="related")
                self.console.print(
                    f"    [dim]Historical sources found {len(hist_results.get('ips', []))} IPs[/dim]"
                )

            # Historical and Shodan evidence survive even if it refers to
            # the same IP as independently attributed target evidence.
            self._attach_related_shodan_context()
            self._save_session()

            # ── Module 5: ASN Intelligence ──────────────────────────
            self.console.print("[bold green][5/6][/bold green] ASN & BGP Intelligence...")
            all_ips = list(self.discovered_ips.keys())
            from core.asn_intel import ASNIntelligence
            asn_intel = ASNIntelligence(all_ips, self.console, session)
            asn_results = await asn_intel.run()

            results["asn_data"] = asn_results
            # ASN information enriches observed addresses but never creates leads.
            self.console.print(
                f"    [dim]Resolved ASN for {len(asn_results.get('resolved', {}))} exact-target candidate IPs[/dim]"
            )

            # ── Module 6: Origin Validation ─────────────────────────
            self.console.print("[bold green][6/6][/bold green] Validating Origin IPs...")
            if not self.config.get("validate"):
                self.console.print("    [dim]Validation skipped (--no-validate)[/dim]")
                results["ips"] = {ip: {**meta, "confidence": 0.0, "validated": False, "confirmed": False, "verification_status": "not_tested"}
                                  for ip, meta in self.discovered_ips.items()}
            else:
                from core.validator import OriginValidator
                validator = OriginValidator(
                    self.target,
                    self.root_domain,
                    self.console,
                    session,
                    concurrency=self.config.get("validation_concurrency", 10),
                    authorized_cidrs=self.config.get("authorized_cidrs", ()),
                )
                validated = await validator.validate_all(self.discovered_ips)
                results["ips"] = validated

                origins = [
                    ip for ip, data in validated.items()
                    if data.get("confirmed", False)
                ]
                results["validated_origins"] = origins
                self.console.print(
                    f"    [dim]Confirmed {len(origins)} origin IP(s)[/dim]"
                )

        # Classify unrelated-sibling and CDN evidence outside the origin shortlist.
        results["related_infrastructure"] = {
            ip: meta for ip, meta in self.related_ips.items()
            if ip not in self.discovered_ips and ip not in self.cdn_edges
        }
        results["cdn_edges"] = self.cdn_edges

        # ── Summary ─────────────────────────────────────────────────
        results["summary"] = {
            "total_ips_found": len(self.discovered_ips),
            "confirmed_origins": len(results.get("validated_origins", [])),
            "related_ip_count": len(results["related_infrastructure"]),
            "cdn_edge_count": len(self.cdn_edges),
            "total_subdomains": len(results["subdomains"]),
            "sources_used": self._get_sources_used(),
        }

        return results

    def _get_sources_used(self) -> list[str]:
        sources = set()
        for registry in (self.discovered_ips, self.related_ips, self.cdn_edges):
            for ip_data in registry.values():
                sources.update(ip_data.get("sources", []))
        return list(sources)
