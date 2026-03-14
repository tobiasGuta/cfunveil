"""
core/engine.py - Main orchestration engine
Runs all modules concurrently and aggregates results
"""

import asyncio
import aiohttp
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.table import Table

from core.dns_enum import DNSEnumerator
from core.cert_intel import CertIntelligence
from core.shodan_pivot import ShodanPivot
from core.headers_probe import HeadersProbe
from core.asn_intel import ASNIntelligence
from core.historical import HistoricalSources
from core.validator import OriginValidator


class ReconEngine:
    def __init__(self, config: dict, console: Console):
        self.config = config
        self.console = console
        self.target = config["target"]
        # Extract root domain from subdomain
        parts = self.target.split(".")
        self.root_domain = ".".join(parts[-2:]) if len(parts) > 2 else self.target

        self.discovered_ips: dict[str, dict] = {}  # ip -> metadata

    def _add_ip(self, ip: str, source: str, extra: dict = None):
        """Thread-safe IP registration with source tracking"""
        if not ip or not self._is_valid_ip(ip):
            return
        if ip not in self.discovered_ips:
            self.discovered_ips[ip] = {"sources": [], "details": {}}
        if source not in self.discovered_ips[ip]["sources"]:
            self.discovered_ips[ip]["sources"].append(source)
        if extra:
            self.discovered_ips[ip]["details"].update(extra)

    def _is_valid_ip(self, ip: str) -> bool:
        import re
        pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if not re.match(pattern, ip):
            return False
        parts = ip.split(".")
        return all(0 <= int(p) <= 255 for p in parts)

    async def run(self) -> dict:
        results = {
            "target": self.target,
            "root_domain": self.root_domain,
            "subdomains": [],
            "ips": {},
            "validated_origins": [],
            "asn_data": {},
            "summary": {}
        }

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
                self._add_ip(ip, "Email-Header")

            # ── Module 1: DNS Enumeration ─────────────────────────────
            self.console.print("[bold green][1/6][/bold green] DNS Enumeration & Subdomain Harvest...")
            dns_enum = DNSEnumerator(self.target, self.root_domain, self.console)
            dns_results = await dns_enum.run()

            for ip in dns_results.get("ips", []):
                self._add_ip(ip, "DNS")
            results["subdomains"] = dns_results.get("subdomains", [])
            self.console.print(f"    [dim]Found {len(dns_results.get('ips', []))} IPs, "
                               f"{len(dns_results.get('subdomains', []))} subdomains[/dim]")

            # ── Module 2: SSL Certificate Intelligence ───────────────
            self.console.print("[bold green][2/6][/bold green] SSL Certificate Transparency (crt.sh + Censys)...")
            cert_intel = CertIntelligence(
                self.root_domain, self.config, self.console, session
            )
            cert_results = await cert_intel.run()

            for ip in cert_results.get("ips", []):
                self._add_ip(ip, "SSL-Cert")
            results["subdomains"] = list(set(
                results["subdomains"] + cert_results.get("subdomains", [])
            ))
            self.console.print(f"    [dim]Found {len(cert_results.get('ips', []))} IPs from cert data[/dim]")

            # ── Module 3: Shodan Pivot ───────────────────────────────
            if self.config.get("shodan_key"):
                self.console.print("[bold green][3/6][/bold green] Shodan Intelligence Pivot...")
                shodan = ShodanPivot(
                    self.target, self.root_domain, self.config, self.console
                )
                shodan_results = await shodan.run()

                for ip, meta in shodan_results.get("ips", {}).items():
                    self._add_ip(ip, "Shodan", meta)
                self.console.print(
                    f"    [dim]Shodan returned {len(shodan_results.get('ips', {}))} IPs[/dim]"
                )
            else:
                self.console.print("[bold yellow][3/6][/bold yellow] Shodan — [dim]skipped (no API key)[/dim]")

            # ── Module 4: Historical Sources ─────────────────────────
            self.console.print("[bold green][4/6][/bold green] Historical DNS & Passive Sources...")
            historical = HistoricalSources(
                self.root_domain, self.config, self.console, session
            )
            hist_results = await historical.run()

            for ip in hist_results.get("ips", []):
                self._add_ip(ip, "Historical-DNS")
            self.console.print(
                f"    [dim]Historical sources found {len(hist_results.get('ips', []))} IPs[/dim]"
            )

            # ── Module 5: ASN Intelligence ──────────────────────────
            self.console.print("[bold green][5/6][/bold green] ASN & BGP Intelligence...")
            all_ips = list(self.discovered_ips.keys())
            asn_intel = ASNIntelligence(all_ips, self.console, session)
            asn_results = await asn_intel.run()

            results["asn_data"] = asn_results
            # Add any sibling IPs found through ASN expansion
            for ip in asn_results.get("sibling_ips", []):
                self._add_ip(ip, "ASN-Expansion")
            self.console.print(
                f"    [dim]Resolved ASN for {len(asn_results.get('resolved', {}))} IPs[/dim]"
            )

            # ── Module 6: Origin Validation ─────────────────────────
            self.console.print("[bold green][6/6][/bold green] Validating Origin IPs...")
            if not self.config.get("validate"):
                self.console.print("    [dim]Validation skipped (--no-validate)[/dim]")
                results["ips"] = {ip: {**meta, "confidence": 0, "validated": False}
                                  for ip, meta in self.discovered_ips.items()}
            else:
                validator = OriginValidator(
                    self.target,
                    self.root_domain,
                    self.console,
                    session,
                    concurrency=self.config.get("validation_concurrency", 10),
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

        # ── Summary ─────────────────────────────────────────────────
        results["summary"] = {
            "total_ips_found": len(self.discovered_ips),
            "confirmed_origins": len(results.get("validated_origins", [])),
            "total_subdomains": len(results["subdomains"]),
            "sources_used": self._get_sources_used(),
        }

        return results

    def _get_sources_used(self) -> list[str]:
        sources = set()
        for ip_data in self.discovered_ips.values():
            sources.update(ip_data.get("sources", []))
        return list(sources)
