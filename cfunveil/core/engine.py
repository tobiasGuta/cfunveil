"""
core/engine.py - Main orchestration engine
Runs all modules concurrently and aggregates results
"""

import asyncio
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.table import Table

# Defer imports of heavy optional modules until runtime to improve import-time
# resilience (avoids requiring all optional deps just to import the engine).


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
        # Accept both IPv4 and IPv6 using the stdlib `ipaddress` module
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except Exception:
            return False

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
                self._add_ip(ip, "Email-Header")

            # ── Module 1: DNS Enumeration ─────────────────────────────
            self.console.print("[bold green][1/6][/bold green] DNS Enumeration & Subdomain Harvest...")
            from core.dns_enum import DNSEnumerator
            dns_enum = DNSEnumerator(self.target, self.root_domain, self.console)
            dns_results = await dns_enum.run()

            for ip in dns_results.get("ips", []):
                self._add_ip(ip, "DNS")
            results["subdomains"] = dns_results.get("subdomains", [])
            self.console.print(f"    [dim]Found {len(dns_results.get('ips', []))} IPs, "
                               f"{len(dns_results.get('subdomains', []))} subdomains[/dim]")

            # ── Module 2: SSL Certificate Intelligence ───────────────
            self.console.print("[bold green][2/6][/bold green] SSL Certificate Transparency (crt.sh + Censys)...")
            from core.cert_intel import CertIntelligence
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
                self.root_domain, self.config, self.console, session
            )

            if self.config.get("no_wait"):
                # Start long-running tasks concurrently
                tasks = []
                if shodan:
                    shodan_task = asyncio.create_task(shodan.run())
                    tasks.append(shodan_task)
                if fofa:
                    fofa_task = asyncio.create_task(fofa.run())
                    tasks.append(fofa_task)
                if zoomeye:
                    zoomeye_task = asyncio.create_task(zoomeye.run())
                    tasks.append(zoomeye_task)
                hist_task = asyncio.create_task(historical.run())
                tasks.append(hist_task)

                # Print interim summary while these run
                self.console.print("    [dim]Interim summary (continuing long scans in background)...[/dim]")
                self.console.print(f"    [dim]IPs discovered so far: {len(self.discovered_ips)}[/dim]")

                # Collect results as tasks finish, ensure we don't skip any results
                for finished in asyncio.as_completed(tasks):
                    try:
                        res = await finished
                    except Exception as e:
                        self.console.print(f"    [dim yellow]A background module failed: {e}[/dim yellow]")
                        continue

                    # Identify which task finished
                    if finished is shodan_task:
                        shodan_results = res or {}
                        for ip, meta in shodan_results.get("ips", {}).items():
                            self._add_ip(ip, "Shodan", meta)
                        self.console.print(f"    [dim]Shodan returned {len(shodan_results.get('ips', {}))} IPs[/dim]")
                    elif finished is fofa_task:
                        fofa_results = res or {}
                        for ip, meta in fofa_results.get("ips", {}).items():
                            self._add_ip(ip, "FOFA", meta)
                        self.console.print(f"    [dim]FOFA returned {len(fofa_results.get('ips', {}))} IPs[/dim]")
                    elif finished is zoomeye_task:
                        zoomeye_results = res or {}
                        for ip, meta in zoomeye_results.get("ips", {}).items():
                            self._add_ip(ip, "ZoomEye", meta)
                        self.console.print(f"    [dim]ZoomEye returned {len(zoomeye_results.get('ips', {}))} IPs[/dim]")
                    elif finished is hist_task:
                        hist_results = res or {}
                        if isinstance(hist_results.get("ips"), dict):
                            for ip, meta in hist_results.get("ips", {}).items():
                                self._add_ip(ip, "Historical-DNS", meta)
                        else:
                            for ip in hist_results.get("ips", []):
                                self._add_ip(ip, "Historical-DNS")
                        self.console.print(f"    [dim]Historical sources found {len(hist_results.get('ips', []))} IPs[/dim]")

            else:
                # Blocking (original) behavior
                if shodan:
                    shodan_results = await shodan.run()
                    for ip, meta in shodan_results.get("ips", {}).items():
                        self._add_ip(ip, "Shodan", meta)
                    self.console.print(
                        f"    [dim]Shodan returned {len(shodan_results.get('ips', {}))} IPs[/dim]"
                    )
                else:
                    self.console.print("[bold yellow][3/6][/bold yellow] Shodan — [dim]skipped (no API key)[/dim]")

                if fofa:
                    fofa_results = await fofa.run()
                    for ip, meta in fofa_results.get("ips", {}).items():
                        self._add_ip(ip, "FOFA", meta)
                    self.console.print(f"    [dim]FOFA returned {len(fofa_results.get('ips', {}))} IPs[/dim]")

                if zoomeye:
                    zoomeye_results = await zoomeye.run()
                    for ip, meta in zoomeye_results.get("ips", {}).items():
                        self._add_ip(ip, "ZoomEye", meta)
                    self.console.print(f"    [dim]ZoomEye returned {len(zoomeye_results.get('ips', {}))} IPs[/dim]")

                hist_results = await historical.run()
                if isinstance(hist_results.get("ips"), dict):
                    for ip, meta in hist_results.get("ips", {}).items():
                        self._add_ip(ip, "Historical-DNS", meta)
                else:
                    for ip in hist_results.get("ips", []):
                        self._add_ip(ip, "Historical-DNS")
                self.console.print(
                    f"    [dim]Historical sources found {len(hist_results.get('ips', []))} IPs[/dim]"
                )

            # ── Module 5: ASN Intelligence ──────────────────────────
            self.console.print("[bold green][5/6][/bold green] ASN & BGP Intelligence...")
            all_ips = list(self.discovered_ips.keys())
            from core.asn_intel import ASNIntelligence
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
                from core.validator import OriginValidator
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
