"""
core/engine.py - Main orchestration engine
Runs all modules concurrently and aggregates results
"""

import json
import os
import re
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
        self.target = config["target"].rstrip(".").lower()
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9-]{2,63}", self.target):
            raise ValueError("target must be a valid domain name, not a URL or path")
        parts = self.target.rstrip(".").lower().split(".")
        if len(parts) < 2 or not all(parts):
            raise ValueError("target must be a domain name")
        self.root_domain = ".".join(parts[-2:])
        self.discovered_ips: dict[str, dict] = {}
        self.session_file = f"cfunveil_{self.target.replace('.', '_')}_session.json"
        self.completed_modules: set[str] = set()
        self.subdomains: set[str] = set()

        if self.config.get("resume") and os.path.exists(self.session_file):
            with open(self.session_file, "r", encoding="utf-8") as f:
                state = json.load(f)
            if state.get("target") != self.target or state.get("version") != 1:
                raise ValueError("Session target/version mismatch; start a new scan")
            self.discovered_ips = state.get("discovered_ips", {})
            self.completed_modules = set(state.get("completed_modules", []))
            self.subdomains = set(state.get("subdomains", []))
            self.console.print(f"[green][+] Restored {len(self.completed_modules)} completed modules[/green]")

    def _save_session(self):
        """Atomically checkpoint discoveries without ever clearing them."""
        import tempfile
        state = {
            "version": 1,
            "target": self.target,
            "discovered_ips": self.discovered_ips,
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
            if 'dns' not in self.completed_modules:
                self.console.print("[bold green][1/6][/bold green] DNS Enumeration & Subdomain Harvest...")
                from core.dns_enum import DNSEnumerator
                dns_enum = DNSEnumerator(self.target, self.root_domain, self.console)
                dns_results = await dns_enum.run()

                for ip in dns_results.get("ips", []):
                    self._add_ip(ip, "DNS")
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
                    self.root_domain, self.config, self.console, session
                )
                cert_results = await cert_intel.run()

                for ip in cert_results.get("ips", []):
                    self._add_ip(ip, "SSL-Cert")
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
                self.root_domain, self.config, self.console, session
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
                    if name == "historical":
                        found = payload.get("ips", {})
                        iterator = found.items() if isinstance(found, dict) else ((ip, {}) for ip in found)
                        for ip, meta in iterator:
                            self._add_ip(ip, "Historical-DNS", meta)
                    else:
                        for ip, meta in payload.get("ips", {}).items():
                            self._add_ip(ip, {"shodan": "Shodan", "fofa": "FOFA", "zoomeye": "ZoomEye"}[name], meta)
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
