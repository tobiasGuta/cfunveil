"""
core/historical.py - Historical DNS & Passive Sources
Aggregates IPs from multiple free historical DNS sources
"""

import asyncio
import aiohttp
import re
from rich.console import Console

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


class HistoricalSources:
    def __init__(self, root_domain: str, config: dict, console: Console, session: aiohttp.ClientSession):
        self.root_domain = root_domain
        self.config = config
        self.console = console
        self.session = session
        self.found_ips: set[str] = set()

    async def run(self) -> dict:
        tasks = [
            self._query_hackertarget(),
            self._query_viewdns(),
            self._query_wayback(),
            self._query_threatcrowd(),
            self._query_urlscan(),
        ]

        if self.config.get("st_key"):
            tasks.append(self._query_securitytrails())

        await asyncio.gather(*tasks, return_exceptions=True)

        return {"ips": list(self.found_ips)}

    async def _query_hackertarget(self):
        """HackerTarget free API — DNS history"""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.root_domain}"
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return
                text = await resp.text()

            # Format: subdomain,ip
            for line in text.splitlines():
                if "," in line:
                    parts = line.split(",")
                    if len(parts) == 2:
                        ip = parts[1].strip()
                        if IP_REGEX.match(ip):
                            self.found_ips.add(ip)

            self.console.print(f"    [dim]HackerTarget: done[/dim]")
        except Exception as e:
            self.console.print(f"    [dim yellow]HackerTarget: {e}[/dim yellow]")

    async def _query_viewdns(self):
        """ViewDNS.info IP History — finds historical A records"""
        try:
            url = f"https://viewdns.info/iphistory/?domain={self.root_domain}"
            headers = {"User-Agent": "Mozilla/5.0 (compatible; recon/1.0)"}
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return
                html = await resp.text()

            # Extract IPs from the HTML table
            ips = IP_REGEX.findall(html)
            for ip in ips:
                # Filter out page IPs (viewdns servers etc)
                octets = ip.split(".")
                if octets[0] not in ["0", "127", "10", "192", "172"]:
                    self.found_ips.add(ip)

            self.console.print(f"    [dim]ViewDNS: done[/dim]")
        except Exception as e:
            self.console.print(f"    [dim yellow]ViewDNS: {e}[/dim yellow]")

    async def _query_wayback(self):
        """
        Wayback Machine CDX API — extract IPs from X-Forwarded-For,
        X-Real-IP headers stored in archive responses.
        Old captures often have real backend IPs in headers.
        """
        try:
            url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={self.root_domain}/*"
                f"&output=json&limit=50&fl=statuscode,timestamp,original"
                f"&filter=statuscode:200"
            )
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()

            # Just log count for now — actual header extraction needs per-URL fetch
            if data and len(data) > 1:
                self.console.print(f"    [dim]Wayback: {len(data)-1} archived URLs[/dim]")

        except Exception:
            pass

    async def _query_threatcrowd(self):
        """ThreatCrowd (AlienVault) — DNS resolution history"""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.root_domain}/passive_dns"
            headers = {"User-Agent": "Mozilla/5.0"}
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()

            passive_dns = data.get("passive_dns", [])
            for record in passive_dns:
                address = record.get("address", "")
                if IP_REGEX.match(address):
                    self.found_ips.add(address)
                    
            self.console.print(f"    [dim]AlienVault OTX: {len(passive_dns)} DNS records[/dim]")

        except Exception as e:
            self.console.print(f"    [dim yellow]AlienVault: {e}[/dim yellow]")

    async def _query_urlscan(self):
        """urlscan.io — extracts real IPs from past scans"""
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.root_domain}&size=50"
            headers = {"User-Agent": "Mozilla/5.0"}
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()

            results = data.get("results", [])
            for result in results:
                # urlscan records the actual server IP at scan time
                page = result.get("page", {})
                ip = page.get("ip", "")
                if ip and IP_REGEX.match(ip):
                    self.found_ips.add(ip)

            self.console.print(f"    [dim]urlscan.io: {len(results)} scan results[/dim]")

        except Exception as e:
            self.console.print(f"    [dim yellow]urlscan.io: {e}[/dim yellow]")

    async def _query_securitytrails(self):
        """SecurityTrails API — best historical DNS data (requires API key)"""
        try:
            headers = {
                "APIKEY": self.config["st_key"],
                "Content-Type": "application/json",
            }

            # Historical DNS records
            url = f"https://api.securitytrails.com/v1/history/{self.root_domain}/dns/a"
            from core.utils import http_get_with_retry
            resp = await http_get_with_retry(self.session, url, headers=headers, attempts=3, timeout=10)
            if not resp or resp.status != 200:
                return
            data = await resp.json()

            records = data.get("records", [])
            for record in records:
                for value in record.get("values", []):
                    ip = value.get("ip", "")
                    if ip:
                        self.found_ips.add(ip)

            self.console.print(f"    [dim]SecurityTrails: {len(records)} historical A records[/dim]")

            # Also get subdomains
            url2 = f"https://api.securitytrails.com/v1/domain/{self.root_domain}/subdomains"
            resp2 = await http_get_with_retry(self.session, url2, headers=headers, attempts=3, timeout=10)
            if resp2 and resp2.status == 200:
                data2 = await resp2.json()
                subdomains = data2.get("subdomains", [])
                self.console.print(f"    [dim]SecurityTrails: {len(subdomains)} subdomains found[/dim]")

        except Exception as e:
            self.console.print(f"    [dim yellow]SecurityTrails: {e}[/dim yellow]")
