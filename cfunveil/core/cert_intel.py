"""
core/cert_intel.py - SSL Certificate Transparency Intelligence
Queries crt.sh (free) and Censys (API key optional)
"""

import asyncio
import aiohttp
import ssl
import socket
import re
from rich.console import Console

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


class CertIntelligence:
    def __init__(self, root_domain: str, config: dict, console: Console, session: aiohttp.ClientSession):
        self.root_domain = root_domain
        self.config = config
        self.console = console
        self.session = session
        self.found_ips: set[str] = set()
        self.found_subdomains: set[str] = set()

    async def run(self) -> dict:
        tasks = [
            self._query_crtsh(),
            self._query_crtsh_alt(),       # Second query with wildcard
        ]

        if self.config.get("censys_id") and self.config.get("censys_secret"):
            tasks.append(self._query_censys())

        await asyncio.gather(*tasks, return_exceptions=True)

        # Try to resolve discovered subdomains to IPs
        await self._resolve_subdomains()

        return {
            "ips": list(self.found_ips),
            "subdomains": list(self.found_subdomains),
        }

    async def _query_crtsh(self):
        """Query crt.sh Certificate Transparency logs"""
        try:
            url = f"https://crt.sh/?q={self.root_domain}&output=json"
            from core.utils import http_get_with_retry
            resp = await http_get_with_retry(self.session, url, attempts=3, timeout=20)
            if not resp or resp.status != 200:
                return
            certs = await resp.json(content_type=None)

            for cert in certs:
                name_value = cert.get("name_value", "")
                for entry in name_value.splitlines():
                    entry = entry.strip().lstrip("*.")
                    if entry and self.root_domain in entry:
                        self.found_subdomains.add(entry)
                    # Sometimes IPs appear directly in cert SANs
                    ips = IP_REGEX.findall(entry)
                    self.found_ips.update(ips)

            self.console.print(f"    [dim]crt.sh: {len(certs)} certificates found[/dim]")

        except Exception as e:
            self.console.print(f"    [dim yellow]crt.sh error: {e}[/dim yellow]")

    async def _query_crtsh_alt(self):
        """Query crt.sh for exact subdomain"""
        try:
            url = f"https://crt.sh/?q=%.{self.root_domain}&output=json"
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    return
                certs = await resp.json(content_type=None)

            for cert in certs:
                issuer = cert.get("issuer_name", "")
                name_value = cert.get("name_value", "")
                for entry in name_value.splitlines():
                    entry = entry.strip().lstrip("*.")
                    if entry and self.root_domain in entry:
                        self.found_subdomains.add(entry)

        except Exception:
            pass

    async def _query_censys(self):
        """Query Censys certificates via Platform API (PAT) if available, else fallback to legacy API.

        Uses Personal Access Token (PAT) with Bearer auth and optional X-Organization-ID header.
        """
        try:
            pat = self.config.get("censys_pat")
            org = self.config.get("censys_org")

            # Try Platform API (PAT)
            if pat:
                url = "https://api.platform.censys.io/v1/search/certificates"
                headers = {
                    "Authorization": f"Bearer {pat}",
                    "Accept": "application/vnd.censys.api.v3.certificate.v1+json",
                }
                if org:
                    headers["X-Organization-ID"] = org

                body = {"query": f"parsed.names: {self.root_domain}", "page": 1, "per_page": 100}
                from core.utils import http_post_with_retry
                resp = await http_post_with_retry(self.session, url, json_body=body, headers=headers, attempts=3, timeout=15)
                if resp and resp.status == 200:
                    data = await resp.json()
                    hits = data.get("results") or data.get("hits") or []
                    for hit in hits:
                        names = []
                        parsed = hit.get("parsed") if isinstance(hit.get("parsed"), dict) else None
                        if parsed:
                            names = parsed.get("names", [])
                        names = names or hit.get("names") or []
                        for name in names:
                            if self.root_domain in name:
                                self.found_subdomains.add(name.lstrip("*."))

                    self.console.print(f"    [dim]Censys (Platform API): {len(hits)} cert results[/dim]")
                    return

            # Fallback to legacy Censys v2 (id/secret)
            if self.config.get("censys_id") and self.config.get("censys_secret"):
                import base64
                auth = base64.b64encode(
                    f"{self.config['censys_id']}:{self.config['censys_secret']}".encode()
                ).decode()

                headers = {"Authorization": f"Basic {auth}"}
                url = "https://search.censys.io/api/v2/certificates/search"
                params = {"q": f"parsed.names: {self.root_domain}", "per_page": 100}
                from core.utils import http_get_with_retry
                resp = await http_get_with_retry(self.session, url, headers=headers, params=params, attempts=3, timeout=15)
                if not resp or resp.status != 200:
                    return
                data = await resp.json()

                hits = data.get("result", {}).get("hits", [])
                for hit in hits:
                    names = hit.get("parsed", {}).get("names", [])
                    for name in names:
                        if self.root_domain in name:
                            self.found_subdomains.add(name.lstrip("*."))

                self.console.print(f"    [dim]Censys (legacy): {len(hits)} cert hits[/dim]")

        except Exception as e:
            self.console.print(f"    [dim yellow]Censys error: {e}[/dim yellow]")

    async def _resolve_subdomains(self):
        """Resolve discovered subdomains to IPs"""
        import aiodns
        resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "1.1.1.1"])

        async def resolve_one(sub: str):
            try:
                result = await resolver.query(sub, "A")
                for r in result:
                    self.found_ips.add(r.host)
            except Exception:
                pass

        tasks = [resolve_one(sub) for sub in list(self.found_subdomains)[:200]]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def get_cert_domains_for_ip(self, ip: str) -> list[str]:
        """
        Grab SSL cert from an IP directly and extract SANs.
        Used by validator to confirm origin.
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()
            cert = await loop.run_in_executor(None, self._get_cert_sync, ip)

            domains = []
            for field in cert.get("subjectAltName", []):
                if field[0].lower() == "dns":
                    domains.append(field[1])
            return domains
        except Exception:
            return []

    def _get_cert_sync(self, ip: str) -> dict:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = ctx.wrap_socket(socket.socket(), server_hostname=ip)
        conn.settimeout(5)
        conn.connect((ip, 443))
        cert = conn.getpeercert()
        conn.close()
        return cert
