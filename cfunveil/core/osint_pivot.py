"""
core/osint_pivot.py - Expanded OSINT sources (FOFA, ZoomEye)
Provides internet-wide scanning datasets partially independent of Shodan.
"""

import aiohttp
import base64
import asyncio
from rich.console import Console

class FOFAPivot:
    def __init__(self, target: str, root_domain: str, config: dict, console: Console, session: aiohttp.ClientSession):
        self.root_domain = root_domain
        self.config = config
        self.console = console
        self.session = session
        self.fofa_email = config.get("fofa_email")
        self.fofa_key = config.get("fofa_key")
        self.found_ips = {}
        import logging
        self.logger = logging.getLogger("cfunveil.fofa")

    async def run(self) -> dict:
        if not self.fofa_email or not self.fofa_key:
            return {"ips": {}}
            
        queries = [
            f'domain="{self.root_domain}"',
            f'cert="{self.root_domain}"'
        ]
        
        for q in queries:
            qbase64 = base64.b64encode(q.encode()).decode()
            url = f"https://fofa.info/api/v1/search/all?email={self.fofa_email}&key={self.fofa_key}&qbase64={qbase64}&size=100&fields=ip,port,host,country,org"
            try:
                self.console.print(f"    [dim]FOFA: {q}...[/dim]")
                async with self.session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if not data.get("error"):
                            for row in data.get("results", []):
                                ip, port, host, country, org = row
                                if "cloudflare" not in (org or "").lower() and ip:
                                    self.found_ips[ip] = {
                                        "org": org,
                                        "country": country,
                                        "ports": [port] if port else [],
                                        "hostnames": [host] if host else []
                                    }
            except Exception as e:
                self.logger.debug(f"FOFA query failed: {e}")
                
        return {"ips": self.found_ips}


class ZoomEyePivot:
    def __init__(self, target: str, root_domain: str, config: dict, console: Console, session: aiohttp.ClientSession):
        self.root_domain = root_domain
        self.config = config
        self.console = console
        self.session = session
        self.zoomeye_key = config.get("zoomeye_key")
        self.found_ips = {}
        import logging
        self.logger = logging.getLogger("cfunveil.zoomeye")

    async def run(self) -> dict:
        if not self.zoomeye_key:
            return {"ips": {}}
            
        queries = [
            f'site:"{self.root_domain}"',
            f'ssl:"{self.root_domain}"'
        ]
        headers = {"API-KEY": self.zoomeye_key}
        
        for q in queries:
            import urllib.parse
            url = f"https://api.zoomeye.org/host/search?query={urllib.parse.quote(q)}"
            try:
                self.console.print(f"    [dim]ZoomEye: {q}...[/dim]")
                async with self.session.get(url, headers=headers, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for match in data.get("matches", []):
                            ip = match.get("ip")
                            org = match.get("geoinfo", {}).get("organization", "")
                            if "cloudflare" not in org.lower() and ip:
                                self.found_ips[ip] = {
                                    "org": org,
                                    "country": match.get("geoinfo", {}).get("country", {}).get("names", {}).get("en", ""),
                                    "ports": [match.get("portinfo", {}).get("port")]
                                }
            except Exception as e:
                self.logger.debug(f"ZoomEye query failed: {e}")

        return {"ips": self.found_ips}
