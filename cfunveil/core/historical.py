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
        self.found_ips: dict[str, dict] = {}

    def _add_historical_ip(self, ip: str, domain: str, source: str, first_seen: str = None, last_seen: str = None):
        """Normalize and aggressively deduplicate historical records."""
        if not ip or not self._is_valid_ip(ip):
            return
            
        if ip not in self.found_ips:
            self.found_ips[ip] = {
                "records": [],
                "sources": set(),
                "oldest_seen": "9999",
                "newest_seen": "0000"
            }
            
        data = self.found_ips[ip]
        if source not in data["sources"]:
            data["sources"].add(source)
            
        # Add record
        record = {"domain": domain, "source": source}
        if first_seen: record["first_seen"] = first_seen
        if last_seen: record["last_seen"] = last_seen
        
        data["records"].append(record)
        
        # Track earliest date (simple string comparison works for most YYYY-MM-DD or YYYY formats)
        if first_seen and first_seen < data["oldest_seen"]:
            data["oldest_seen"] = first_seen
        if last_seen and last_seen > data["newest_seen"]:
            data["newest_seen"] = last_seen

    async def _check_wayback(self):
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.root_domain}&output=json&fl=original,timestamp,statuscode"
        try:
            async with self.session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if len(data) > 1:
                        for row in data[1:]:
                            original_url = row[0]
                            timestamp = row[1]
                            year = timestamp[:4] if len(timestamp) >= 4 else None
                            # parse url and IP if present
                            import urllib.parse
                            parsed = urllib.parse.urlparse(original_url)
                            netloc = parsed.netloc.split(':')[0]
                            if self._is_valid_ip(netloc):
                                self._add_historical_ip(netloc, self.root_domain, "wayback", first_seen=year, last_seen=year)
        except Exception:
            pass

    def _is_valid_ip(self, ip: str) -> bool:
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except Exception:
            return False

    async def run(self) -> dict:
        tasks = [
            self._check_wayback(),
            self._query_hackertarget(),
            self._query_viewdns(),
            self._query_wayback(),
            self._query_threatcrowd(),
            self._query_urlscan(),
            self._query_rapiddns(),
        ]

        if self.config.get("dnsdb_key"):
            tasks.append(self._query_dnsdb())
        if self.config.get("circl_user") and self.config.get("circl_pass"):
            tasks.append(self._query_circl())

        if self.config.get("st_key"):
            tasks.append(self._query_securitytrails())

        await asyncio.gather(*tasks, return_exceptions=True)

        # Convert sets to list for JSON serialization before returning
        for ip, meta in self.found_ips.items():
            meta["sources"] = list(meta["sources"])
            if meta["oldest_seen"] == "9999": meta["oldest_seen"] = None
            if meta["newest_seen"] == "0000": meta["newest_seen"] = None

        return {"ips": self.found_ips}

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
                        sub = parts[0].strip()
                        ip = parts[1].strip()
                        if IP_REGEX.match(ip):
                            self._add_historical_ip(ip, sub, "hackertarget")

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
                    self._add_historical_ip(ip, self.root_domain, "viewdns")

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
                first = record.get("first", "")
                last = record.get("last", "")
                if IP_REGEX.match(address):
                    self._add_historical_ip(address, record.get("hostname", self.root_domain), "alienvault", first_seen=first, last_seen=last)
                    
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
                task = result.get("task", {})
                ip = page.get("ip", "")
                date = task.get("time", "")
                if ip and IP_REGEX.match(ip):
                    self._add_historical_ip(ip, page.get("domain", self.root_domain), "urlscan", first_seen=date, last_seen=date)

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
                        self._add_historical_ip(ip, self.root_domain, "securitytrails", first_seen=record.get("first_seen"), last_seen=record.get("last_seen"))

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

    async def _query_rapiddns(self):
        """RapidDNS — Extracts A records from RapidDNS.io"""
        try:
            url = f"https://rapiddns.io/s/{self.root_domain}?full=1&down=1"
            headers = {"User-Agent": "Mozilla/5.0"}
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return
                csv = await resp.text()

            # Format is CSV-like. We can just run regex.
            # But the columns are usually domain,A,ip
            # We'll just extract IPs and subdomains using regex on lines
            count = 0
            for line in csv.splitlines():
                parts = line.split(',')
                if len(parts) >= 3 and parts[1] == 'A':
                    domain = parts[0].strip()
                    ip = parts[2].strip()
                    if ip and self._is_valid_ip(ip):
                        self._add_historical_ip(ip, domain, "rapiddns")
                        count += 1
            if count > 0:
                self.console.print(f"    [dim]RapidDNS: {count} DNS records[/dim]")
        except Exception as e:
            self.console.print(f"    [dim yellow]RapidDNS: {e}[/dim yellow]")

    async def _query_dnsdb(self):
        """Farsight Security DNSDB"""
        try:
            headers = {
                "X-API-Key": self.config["dnsdb_key"],
                "Accept": "application/json"
            }
            url = f"https://api.dnsdb.info/lookup/rrset/name/{self.root_domain}?limit=100"
            from core.utils import http_get_with_retry
            resp = await http_get_with_retry(self.session, url, headers=headers, attempts=3, timeout=10)
            if not resp or resp.status != 200:
                return
            
            text = await resp.text()
            count = 0
            for line in text.splitlines():
                if not line.strip(): continue
                import json
                try:
                    record = json.loads(line)
                    if record.get("rrtype") == "A":
                        for ip in record.get("rdata", []):
                            if self._is_valid_ip(ip):
                                self._add_historical_ip(ip, record.get("rrname", self.root_domain).rstrip('.'), "dnsdb", 
                                                        first_seen=str(record.get("time_first", "")), 
                                                        last_seen=str(record.get("time_last", "")))
                                count += 1
                except Exception:
                    pass
            self.console.print(f"    [dim]DNSDB: {count} records[/dim]")
        except Exception as e:
            self.console.print(f"    [dim yellow]DNSDB: {e}[/dim yellow]")

    async def _query_circl(self):
        """CIRCL Passive DNS"""
        try:
            import base64
            auth = base64.b64encode(f"{self.config['circl_user']}:{self.config['circl_pass']}".encode()).decode()
            headers = {
                "Authorization": f"Basic {auth}",
                "Accept": "application/json"
            }
            url = f"https://www.circl.lu/pdns/query/{self.root_domain}"
            from core.utils import http_get_with_retry
            resp = await http_get_with_retry(self.session, url, headers=headers, attempts=3, timeout=10)
            if not resp or resp.status != 200:
                return
            
            text = await resp.text()
            count = 0
            for line in text.splitlines():
                if not line.strip(): continue
                import json
                try:
                    record = json.loads(line)
                    if record.get("rrtype") == "A":
                        ip = record.get("rdata")
                        if ip and self._is_valid_ip(ip):
                            self._add_historical_ip(ip, record.get("rrname", self.root_domain), "circl", 
                                                    first_seen=str(record.get("time_first", "")), 
                                                    last_seen=str(record.get("time_last", "")))
                            count += 1
                except Exception:
                    pass
            self.console.print(f"    [dim]CIRCL: {count} records[/dim]")
        except Exception as e:
            self.console.print(f"    [dim yellow]CIRCL: {e}[/dim yellow]")
