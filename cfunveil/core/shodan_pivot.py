"""
core/shodan_pivot.py - Shodan Intelligence Pivot
Full Shodan API integration with premium student key support
Multiple search strategies to find origin IPs
"""

import asyncio
import shodan
from rich.console import Console


# CloudFlare's ASN to exclude from results
CF_ASNS = {"AS13335", "AS209242"}


class ShodanPivot:
    def __init__(self, target: str, root_domain: str, config: dict, console: Console):
        self.target = target
        self.root_domain = root_domain
        self.config = config
        self.console = console
        self.api = shodan.Shodan(config["shodan_key"])
        self.found_ips: dict[str, dict] = {}
        import logging
        self.logger = logging.getLogger("cfunveil.shodan")
        # allow overriding CF ASNs via config
        custom = config.get("cf_asns")
        if custom:
            try:
                self.cf_asns = set([c.strip() for c in custom])
            except Exception:
                self.cf_asns = CF_ASNS
        else:
            self.cf_asns = CF_ASNS

    async def run(self) -> dict:
        """Run all Shodan search strategies concurrently"""
        loop = asyncio.get_event_loop()

        # strategies: list of (name, func, args_tuple)
        strategies = [
            ("SSL cert pivot (no CF)", self._ssl_cert_pivot, None),
            ("Hostname search", self._hostname_search, None),
            ("HTTP title/body search", self._http_search, None),
            ("Favicon hash search", self._favicon_search, None),
        ]

        if self.config.get("deep"):
            strategies += [
                ("Headers fingerprint", self._headers_search, None),
                ("ASN expansion", self._asn_search, None),
                ("Copyright search", self._copyright_search, (self.config.get("copyright"),)),
            ]

        for name, strategy, args in strategies:
            try:
                self.console.print(f"    [dim]Shodan: {name}...[/dim]")
                if args:
                    await loop.run_in_executor(None, strategy, *args)
                else:
                    await loop.run_in_executor(None, strategy)
            except shodan.APIError as e:
                msg = str(e)
                if "query credits" in msg.lower():
                    self.console.print(f"    [yellow]Shodan: query credits low — stopping[/yellow]")
                    break
                self.console.print(f"    [dim yellow]Shodan {name}: {e}[/dim yellow]")
                self.logger.debug("Shodan APIError in %s: %s", name, e)
            except Exception as e:
                # log unexpected errors in debug, but continue
                self.console.print(f"    [dim yellow]Shodan {name} error: {e}[/dim yellow]")
                self.logger.debug("Unexpected error in Shodan strategy %s: %s", name, e)

        return {"ips": self.found_ips}

    def _add_result(self, result: dict):
        """Parse a Shodan result and add to found IPs if not CF"""
        ip = result.get("ip_str", "")
        if not ip:
            return

        # Filter CloudFlare IPs by ASN
        asn = result.get("asn", "")
        if asn in self.cf_asns:
            return
        org = result.get("org", "")
        if "cloudflare" in org.lower():
            return

        self.found_ips[ip] = {
            "org": org,
            "asn": asn,
            "country": result.get("location", {}).get("country_name", ""),
            "ports": result.get("ports", []),
            "hostnames": result.get("hostnames", []),
            "os": result.get("os"),
            "isp": result.get("isp", ""),
            "domains": result.get("domains", []),
            "tags": result.get("tags", []),
            "shodan_data": {
                "last_update": result.get("last_update"),
                "product": result.get("product"),
                "version": result.get("version"),
            }
        }

    # ── Search Strategy 1: SSL Cert Pivot (Most Reliable) ────────────
    def _ssl_cert_pivot(self):
        """
        Search for IPs with SSL certs matching domain, EXCLUDING CloudFlare.
        This is the single most effective Shodan technique for CF bypass.
        """
        queries = [
            f'ssl:"{self.root_domain}" -org:"Cloudflare"',
            f'ssl.cert.subject.cn:"{self.root_domain}" -org:"Cloudflare"',
            f'ssl.cert.subject.cn:"*.{self.root_domain}" -org:"Cloudflare"',
        ]

        for query in queries:
            try:
                from core.utils import sync_retry
                results = sync_retry(self.api.search, query, limit=100, attempts=3, exceptions=(shodan.APIError,))
                for match in results.get("matches", []):
                    self._add_result(match)
            except shodan.APIError as e:
                self.logger.debug("SSL cert pivot query failed: %s", e)
            except Exception as e:
                self.logger.debug("SSL cert pivot unexpected error: %s", e)

    # ── Search Strategy 2: Hostname Search ───────────────────────────
    def _hostname_search(self):
        """Search Shodan's hostname index for the target domain"""
        queries = [
            f'hostname:"{self.root_domain}" -org:"Cloudflare"',
            f'hostname:"{self.target}" -org:"Cloudflare"',
        ]

        for query in queries:
            try:
                from core.utils import sync_retry
                results = sync_retry(self.api.search, query, limit=100, attempts=3, exceptions=(shodan.APIError,))
                for match in results.get("matches", []):
                    self._add_result(match)
            except shodan.APIError as e:
                self.logger.debug("Hostname search failed: %s", e)
            except Exception as e:
                self.logger.debug("Hostname search unexpected error: %s", e)

    # ── Search Strategy 3: HTTP Content Search ───────────────────────
    def _http_search(self):
        """Search HTTP responses for domain references — finds origin servers"""
        queries = [
            f'http.html:"{self.root_domain}" -org:"Cloudflare"',
            f'http.headers_hash:* hostname:"{self.root_domain}" -org:"Cloudflare"',
        ]

        for query in queries:
            try:
                results = self.api.search(query, limit=50)
                for match in results.get("matches", []):
                    self._add_result(match)
            except shodan.APIError as e:
                self.logger.debug("HTTP content search failed: %s", e)
            except Exception as e:
                self.logger.debug("HTTP content search unexpected error: %s", e)

    def _copyright_search(self, copyright_string: str):
        """Search for a unique copyright or other string in HTTP response bodies."""
        if not copyright_string:
            return
        query = f'http.html:"{copyright_string}" -org:"Cloudflare"'
        try:
            results = self.api.search(query, limit=100)
            for match in results.get("matches", []):
                self._add_result(match)
        except shodan.APIError as e:
            self.logger.debug("Copyright search failed: %s", e)
        except Exception as e:
            self.logger.debug("Copyright search unexpected error: %s", e)

    # ── Search Strategy 4: Favicon Hash ──────────────────────────────
    def _favicon_search(self):
        """
        Fetch target favicon, compute Shodan hash, find same favicon on other IPs.
        Origin servers often have the same favicon as the CF-fronted site.
        """
        import base64
        import urllib.request

        try:
            url = f"https://{self.target}/favicon.ico"
            favicon_data = None
            # Try cloudscraper first to bypass challenges
            try:
                import cloudscraper
                scraper = cloudscraper.create_scraper(
                    browser={"browser": "chrome", "platform": "windows", "desktop": True}
                )
                resp = scraper.get(url, timeout=10)
                if getattr(resp, 'status_code', None) == 200 and getattr(resp, 'content', None):
                    favicon_data = resp.content
            except Exception:
                favicon_data = None

            # fallback to urllib
            if not favicon_data:
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    response = urllib.request.urlopen(req, timeout=5)
                    favicon_data = response.read()
                except Exception:
                    favicon_data = None

            if not favicon_data:
                self.logger.debug("No favicon data fetched for %s", self.target)
                return

            # Compute Shodan-compatible MurmurHash from base64-encoded favicon
            favicon_b64 = base64.encodebytes(favicon_data)
            favicon_hash = self._murmurhash(favicon_b64)

            self.console.print(f"    [dim]Favicon hash: {favicon_hash}[/dim]")

            query = f'http.favicon.hash:{favicon_hash} -org:"Cloudflare"'
            try:
                results = self.api.search(query, limit=50)
                for match in results.get("matches", []):
                    self._add_result(match)
            except shodan.APIError as e:
                self.logger.debug("Favicon search failed: %s", e)
            except Exception as e:
                self.logger.debug("Favicon search unexpected error: %s", e)

        except Exception as e:
            self.logger.debug("Favicon fetch/search failed: %s", e)

    # ── Search Strategy 5: HTTP Headers Fingerprint ──────────────────
    def _headers_search(self):
        """Deep: search for unique headers that may fingerprint the origin"""
        queries = [
            # Custom server headers
            f'http.headers:"X-Powered-By" hostname:"{self.root_domain}" -org:"Cloudflare"',
            # App-specific headers
            f'http.headers:"X-{self.root_domain.split(".")[0]}" -org:"Cloudflare"',
        ]

        for query in queries:
            try:
                results = self.api.search(query, limit=50)
                for match in results.get("matches", []):
                    self._add_result(match)
            except Exception:
                pass

    # ── Search Strategy 6: ASN Expansion ─────────────────────────────
    def _asn_search(self):
        """
        Deep: If we already found an IP, find its ASN, then search for
        ALL IPs in that ASN that match the domain — finds siblings.
        """
        if not self.found_ips:
            return

        seen_asns = set()
        for ip_data in self.found_ips.values():
            asn = ip_data.get("asn", "")
            if asn and asn not in seen_asns and asn not in CF_ASNS:
                seen_asns.add(asn)

        for asn in list(seen_asns)[:3]:  # Limit to 3 ASNs
            try:
                query = f'asn:{asn} hostname:"{self.root_domain}"'
                results = self.api.search(query, limit=50)
                for match in results.get("matches", []):
                    self._add_result(match)
            except Exception:
                pass

    # ── Shodan Host Info (detailed lookup for confirmed IPs) ─────────
    def get_host_detail(self, ip: str) -> dict:
        """Full Shodan host lookup — use after confirming an IP is the origin"""
        try:
            host = self.api.host(ip)
            try:
                # Try to fetch favicon using cloudscraper (handles JS/anti-bot)
                url = f"https://{self.target}/favicon.ico"
                favicon_data = None
                try:
                    import cloudscraper
                    scraper = cloudscraper.create_scraper(
                        browser={"browser": "chrome", "platform": "windows", "desktop": True}
                    )
                    resp = scraper.get(url, timeout=10)
                    if resp.status_code == 200 and resp.content:
                        favicon_data = resp.content
                except Exception:
                    # fallback to urllib
                    try:
                        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                        response = urllib.request.urlopen(req, timeout=5)
                        favicon_data = response.read()
                    except Exception:
                        favicon_data = None

                if not favicon_data:
                    self.logger.debug("No favicon data fetched for %s", self.target)
                    return

                # Compute Shodan-compatible MurmurHash from base64-encoded favicon
                favicon_b64 = base64.encodebytes(favicon_data)
                favicon_hash = self._murmurhash(favicon_b64)

                self.console.print(f"    [dim]Favicon hash: {favicon_hash}[/dim]")

                query = f'http.favicon.hash:{favicon_hash} -org:"Cloudflare"'
                try:
                    results = self.api.search(query, limit=50)
                    for match in results.get("matches", []):
                        self._add_result(match)
                except shodan.APIError as e:
                    self.logger.debug("Favicon search failed: %s", e)
                except Exception as e:
                    self.logger.debug("Favicon search unexpected error: %s", e)

                "tags": host.get("tags", []),
                "hostnames": host.get("hostnames", []),
                "last_update": host.get("last_update"),
            }
        except Exception as e:
            return {"ip": ip, "error": str(e)}

    def get_account_info(self) -> dict:
        """Show Shodan API credit usage"""
        try:
            info = self.api.info()
            return {
                "query_credits": info.get("query_credits"),
                "scan_credits": info.get("scan_credits"),
                "unlocked": info.get("unlocked"),
                "plan": info.get("plan"),
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _murmurhash(data: bytes) -> int:
        """Compute Shodan-compatible MurmurHash3 for favicon"""
        import struct

        h = 0
        data = data if isinstance(data, (bytes, bytearray)) else data.encode()
        length = len(data)
        remainder = length & 3
        bytes_ = length >> 2
        offset = 0

        while offset < bytes_ * 4:
            k = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            k = (k * 0xcc9e2d51) & 0xFFFFFFFF
            k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
            k = (k * 0x1b873593) & 0xFFFFFFFF
            h ^= k
            h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
            h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF

        tail = data[bytes_ * 4:]
        k = 0
        if remainder == 3:
            k ^= tail[2] << 16
        if remainder >= 2:
            k ^= tail[1] << 8
        if remainder >= 1:
            k ^= tail[0]
            k = (k * 0xcc9e2d51) & 0xFFFFFFFF
            k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
            k = (k * 0x1b873593) & 0xFFFFFFFF
            h ^= k

        h ^= length
        h ^= h >> 16
        h = (h * 0x85ebca6b) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 0xc2b2ae35) & 0xFFFFFFFF
        h ^= h >> 16

        # Convert to signed int (Shodan uses signed)
        if h > 0x7FFFFFFF:
            h -= 0x100000000
        return h
