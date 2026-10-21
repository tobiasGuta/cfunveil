"""
core/shodan_pivot.py - Shodan Intelligence Pivot
Shodan intelligence search with per-match provenance and safe source attribution
"""

import asyncio
import shodan
from rich.console import Console
from core.shodan_evidence import describe_shodan_match
from core.shodan_query_metrics import ShodanQueryMetrics


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
        self.query_metrics = ShodanQueryMetrics()
        # A disabled-by-default page cap plus one scan-wide additional-page
        # request budget. Check again here for callers bypassing Click.
        def bounded_integer(name, default, low, high):
            value = config.get(name, default)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} must be an integer from {low} to {high}")
            return value

        self.max_pages = bounded_integer("shodan_max_pages", 1, 1, 5)
        self.extra_page_budget = bounded_integer(
            "shodan_extra_page_budget", 8, 0, 20,
        )
        self.extra_page_requests_used = 0
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
        """Run Shodan strategies sequentially, retaining each query's evidence"""
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
                ("JARM fingerprinting", self._jarm_search, None),
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

        return {
            "ips": self.found_ips,
            "query_metrics": self.query_metrics.snapshot(),
            "pagination_budget": {
                "max_pages_per_query": self.max_pages,
                "extra_page_request_budget": self.extra_page_budget,
                "extra_page_requests_attempted": self.extra_page_requests_used,
                # The API does not give per-request actual credit deduction.
                "actual_query_credits_used": None,
            },
        }

    def _add_result(self, result: dict, *, strategy: str, query: str):
        """Accumulate compact banner evidence without promoting an origin lead.

        Different queries and timestamps may find the same IP. Keep both; a
        duplicate of the same observation is collapsed. Shodan's broad search
        hits are always *related*, never proof of an exact-target origin.
        """
        if not isinstance(result, dict):
            return
        ip = result.get("ip_str")
        if not isinstance(ip, str) or not ip:
            return

        asn = result.get("asn") or ""
        org = result.get("org") or ""
        if asn in self.cf_asns or (
            isinstance(org, str) and "cloudflare" in org.lower()
        ):
            return

        observation = describe_shodan_match(
            result, target=self.target, root_domain=self.root_domain,
            strategy=strategy, query=query,
        )
        entry = self.found_ips.setdefault(ip, {
            "org": "", "asn": "", "country": "", "ports": [],
            "hostnames": [], "os": None, "isp": "", "domains": [],
            "tags": [], "shodan_data": {
                "last_update": None, "product": None, "version": None, "jarm": None,
            },
            "shodan_evidence": [], "shodan_relations": [],
            "shodan_observations_truncated": 0,
        })

        location = result.get("location")
        location = location if isinstance(location, dict) else {}
        ssl_data = result.get("ssl")
        ssl_data = ssl_data if isinstance(ssl_data, dict) else {}

        # Retain first nonempty summary values for old report consumers.
        values = {
            "org": org, "asn": asn,
            "country": location.get("country_name"),
            "os": result.get("os"),
            "isp": result.get("isp"),
        }
        for key, value in values.items():
            if value and not entry.get(key):
                entry[key] = value

        for key in ("hostnames", "domains", "tags", "ports"):
            raw = result.get(key)
            items = raw if isinstance(raw, (list, tuple)) else []
            if key == "ports" and observation["port"] is not None:
                items = [*items, observation["port"]]
            if key == "hostnames":
                items = observation["hostnames"]
            for item in items:
                if isinstance(item, (str, int)) and item not in entry[key]:
                    entry[key].append(item)

        summary = {
            "last_update": result.get("last_update"),
            "product": result.get("product"),
            "version": result.get("version"),
            "jarm": ssl_data.get("jarm"),
        }
        for key, value in summary.items():
            if value is not None and entry["shodan_data"].get(key) is None:
                entry["shodan_data"][key] = value

        if observation["relation"] not in entry["shodan_relations"]:
            entry["shodan_relations"].append(observation["relation"])

        # Prevent unbounded reports when searches repeatedly return one IP.
        observations = entry["shodan_evidence"]
        if observation not in observations:
            if len(observations) < 128:
                observations.append(observation)
            else:
                entry["shodan_observations_truncated"] += 1
        return (ip, observation)

    def _execute_query(self, query: str, *, strategy: str, limit: int,
                       retry: bool = False):
        """Fetch one page by default, or bounded pages when explicitly enabled.

        The Shodan API uses 100-result pages. Single-page mode retains the
        original configured limit and retry behavior. With pagination enabled,
        fetch 100 on page one to avoid skipping indices 51–100 for strategies
        whose legacy single-page limit was 50.
        """
        page_limit = 100 if self.max_pages > 1 else limit
        for page in range(1, self.max_pages + 1):
            if page > 1:
                # Charge budget BEFORE the search call, including a failed
                # attempt. Extra pages are never retried; the existing
                # first-page retry policy is untouched.
                if self.extra_page_requests_used >= self.extra_page_budget:
                    self.query_metrics.mark_stop("global_extra_page_budget")
                    break
                self.extra_page_requests_used += 1
            try:
                if page == 1 and retry:
                    from core.utils import sync_retry
                    payload = sync_retry(
                        self.api.search, query, limit=page_limit, attempts=3,
                        exceptions=(shodan.APIError,),
                    )
                elif page == 1:
                    payload = self.api.search(query, limit=page_limit)
                else:
                    payload = self.api.search(
                        query, page=page, limit=page_limit,
                    )
                if not isinstance(payload, dict):
                    raise ValueError("Shodan search response must be an object")
                matches = payload.get("matches", [])
                if not isinstance(matches, list):
                    raise ValueError("Shodan matches must be a list")
                accepted = []
                for match in matches:
                    retained = self._add_result(
                        match, strategy=strategy, query=query,
                    )
                    if retained is not None:
                        accepted.append(retained)
                provider_total = payload.get("total")
                if (
                    not isinstance(provider_total, int)
                    or isinstance(provider_total, bool)
                    or provider_total < 0
                ):
                    provider_total = None
                self.query_metrics.success(
                    strategy=strategy, query=query, page=page,
                    limit=page_limit, matches=matches, accepted=accepted,
                    provider_total=provider_total,
                )
            except Exception as exc:
                self.query_metrics.failure(
                    strategy=strategy, query=query, page=page,
                    limit=page_limit, error_type=type(exc).__name__,
                )
                raise

            # Legacy single-page calls may intentionally request only 50
            # results. Reaching that cap is not end-of-provider coverage.
            if self.max_pages == 1:
                if provider_total is not None and len(matches) >= provider_total:
                    self.query_metrics.mark_stop("provider_total_reached")
                elif len(matches) >= page_limit or (
                    provider_total is not None and provider_total > len(matches)
                ):
                    self.query_metrics.mark_stop("per_query_page_cap")
                else:
                    self.query_metrics.mark_stop("short_page")
                break

            # Only follow full-sized pages. A partial page with total >100
            # must not trick us into skipping unseen first-page entries.
            if provider_total is not None and page * 100 >= provider_total:
                self.query_metrics.mark_stop("provider_total_reached")
                break
            if len(matches) < 100:
                self.query_metrics.mark_stop("short_page")
                break
            if page == self.max_pages:
                self.query_metrics.mark_stop("per_query_page_cap")
                break

    # ── Search Strategy 1: SSL Cert Pivot (Most Reliable) ────────────
    def _ssl_cert_pivot(self):
        """
        Search for IPs with SSL certs matching domain, EXCLUDING CloudFlare.
        A matching certificate is only related intelligence, not bypass proof.
        """
        queries = [
            f'ssl:"{self.root_domain}" -org:"Cloudflare"',
            f'ssl.cert.subject.cn:"{self.root_domain}" -org:"Cloudflare"',
            f'ssl.cert.subject.cn:"*.{self.root_domain}" -org:"Cloudflare"',
        ]

        for query in queries:
            try:
                self._execute_query(query, strategy="ssl_certificate", limit=100, retry=True)
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
                self._execute_query(query, strategy="hostname", limit=100, retry=True)
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
                self._execute_query(query, strategy="http_content", limit=50)
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
            self._execute_query(query, strategy="copyright", limit=100)
        except shodan.APIError as e:
            self.logger.debug("Copyright search failed: %s", e)
        except Exception as e:
            self.logger.debug("Copyright search unexpected error: %s", e)

    # ── Search Strategy 4: Favicon Hash ──────────────────────────────
    def _favicon_search(self):
        """
        Fetch target favicon, compute Shodan hash, find same favicon on other IPs.
        Favicon reuse is only a weak fingerprint; it cannot establish ownership.
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
                self.query_metrics.skipped(strategy="favicon_hash", reason="favicon_unavailable")
                return

            # Compute Shodan-compatible MurmurHash from base64-encoded favicon
            favicon_b64 = base64.encodebytes(favicon_data)
            favicon_hash = self._murmurhash(favicon_b64)

            self.console.print(f"    [dim]Favicon hash: {favicon_hash}[/dim]")

            query = f'http.favicon.hash:{favicon_hash} -org:"Cloudflare"'
            try:
                self._execute_query(query, strategy="favicon_hash", limit=50)
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
                self._execute_query(query, strategy="http_headers", limit=50)
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
                self._execute_query(query, strategy="asn", limit=50)
            except Exception:
                pass

    # ── Search Strategy 7: JARM Fingerprinting ───────────────────────
    def _jarm_search(self):
        """
        Deep: Extract JARM hashes from related discovered IPs,
        and find other non-CDN servers sharing the same TLS fingerprint.
        """
        jarm_hashes = set()
        for data in self.found_ips.values():
            jarm = data.get("shodan_data", {}).get("jarm")
            if jarm and jarm != "00000000000000000000000000000000000000000000000000000000000000":
                jarm_hashes.add(jarm)

        for j_hash in list(jarm_hashes)[:3]: # Limit to 3 distinct JARMs
            try:
                # Require hostname to match or we'll get too much noise
                query = f'ssl.jarm:{j_hash} hostname:"{self.root_domain}" -org:"Cloudflare"'
                self._execute_query(query, strategy="jarm", limit=50)
            except Exception as e:
                self.logger.debug("JARM search failed for hash %s: %s", j_hash, e)

    # ── Shodan Host Info (detailed lookup for confirmed IPs) ─────────
    def get_host_detail(self, ip: str) -> dict:
        """Full Shodan host lookup — use after confirming an IP is the origin"""
        try:
            host = self.api.host(ip)
            return {
                "ip": ip,
                "tags": host.get("tags", []),
                "hostnames": host.get("hostnames", []),
                "last_update": host.get("last_update"),
                "host": host,
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
