"""
core/headers_probe.py - HTTP Header Fingerprinting
Direct IP probing with Host header override to confirm origin bypass
"""

import asyncio
import aiohttp
import re
from rich.console import Console

# Headers present on CloudFlare responses
CF_HEADERS = {
    "cf-ray", "cf-cache-status", "cf-request-id",
    "cf-visitor", "cf-connecting-ip", "cf-ipcountry"
}

# Headers that indicate WAF/proxy presence
WAF_HEADERS = {
    "x-sucuri-id", "x-sucuri-cache",
    "x-akamai-transformed", "x-check-cacheable",
    "x-fastly-request-id", "x-varnish",
}

# Interesting headers that reveal backend technology
INTERESTING_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-drupal-cache", "x-wp-total", "x-pingback",
    "x-generator", "x-runtime", "x-request-id",
    "x-frame-options", "content-security-policy",
    "strict-transport-security",
]


class HeadersProbe:
    def __init__(self, target: str, console: Console, session: aiohttp.ClientSession):
        self.target = target
        self.console = console
        self.session = session
        import logging
        self.logger = logging.getLogger("cfunveil.headers")

    async def probe(self, ip: str, domain: str = None, port: int = 443) -> dict | None:
        """
        Probe an IP with Host header override.
        Returns response metadata if successful.
        """
        if domain is None:
            domain = self.target

        headers = {
            "Host": domain,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        results = []

        # Try HTTPS first, then HTTP
        for scheme, p in [("https", 443), ("http", 80)]:
            url = f"{scheme}://{ip}:{p}/"
            try:
                async with self.session.get(
                    url,
                    headers=headers,
                    allow_redirects=True,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=8)
                ) as resp:

                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                    is_cf = any(h in resp_headers for h in CF_HEADERS)
                    is_waf = any(h in resp_headers for h in WAF_HEADERS)

                    interesting = {
                        h: resp_headers[h]
                        for h in INTERESTING_HEADERS
                        if h in resp_headers
                    }

                    # Try to read a small chunk of body to find domain references
                    body_preview = ""
                    try:
                        body = await asyncio.wait_for(resp.read(), timeout=3)
                        body_text = body[:2000].decode("utf-8", errors="ignore")
                        # Check if domain appears in body (strong indicator)
                        body_preview = body_text[:500]
                    except Exception as e:
                        self.logger.debug("Error reading body from %s: %s", url, e)

                    result = {
                        "ip": ip,
                        "url": url,
                        "scheme": scheme,
                        "port": p,
                        "status": resp.status,
                        "is_cloudflare": is_cf,
                        "is_waf": is_waf,
                        "headers": interesting,
                        "all_headers": dict(resp_headers),
                        "body_preview": body_preview,
                        "server": resp_headers.get("server", ""),
                        "content_type": resp_headers.get("content-type", ""),
                        "domain_in_body": domain in body_preview,
                    }

                    results.append(result)

                    # If we got a good HTTP response, no need to try more
                    if resp.status < 500:
                        break

            except asyncio.TimeoutError:
                self.logger.debug("Timeout probing %s", url)
            except aiohttp.ClientConnectorError:
                self.logger.debug("Connection error probing %s", url)
            except Exception as e:
                self.logger.debug("Unexpected error probing %s: %s", url, e)

        return results[0] if results else None

    async def probe_multiple_ports(self, ip: str, domain: str = None) -> list[dict]:
        """Probe common alternative ports — dev servers often run on non-standard ports"""
        COMMON_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 4000, 5000, 9000]

        if domain is None:
            domain = self.target

        tasks = [self.probe(ip, domain, port) for port in COMMON_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return [r for r in results if r and not isinstance(r, Exception)]

    async def detect_waf(self, ip: str, domain: str = None) -> dict:
        """Send malicious-looking payload to trigger WAF — identifies protection layer"""
        if domain is None:
            domain = self.target

        headers = {
            "Host": domain,
            "User-Agent": "Mozilla/5.0 (sqlmap/1.0)",
        }

        probe_paths = [
            "/?id=1'",                  # SQLi
            "/?q=<script>alert(1)</script>",  # XSS
            "/.env",                    # Sensitive file
            "/admin",                   # Admin path
        ]

        waf_detected = False
        waf_type = None

        for path in probe_paths[:2]:  # Limit probes
            try:
                url = f"https://{ip}{path}"
                async with self.session.get(
                    url,
                    headers=headers,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                    if resp.status in [403, 406, 429, 503]:
                        waf_detected = True
                        if "cf-ray" in resp_headers:
                            waf_type = "CloudFlare WAF"
                        elif "x-sucuri" in str(resp_headers):
                            waf_type = "Sucuri WAF"
                        else:
                            waf_type = f"Unknown WAF (HTTP {resp.status})"

            except Exception as e:
                self.logger.debug("WAF probe exception for %s: %s", url, e)

        return {"waf_detected": waf_detected, "waf_type": waf_type}
