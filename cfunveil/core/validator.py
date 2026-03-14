"""
core/validator.py - Origin IP Validator
Confirms discovered IPs are the real origin server.
Confidence scoring 0-100 with evidence chain.
"""

import asyncio
import aiohttp
import ssl
import socket
from rich.console import Console
from core.headers_probe import HeadersProbe


class OriginValidator:
    def __init__(self, target: str, root_domain: str, console: Console, session: aiohttp.ClientSession, concurrency: int = 10):
        self.target = target
        self.root_domain = root_domain
        self.console = console
        self.session = session
        self.probe = HeadersProbe(target, console, session)
        self.concurrency = concurrency
        import logging
        self.logger = logging.getLogger("cfunveil.validator")

    async def validate_all(self, discovered_ips: dict) -> dict:
        """Validate all discovered IPs concurrently"""
        # Limit concurrency for validation (don't hammer)
        semaphore = asyncio.Semaphore(self.concurrency or 10)

        async def validate_with_sem(ip, metadata):
            async with semaphore:
                return ip, await self.validate_ip(ip, metadata)

        tasks = [
            validate_with_sem(ip, meta)
            for ip, meta in discovered_ips.items()
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        validated = {}
        for result in results:
            if isinstance(result, tuple):
                ip, data = result
                validated[ip] = data

        return validated

    async def validate_ip(self, ip: str, metadata: dict) -> dict:
        """
        Run all validation checks on a single IP.
        Returns enriched metadata with confidence score.
        """
        confidence = 0
        evidence = []
        warnings = []

        base = {**metadata, "confidence": 0, "evidence": [], "confirmed": False}

        # ── Check 1: HTTP probe with Host header ─────────────────────
        probe_result = await self.probe.probe(ip, self.target)

        if probe_result is None:
            # No response at all
            base["reachable"] = False
            base["confidence"] = 0
            return base

        base["reachable"] = True
        base["http_status"] = probe_result.get("status")
        base["server_header"] = probe_result.get("server", "")
        base["headers"] = probe_result.get("headers", {})
        base["body_preview"] = probe_result.get("body_preview", "")

        # ── Scoring ──────────────────────────────────────────────────

        # Not CloudFlare = strong positive signal
        if not probe_result.get("is_cloudflare"):
            confidence += 35
            evidence.append("No CloudFlare headers in response")
        else:
            confidence -= 50
            warnings.append("CloudFlare headers detected — likely still behind CF")

        # Successful HTTP response
        status = probe_result.get("status", 0)
        if status in [200, 301, 302]:
            confidence += 20
            evidence.append(f"HTTP {status} response to Host override")
        elif status in [403, 401]:
            confidence += 10
            evidence.append(f"HTTP {status} — server responding, auth required")
        elif status in [500, 502, 503]:
            confidence += 5
            evidence.append(f"HTTP {status} — backend visible but erroring")

        # Domain appears in response body
        if probe_result.get("domain_in_body"):
            confidence += 15
            evidence.append("Target domain found in response body")

        # ── Check 2: SSL Certificate validation ─────────────────────
        cert_domains = await self._get_cert_domains(ip)
        if cert_domains:
            base["cert_domains"] = cert_domains
            if self.root_domain in cert_domains or self.target in cert_domains:
                confidence += 30
                evidence.append(f"SSL certificate valid for {self.root_domain}")
            # Wildcard cert
            elif any(f"*.{self.root_domain}" in d for d in cert_domains):
                confidence += 25
                evidence.append(f"Wildcard SSL cert for *.{self.root_domain}")
            elif any(self.root_domain in d for d in cert_domains):
                confidence += 15
                evidence.append("SSL cert contains domain reference")

        # ── Check 3: Not a known CDN/proxy ──────────────────────────
        server_header = probe_result.get("server", "").lower()
        cdn_signatures = ["cloudflare", "akamai", "fastly", "varnish", "squid"]
        if not any(sig in server_header for sig in cdn_signatures):
            confidence += 5
            evidence.append(f"Server header doesn't indicate CDN: '{probe_result.get('server', 'none')}'")

        # Origin server signatures
        origin_signatures = ["nginx", "apache", "iis", "gunicorn", "uvicorn", "caddy", "lighttpd"]
        if any(sig in server_header for sig in origin_signatures):
            confidence += 10
            evidence.append(f"Origin server detected: {server_header}")

        # ── Check 4: Reverse DNS ─────────────────────────────────────
        rdns = await self._reverse_dns(ip)
        base["rdns"] = rdns
        if rdns and self.root_domain in rdns:
            confidence += 15
            evidence.append(f"Reverse DNS points to domain: {rdns}")

        # ── Final scoring ────────────────────────────────────────────
        confidence = max(0, min(100, confidence))
        confirmed = confidence >= 60

        base.update({
            "confidence": confidence,
            "evidence": evidence,
            "warnings": warnings,
            "confirmed": confirmed,
            "cert_domains": cert_domains,
            "rdns": rdns,
        })

        return base

    async def _get_cert_domains(self, ip: str) -> list[str]:
        """Extract SANs from SSL cert on the IP"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()

            def _get_cert():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    s.connect((ip, 443))
                    ss = ctx.wrap_socket(s, server_hostname=ip)
                    cert = ss.getpeercert()
                    ss.close()
                    return cert
                except Exception:
                    return {}

            cert = await asyncio.wait_for(
                loop.run_in_executor(None, _get_cert),
                timeout=6
            )

            domains = []
            for field_type, value in cert.get("subjectAltName", []):
                if field_type.upper() == "DNS":
                    domains.append(value)
            # Also check CN
            for field in cert.get("subject", []):
                for k, v in field:
                    if k == "commonName":
                        domains.append(v)

            return list(set(domains))

        except Exception:
            return []

    async def _reverse_dns(self, ip: str) -> str:
        """PTR record lookup"""
        try:
            import aiodns
            resolver = aiodns.DNSResolver()
            # Build reverse DNS query
            parts = ip.split(".")
            ptr = ".".join(reversed(parts)) + ".in-addr.arpa"
            result = await resolver.query(ptr, "PTR")
            if result:
                return result[0].name
        except Exception:
            pass
        return ""
