"""Bounded, non-following origin probes.

Every candidate request connects to the literal public IP while using the requested
hostname for both HTTP Host and TLS SNI/certificate verification. Redirects are
recorded, never followed. This module does not scan arbitrary ports or paths.
"""
import asyncio
import hashlib
import ipaddress
import ssl

import aiohttp
from rich.console import Console


CF_HEADERS = {"cf-ray", "cf-cache-status", "cf-request-id", "cf-visitor"}
MAX_BODY = 65536


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


class HeadersProbe:
    def __init__(self, target: str, console: Console, session: aiohttp.ClientSession):
        self.target = target
        self.console = console
        self.session = session

    async def _request(self, url: str, *, host: str | None = None, sni: str | None = None) -> dict | None:
        kwargs = {
            "headers": {"Host": host} if host else {},
            "allow_redirects": False,
            "timeout": aiohttp.ClientTimeout(total=8),
        }
        # Override connector-level insecure settings for BOTH the hostname
        # HTTPS baseline and direct-IP probes. TLS verification is mandatory
        # for verification evidence, regardless of the shared API connector.
        if url.startswith("https://"):
            kwargs["ssl"] = ssl.create_default_context()
        # server_hostname controls SNI AND hostname checking on IP literals.
        if sni is not None:
            kwargs["server_hostname"] = sni

        try:
            async with self.session.get(url, **kwargs) as response:
                raw_headers = {k.lower(): v for k, v in response.headers.items()}
                # aiohttp may release response.connection before the body is read.
                # Capture the transport peer first, using the response protocol when
                # the high-level connection has already been returned to the pool.
                connection = response.connection
                transport = (
                    connection.transport if connection is not None
                    else getattr(getattr(response, "_protocol", None), "transport", None)
                )
                peer = transport.get_extra_info("peername") if transport else None
                connected_ip = str(peer[0]) if peer else None

                # A bounded read avoids unbounded response-body memory consumption.
                body = await asyncio.wait_for(response.content.read(MAX_BODY + 1), timeout=3)
                complete = len(body) <= MAX_BODY
                body_hash = hashlib.sha256(body).hexdigest() if complete else None

                return {
                    "url": url,
                    "status": response.status,
                    "scheme": "https" if url.startswith("https://") else "http",
                    "server": raw_headers.get("server", ""),
                    "headers": raw_headers,
                    "all_headers": raw_headers,
                    "is_cloudflare": bool(CF_HEADERS.intersection(raw_headers)),
                    "location": raw_headers.get("location"),
                    "redirect_chain": [],
                    "body_length": len(body) if complete else None,
                    "body_hash": body_hash,
                    "body_preview": body[:300].decode("utf-8", errors="replace"),
                    "body_complete": complete,
                    "tls_verified": url.startswith("https://"),
                    "connected_ip": connected_ip,
                }
        except (aiohttp.ClientError, asyncio.TimeoutError, ssl.SSLError, ValueError):
            return None

    async def baseline(self, domain: str | None = None) -> dict | None:
        """Single HTTPS baseline against the normal hostname; never follow redirects."""
        domain = domain or self.target
        result = await self._request(f"https://{domain}/")
        if result is not None:
            result["baseline"] = True
        return result

    async def probe(self, ip: str, domain: str | None = None, port: int = 443) -> dict | None:
        """Single bounded probe on 443, falling back to 80 if TLS cannot be verified.

        Nonstandard ports require a separate explicitly authorized workflow.
        """
        domain = domain or self.target
        if not is_public_ip(ip):
            return None
        # A user-controlled port must not expand the network scope.
        if port not in (80, 443):
            return None

        ip_url = f"[{ip}]" if ":" in ip else ip
        schemes = (("https", 443), ("http", 80)) if port == 443 else (("http", 80),)
        for scheme, candidate_port in schemes:
            url = f"{scheme}://{ip_url}:{candidate_port}/"
            result = await self._request(url, host=domain, sni=domain if scheme == "https" else None)
            if result is None:
                continue
            # We only accept a response from the candidate IP itself; this does
            # not rely on redirects or DNS after the connection has been made.
            peer = result.get("connected_ip")
            result["peer_verified"] = peer is not None and ipaddress.ip_address(peer) == ipaddress.ip_address(ip)
            result["ip"] = ip
            return result
        return None
