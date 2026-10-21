"""
core/dns_enum.py - DNS Enumeration & Subdomain Harvesting
Async DNS queries across all record types + subdomain brute-force
"""

import asyncio
import re
import aiodns
from rich.console import Console

# Subdomains that commonly bypass CloudFlare / expose real IPs
LEAK_SUBDOMAINS = [
    # Infrastructure
    "direct", "origin", "origin-www", "real", "backend",
    # Email (biggest leaker)
    "mail", "mail2", "smtp", "smtp2", "imap", "pop", "pop3",
    "mx", "mx1", "mx2", "webmail", "email",
    # Hosting panels
    "cpanel", "whm", "plesk", "panel", "hosting",
    # Dev/staging (often not proxied)
    "dev", "dev2", "staging", "stage", "stg", "preprod",
    "test", "testing", "uat", "qa", "sandbox", "demo",
    "beta", "alpha", "preview", "canary",
    # APIs
    "api", "api2", "api-dev", "api-staging", "rest", "graphql",
    # Remote access
    "vpn", "remote", "ssh", "bastion", "jump",
    # Services
    "git", "gitlab", "github", "jenkins", "jira", "confluence",
    "admin", "dashboard", "portal", "internal", "intranet",
    # CDN/Media (often has real IP)
    "static", "assets", "cdn", "media", "img", "images",
    "upload", "uploads", "files", "dl", "download",
    # Monitoring
    "monitor", "status", "metrics", "grafana", "kibana",
    # Database/infra
    "db", "database", "mysql", "postgres", "redis", "elastic",
    # Autodiscovery
    "autodiscover", "autoconfig", "lyncdiscover",
    # Nameservers
    "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    # FTP
    "ftp", "ftp2", "sftp",
    # Wildcards
    "www", "www2", "m", "mobile", "app",
]

RECORD_TYPES = ["A", "MX", "TXT", "NS", "AAAA", "SOA"]

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Source: Cloudflare's published IPv4/IPv6 network list (www.cloudflare.com/ips/).
# Static, deterministic snapshot; avoids fragile string-prefix comparisons.
import ipaddress

CLOUDFLARE_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
    "2c0f:f248::/32",
))


def is_cloudflare_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
        return any(address in network for network in CLOUDFLARE_NETWORKS)
    except ValueError:
        return False


class DNSEnumerator:
    """Collect only hostname-address associations; TXT/MX/NS are not origins."""

    def __init__(self, target: str, root_domain: str, console: Console):
        self.target = target.lower().rstrip(".")
        self.root_domain = root_domain.lower().rstrip(".")
        self.console = console
        self.found_ips: set[str] = set()
        self.found_subdomains: set[str] = set()
        self.records: dict[str, list[dict]] = {}
        self.ns_anomalies: list = []

    def _add_address(self, ip: str, domain: str, rtype: str):
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return
        if not address.is_global:
            return
        domain = domain.lower().rstrip(".")
        self.found_ips.add(ip)
        if domain == self.target or domain.endswith("." + self.root_domain):
            self.found_subdomains.add(domain)
        evidence = {"domain": domain, "record_type": rtype}
        records = self.records.setdefault(ip, [])
        if evidence not in records:
            records.append(evidence)

    async def run(self) -> dict:
        resolver = aiodns.DNSResolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

        # When given a specific host, do not silently enumerate every sibling
        # domain, mail host, SPF range, nameserver, and subdomain of the root.
        targets = [self.target] if self.target != self.root_domain else [self.root_domain]
        if self.target == self.root_domain:
            targets += [f"{name}.{self.root_domain}" for name in LEAK_SUBDOMAINS]

        await asyncio.gather(
            *(self._query(resolver, host, kind) for host in targets for kind in ("A", "AAAA", "CNAME")),
            return_exceptions=True,
        )
        edges = {ip for ip in self.found_ips if is_cloudflare_ip(ip)}
        if edges:
            self.console.print(f"    [dim]Classified {len(edges)} Cloudflare edge IP(s)[/dim]")
        return {
            "ips": sorted(self.found_ips - edges),
            "cloudflare_ips": sorted(edges),
            "records": self.records,
            "subdomains": sorted(self.found_subdomains),
            "ns_anomalies": self.ns_anomalies,
        }

    async def _query(self, resolver, domain: str, kind: str):
        try:
            response = await resolver.query(domain, kind)
            if kind in ("A", "AAAA"):
                for record in response:
                    self._add_address(record.host, domain, kind)
            elif kind == "CNAME":
                # DNS alias targets are not automatically subdomains or origin IPs.
                for record in response:
                    destination = record.cname.rstrip(".").lower()
                    if destination != domain:
                        await self._query_alias(resolver, destination, domain)
        except Exception:
            # NXDOMAIN/no answer/timeouts are expected in DNS discovery.
            return

    async def _query_alias(self, resolver, destination: str, original: str):
        # Resolve at most one explicit alias hop. The evidence stays bound to the
        # requested hostname; we never expand arbitrary zones from an alias.
        try:
            for kind in ("A", "AAAA"):
                try:
                    response = await resolver.query(destination, kind)
                    for record in response:
                        self._add_address(record.host, original, "CNAME-" + kind)
                except Exception:
                    continue
        except Exception:
            return
