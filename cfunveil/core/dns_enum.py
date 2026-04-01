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
CLOUDFLARE_RANGES = [
    "103.21.244.", "103.22.200.", "103.31.4.",
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
    "108.162.192.", "131.0.72.", "141.101.64.", "141.101.65.",
    "162.158.", "172.64.", "172.65.", "172.66.", "172.67.",
    "173.245.48.", "188.114.96.", "188.114.97.",
    "190.93.240.", "197.234.240.", "198.41.128.", "198.41.129.",
]


def is_cloudflare_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in CLOUDFLARE_RANGES)


def extract_ips_from_text(text: str) -> list[str]:
    return IP_REGEX.findall(str(text))


class DNSEnumerator:
    def __init__(self, target: str, root_domain: str, console: Console):
        self.target = target
        self.root_domain = root_domain
        self.console = console
        self.found_ips: set[str] = set()
        self.found_subdomains: set[str] = set()

    async def run(self) -> dict:
        resolver = aiodns.DNSResolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

        tasks = []

        # 1. Query all record types on the exact target + root domain
        for domain in set([self.target, self.root_domain]):
            for rtype in RECORD_TYPES:
                tasks.append(self._query(resolver, domain, rtype))

        # 2. Brute-force subdomain list
        for sub in LEAK_SUBDOMAINS:
            fqdn = f"{sub}.{self.root_domain}"
            tasks.append(self._query(resolver, fqdn, "A"))
            tasks.append(self._query(resolver, fqdn, "CNAME"))

        await asyncio.gather(*tasks, return_exceptions=True)
        
        # 3. Nameserver Consistency Checks
        # Identify subdomains with delegated NS records that differ from the root domain.
        root_ns_records = set()
        try:
            root_ns_res = await resolver.query(self.root_domain, "NS")
            for r in root_ns_res:
                root_ns_records.add(r.host.rstrip("."))
        except Exception:
            pass

        self.ns_anomalies = []
        if root_ns_records:
            ns_tasks = [self._check_subdomain_ns(resolver, sub, root_ns_records) 
                        for sub in list(self.found_subdomains) 
                        if sub != self.root_domain and sub.endswith(self.root_domain)]
            if ns_tasks:
                await asyncio.gather(*ns_tasks, return_exceptions=True)
                
        if self.ns_anomalies:
            for sub, ns_list in self.ns_anomalies:
                self.console.print(f"    [dim yellow]NS Divergence:[/dim yellow] {sub} uses {ns_list} (differs from root NS)")

        # Filter out CloudFlare IPs
        real_ips = {ip for ip in self.found_ips if not is_cloudflare_ip(ip)}
        cf_ips = {ip for ip in self.found_ips if is_cloudflare_ip(ip)}

        if cf_ips:
            self.console.print(f"    [dim]Filtered {len(cf_ips)} CloudFlare IP(s)[/dim]")

        return {
            "ips": list(real_ips),
            "subdomains": list(self.found_subdomains),
            "cloudflare_ips": list(cf_ips),
            "ns_anomalies": self.ns_anomalies,
        }

    async def _check_subdomain_ns(self, resolver, subdomain, root_ns):
        try:
            res = await resolver.query(subdomain, "NS")
            sub_ns = set(r.host.rstrip(".") for r in res)
            if sub_ns and not sub_ns.issubset(root_ns):
                self.ns_anomalies.append((subdomain, list(sub_ns)))
                # Resolve these anomalous nameservers to IPs (they might host the origin)
                for ns in sub_ns:
                    await self._query(resolver, ns, "A")
        except Exception:
            pass

    async def _query(self, resolver: aiodns.DNSResolver, domain: str, rtype: str):
        try:
            result = await resolver.query(domain, rtype)

            if rtype == "A":
                for r in result:
                    ip = r.host
                    self.found_ips.add(ip)
                    self.found_subdomains.add(domain)

            elif rtype == "MX":
                for r in result:
                    # MX host might resolve to real IP
                    mx_host = r.host.rstrip(".")
                    self.found_subdomains.add(mx_host)
                    # Try to resolve MX host
                    await self._query(resolver, mx_host, "A")
                    
                    # Also try to resolve the /24 around MX? 
                    # Not doing it immediately here because we need the IP first.
                    # It will be caught if resolving MX adds an IP. We can let the ASN/BGP step expand it,
                    # or just rely on the A record we just submitted.

            elif rtype == "NS":
                for r in result:
                    ns_host = r.host.rstrip(".")
                    self.found_subdomains.add(ns_host)

            elif rtype == "TXT":
                for r in result:
                    text_data = str(r.text)
                    # SPF records often contain real IPs: "ip4:1.2.3.4"
                    ips = extract_ips_from_text(text_data)
                    for ip in ips:
                        self.found_ips.add(ip)
                    
                    # SPF CIDR expansion
                    if "v=spf1" in text_data:
                        import ipaddress
                        # Extract ip4: and ip6: CIDRs
                        import re
                        cidrs = re.findall(r'ip[46]:([^ ]+)', text_data)
                        for cidr in cidrs:
                            try:
                                net = ipaddress.ip_network(cidr, strict=False)
                                # Basic expansion, limit to /24 or smaller to avoid exploding
                                if net.num_addresses <= 256:
                                    for host in net.hosts():
                                        self.found_ips.add(str(host))
                                elif net.num_addresses > 256:
                                    # Pick just a few as samples or add network identifier
                                    self.found_ips.add(str(net[1]))
                                    self.found_ips.add(str(net[-2]))
                            except Exception:
                                pass
                        
                        # Note: 'include:' recursion would require firing another DNS query
                        includes = re.findall(r'include:([^ ]+)', text_data)
                        for inc in includes:
                            asyncio.create_task(self._query(resolver, inc, "TXT"))
                            

            elif rtype == "CNAME":
                for r in result:
                    target = r.cname.rstrip(".")
                    self.found_subdomains.add(target)
                    # If CNAME doesn't point to CF, resolve it
                    if "cloudflare" not in target:
                        await self._query(resolver, target, "A")

            elif rtype == "AAAA":
                pass  # IPv6 — log but don't process for CF bypass

            elif rtype == "SOA":
                # SOA mname often leaks nameserver IP
                mname = result.nsname.rstrip(".")
                self.found_subdomains.add(mname)
                await self._query(resolver, mname, "A")

        except Exception:
            pass  # DNS NXDOMAIN, timeout etc — expected
