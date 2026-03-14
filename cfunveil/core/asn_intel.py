"""
core/asn_intel.py - ASN & BGP Intelligence
Resolves IPs to ASN/org data, detects cloud providers,
and expands small CIDR ranges to find sibling servers
"""

import asyncio
import aiohttp
from rich.console import Console

# Known cloud/hosting provider ASNs — if origin is on these, it's likely a real server
CLOUD_ASNS = {
    "AS16509": "Amazon AWS",
    "AS14618": "Amazon AWS",
    "AS15169": "Google Cloud",
    "AS396982": "Google Cloud",
    "AS8075": "Microsoft Azure",
    "AS8069": "Microsoft Azure",
    "AS20940": "Akamai",
    "AS54113": "Fastly",
    "AS19679": "Dropbox",
    "AS63949": "Linode/Akamai",
    "AS14061": "DigitalOcean",
    "AS24940": "Hetzner",
    "AS16276": "OVH",
    "AS36352": "ColoCrossing",
    "AS55081": "Cloudways",
}

CF_ASNS = {"AS13335", "AS209242"}


class ASNIntelligence:
    def __init__(self, ips: list[str], console: Console, session: aiohttp.ClientSession):
        self.ips = ips
        self.console = console
        self.session = session

    async def run(self) -> dict:
        if not self.ips:
            return {"resolved": {}, "sibling_ips": []}

        tasks = [self._lookup_ip(ip) for ip in self.ips[:50]]  # Limit to 50 IPs
        results = await asyncio.gather(*tasks, return_exceptions=True)

        resolved = {}
        sibling_ips = []

        for result in results:
            if isinstance(result, dict) and result.get("ip"):
                ip = result["ip"]
                resolved[ip] = result

                # For small CIDRs on interesting providers, expand range
                if (result.get("asn") not in CF_ASNS and
                        result.get("prefix") and
                        self._cidr_size(result["prefix"]) <= 256):
                    siblings = self._expand_cidr(result["prefix"])
                    sibling_ips.extend(siblings[:20])  # Max 20 siblings per CIDR

        return {
            "resolved": resolved,
            "sibling_ips": list(set(sibling_ips) - set(self.ips)),
        }

    async def _lookup_ip(self, ip: str) -> dict:
        """Use ipinfo.io (free) for ASN/org lookup"""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status != 200:
                    return await self._fallback_rdap(ip)
                data = await resp.json()

            asn_raw = data.get("org", "")  # e.g. "AS16509 Amazon.com, Inc."
            asn = asn_raw.split(" ")[0] if asn_raw else ""
            org = " ".join(asn_raw.split(" ")[1:]) if asn_raw else ""

            return {
                "ip": ip,
                "asn": asn,
                "org": org,
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "region": data.get("region", ""),
                "prefix": data.get("prefix", ""),
                "hostname": data.get("hostname", ""),
                "is_cloud": asn in CLOUD_ASNS,
                "cloud_provider": CLOUD_ASNS.get(asn),
                "is_cloudflare": asn in CF_ASNS,
            }

        except Exception:
            return await self._fallback_rdap(ip)

    async def _fallback_rdap(self, ip: str) -> dict:
        """Fallback to ARIN RDAP if ipinfo fails"""
        try:
            url = f"https://rdap.arin.net/registry/ip/{ip}"
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status != 200:
                    return {"ip": ip}
                data = await resp.json()

            return {
                "ip": ip,
                "org": data.get("name", ""),
                "asn": data.get("handle", ""),
                "prefix": self._extract_cidr(data),
                "is_cloud": False,
                "is_cloudflare": False,
            }
        except Exception:
            return {"ip": ip}

    def _extract_cidr(self, rdap_data: dict) -> str:
        try:
            cidrs = rdap_data.get("cidr0_cidrs", [])
            if cidrs:
                c = cidrs[0]
                return f"{c['v4prefix']}/{c['length']}"
        except Exception:
            pass
        return ""

    def _cidr_size(self, cidr: str) -> int:
        """Return number of IPs in a CIDR block"""
        try:
            prefix_len = int(cidr.split("/")[1])
            return 2 ** (32 - prefix_len)
        except Exception:
            return 99999

    def _expand_cidr(self, cidr: str) -> list[str]:
        """Expand CIDR to list of IPs (max 256)"""
        try:
            import ipaddress
            network = ipaddress.IPv4Network(cidr, strict=False)
            return [str(ip) for ip in list(network.hosts())[:256]]
        except Exception:
            return []
