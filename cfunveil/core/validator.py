"""Evidence-based origin validation with an explicit active-network allowlist.

Scores rank leads; they are heuristic weights, NOT probability estimates.
Only a verified direct connection that independently matches the target
application becomes a confirmed origin candidate. No WAF-bypass claim is made.
"""
import asyncio
import ipaddress

import aiohttp
from rich.console import Console
from core.headers_probe import HeadersProbe, is_public_ip


class OriginValidator:
    def __init__(
        self, target: str, root_domain: str, console: Console,
        session: aiohttp.ClientSession, concurrency: int = 10,
        authorized_cidrs=(),
    ):
        self.target = target
        self.root_domain = root_domain
        self.console = console
        self.session = session
        self.probe = HeadersProbe(target, console, session)
        self.concurrency = max(1, min(int(concurrency), 20))
        self.allowed_networks = tuple(
            ipaddress.ip_network(net, strict=False) for net in authorized_cidrs
        )
        self.baseline = None

    def _is_authorized(self, ip: str) -> bool:
        if not is_public_ip(ip):
            return False
        address = ipaddress.ip_address(ip)
        return any(address in network for network in self.allowed_networks)

    async def validate_all(self, discovered_ips: dict) -> dict:
        if self.allowed_networks and any(self._is_authorized(ip) for ip in discovered_ips):
            self.baseline = await self.probe.baseline(self.target)

        semaphore = asyncio.Semaphore(self.concurrency)

        async def one(ip, metadata):
            async with semaphore:
                try:
                    return ip, await self.validate_ip(ip, metadata)
                except Exception as exc:
                    return ip, {
                        **metadata, "confidence": 0.0, "confirmed": False,
                        "verification_status": "error", "warnings": [str(exc)],
                        "evidence": [], "reachable": False,
                    }

        return dict(await asyncio.gather(
            *(one(ip, metadata) for ip, metadata in discovered_ips.items())
        ))

    async def validate_ip(self, ip: str, metadata: dict, scoring_version: str = "v2") -> dict:
        """Classify the candidate based on bounded, in-scope evidence."""
        result = {
            **metadata, "reachable": False, "confirmed": False,
            "confidence": 0.0, "evidence": [], "warnings": [],
            "verification_status": "not_tested", "application_match": False,
        }
        if not self._is_authorized(ip):
            result["verification_status"] = (
                "out_of_scope" if is_public_ip(ip) else "non_public_address"
            )
            return result

        sources = metadata.get("sources", [])
        score = 0.0
        # Historical and passive sources are weak attribution clues only.
        if "Historical-DNS" in sources:
            score += 0.10
            result["evidence"].append("Historical DNS association (not proof of current ownership)")
        if "DNS" in sources:
            score += 0.05
            result["evidence"].append("DNS association")
        if len(set(sources)) > 1:
            score += 0.05
            result["evidence"].append("Multiple discovery sources")

        direct = await self.probe.probe(ip, self.target)
        if direct is None:
            result.update(confidence=round(score, 2), verification_status="unreachable")
            return result

        result.update(
            reachable=bool(direct.get("peer_verified")),
            http_status=direct.get("status"),
            server_header=direct.get("server", ""),
            body_hash=direct.get("body_hash"),
            body_length=direct.get("body_length"),
            redirect_location=direct.get("location"),
            connected_ip=direct.get("connected_ip"),
            tls_verified=bool(direct.get("tls_verified")),
            scheme=direct.get("scheme"),
        )
        if not direct.get("peer_verified"):
            result["warnings"].append("Direct connection IP could not be independently verified")
            result["verification_status"] = "inconclusive"
            result["confidence"] = round(score, 2)
            return result
        if direct.get("is_cloudflare"):
            result["verification_status"] = "cdn_or_proxy"
            result["warnings"].append("CDN headers present on the direct-IP response")
            result["confidence"] = round(score, 2)
            return result

        status = direct.get("status")
        if status is not None and 300 <= status < 400:
            result["warnings"].append(
                "Redirect observed but not followed; this does not prove origin access"
            )
            result["verification_status"] = "redirect_only"
            result["confidence"] = round(score, 2)
            return result

        if direct.get("tls_verified"):
            score += 0.35
            result["evidence"].append("TLS certificate validated for hostname on direct IP using SNI")
        elif direct.get("scheme") == "http":
            result["warnings"].append("Plain HTTP response is insufficient for confirmation")

        baseline = self.baseline
        same_body = bool(
            baseline and baseline.get("scheme") == "https"
            and baseline.get("tls_verified") is True
            and baseline.get("status") == 200
            and status == 200 and baseline.get("body_complete")
            and direct.get("body_complete")
            and baseline.get("body_length") is not None
            and baseline["body_length"] >= 256
            and baseline.get("body_hash") is not None
            and baseline["body_hash"] == direct.get("body_hash")
        )
        if same_body:
            score += 0.45
            result["evidence"].append(
                "Complete nontrivial response body exactly matches the HTTPS hostname baseline"
            )
        elif not baseline or not (
            baseline.get("scheme") == "https"
            and baseline.get("tls_verified") is True
        ):
            result["warnings"].append(
                "No certificate-verified HTTPS hostname baseline available"
            )
        else:
            result["warnings"].append("No exact baseline body match; dynamic pages may be inconclusive")

        result["application_match"] = same_body
        # Do not equate a similar response, a certificate alone, or a ranking
        # score with a verified origin, let alone proof of a WAF bypass.
        confirmed = bool(same_body and direct.get("tls_verified") and not direct.get("is_cloudflare"))
        result["confirmed"] = confirmed
        result["verification_status"] = (
            "verified_direct_application" if confirmed
            else "related_service" if direct.get("tls_verified")
            else "inconclusive"
        )
        result["confidence"] = round(min(1.0, max(0.0, score)), 2)
        result["explanation"] = {
            "score": result["confidence"],
            "is_confirmed": confirmed,
            "category_breakdown": {
                "discovery": round(min(score, 0.20), 2),
                "application_match": 0.45 if same_body else 0.0,
            },
            "contributing_factors": list(result["evidence"]) + list(result["warnings"]),
        }
        return result
