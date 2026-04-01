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

    async def validate_ip(self, ip: str, metadata: dict, scoring_version: str = "v2") -> dict:
        """
        Run all validation checks on a single IP.
        Returns enriched metadata with confidence score.
        """
        base = {**metadata, "reachable": False, "confidence": 0, "evidence": [], "warnings": [], "confirmed": False}

        signals = {"network": [], "tls": [], "dns": [], "context": []}
        legacy_confidence = 0
        legacy_evidence = []
        warnings = []
        
        def add_signal(category, v1_score, v2_weight, desc, is_warning=False):
            nonlocal legacy_confidence
            if is_warning:
                legacy_confidence -= v1_score
                warnings.append(desc)
                signals[category].append({"weight": -v2_weight, "desc": desc, "warning": True})
            else:
                legacy_confidence += v1_score
                legacy_evidence.append(desc)
                signals[category].append({"weight": v2_weight, "desc": desc, "warning": False})

        # ── Check 1: HTTP probe with Host header ─────────────────────
        probe_result = await self.probe.probe(ip, self.target)

        if probe_result is None:
            base["reachable"] = False
            probe_result = {} 
        else:
            base["reachable"] = True

        base["http_status"] = probe_result.get("status")
        base["server_header"] = probe_result.get("server", "")
        base["headers"] = probe_result.get("headers", {})
        base["body_preview"] = probe_result.get("body_preview", "")
        base["redirect_chain"] = probe_result.get("redirect_chain", [])

        # Check redirect chains
        for redir in base["redirect_chain"]:
            loc = redir.get("location", "")
            if not loc: continue
            import re
            ip_match = re.search(r'https?://([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', loc)
            if ip_match:
                leaked_ip = ip_match.group(1)
                if leaked_ip == ip:
                    add_signal("network", 30, 0.4, "Host redirected to itself via bare IP (Strong Origin Identifier)")
            elif "localhost" in loc or "127.0.0.1" in loc:
                add_signal("network", 15, 0.15, "Host redirected to localhost (Dev/Origin config)")
            
            if re.search(r':[0-9]+', loc) and not loc.endswith((':80', ':443')):    
                add_signal("network", 20, 0.2, f"Host redirected to anomalous port in Location header ({loc})")

        # ── Check 1b: Port 80 raw socket probe ──────────────────────
        if not base["reachable"]:
            try:
                import socket, asyncio
                loop = asyncio.get_event_loop()
                def _raw_probe():
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((ip, 80))
                    req = f"GET / HTTP/1.0\r\nHost: {self.target}\r\n\r\n"
                    s.sendall(req.encode())
                    return s.recv(1024).decode(errors="ignore")

                raw_resp = await asyncio.wait_for(loop.run_in_executor(None, _raw_probe), timeout=4)
                if raw_resp and "HTTP/" in raw_resp:
                    base["reachable"] = True
                    base["http_status"] = 200 
                    if "cloudflare" not in raw_resp.lower():
                        add_signal("network", 30, 0.3, "Responded gracefully to direct Port 80 raw probe")
            except Exception:
                pass

        # ── Check 1c: GreyNoise Contextual Filtering ─────────────────
        gn_data = await self._check_greynoise(ip)
        base["greynoise"] = gn_data
        
        if gn_data.get("noise"):
            add_signal("context", 40, 0.6, f"GreyNoise: Known internet background scanner ({gn_data.get('classification', 'unknown')})", is_warning=True)
        if gn_data.get("riot"):
            add_signal("context", 20, 0.4, f"GreyNoise: Known benign service (RIOT: {gn_data.get('name', 'unknown')})", is_warning=True)

        # ── Check 1d: Differential Response Fingerprinting ───────────
        if getattr(self, "baseline", None) and probe_result:
            p_len = probe_result.get("body_length", 0)
            b_len = self.baseline.get("body_length", 0)
            
            if p_len > 0 and self.baseline.get("body_hash") == probe_result.get("body_hash"):
                add_signal("network", 40, 0.6, "Exact response body match with CDN fronted request (Differential)")
            elif b_len > 0 and (abs(p_len - b_len) / b_len) < 0.05:
                add_signal("network", 20, 0.3, "Response body size tightly matches CDN baseline (Differential)")
                
            matched_custom = 0
            for k, v in self.baseline.get("custom_headers", {}).items():
                if k in probe_result.get("all_headers", {}):
                    matched_custom += 1
            if matched_custom > 0:
                add_signal("network", 15, 0.2, f"Matched {matched_custom} custom headers with CDN baseline (Differential)")

        if base["reachable"]:
            if not probe_result.get("is_cloudflare"):
                add_signal("context", 35, 0.3, "No CloudFlare headers in HTTP response")
            else:
                add_signal("context", 50, 0.7, "CloudFlare headers detected — likely still behind CF", is_warning=True)

        status = probe_result.get("status", 0)
        if status in [200, 301, 302]:
            add_signal("network", 20, 0.2, f"HTTP {status} response to Host override")
        elif status in [403, 401]:
            add_signal("network", 10, 0.1, f"HTTP {status} — server responding, auth required")
        elif status in [500, 502, 503]:
            add_signal("network", 5, 0.05, f"HTTP {status} — backend visible but erroring")

        if probe_result.get("domain_in_body"):
            add_signal("network", 15, 0.15, "Target domain found in response body")

        # ── Check 1e: Service Banner Collection ──────────────────────
        banners = await self._grab_banners(ip)
        base["banners"] = banners
        for port, banner in banners.items():
            if self.root_domain.lower() in banner.lower():
                add_signal("network", 20, 0.25, f"Target domain found in non-HTTP banner on port {port}")

        # ── Check 2: SSL Certificate validation (Multi-Port) ─────────
        cert_info = await self._get_cert_domains(ip)
        if cert_info:
            base["cert_domains"] = cert_info
            exact_match = False
            wildcard_match = False
            mismatch_ports = []
            
            for port, domains in cert_info.items():
                if self.target in domains or self.root_domain in domains:
                    exact_match = True
                    add_signal("tls", 0, 0.5, f"Exact SSL match on port {port} for {self.root_domain}")
                elif any(f"*.{self.root_domain}" in d for d in domains):
                    wildcard_match = True
                    add_signal("tls", 0, 0.3, f"Wildcard SSL match on port {port} for *.{self.root_domain}")
                elif domains: 
                    mismatch_ports.append(str(port))
            
            if exact_match:
                legacy_confidence += 25
                legacy_evidence.append(f"Exact SSL match on port {port} for {self.root_domain}")
            elif wildcard_match:
                legacy_confidence += 15
                legacy_evidence.append(f"Wildcard SSL match on port {port} for *.{self.root_domain}")
            elif mismatch_ports:
                add_signal("tls", 5, 0.1, f"Mismatched SSL certificate on ports {','.join(mismatch_ports)}", is_warning=True)

        # ── Check 3: Not a known CDN/proxy ──────────────────────────
        if base["reachable"]:
            server_header = probe_result.get("server", "").lower()
            cdn_signatures = ["cloudflare", "akamai", "fastly", "varnish", "squid"]
            if not any(sig in server_header for sig in cdn_signatures):
                add_signal("context", 5, 0.05, f"Server header doesn't indicate CDN: '{probe_result.get('server', 'none')}'")

            origin_signatures = ["nginx", "apache", "iis", "gunicorn", "uvicorn", "caddy", "lighttpd"]
            if any(sig in server_header for sig in origin_signatures):
                add_signal("network", 10, 0.1, f"Origin server detected: {server_header}")

        # ── Check 4: Historical DNS Relevance ────────────────────────
        oldest = metadata.get("oldest_seen")
        if "Historical-DNS" in base.get("sources", []) and oldest:
            import datetime
            current_year = datetime.datetime.now().year
            try:
                year_seen = int(oldest[:4])
                age = current_year - year_seen
                
                if age > 5:
                    legacy_confidence += 10
                    legacy_evidence.append(f"Highly legacy DNS record detected (First seen {year_seen})")
                    signals["dns"].append({"weight": 0.05, "desc": f"Highly legacy DNS record detected (First seen {year_seen})", "warning": False})
                elif age > 2:
                    legacy_confidence += 5
                    legacy_evidence.append(f"Historical DNS record detected (First seen {year_seen})")
                    signals["dns"].append({"weight": 0.1, "desc": f"Historical DNS record detected (First seen {year_seen})", "warning": False})
                else: 
                    # Recent is better in v2
                    signals["dns"].append({"weight": 0.3, "desc": f"Recent Historical DNS record detected (First seen {year_seen})", "warning": False})
            except Exception:
                pass

        # ── Check 5: Reverse DNS ─────────────────────────────────────
        rdns = await self._reverse_dns(ip)
        base["rdns"] = rdns
        if rdns and self.root_domain in rdns:
            add_signal("dns", 15, 0.2, f"Reverse DNS points to domain: {rdns}")

        # ── Final scoring ────────────────────────────────────────────
        
        # Calculate v2 normalized score
        def _calc_v2():
            # Category soft caps
            caps = {
                "network": 0.6,
                "tls": 0.5,
                "dns": 0.3,
                "context": 0.4
            }
            
            cat_scores = {}
            explanations = []
            
            for cat, sigs in signals.items():
                cat_score = sum(s["weight"] for s in sigs)
                cat_scores[cat] = cat_score
                
            # Apply warnings/negative completely
            total_penalty = 0
            for cat, sigs in signals.items():
                 for s in sigs:
                     if s["warning"]:
                         total_penalty += s["weight"] # negative

            # Apply caps: we only cap positive weights
            final_cat_scores = {}
            for cat in caps.keys():
                pos_score = sum(s["weight"] for s in signals[cat] if not s["warning"])
                import math
                capped = pos_score if pos_score <= caps[cat] else caps[cat] + 0.1 * math.log(1 + pos_score - caps[cat]) 
                # Add penalty back
                neg_score = sum(s["weight"] for s in signals[cat] if s["warning"])
                final_cat_scores[cat] = capped + neg_score
            
            base_score = sum(final_cat_scores.values())
            
            # Correlation Boosting
            has_tls_match = any("Exact SSL match" in s["desc"] for s in signals["tls"]) or any("Wildcard SSL match" in s["desc"] for s in signals["tls"])
            has_network_match = any("Exact response body match" in s["desc"] for s in signals["network"]) or any("Host redirected to itself via bare IP" in s["desc"] for s in signals["network"]) or any("Target domain found in response body" in s["desc"] for s in signals["network"])
            
            boost = 0
            if has_tls_match and has_network_match:
                boost += 0.2
                explanations.append("Boost(+0.20): Strong correlation between TLS and Network HTTP match.")
                
            has_hist_dns = any("Historical DNS" in s["desc"] for s in signals["dns"])
            # We don't have ns_divergence passed into this method explicitly via metadata, so omitted for now or added if present
            has_ns_divergence = metadata.get("ns_divergence", False)
            if has_hist_dns and has_ns_divergence:
                boost += 0.15
                explanations.append("Boost(+0.15): Correlation between Historical DNS and NS divergence.")

            final_score = max(0.0, min(1.0, base_score + boost))
            
            # Build explainability layer
            explanation = {
                "score": round(final_score, 2),
                "is_confirmed": final_score >= 0.8,
                "category_breakdown": { k: round(v, 2) for k,v in final_cat_scores.items() },
                "contributing_factors": []
            }
            
            for cat, sigs in signals.items():
                for s in sigs:
                     explanation["contributing_factors"].append(f"[{cat}] {'(-penalty)' if s['warning'] else '(+signal)'} {s['desc']}")
            
            for eb in explanations:
                explanation["contributing_factors"].append(f"[boost] {eb}")
                
            return final_score, explanation

        v2_score, explanation = _calc_v2()

        legacy_confidence = max(0, min(100, legacy_confidence))
        
        if scoring_version == "v2":
            base.update({
                "confidence": v2_score,
                "evidence": explanation["contributing_factors"],
                "warnings": warnings,
                "confirmed": explanation["is_confirmed"],
                "explanation": explanation
            })
        else:
            base.update({
                "confidence": legacy_confidence,
                "evidence": legacy_evidence,
                "warnings": warnings,
                "confirmed": legacy_confidence >= 60,
                "explanation": None
            })

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
