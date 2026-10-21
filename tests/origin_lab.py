"""Offline TLS origin benchmark: all sockets bind to 127/8, never to external hosts.

This module lives under tests, not cfunveil's production package. The lab-only
validator and probe override private-address rejection exclusively for the
hardcoded loopback fixtures; production authorization stays fail-closed.
"""
import asyncio
import ipaddress
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

from aiohttp import ClientSession, TCPConnector, web
from rich.console import Console

from core.engine import ReconEngine
from core.headers_probe import HeadersProbe
from core.validator import OriginValidator

TARGET = "api.lab.test"
BASELINE_IP = "127.0.0.10"
ORIGIN_IP = "127.0.0.11"
DECOY_IP = "127.0.0.12"
PROXY_IP = "127.0.0.13"
REDIRECT_IP = "127.0.0.14"
UNREACHABLE_IP = "127.0.0.15"
OUT_OF_SCOPE_IP = "127.0.0.99"
BODY = ("known-test-application|static-content|".encode() * 25)


class _LabProbe(HeadersProbe):
    """Tests only: route to loopback, retaining actual HTTPS/SNI and peer checks."""

    def __init__(self, console, session, ports):
        super().__init__(TARGET, console, session)
        self.ports = ports
        self.requests = []

    async def baseline(self, domain=None):
        self.requests.append(("baseline", BASELINE_IP))
        data = await self._request(
            f"https://{BASELINE_IP}:{self.ports[BASELINE_IP]}/",
            host=domain or TARGET, sni=domain or TARGET,
        )
        if data:
            data["baseline"] = True
        return data

    async def probe(self, ip, domain=None, port=443):
        # Exact loopback fixtures only; do not add a public-IP or arbitrary-host
        # override to production HeadersProbe.
        if ip not in self.ports or ip == BASELINE_IP:
            return None
        assert ipaddress.ip_address(ip).is_loopback
        self.requests.append(("direct", ip))
        data = await self._request(
            f"https://{ip}:{self.ports[ip]}/",
            host=domain or TARGET, sni=domain or TARGET,
        )
        if data is not None:
            peer = data.get("connected_ip")
            data["peer_verified"] = peer is not None and peer == ip
            data["ip"] = ip
        return data


class _LabValidator(OriginValidator):
    """Allow only the fixed simulated candidates in this test-only subclass."""

    def _is_authorized(self, ip):
        return ip in {
            ORIGIN_IP, DECOY_IP, PROXY_IP, REDIRECT_IP, UNREACHABLE_IP
        }


async def _start_https_server(ip, context, *, status=200, body=BODY, headers=None):
    async def serve(request):
        return web.Response(
            status=status, body=body, headers=headers or {},
        )

    app = web.Application()
    app.router.add_get("/", serve)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, ip, 0, ssl_context=context)
    try:
        await site.start()
    except BaseException:
        await runner.cleanup()
        raise
    port = site._server.sockets[0].getsockname()[1]
    return runner, port


def _make_certificate(directory):
    if not shutil.which("openssl"):
        raise RuntimeError("OpenSSL CLI required for loopback TLS benchmark")
    cert = directory / "lab-cert.pem"
    key = directory / "lab-key.pem"
    command = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-sha256", "-nodes", "-days", "1",
        "-keyout", str(key), "-out", str(cert),
        "-subj", f"/CN={TARGET}",
        "-addext", f"subjectAltName=DNS:{TARGET}",
        "-addext", "basicConstraints=critical,CA:TRUE",
    ]
    subprocess.run(command, check=True, capture_output=True, timeout=20)
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl.load_cert_chain(str(cert), str(key))
    trusted_client_ssl = ssl.create_default_context(cafile=str(cert))
    trusted_client_ssl.check_hostname = True
    trusted_client_ssl.verify_mode = ssl.CERT_REQUIRED
    return server_ssl, trusted_client_ssl


def _discovered_leads(*, include_origin):
    """Replay synthetic hostname-attributed intelligence, no API requests."""
    engine = ReconEngine({"target": TARGET}, Console(quiet=True))
    evidence = {"records": [{"domain": TARGET, "source": "lab-passive-dns"}]}
    if include_origin:
        engine._add_historical_ip(ORIGIN_IP, evidence)
    engine._add_historical_ip(DECOY_IP, evidence)
    engine._add_historical_ip(PROXY_IP, evidence)
    engine._add_historical_ip(REDIRECT_IP, evidence)
    # An unrelated sibling is *not* promoted to a target-origin lead.
    engine._add_historical_ip("127.0.0.16", {
        "records": [{"domain": "mail.lab.test", "source": "lab-passive-dns"}]
    })
    return engine


async def run_benchmark():
    """Run deterministic discovery replay + actual local TLS verification.

    Tests logical classification and HTTPS evidence with loopback servers, not
    real-world discovery coverage, ownership, or public-IP routing.
    """
    runners = []
    with tempfile.TemporaryDirectory(prefix="cfunveil-lab-") as work:
        server_ssl, client_ssl = _make_certificate(Path(work))
        configs = (
            (BASELINE_IP, 200, BODY, {}),
            (ORIGIN_IP, 200, BODY, {}),
            (DECOY_IP, 200, b"distinct application " * 32, {}),
            (PROXY_IP, 200, BODY, {"cf-ray": "lab-edge"}),
            (REDIRECT_IP, 302, b"redirect only", {
                "Location": "https://redirect-not-followed.invalid/"
            }),
        )
        ports = {}
        try:
            for ip, status, body, headers in configs:
                runner, port = await _start_https_server(
                    ip, server_ssl, status=status, body=body, headers=headers
                )
                runners.append(runner)
                ports[ip] = port

            # Find a port guaranteed to refuse connections: no service is
            # started at the unreachable fixture's unique loopback address.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((UNREACHABLE_IP, 0))
                ports[UNREACHABLE_IP] = s.getsockname()[1]

            seeded = _discovered_leads(include_origin=True)
            hidden = _discovered_leads(include_origin=False)
            assert ORIGIN_IP in seeded.discovered_ips
            assert ORIGIN_IP not in hidden.discovered_ips
            assert "127.0.0.16" in seeded.related_ips

            # HeadersProbe creates its own TLS context for each direct request.
            # Override only inside this process to trust the generated lab CA.
            with patch(
                "core.headers_probe.ssl.create_default_context",
                return_value=client_ssl,
            ):
                async with ClientSession(connector=TCPConnector(ssl=client_ssl), trust_env=False) as session:
                    validator = _LabValidator(
                        TARGET, "lab.test", Console(quiet=True), session,
                        authorized_cidrs=["127.0.0.0/24"],
                    )
                    probe = _LabProbe(Console(quiet=True), session, ports)
                    validator.probe = probe
                    candidates = dict(seeded.discovered_ips)
                    candidates[UNREACHABLE_IP] = {"sources": ["lab-passive-dns"]}
                    candidates[OUT_OF_SCOPE_IP] = {"sources": ["lab-passive-dns"]}
                    classified = await validator.validate_all(candidates)

            statuses = {
                ip: {
                    "status": item.get("verification_status"),
                    "confirmed": bool(item.get("confirmed")),
                    "reachable": bool(item.get("reachable")),
                    "tls_verified": bool(item.get("tls_verified")),
                }
                for ip, item in classified.items()
            }
            true_positive = sum(
                item["confirmed"] for ip, item in statuses.items() if ip == ORIGIN_IP
            )
            false_positive = sum(
                item["confirmed"] for ip, item in statuses.items() if ip != ORIGIN_IP
            )
            report = {
                "benchmark": "local_only_tls_origin_lab",
                "target": TARGET,
                "scope": "127.0.0.0/8 loopback only; synthetic passive-DNS evidence",
                "discovery": {
                    "known_origin_seeded": ORIGIN_IP in seeded.discovered_ips,
                    "known_origin_absent_without_evidence": ORIGIN_IP not in hidden.discovered_ips,
                    "related_hostname_not_a_candidate": "127.0.0.16" not in seeded.discovered_ips,
                    "seeded_origin_recall": int(ORIGIN_IP in seeded.discovered_ips),
                    "hidden_origin_recall": int(ORIGIN_IP in hidden.discovered_ips),
                },
                "verification": {
                    "true_positives": true_positive,
                    "false_positives": false_positive,
                    "classification": statuses,
                    "baseline_https_valid": bool(validator.baseline and validator.baseline.get("tls_verified")),
                    "no_out_of_scope_probe": ("direct", OUT_OF_SCOPE_IP) not in probe.requests,
                    "no_redirect_following": all(
                        ipaddress.ip_address(item[1]).is_loopback for item in probe.requests
                    ),
                },
                "limitations": [
                    "Known origin supplied via synthetic passive-DNS evidence; no internet-scale discovery tested",
                    "Generated TLS trust root and lab-only loopback authorization override never used in production",
                    "Loopback reverse proxy is represented by a cf-ray response header, not a deployed CDN",
                    "Matching static responses do not establish WAF bypass or an application vulnerability",
                ],
            }
            return report
        finally:
            for runner in reversed(runners):
                await runner.cleanup()


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run_benchmark()), indent=2, sort_keys=True))
