import os
import sys
from unittest.mock import AsyncMock, MagicMock
import ssl

import pytest
from click.testing import CliRunner
from rich.console import Console

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "cfunveil"))

from main import main
from core.headers_probe import HeadersProbe
from core.cert_intel import CertIntelligence


def test_cli_help_imports_successfully():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0, result.output
    assert "--authorized-cidr" in result.output


def test_bad_cidr_fails_before_network():
    result = CliRunner().invoke(main, [
        "-t", "example.com", "--authorized-cidr", "127.0.0.0/8",
    ])
    assert result.exit_code != 0
    assert "globally routable" in result.output


@pytest.mark.asyncio
async def test_censys_pat_is_scheduled():
    intel = CertIntelligence(
        "example.com", {"no_wildcards": True, "censys_pat": "test"},
        Console(), MagicMock(),
    )
    intel._query_crtsh = AsyncMock()
    intel._query_censys = AsyncMock()
    intel._resolve_subdomains = AsyncMock()
    await intel.run()
    intel._query_censys.assert_awaited_once()


@pytest.mark.asyncio
async def test_http_probe_disables_redirect_and_verifies_tls_name():
    class Response:
        status = 200
        headers = {"server": "nginx"}
        content = MagicMock(read=AsyncMock(return_value=b"x" * 400))
        connection = MagicMock(transport=MagicMock(
            get_extra_info=lambda name: ("8.8.8.8", 443)
        ))
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return False

    session = MagicMock()
    session.get.return_value = Response()
    probe = HeadersProbe("example.com", Console(), session)
    result = await probe._request(
        "https://8.8.8.8:443/", host="example.com", sni="example.com"
    )
    assert result["body_length"] == 400
    kwargs = session.get.call_args.kwargs
    assert kwargs["allow_redirects"] is False
    assert kwargs["headers"]["Host"] == "example.com"
    assert kwargs["server_hostname"] == "example.com"
    assert isinstance(kwargs["ssl"], ssl.SSLContext)


@pytest.mark.asyncio
async def test_real_loopback_transport_read_and_no_redirect():
    """Exercise real aiohttp connection bookkeeping without external traffic."""
    from aiohttp import ClientSession, web

    async def handler(request):
        return web.Response(
            status=302, headers={"Location": "https://should-not-be-fetched.invalid/"}
        )

    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    try:
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        async with ClientSession() as session:
            p = HeadersProbe("example.com", Console(), session)
            data = await p._request(f"http://127.0.0.1:{port}/", host="example.com")
        assert data["status"] == 302
        assert data["connected_ip"] == "127.0.0.1"
        assert data["location"] == "https://should-not-be-fetched.invalid/"
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_passive_json_helper_buffers_response_after_context():
    from aiohttp import ClientSession, web
    from core.utils import http_get_with_retry

    async def handler(request):
        return web.json_response({"answer": "ok"})

    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    try:
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        async with ClientSession() as session:
            result = await http_get_with_retry(session, f"http://127.0.0.1:{port}/")
            assert result.status == 200
            assert await result.json() == {"answer": "ok"}
    finally:
        await runner.cleanup()


def test_html_report_escapes_data_and_scales_scores(tmp_path):
    from output.reporter import generate_report

    outfile = tmp_path / "result.html"
    generate_report({
        "summary": {"total_ips_found": 1},
        "ips": {
            "8.8.8.8": {
                "confidence": 0.8, "confirmed": False,
                "verification_status": "related_service",
                "sources": ["<script>alert(1)</script>"],
                "warnings": ['<img src=x onerror=alert(1)>'],
            }
        }
    }, str(outfile), "example.com")
    text = outfile.read_text()
    assert "80/100" in text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text
    assert "&lt;img" in text


def test_all_does_not_override_explicit_no_validate(monkeypatch):
    captured = {}

    class FakeEngine:
        def __init__(self, config, console):
            captured.update(config)

        async def run(self):
            return {"ips": {}, "subdomains": [], "summary": {}}

    monkeypatch.setattr("main.ReconEngine", FakeEngine)
    monkeypatch.setattr("main.print_summary", lambda *args, **kwargs: None)
    result = CliRunner().invoke(main, ["-t", "example.com", "--all", "--no-validate", "--quiet"])
    assert result.exit_code == 0, result.output
    assert captured["deep"] is True
    assert captured["validate"] is False
