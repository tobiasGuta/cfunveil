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
