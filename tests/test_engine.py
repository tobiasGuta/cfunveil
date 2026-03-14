import os
import sys
from rich.console import Console

# Ensure the package directory is on sys.path so tests can import `core`
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PKG_DIR = os.path.join(ROOT, "cfunveil")
if PKG_DIR not in sys.path:
    sys.path.insert(0, PKG_DIR)

from core.engine import ReconEngine


def test_is_valid_ip_ipv4_and_ipv6():
    config = {"target": "example.com"}
    console = Console()
    engine = ReconEngine(config, console)

    assert engine._is_valid_ip("8.8.8.8") is True
    assert engine._is_valid_ip("::1") is True
    assert engine._is_valid_ip("2001:4860:4860::8888") is True
    assert engine._is_valid_ip("not-an-ip") is False
