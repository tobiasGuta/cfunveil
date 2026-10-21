import json
import os
import sys

import pytest
from rich.console import Console

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PKG_DIR = os.path.join(ROOT, "cfunveil")
if PKG_DIR not in sys.path:
    sys.path.insert(0, PKG_DIR)

from core.engine import ReconEngine


def test_is_valid_ip_ipv4_and_ipv6():
    engine = ReconEngine({"target": "example.com"}, Console())
    assert engine._is_valid_ip("8.8.8.8") is True
    assert engine._is_valid_ip("2001:4860:4860::8888") is True
    assert engine._is_valid_ip("not-an-ip") is False


def test_clean_start_keeps_discovered_ips_and_root_domain(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = ReconEngine({"target": "example.com"}, Console())
    assert engine.root_domain == "example.com"
    engine._add_ip("8.8.8.8", "Historical-DNS")
    engine.completed_modules.add("dns")
    engine._save_session()
    assert "8.8.8.8" in engine.discovered_ips
    state = json.loads((tmp_path / "cfunveil_example_com_session.json").read_text())
    assert state["target"] == "example.com"
    assert "8.8.8.8" in state["discovered_ips"]


def test_resume_preserves_prior_evidence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = ReconEngine({"target": "example.com"}, Console())
    engine._add_ip("8.8.8.8", "DNS")
    engine.completed_modules.add("dns")
    engine._save_session()

    resumed = ReconEngine({"target": "example.com", "resume": True}, Console())
    assert resumed.discovered_ips["8.8.8.8"]["sources"] == ["DNS"]
    assert "dns" in resumed.completed_modules


def test_resume_rejects_mismatched_target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "cfunveil_example_com_session.json"
    path.write_text(json.dumps({
        "version": 1, "target": "another.com",
        "discovered_ips": {}, "completed_modules": [], "subdomains": [],
    }))
    with pytest.raises(ValueError, match="mismatch"):
        ReconEngine({"target": "example.com", "resume": True}, Console())
