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
    state = json.loads((tmp_path / "cfunveil_example_com_session_v4.json").read_text())
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
    path = tmp_path / "cfunveil_example_com_session_v4.json"
    path.write_text(json.dumps({
        "version": 4, "target": "another.com",
        "discovered_ips": {}, "completed_modules": [], "subdomains": [],
    }))
    with pytest.raises(ValueError, match="mismatch"):
        ReconEngine({"target": "example.com", "resume": True}, Console())


def test_candidates_are_separated_by_hostname_and_cdn():
    engine = ReconEngine({"target": "api-cloudfront.life360.com"}, Console())
    engine._add_historical_ip("104.18.37.240", {
        "records": [
            {"domain": "api-cloudfront.life360.com", "source": "urlscan"}
        ]
    })
    engine._add_historical_ip("54.174.220.14", {
        "records": [
            {"domain": "amplitude-go-dev.internal-data.dev.life360.com", "source": "urlscan"}
        ]
    })
    engine._add_historical_ip("54.159.219.253", {
        "records": [
            {"domain": "api-cloudfront.life360.com", "source": "securitytrails"}
        ]
    })
    assert "104.18.37.240" in engine.cdn_edges
    assert "104.18.37.240" not in engine.discovered_ips
    assert "54.174.220.14" in engine.related_ips
    assert "54.174.220.14" not in engine.discovered_ips
    assert engine.discovered_ips["54.159.219.253"]["records"][0]["domain"] == "api-cloudfront.life360.com"


def test_checkpoint_roundtrips_related_and_cdn_evidence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = ReconEngine({"target": "api-cloudfront.life360.com"}, Console())
    engine._add_ip("8.8.8.8", "Historical-DNS", {
        "records": [{"domain": "other.life360.com", "source": "urlscan"}]
    }, category="related")
    engine._add_ip("104.18.37.240", "DNS", {
        "records": [{"domain": "api-cloudfront.life360.com", "record_type": "A"}]
    }, category="cdn")
    engine._save_session()
    resumed = ReconEngine({"target": "api-cloudfront.life360.com", "resume": True}, Console())
    assert "8.8.8.8" in resumed.related_ips
    assert resumed.cdn_edges["104.18.37.240"]["records"][0]["domain"] == "api-cloudfront.life360.com"


def test_sibling_only_cloudflare_address_is_related_not_target_edge():
    engine = ReconEngine({"target": "api-cloudfront.life360.com"}, Console())
    engine._add_historical_ip("172.64.150.73", {
        "sources": ["urlscan"],
        "records": [
            {"domain": "datagrail.partner.dev.life360.com", "source": "urlscan"}
        ],
    })
    assert "172.64.150.73" in engine.related_ips
    assert "172.64.150.73" not in engine.cdn_edges
    assert "172.64.150.73" not in engine.discovered_ips


def test_exact_target_cloudflare_edge_retains_sibling_history():
    engine = ReconEngine({"target": "api-cloudfront.life360.com"}, Console())
    engine._add_ip("104.18.37.240", "DNS", {
        "records": [{"domain": "api-cloudfront.life360.com", "record_type": "A"}]
    }, category="cdn")
    engine._add_historical_ip("104.18.37.240", {
        "sources": ["urlscan"],
        "records": [
            {"domain": "api-cloudfront.life360.com", "source": "urlscan"},
            {"domain": "www.life360.com", "source": "urlscan"},
        ],
    })
    assert "104.18.37.240" in engine.cdn_edges
    assert len(engine.cdn_edges["104.18.37.240"]["records"]) == 3
    assert "104.18.37.240" not in engine.related_ips


def test_new_checkpoint_version_does_not_resume_old_classifications(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    old = tmp_path / "cfunveil_api-cloudfront_life360_com_session_v3.json"
    old.write_text(json.dumps({
        "version": 3, "target": "api-cloudfront.life360.com",
        "cdn_edges": {"172.64.150.73": {"sources": ["Historical-DNS"]}},
        "completed_modules": ["dns"],
    }))
    engine = ReconEngine({"target": "api-cloudfront.life360.com", "resume": True}, Console())
    assert engine.cdn_edges == {}
    assert not engine.completed_modules
    assert engine.session_file.endswith("_session_v4.json")
