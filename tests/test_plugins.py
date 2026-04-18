"""Tests for entry-point scan plugins."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from django_security_hunter.config import GuardConfig
from django_security_hunter.engine import run_scan
from django_security_hunter.models import Finding
from django_security_hunter.plugins import (
    SCAN_PLUGINS_GROUP,
    run_scan_plugins,
    scan_plugins_enabled,
)


def _sample_finding() -> Finding:
    return Finding(
        rule_id="CUSTOM001",
        severity="INFO",
        title="Plugin test",
        message="hello",
        path="x.py",
        line=1,
    )


def test_scan_plugins_disabled_by_config(tmp_path: Path) -> None:
    cfg = GuardConfig(enable_scan_plugins=False)
    findings, meta = run_scan_plugins(tmp_path, cfg, {})
    assert findings == []
    assert meta.get("enabled") is False


def test_scan_plugins_disabled_by_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DJANGO_SECURITY_HUNTER_PLUGINS", "0")
    cfg = GuardConfig(enable_scan_plugins=True)
    assert scan_plugins_enabled(cfg) is False
    findings, meta = run_scan_plugins(tmp_path, cfg, {})
    assert findings == []
    assert meta.get("status") == "skipped"


def test_scan_plugins_runs_entry_point(tmp_path: Path) -> None:
    ep = MagicMock()
    ep.name = "demo"
    ep.load.return_value = lambda root, c, ctx: [_sample_finding()]

    cfg = GuardConfig(enable_scan_plugins=True)
    with patch(
        "django_security_hunter.plugins.entry_points",
        return_value=[ep],
    ):
        findings, meta = run_scan_plugins(tmp_path, cfg, {"loaded": False})

    assert len(findings) == 1
    assert findings[0].rule_id == "CUSTOM001"
    assert meta["enabled"] is True
    assert meta["total_findings"] == 1
    assert any(p["name"] == "demo" and p["status"] == "ok" for p in meta["plugins"])


def test_scan_plugin_load_error_recorded(tmp_path: Path) -> None:
    ep = MagicMock()
    ep.name = "broken"
    ep.load.side_effect = RuntimeError("missing deps")

    cfg = GuardConfig(enable_scan_plugins=True)
    with patch(
        "django_security_hunter.plugins.entry_points",
        return_value=[ep],
    ):
        findings, meta = run_scan_plugins(tmp_path, cfg, {})

    assert findings == []
    assert any(
        p["name"] == "broken" and p["status"] == "load_error" for p in meta["plugins"]
    )


def test_scan_plugin_exception_isolated(tmp_path: Path) -> None:
    def boom(_root, _c, _ctx):
        raise ValueError("nope")

    ep_ok = MagicMock()
    ep_ok.name = "good"
    ep_ok.load.return_value = lambda r, c, ctx: [_sample_finding()]
    ep_bad = MagicMock()
    ep_bad.name = "bad"
    ep_bad.load.return_value = boom

    cfg = GuardConfig(enable_scan_plugins=True)
    with patch(
        "django_security_hunter.plugins.entry_points",
        return_value=[ep_bad, ep_ok],
    ):
        findings, meta = run_scan_plugins(tmp_path, cfg, {})

    assert len(findings) == 1
    assert any(p["name"] == "bad" and p["status"] == "error" for p in meta["plugins"])
    assert any(p["name"] == "good" and p["status"] == "ok" for p in meta["plugins"])


def test_run_scan_includes_scan_plugins_metadata(tmp_path: Path) -> None:
    with patch(
        "django_security_hunter.plugins.entry_points",
        return_value=[],
    ):
        report = run_scan(tmp_path.resolve())
    assert "scan_plugins" in report.metadata
    assert report.metadata["scan_plugins"].get("entry_point_group") == SCAN_PLUGINS_GROUP
