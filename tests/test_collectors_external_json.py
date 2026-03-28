"""Unit tests for pip-audit, Bandit, and Semgrep JSON mapping (DJG060–DJG062)."""

from __future__ import annotations

from pathlib import Path

import pytest

from django_security_hunter.collectors.bandit_runner import findings_from_bandit_json
from django_security_hunter.collectors.pip_audit_runner import findings_from_pip_audit_json
from django_security_hunter.collectors.semgrep_runner import findings_from_semgrep_json
from django_security_hunter.config import GuardConfig
from django_security_hunter.engine import run_scan
from django_security_hunter.models import Finding


def test_pip_audit_maps_high_and_critical_only() -> None:
    data = {
        "dependencies": [
            {
                "name": "urllib3",
                "version": "1.26.0",
                "vulns": [
                    {
                        "id": "GHSA-abc",
                        "description": "Leak",
                        "severity": "high",
                        "fix_versions": ["2.0.0"],
                        "aliases": ["CVE-2023-1"],
                    },
                    {
                        "id": "GHSA-low",
                        "severity": "medium",
                        "description": "ignored",
                    },
                ],
            }
        ]
    }
    fs = findings_from_pip_audit_json(data, artifact_path="pyproject.toml")
    assert len(fs) == 1
    assert fs[0].rule_id == "DJG060"
    assert fs[0].severity == "HIGH"
    assert "urllib3" in fs[0].message
    assert fs[0].fix_hint
    assert fs[0].path == "pyproject.toml"


def test_pip_audit_severity_object_form() -> None:
    data = {
        "dependencies": [
            {
                "name": "x",
                "version": "1",
                "vulns": [{"id": "V1", "severity": {"name": "CRITICAL"}}],
            }
        ]
    }
    fs = findings_from_pip_audit_json(data)
    assert len(fs) == 1
    assert fs[0].severity == "CRITICAL"


def test_bandit_maps_result() -> None:
    data = {
        "results": [
            {
                "test_id": "B101",
                "filename": "app/views.py",
                "line_number": 10,
                "issue_text": "Use of assert",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
            }
        ]
    }
    fs = findings_from_bandit_json(data)
    assert len(fs) == 1
    assert fs[0].rule_id == "DJG061"
    assert fs[0].severity == "HIGH"
    assert fs[0].line == 10
    assert fs[0].path == "app/views.py"
    assert fs[0].fix_hint


def test_semgrep_maps_result() -> None:
    data = {
        "results": [
            {
                "check_id": "python.lang.security.audit",
                "path": "bad.py",
                "start": {"line": 3, "col": 1},
                "extra": {"message": "insecure", "severity": "ERROR"},
            }
        ]
    }
    fs = findings_from_semgrep_json(data)
    assert len(fs) == 1
    assert fs[0].rule_id == "DJG062"
    assert fs[0].severity == "HIGH"
    assert fs[0].line == 3
    assert fs[0].path == "bad.py"


def test_run_scan_with_pip_audit_enabled_invokes_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from django_security_hunter.collectors import pip_audit_runner

    def fake(_root: Path) -> tuple[list[Finding], dict]:
        return (
            [
                Finding(
                    rule_id="DJG060",
                    severity="HIGH",
                    title="t",
                    message="m",
                    fix_hint="fix",
                )
            ],
            {"status": "ok", "finding_count": 1},
        )

    monkeypatch.setattr(pip_audit_runner, "run_pip_audit", fake)
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='x'\nversion='0'\n", encoding="utf-8"
    )
    cfg = GuardConfig(pip_audit=True)
    report = run_scan(tmp_path, settings_module=None, cfg=cfg)
    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "DJG060"
    assert report.metadata.get("integrations", {}).get("pip_audit", {}).get(
        "status"
    ) == "ok"

