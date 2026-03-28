from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from django_security_hunter.config import GuardConfig
from django_security_hunter.rules.dependency_audit import run_dependency_audit_rules


def test_djg060_skipped_without_env_or_config(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("DJANGO_SECURITY_HUNTER_PIP_AUDIT", raising=False)
    assert run_dependency_audit_rules(tmp_path, GuardConfig(pip_audit=False)) == []


def test_djg060_enabled_via_config(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("DJANGO_SECURITY_HUNTER_PIP_AUDIT", raising=False)
    sample = (
        '[{"name": "urllib3", "version": "1.0.0", '
        '"vulns": [{"id": "GHSA-xxxx", "description": "TLS issue"}]}]'
    )
    with patch(
        "django_security_hunter.rules.dependency_audit.subprocess.run"
    ) as run_mock:
        run_mock.return_value.stdout = sample
        run_mock.return_value.stderr = ""
        findings = run_dependency_audit_rules(
            tmp_path, GuardConfig(pip_audit=True)
        )
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG060"


def test_djg060_env_off_overrides_config(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DJANGO_SECURITY_HUNTER_PIP_AUDIT", "0")
    assert (
        run_dependency_audit_rules(tmp_path, GuardConfig(pip_audit=True)) == []
    )


def test_djg060_parses_pip_audit_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DJANGO_SECURITY_HUNTER_PIP_AUDIT", "1")
    sample = (
        '[{"name": "urllib3", "version": "1.0.0", '
        '"vulns": [{"id": "GHSA-xxxx", "description": "TLS issue"}]}]'
    )
    with patch(
        "django_security_hunter.rules.dependency_audit.subprocess.run"
    ) as run_mock:
        run_mock.return_value.stdout = sample
        run_mock.return_value.stderr = ""
        findings = run_dependency_audit_rules(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "DJG060"
    assert f.severity == "HIGH"
    assert "urllib3" in f.message
    assert "GHSA-xxxx" in f.message
    assert f.fix_hint


def test_djg060_critical_from_cvss_score(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DJANGO_SECURITY_HUNTER_PIP_AUDIT", "1")
    sample = (
        '[{"name": "badlib", "version": "0.1", '
        '"vulns": [{"id": "GHSA-y", "severity": [{"type": "CVSS_V3", "score": "9.8"}]}]}]'
    )
    with patch(
        "django_security_hunter.rules.dependency_audit.subprocess.run"
    ) as run_mock:
        run_mock.return_value.stdout = sample
        run_mock.return_value.stderr = ""
        findings = run_dependency_audit_rules(tmp_path)
    assert findings[0].severity == "CRITICAL"


def test_djg060_dict_wrapper_format(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DJANGO_SECURITY_HUNTER_PIP_AUDIT", "1")
    sample = (
        '{"dependencies": ['
        '{"name": "requests", "version": "2.0", '
        '"vulnerabilities": ["CVE-1234"]}'
        "]}"
    )
    with patch(
        "django_security_hunter.rules.dependency_audit.subprocess.run"
    ) as run_mock:
        run_mock.return_value.stdout = sample
        run_mock.return_value.stderr = ""
        findings = run_dependency_audit_rules(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG060"
