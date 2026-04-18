"""Env overrides for scan-time external integrations (README parity with code)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from django_security_hunter.config import GuardConfig
from django_security_hunter.rules.external_integrations import (
    run_external_integration_findings,
)


def test_djangoguard_bandit_env_on_runs_bandit_when_toml_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DJANGOGUARD_BANDIT", "1")
    cfg = GuardConfig(bandit=False, pip_audit=False, semgrep=False)
    with patch(
        "django_security_hunter.rules.external_integrations.bandit_runner.run_bandit",
        return_value=([], {"status": "ok", "finding_count": 0}),
    ) as m_bandit:
        _, meta = run_external_integration_findings(tmp_path, cfg)
    m_bandit.assert_called_once()
    assert meta["bandit"]["enabled"] is True


def test_django_security_hunter_pip_audit_env_on_runs_pip_audit_when_toml_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DJANGO_SECURITY_HUNTER_PIP_AUDIT", "on")
    cfg = GuardConfig(pip_audit=False, bandit=False, semgrep=False)
    with patch(
        "django_security_hunter.rules.external_integrations.pip_audit_runner.run_pip_audit",
        return_value=([], {"status": "ok", "finding_count": 0}),
    ) as m_pip:
        _, meta = run_external_integration_findings(tmp_path, cfg)
    m_pip.assert_called_once()
    assert meta["pip_audit"]["enabled"] is True
