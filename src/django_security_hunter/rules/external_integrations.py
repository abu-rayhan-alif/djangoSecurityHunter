"""Optional external scanners (pip-audit, Bandit, Semgrep) mapped to DJG060–DJG062."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from django_security_hunter.collectors import bandit_runner, pip_audit_runner, semgrep_runner
from django_security_hunter.config import GuardConfig
from django_security_hunter.models import Finding


def run_external_integration_findings(
    project_root: Path, cfg: GuardConfig
) -> tuple[list[Finding], dict[str, Any]]:
    """Run enabled integrations and return findings plus per-tool metadata."""
    findings: list[Finding] = []
    integrations: dict[str, Any] = {}

    if cfg.pip_audit:
        f, meta = pip_audit_runner.run_pip_audit(project_root)
        findings.extend(f)
        integrations["pip_audit"] = {"enabled": True, **meta}
    else:
        integrations["pip_audit"] = {"enabled": False, "status": "skipped"}

    if cfg.bandit:
        f, meta = bandit_runner.run_bandit(project_root)
        findings.extend(f)
        integrations["bandit"] = {"enabled": True, **meta}
    else:
        integrations["bandit"] = {"enabled": False, "status": "skipped"}

    if cfg.semgrep:
        f, meta = semgrep_runner.run_semgrep(project_root)
        findings.extend(f)
        integrations["semgrep"] = {"enabled": True, **meta}
    else:
        integrations["semgrep"] = {"enabled": False, "status": "skipped"}

    return findings, integrations


