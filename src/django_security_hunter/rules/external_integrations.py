"""Optional external scanners (pip-audit, Bandit, Semgrep) mapped to DJG060–DJG062."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from django_security_hunter.collectors import bandit_runner, pip_audit_runner, semgrep_runner
from django_security_hunter.config import GuardConfig, env_tri_bool
from django_security_hunter.models import Finding

logger = logging.getLogger(__name__)


def run_external_integration_findings(
    project_root: Path, cfg: GuardConfig
) -> tuple[list[Finding], dict[str, Any]]:
    """Run enabled integrations and return findings plus per-tool metadata."""
    findings: list[Finding] = []
    integrations: dict[str, Any] = {}

    if env_tri_bool(cfg.pip_audit, "DJANGO_SECURITY_HUNTER_PIP_AUDIT"):
        logger.debug("External integration: pip-audit enabled for %s", project_root)
        f, meta = pip_audit_runner.run_pip_audit(project_root)
        findings.extend(f)
        integrations["pip_audit"] = {"enabled": True, **meta}
    else:
        logger.debug("External integration: pip-audit skipped (not enabled in config)")
        integrations["pip_audit"] = {"enabled": False, "status": "skipped"}

    if env_tri_bool(cfg.bandit, "DJANGOGUARD_BANDIT"):
        logger.debug("External integration: Bandit enabled for %s", project_root)
        f, meta = bandit_runner.run_bandit(project_root)
        findings.extend(f)
        integrations["bandit"] = {"enabled": True, **meta}
    else:
        logger.debug("External integration: Bandit skipped (not enabled in config)")
        integrations["bandit"] = {"enabled": False, "status": "skipped"}

    if env_tri_bool(cfg.semgrep, "DJANGOGUARD_SEMGREP"):
        logger.debug("External integration: Semgrep enabled for %s", project_root)
        f, meta = semgrep_runner.run_semgrep(project_root)
        findings.extend(f)
        integrations["semgrep"] = {"enabled": True, **meta}
    else:
        logger.debug("External integration: Semgrep skipped (not enabled in config)")
        integrations["semgrep"] = {"enabled": False, "status": "skipped"}

    return findings, integrations


