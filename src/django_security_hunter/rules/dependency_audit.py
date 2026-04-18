from __future__ import annotations

import json
import logging
import re
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

from django_security_hunter.config import GuardConfig, env_tri_bool
from django_security_hunter.models import Finding

logger = logging.getLogger(__name__)

_MAX_FINDINGS = 40


def _pip_audit_should_run(cfg: GuardConfig) -> bool:
    """Env overrides TOML: explicit off wins; explicit on wins; else ``cfg.pip_audit``."""
    return env_tri_bool(cfg.pip_audit, "DJANGO_SECURITY_HUNTER_PIP_AUDIT")


def _parse_cvss_score_fragment(s: str) -> float:
    if not s:
        return 0.0
    m = re.search(r"\b(\d(?:\.\d+)?)\b", s)
    if not m:
        return 0.0
    try:
        v = float(m.group(1))
        return v if 0.0 <= v <= 10.0 else 0.0
    except ValueError:
        return 0.0


def _vuln_severity(vuln: Any) -> str:
    """Map pip-audit/OSV-style vuln dict to HIGH or CRITICAL (CVSS-style scores)."""
    if not isinstance(vuln, dict):
        return "HIGH"

    best = 0.0
    sev = vuln.get("severity")
    if isinstance(sev, list):
        for item in sev:
            if isinstance(item, dict):
                best = max(best, _parse_cvss_score_fragment(str(item.get("score", ""))))
    elif isinstance(sev, str):
        u = sev.upper()
        if "CRITICAL" in u:
            return "CRITICAL"
        if "HIGH" in u:
            return "HIGH"

    for key in ("cvss", "cvss_score", "base_score"):
        val = vuln.get(key)
        if val is not None:
            try:
                v = float(val)
                if 0.0 <= v <= 10.0:
                    best = max(best, v)
            except (TypeError, ValueError):
                pass

    if best >= 9.0:
        return "CRITICAL"
    if best >= 7.0:
        return "HIGH"

    desc = str(vuln.get("description", "") or vuln.get("details", "")).upper()
    if "CRITICAL" in desc[:300]:
        return "CRITICAL"

    return "HIGH"


def run_dependency_audit_rules(
    project_root: Path, cfg: GuardConfig | None = None
) -> list[Finding]:
    """Run pip-audit when enabled via config (``pip_audit``) or env (see README)."""
    cfg = cfg or GuardConfig()
    if not _pip_audit_should_run(cfg):
        return []
    root = project_root.resolve()
    logger.debug(
        "Running pip-audit for dependency audit rules (DJG060) in %s", root
    )
    try:
        proc = subprocess.run(  # nosec B603
            [
                sys.executable,
                "-m",
                "pip_audit",
                "-f",
                "json",
                "--progress-spinner",
                "off",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("pip-audit subprocess failed in dependency_audit: %s", exc)
        return []
    raw = (proc.stdout or "").strip()
    if not raw:
        logger.debug(
            "pip-audit returned empty stdout (exit_code=%s)", proc.returncode
        )
        return []
    try:
        data: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("pip-audit JSON parse failed in dependency_audit: %s", exc)
        return []
    rows: list[Any]
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("dependencies") or data.get("packages") or []
    else:
        logger.warning(
            "pip-audit JSON root has unexpected type %s in dependency_audit; skipping",
            type(data).__name__,
        )
        return []
    if not isinstance(rows, list):
        logger.warning(
            "pip-audit dependency rows are not a list (got %s); skipping dependency_audit mapping",
            type(rows).__name__,
        )
        return []
    findings: list[Finding] = []
    for row in rows:
        if len(findings) >= _MAX_FINDINGS:
            break
        if not isinstance(row, dict):
            continue
        name = str(row.get("name", "?"))
        version = str(row.get("version", ""))
        vulns = row.get("vulns") or row.get("vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            if len(findings) >= _MAX_FINDINGS:
                break
            vid, desc = _vuln_summary(v)
            severity = _vuln_severity(v) if isinstance(v, dict) else "HIGH"
            findings.append(
                Finding(
                    rule_id="DJG060",
                    severity=severity,
                    title=f"Vulnerable dependency: {name}",
                    message=f"{name} {version}: {vid}. {desc}".strip(),
                    path="requirements",
                    fix_hint=(
                        "Upgrade to a patched version (pip install -U ...) or replace the package; "
                        "re-run pip-audit after changes.\n"
                    ),
                )
            )
    return findings


def _vuln_summary(vuln: Any) -> tuple[str, str]:
    if isinstance(vuln, str):
        return vuln, ""
    if isinstance(vuln, dict):
        vid = str(
            vuln.get("id")
            or (vuln.get("aliases") or ["unknown"])[0]
            or "unknown"
        )
        desc = str(vuln.get("description") or vuln.get("details") or "")[:400]
        return vid, desc
    return str(vuln), ""
