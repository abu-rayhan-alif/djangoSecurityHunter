"""Run pip-audit and parse JSON output (DJG060)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from djsecinspect.limits import MAX_FINDINGS_PER_SCANNER, MAX_SCANNER_JSON_BYTES
from djsecinspect.models import Finding

_TIMEOUT_SEC = 180


def _dependency_report_path(root: Path) -> str:
    """Best-effort path for SARIF/JSON location (dependency graph is project-wide)."""
    r = root.resolve()
    if (r / "pyproject.toml").is_file():
        return "pyproject.toml"
    if (r / "requirements.txt").is_file():
        return "requirements.txt"
    return "dependencies"


def _vuln_severity(vuln: dict[str, Any]) -> str:
    raw = vuln.get("severity")
    if isinstance(raw, dict):
        return str(raw.get("name") or raw.get("value") or "").strip().lower()
    if isinstance(raw, str):
        return raw.strip().lower()
    return ""


def _finding_severity_from_audit(sev: str) -> str:
    if sev == "critical":
        return "CRITICAL"
    if sev == "high":
        return "HIGH"
    return "HIGH"  # defensive default for unknown-but-present


def findings_from_pip_audit_json(
    data: Any, artifact_path: str = "pyproject.toml"
) -> list[Finding]:
    """Map pip-audit JSON to DJG060 findings (HIGH/CRITICAL only)."""
    findings: list[Finding] = []
    if not isinstance(data, dict):
        return findings
    deps = data.get("dependencies")
    if not isinstance(deps, list):
        return findings

    n_emitted = 0
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name", "?"))
        ver = str(dep.get("version", "?"))
        vulns = dep.get("vulns")
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if n_emitted >= MAX_FINDINGS_PER_SCANNER:
                return findings
            if not isinstance(vuln, dict):
                continue
            sev = _vuln_severity(vuln)
            if sev not in ("high", "critical"):
                continue
            vid = str(vuln.get("id") or "unknown")
            desc = str(vuln.get("description") or "")[:800]
            aliases = vuln.get("aliases")
            alias_s = ""
            if isinstance(aliases, list) and aliases:
                alias_s = ", ".join(str(a) for a in aliases[:5])
            fix = vuln.get("fix_versions")
            fix_s = ""
            if isinstance(fix, list) and fix:
                fix_s = "Upgrade to: " + ", ".join(str(x) for x in fix[:5])

            msg = f"Dependency `{name}` {ver}: vulnerability {vid} ({sev})."
            if alias_s:
                msg += f" Aliases: {alias_s}."
            if desc:
                msg += f" {desc[:400]}"

            findings.append(
                Finding(
                    rule_id="DJG060",
                    severity=_finding_severity_from_audit(sev),
                    title="pip-audit: vulnerable dependency",
                    message=msg,
                    path=artifact_path,
                    fix_hint=(
                        (fix_s + " ") if fix_s else ""
                    )
                    + "Run `pip-audit` locally, pin fixed versions, and re-lock dependencies.",
                    tags=["dependencies", "pip-audit"],
                )
            )
            n_emitted += 1
    return findings


def run_pip_audit(project_root: Path) -> tuple[list[Finding], dict[str, Any]]:
    """Execute ``pip-audit --format json`` in ``project_root``."""
    root = project_root.resolve()
    cmd = [sys.executable, "-m", "pip_audit", "--format", "json"]
    try:
        proc = subprocess.run(
            cmd,
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_TIMEOUT_SEC,
            check=False,
        )
    except FileNotFoundError:
        return [], {"status": "error", "reason": "python_not_found"}
    except subprocess.TimeoutExpired:
        return [], {"status": "error", "reason": "timeout"}

    out = proc.stdout or ""
    if len(out) > MAX_SCANNER_JSON_BYTES:
        return [], {"status": "error", "reason": "output_too_large"}

    if proc.returncode != 0 and not out.strip():
        err = (proc.stderr or proc.stdout or "")[:500]
        return [], {
            "status": "error",
            "reason": "pip_audit_failed",
            "detail": err,
            "exit_code": proc.returncode,
        }

    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return [], {"status": "error", "reason": "invalid_json"}

    art = _dependency_report_path(root)
    findings = findings_from_pip_audit_json(data, artifact_path=art)
    meta: dict[str, Any] = {
        "status": "ok",
        "exit_code": proc.returncode,
        "finding_count": len(findings),
    }
    return findings, meta

