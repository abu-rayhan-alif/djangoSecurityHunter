"""Run pip-audit and parse JSON output (DJG060)."""

from __future__ import annotations

import logging
import json
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

from django_security_hunter.limits import MAX_FINDINGS_PER_SCANNER, MAX_SCANNER_JSON_BYTES
from django_security_hunter.models import Finding

logger = logging.getLogger(__name__)

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
    logger.debug("Running pip-audit: cwd=%s", root)
    try:
        proc = subprocess.run(  # nosec B603
            cmd,
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_TIMEOUT_SEC,
            check=False,
        )
    except FileNotFoundError as exc:
        logger.warning("pip-audit subprocess failed (python not found): %s", exc)
        return [], {"status": "error", "reason": "python_not_found"}
    except subprocess.TimeoutExpired:
        logger.warning("pip-audit timed out after %s seconds", _TIMEOUT_SEC)
        return [], {"status": "error", "reason": "timeout"}
    except OSError as exc:
        logger.warning("pip-audit subprocess failed (OS error): %s", exc)
        return [], {"status": "error", "reason": "subprocess_os_error", "detail": str(exc)[:500]}

    out = proc.stdout or ""
    if len(out) > MAX_SCANNER_JSON_BYTES:
        logger.warning(
            "pip-audit JSON output exceeded %s bytes; skipping parse",
            MAX_SCANNER_JSON_BYTES,
        )
        return [], {"status": "error", "reason": "output_too_large"}

    if proc.returncode != 0 and not out.strip():
        err = (proc.stderr or proc.stdout or "")[:500]
        logger.warning(
            "pip-audit failed (exit_code=%s, no stdout): %s",
            proc.returncode,
            err or "(empty)",
        )
        return [], {
            "status": "error",
            "reason": "pip_audit_failed",
            "detail": err,
            "exit_code": proc.returncode,
        }

    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError as exc:
        logger.warning("pip-audit returned invalid JSON: %s", exc)
        return [], {"status": "error", "reason": "invalid_json"}

    art = _dependency_report_path(root)
    if isinstance(data, list):
        if len(data) > 0:
            logger.warning(
                "pip-audit JSON is a non-empty list at root; expected an object with "
                "'dependencies' (first element type=%s)",
                type(data[0]).__name__,
            )
            return [], {
                "status": "error",
                "reason": "unexpected_json_root_list",
                "exit_code": proc.returncode,
            }
        findings: list[Finding] = []
    elif isinstance(data, dict):
        deps = data.get("dependencies")
        if deps is not None and not isinstance(deps, list):
            logger.warning(
                "pip-audit JSON key 'dependencies' is not a list (got %s); cannot map findings",
                type(deps).__name__,
            )
            return [], {
                "status": "error",
                "reason": "invalid_dependencies_shape",
                "exit_code": proc.returncode,
            }
        findings = findings_from_pip_audit_json(data, artifact_path=art)
    else:
        logger.warning(
            "pip-audit JSON root has unexpected type %s; cannot map findings",
            type(data).__name__,
        )
        return [], {
            "status": "error",
            "reason": "invalid_json_root",
            "exit_code": proc.returncode,
        }
    meta: dict[str, Any] = {
        "status": "ok",
        "exit_code": proc.returncode,
        "finding_count": len(findings),
    }
    logger.debug(
        "pip-audit finished exit_code=%s finding_count=%s",
        proc.returncode,
        len(findings),
    )
    return findings, meta


