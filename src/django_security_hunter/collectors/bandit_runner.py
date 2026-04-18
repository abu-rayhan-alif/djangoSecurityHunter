"""Run Bandit and map JSON output to DJG061 findings."""

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

_TIMEOUT_SEC = 300


def _bandit_severity_to_finding(sev: str) -> str:
    u = sev.strip().upper()
    if u == "HIGH":
        return "HIGH"
    if u == "MEDIUM":
        return "WARN"
    if u == "LOW":
        return "INFO"
    return "WARN"


def findings_from_bandit_json(data: Any) -> list[Finding]:
    """Map Bandit JSON to DJG061 findings."""
    out: list[Finding] = []
    if not isinstance(data, dict):
        return out
    results = data.get("results")
    if not isinstance(results, list):
        return out

    for idx, item in enumerate(results):
        if idx >= MAX_FINDINGS_PER_SCANNER:
            break
        if not isinstance(item, dict):
            continue
        test_id = str(item.get("test_id") or "B???")[:80]
        path = item.get("filename")
        line = item.get("line_number")
        msg = str(item.get("issue_text") or "").strip()
        sev_raw = str(item.get("issue_severity") or "MEDIUM").strip()
        conf = str(item.get("issue_confidence") or "").strip()

        title = f"Bandit {test_id}"
        message = msg or f"Bandit reported {test_id}."
        if conf:
            message += f" (confidence: {conf})"

        fix_hint = (
            "Review the flagged line and Bandit documentation for this test ID; "
            "refactor to remove the pattern or add a narrow `# nosec` with justification."
        )

        try:
            line_i = int(line) if line is not None else None
        except (TypeError, ValueError):
            line_i = None

        out.append(
            Finding(
                rule_id="DJG061",
                severity=_bandit_severity_to_finding(sev_raw),
                title=title,
                message=message,
                path=str(path) if path else None,
                line=line_i,
                fix_hint=fix_hint,
                tags=["bandit", "sast", test_id],
            )
        )
    return out


def _scan_targets(root: Path) -> list[str]:
    r = root.resolve()
    if (r / "src").is_dir():
        return [str(r / "src")]
    return [str(r)]


def run_bandit(project_root: Path) -> tuple[list[Finding], dict[str, Any]]:
    """Run ``python -m bandit -f json`` on the project source tree."""
    root = project_root.resolve()
    targets = _scan_targets(root)
    cmd = [sys.executable, "-m", "bandit", "-f", "json", "-q", "-r", *targets]
    logger.debug("Running Bandit: cwd=%s targets=%s", root, targets)
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
        logger.warning("Bandit subprocess failed (python not found): %s", exc)
        return [], {"status": "error", "reason": "python_not_found"}
    except subprocess.TimeoutExpired:
        logger.warning("Bandit timed out after %s seconds", _TIMEOUT_SEC)
        return [], {"status": "error", "reason": "timeout"}
    except OSError as exc:
        logger.warning("Bandit subprocess failed (OS error): %s", exc)
        return [], {"status": "error", "reason": "subprocess_os_error", "detail": str(exc)[:500]}

    raw = (proc.stdout or "").strip()
    if len(raw) > MAX_SCANNER_JSON_BYTES:
        logger.warning(
            "Bandit JSON output exceeded %s bytes; skipping parse",
            MAX_SCANNER_JSON_BYTES,
        )
        return [], {"status": "error", "reason": "output_too_large"}
    if not raw:
        err = (proc.stderr or "")[:500]
        logger.warning(
            "Bandit produced no JSON (exit_code=%s): %s",
            proc.returncode,
            err or "(empty stderr)",
        )
        return [], {
            "status": "error",
            "reason": "no_json_output",
            "detail": err,
            "exit_code": proc.returncode,
        }

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("Bandit returned invalid JSON: %s", exc)
        return [], {"status": "error", "reason": "invalid_json"}

    if not isinstance(data, dict):
        logger.warning(
            "Bandit JSON root is %s, not an object; cannot parse results",
            type(data).__name__,
        )
        return [], {
            "status": "error",
            "reason": "invalid_json_root",
            "exit_code": proc.returncode,
        }
    results = data.get("results")
    if "results" in data and not isinstance(results, list):
        logger.warning(
            "Bandit JSON key 'results' is not a list (got %s); cannot map findings",
            type(results).__name__,
        )
        return [], {
            "status": "error",
            "reason": "invalid_results_shape",
            "exit_code": proc.returncode,
        }

    findings = findings_from_bandit_json(data)
    meta = {
        "status": "ok",
        "exit_code": proc.returncode,
        "finding_count": len(findings),
    }
    logger.debug(
        "Bandit finished exit_code=%s finding_count=%s",
        proc.returncode,
        len(findings),
    )
    return findings, meta


