"""Run Semgrep and map JSON output to DJG062 findings."""

from __future__ import annotations

import logging
import json
import os
import shutil
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

from django_security_hunter.limits import MAX_FINDINGS_PER_SCANNER, MAX_SCANNER_JSON_BYTES
from django_security_hunter.models import Finding

logger = logging.getLogger(__name__)

_TIMEOUT_SEC = 600
_DEFAULT_SEMGREP_CONFIGS = "p/python,p/django"
_MAX_SEMGREP_CONFIG_TOKEN_LEN = 512


def _semgrep_config_token_ok(token: str) -> bool:
    """Reject tokens that could smuggle extra argv (e.g. leading ``--``) or control chars."""
    if not token or len(token) > _MAX_SEMGREP_CONFIG_TOKEN_LEN:
        return False
    if token[0] == "-":
        return False
    if any(c in token for c in "\n\r\x00"):
        return False
    return True


def resolved_semgrep_configs_from_env() -> list[str]:
    """Split ``DJANGOGUARD_SEMGREP_CONFIGS`` into safe Semgrep ``--config`` values."""
    raw = os.environ.get("DJANGOGUARD_SEMGREP_CONFIGS", _DEFAULT_SEMGREP_CONFIGS)
    out: list[str] = []
    for part in raw.split(","):
        t = part.strip()
        if not _semgrep_config_token_ok(t):
            if t:
                logger.warning("Skipping unsafe Semgrep config token %r", t[:120])
            continue
        out.append(t)
    return out if out else ["p/python"]


def _semgrep_config_cli_args() -> tuple[list[str], list[str]]:
    configs = resolved_semgrep_configs_from_env()
    flags: list[str] = []
    for c in configs:
        flags.extend(["--config", c])
    return flags, configs


def _semgrep_severity(raw: str | None) -> str:
    if not raw:
        return "WARN"
    u = str(raw).strip().upper()
    if u in ("ERROR", "CRITICAL"):
        return "HIGH"
    if u in ("WARNING", "WARN"):
        return "WARN"
    if u == "INFO":
        return "INFO"
    return "WARN"


def findings_from_semgrep_json(data: Any) -> list[Finding]:
    """Map Semgrep CLI JSON to DJG062 findings."""
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
        check_id = str(item.get("check_id") or "semgrep")[:512]
        path = item.get("path")
        extra = item.get("extra")
        msg = ""
        sev_raw: str | None = None
        if isinstance(extra, dict):
            msg = str(extra.get("message") or "").strip()
            sev_raw = extra.get("severity")  # type: ignore[assignment]
            if isinstance(sev_raw, dict):
                sev_raw = str(sev_raw.get("value") or "")
            elif sev_raw is not None and not isinstance(sev_raw, str):
                sev_raw = str(sev_raw)

        start = item.get("start")
        line_i: int | None = None
        col_i: int | None = None
        if isinstance(start, dict):
            try:
                line_i = int(start["line"])
            except (KeyError, TypeError, ValueError):
                line_i = None
            try:
                col_i = int(start.get("col", 1))
            except (TypeError, ValueError):
                col_i = None

        title = f"Semgrep {check_id.split('.')[-1] if '.' in check_id else check_id}"
        message = msg or f"Semgrep rule matched: {check_id}"

        fix_hint = (
            "Review the Semgrep rule and message; fix the underlying issue or "
            "suppress with a documented exception if it is a false positive."
        )

        out.append(
            Finding(
                rule_id="DJG062",
                severity=_semgrep_severity(
                    sev_raw if isinstance(sev_raw, str) else None
                ),
                title=title[:200],
                message=message[:2000],
                path=str(path) if path else None,
                line=line_i,
                column=col_i,
                fix_hint=fix_hint,
                tags=["semgrep", "sast", check_id[:80]],
            )
        )
    return out


def run_semgrep(project_root: Path) -> tuple[list[Finding], dict[str, Any]]:
    """Run ``semgrep scan --json`` using configs from ``DJANGOGUARD_SEMGREP_CONFIGS``."""
    root = project_root.resolve()
    exe = shutil.which("semgrep")
    if not exe or not os.path.isfile(exe):
        logger.warning("semgrep executable not found on PATH")
        return [], {"status": "error", "reason": "semgrep_not_on_path"}

    config_flags, config_names = _semgrep_config_cli_args()
    cmd = [exe, "scan", "--json", "--quiet", *config_flags, str(root)]
    logger.debug(
        "Running Semgrep: exe=%s root=%s configs=%s",
        exe,
        root,
        config_names,
    )
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
        logger.warning("Semgrep subprocess failed: %s", exc)
        return [], {"status": "error", "reason": "semgrep_not_found"}
    except subprocess.TimeoutExpired:
        logger.warning("Semgrep timed out after %s seconds", _TIMEOUT_SEC)
        return [], {"status": "error", "reason": "timeout"}
    except OSError as exc:
        logger.warning("Semgrep subprocess failed (OS error): %s", exc)
        return [], {"status": "error", "reason": "subprocess_os_error", "detail": str(exc)[:500]}

    raw = (proc.stdout or "").strip()
    if len(raw) > MAX_SCANNER_JSON_BYTES:
        logger.warning(
            "Semgrep JSON output exceeded %s bytes; skipping parse",
            MAX_SCANNER_JSON_BYTES,
        )
        return [], {"status": "error", "reason": "output_too_large"}
    if not raw:
        err = (proc.stderr or "")[:500]
        logger.warning(
            "Semgrep produced no JSON (exit_code=%s): %s",
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
        logger.warning("Semgrep returned invalid JSON: %s", exc)
        return [], {"status": "error", "reason": "invalid_json"}

    if not isinstance(data, dict):
        logger.warning(
            "Semgrep JSON root is %s, not an object; cannot parse results",
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
            "Semgrep JSON key 'results' is not a list (got %s); cannot map findings",
            type(results).__name__,
        )
        return [], {
            "status": "error",
            "reason": "invalid_results_shape",
            "exit_code": proc.returncode,
        }

    findings = findings_from_semgrep_json(data)
    meta = {
        "status": "ok",
        "exit_code": proc.returncode,
        "finding_count": len(findings),
        "configs": config_names,
    }
    logger.debug(
        "Semgrep finished exit_code=%s finding_count=%s",
        proc.returncode,
        len(findings),
    )
    return findings, meta


