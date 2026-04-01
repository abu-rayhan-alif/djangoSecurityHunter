from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

from django_security_hunter.config import GuardConfig
from django_security_hunter.models import Finding

_MAX_EACH = 40

_BANDIT_EXCLUDE = ".venv,venv,node_modules,dist,build,.git,.tox,.eggs,.pytest_cache,htmlcov"


def _bandit_should_run(cfg: GuardConfig) -> bool:
    raw = os.environ.get("DJANGOGUARD_BANDIT", "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on"}:
        return True
    return cfg.bandit


def _semgrep_should_run(cfg: GuardConfig) -> bool:
    raw = os.environ.get("DJANGOGUARD_SEMGREP", "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on"}:
        return True
    return cfg.semgrep


def _map_bandit_severity(s: str) -> str:
    u = (s or "").upper()
    if u == "HIGH":
        return "HIGH"
    if u == "MEDIUM":
        return "WARN"
    return "INFO"


def _map_semgrep_severity(s: str) -> str:
    u = (s or "").upper()
    if u in {"ERROR", "CRITICAL"}:
        return "HIGH"
    if u == "WARNING":
        return "WARN"
    return "INFO"


def run_bandit_rules(project_root: Path, cfg: GuardConfig) -> list[Finding]:
    if not _bandit_should_run(cfg):
        return []
    root = project_root.resolve()
    try:
        proc = subprocess.run(  # nosec B603
            [
                sys.executable,
                "-m",
                "bandit",
                "-r",
                ".",
                "-f",
                "json",
                "-q",
                "-x",
                _BANDIT_EXCLUDE,
            ],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []
    raw = (proc.stdout or "").strip()
    if not raw:
        return []
    try:
        data: Any = json.loads(raw)
    except json.JSONDecodeError:
        return []
    rows = data.get("results")
    if not isinstance(rows, list):
        return []
    findings: list[Finding] = []
    for row in rows:
        if len(findings) >= _MAX_EACH:
            break
        if not isinstance(row, dict):
            continue
        tid = str(row.get("test_id", "bandit"))
        text = str(row.get("issue_text", "") or "")[:500]
        fn = str(row.get("filename") or row.get("file") or "?")
        try:
            line = int(row.get("line_number") or row.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        sev = _map_bandit_severity(str(row.get("issue_severity", "")))
        rel = _rel_path(root, fn)
        findings.append(
            Finding(
                rule_id="DJG061",
                severity=sev,
                title=f"Bandit ({tid})",
                message=f"{tid}: {text}".strip(),
                path=rel,
                line=line if line > 0 else None,
                fix_hint=(
                    "Review Bandit finding; fix insecure pattern or suppress with a "
                    "documented rationale (narrow # nosec).\n"
                ),
            )
        )
    return findings


def _rel_path(root: Path, file_path: str) -> str:
    try:
        p = Path(file_path).resolve()
        return str(p.relative_to(root))
    except ValueError:
        return file_path.replace("\\", "/")


def run_semgrep_rules(project_root: Path, cfg: GuardConfig) -> list[Finding]:
    if not _semgrep_should_run(cfg):
        return []
    semgrep = shutil.which("semgrep")
    if not semgrep:
        return []
    root = project_root.resolve()
    configs = [
        x.strip()
        for x in os.environ.get(
            "DJANGOGUARD_SEMGREP_CONFIGS", "p/python,p/django"
        ).split(",")
        if x.strip()
    ]
    if not configs:
        configs = ["p/python"]
    cmd: list[str] = [semgrep, "--json", "-q"]
    for c in configs:
        cmd.extend(["--config", c])
    cmd.extend(
        [
            "--exclude",
            ".venv",
            "--exclude",
            "venv",
            "--exclude",
            "node_modules",
            ".",
        ]
    )
    try:
        proc = subprocess.run(  # nosec B603
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []
    raw = (proc.stdout or "").strip()
    if not raw:
        return []
    try:
        data: Any = json.loads(raw)
    except json.JSONDecodeError:
        return []
    rows = data.get("results")
    if not isinstance(rows, list):
        return []
    findings: list[Finding] = []
    for row in rows:
        if len(findings) >= _MAX_EACH:
            break
        if not isinstance(row, dict):
            continue
        extra = row.get("extra") or {}
        if not isinstance(extra, dict):
            extra = {}
        msg = str(extra.get("message", "") or "")[:500]
        sev = _map_semgrep_severity(str(extra.get("severity", "INFO")))
        path_s = str(row.get("path", "?"))
        start = row.get("start") or {}
        line = int(start.get("line", 0)) if isinstance(start, dict) else 0
        rule_id_sg = str(row.get("check_id") or extra.get("check_id") or "semgrep")
        rel = _rel_path(root, path_s)
        findings.append(
            Finding(
                rule_id="DJG062",
                severity=sev,
                title=f"Semgrep ({rule_id_sg})",
                message=msg or rule_id_sg,
                path=rel,
                line=line if line > 0 else None,
                fix_hint=(
                    "Review Semgrep match; fix issue or adjust rules in "
                    "`DJANGOGUARD_SEMGREP_CONFIGS` (comma-separated --config values).\n"
                ),
            )
        )
    return findings


def run_external_scanner_rules(project_root: Path, cfg: GuardConfig) -> list[Finding]:
    out: list[Finding] = []
    out.extend(run_bandit_rules(project_root, cfg))
    out.extend(run_semgrep_rules(project_root, cfg))
    return out
