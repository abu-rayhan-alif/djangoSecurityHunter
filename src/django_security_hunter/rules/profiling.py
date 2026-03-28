from __future__ import annotations

from pathlib import Path

from django_security_hunter.config import GuardConfig
from django_security_hunter.models import Finding
from django_security_hunter.profile_analysis import (
    build_profile_findings,
    profile_summary_metadata,
)
from django_security_hunter.profile_runner import run_pytest_profile_capture


def run_profiling_rules(
    project_root: Path,
    cfg: GuardConfig,
    settings_module: str | None = None,
) -> tuple[list[Finding], dict[str, object]]:
    """DJG040–DJG042: query count, N+1 signatures, DB time per test (pytest capture)."""
    captures, exit_code, err = run_pytest_profile_capture(project_root, settings_module)
    meta: dict[str, object] = profile_summary_metadata(
        captures,
        pytest_exit_code=exit_code,
        runner="pytest",
        error=err,
    )
    if err:
        return [], meta

    findings = build_profile_findings(
        captures,
        query_count_threshold=cfg.query_count_threshold,
        db_time_ms_threshold=float(cfg.db_time_ms_threshold),
    )
    return findings, meta
