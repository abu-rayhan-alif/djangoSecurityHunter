from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from django_security_hunter.collectors.ast_scanner import iter_python_files
from django_security_hunter.config import GuardConfig
from django_security_hunter.models import Finding


class _NPlusOneVisitor(ast.NodeVisitor):
    """Static N+1 hint (DJG045); runtime duplicate-SQL is DJG041."""

    def __init__(self, rel_path: str, findings: list[Finding]) -> None:
        self.rel_path = rel_path
        self.findings = findings

    def visit_For(self, node: ast.For) -> None:
        names = _for_target_names(node.target)
        if names and _iter_is_queryset_iteration(node.iter):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
                    if sub.value.id in names and sub.attr not in {"pk", "id", "pk_id"}:
                        self.findings.append(
                            Finding(
                                rule_id="DJG045",
                                severity="WARN",
                                title="Possible ORM N+1 (loop over queryset + attribute access)",
                                message=(
                                    f"Loop variable {sub.value.id!r} accesses .{sub.attr} "
                                    "while iterating a queryset; each access may trigger a query."
                                ),
                                path=self.rel_path,
                                line=sub.lineno,
                                fix_hint=(
                                    "Use select_related() for forward FKs and prefetch_related() "
                                    "for reverse/M2M before the loop.\n"
                                ),
                            )
                        )
                        break
        self.generic_visit(node)


def _for_target_names(node: ast.expr) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Tuple):
        out: set[str] = set()
        for elt in node.elts:
            out |= _for_target_names(elt)
        return out
    return set()


def _iter_is_queryset_iteration(node: ast.expr) -> bool:
    if not isinstance(node, ast.Call):
        return False
    fn = node.func
    if not isinstance(fn, ast.Attribute):
        return False
    if fn.attr not in {"all", "filter", "exclude"}:
        return False
    if isinstance(fn.value, ast.Attribute) and fn.value.attr == "objects":
        return True
    return False


def _static_query_heuristics(project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    root = project_root.resolve()
    for path in iter_python_files(project_root):
        try:
            src = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            tree = ast.parse(src, filename=str(path))
        except SyntaxError:
            continue
        rel = str(path.relative_to(root))
        _NPlusOneVisitor(rel, findings).visit(tree)
    return findings


def _apply_db_only_filter(tests: list[dict[str, Any]], db_only: bool) -> list[dict[str, Any]]:
    if not db_only:
        return tests
    return [t for t in tests if t.get("has_django_db")]


def _build_profile_summary(tests: list[dict[str, Any]], cfg: GuardConfig) -> dict[str, Any]:
    db_only = os.environ.get("DJANGOGUARD_PROFILE_DJANGO_DB_ONLY", "").strip() == "1"
    filtered = _apply_db_only_filter(tests, db_only)
    slim = [
        {
            "nodeid": t.get("nodeid", "?"),
            "query_count": int(t.get("query_count") or 0),
            "sql_time_ms": float(t.get("sql_time_ms") or 0),
        }
        for t in filtered
    ]
    by_q = sorted(slim, key=lambda x: x["query_count"], reverse=True)[:10]
    by_t = sorted(slim, key=lambda x: x["sql_time_ms"], reverse=True)[:10]
    dup_examples: list[dict[str, Any]] = []
    for t in filtered:
        dupes: dict = t.get("duplicate_sql") or {}
        for sig, n in dupes.items():
            dup_examples.append(
                {
                    "nodeid": t.get("nodeid", "?"),
                    "repeat_count": int(n),
                    "signature": (sig or "")[:400],
                }
            )
    dup_examples.sort(key=lambda x: x["repeat_count"], reverse=True)
    dup_examples = dup_examples[:15]
    return {
        "tests_profiled": len(filtered),
        "threshold_query_count": cfg.query_count_threshold,
        "threshold_db_time_ms": cfg.db_time_ms_threshold,
        "top_by_query_count": by_q,
        "top_by_sql_time_ms": by_t,
        "duplicate_sql_examples": dup_examples,
    }


def _dupes_summary_lines(dupes: dict[str, int], limit: int = 2) -> str:
    if not dupes:
        return ""
    items = sorted(dupes.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    parts = []
    for sig, n in items:
        preview = (sig[:100] + "…") if len(sig) > 100 else sig
        parts.append(f"{n}x: {preview}")
    return "; ".join(parts)


def _tests_to_findings(tests: list[dict[str, Any]], cfg: GuardConfig) -> list[Finding]:
    findings: list[Finding] = []
    db_only = os.environ.get("DJANGOGUARD_PROFILE_DJANGO_DB_ONLY", "").strip() == "1"
    for t in tests:
        nodeid = str(t.get("nodeid", "?"))
        qc = int(t.get("query_count") or 0)
        st = float(t.get("sql_time_ms") or 0)
        dupes: dict = t.get("duplicate_sql") or {}
        if db_only and not t.get("has_django_db"):
            continue
        if qc > cfg.query_count_threshold:
            sev = "HIGH" if qc > cfg.query_count_threshold * 2 else "WARN"
            findings.append(
                Finding(
                    rule_id="DJG040",
                    severity=sev,
                    title="High DB query count in test",
                    message=f"{nodeid}: {qc} queries (threshold {cfg.query_count_threshold}).",
                    path=nodeid,
                    fix_hint=(
                        "Reduce queries with select_related/prefetch or slimmer test data.\n"
                    ),
                )
            )
        if dupes:
            dup_txt = _dupes_summary_lines(dupes, limit=3)
            findings.append(
                Finding(
                    rule_id="DJG041",
                    severity="HIGH",
                    title="Repeated SQL signature (possible N+1)",
                    message=(
                        f"{nodeid}: repeated normalized SQL signatures (examples: {dup_txt})."
                    ),
                    path=nodeid,
                    fix_hint=(
                        "Use prefetch/select_related or reuse prefetched objects in the test.\n"
                    ),
                )
            )
        if st > cfg.db_time_ms_threshold:
            findings.append(
                Finding(
                    rule_id="DJG042",
                    severity="WARN",
                    title="High cumulative SQL time in test",
                    message=(
                        f"{nodeid}: ~{st:.1f} ms cumulative SQL time "
                        f"(threshold {cfg.db_time_ms_threshold} ms)."
                    ),
                    path=nodeid,
                    fix_hint="Profile slow queries; add indexes or trim fixture work.\n",
                )
            )
    return findings


def _read_profile_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"tests": []}


def _invoke_pytest_profile(project_root: Path, settings_module: str | None, out_path: str) -> None:
    env = os.environ.copy()
    env["DJANGOGUARD_PROFILE_OUT"] = out_path
    if settings_module:
        env["DJANGO_SETTINGS_MODULE"] = settings_module
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--tb=no",
        "-p",
        "django_security_hunter.profile_pytest",
    ]
    subprocess.run(
        cmd,
        cwd=str(project_root.resolve()),
        env=env,
        timeout=600,
        capture_output=True,
        text=True,
        check=False,
    )


def _invoke_django_profile(
    project_root: Path, settings_module: str, out_path: str
) -> None:
    env = os.environ.copy()
    env["DJANGO_SETTINGS_MODULE"] = settings_module
    env["DJANGOGUARD_PROFILE_OUT"] = out_path
    cmd = [
        sys.executable,
        "-m",
        "django_security_hunter.django_profile_runner",
        str(project_root.resolve()),
    ]
    subprocess.run(
        cmd,
        cwd=str(project_root.resolve()),
        env=env,
        timeout=600,
        capture_output=True,
        text=True,
        check=False,
    )


def collect_runtime_query_profile(
    project_root: Path,
    settings_module: str | None,
    cfg: GuardConfig,
) -> tuple[list[Finding], dict[str, Any]]:
    """DJG040–DJG042 from pytest (preferred) or Django DiscoverRunner fallback."""
    if os.environ.get("DJANGOGUARD_SKIP_PYTEST_PROFILE", "").strip() == "1":
        summary = _build_profile_summary([], cfg)
        summary["query_runtime"] = "skipped"
        return [], summary

    fd, out_path = tempfile.mkstemp(suffix=".json", prefix="djg_profile_")
    os.close(fd)
    tests: list[dict[str, Any]] = []
    runner = "none"
    try:
        pytest_spec = importlib.util.find_spec("pytest")
        django_spec = importlib.util.find_spec("django")
        fallback_env = os.environ.get("DJANGOGUARD_PROFILE_DJANGO_FALLBACK", "").strip() == "1"

        if pytest_spec is not None:
            _invoke_pytest_profile(project_root, settings_module, out_path)
            data = _read_profile_json(Path(out_path))
            tests = list(data.get("tests") or [])
            runner = "pytest"

        want_django = (
            settings_module
            and django_spec is not None
            and (
                pytest_spec is None
                or (not tests and fallback_env)
            )
        )
        if want_django:
            _invoke_django_profile(project_root, settings_module, out_path)
            data = _read_profile_json(Path(out_path))
            tests = list(data.get("tests") or [])
            runner = "django"
    except (OSError, subprocess.TimeoutExpired):
        tests = []
    finally:
        Path(out_path).unlink(missing_ok=True)

    summary = _build_profile_summary(tests, cfg)
    summary["query_runtime"] = runner
    findings = _tests_to_findings(tests, cfg)
    return findings, summary


def run_profiling_rules(
    project_root: Path,
    settings_module: str | None = None,
    cfg: GuardConfig | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    cfg = cfg or GuardConfig()
    findings: list[Finding] = []
    findings.extend(_static_query_heuristics(project_root))
    runtime, profile_meta = collect_runtime_query_profile(
        project_root, settings_module, cfg
    )
    findings.extend(runtime)
    return findings, {"profile": profile_meta}
