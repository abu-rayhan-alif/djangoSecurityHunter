"""Integration tests for ``run_scan`` / ``run_profile`` (full pipeline, not isolated rules)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from django_security_hunter.engine import run_profile, run_scan
from django_security_hunter.models import Finding


def _finding_by_rule(findings: list[Finding], rule_id: str) -> Finding:
    matches = [f for f in findings if f.rule_id == rule_id]
    assert len(matches) >= 1, f"expected at least one {rule_id}, got {[f.rule_id for f in findings]}"
    return matches[0]


def test_run_scan_whitespace_only_settings_treated_as_absent(tmp_path: Path) -> None:
    report = run_scan(tmp_path.resolve(), settings_module="   \t  ")
    assert report.mode == "scan"
    assert report.metadata.get("settings_module") is None
    assert report.metadata.get("django_settings_skip_reason") == "no_settings_module"


def test_scan_returns_empty_report_by_default(tmp_path: Path) -> None:
    report = run_scan(tmp_path.resolve())
    assert report.mode == "scan"
    assert report.findings == []
    assert report.metadata.get("django_settings_loaded") is False
    assert report.metadata.get("django_settings_skip_reason") == "no_settings_module"
    assert "django_settings_load_error" not in report.metadata
    dumped = json.dumps(report.to_dict())
    assert "django_settings_load_error" not in dumped


def test_profile_returns_empty_report_by_default(tmp_path: Path) -> None:
    report = run_profile(tmp_path.resolve())
    assert report.mode == "profile"
    assert report.findings == []
    assert "profile" in report.metadata
    prof = report.metadata["profile"]
    assert prof.get("query_runtime") == "skipped"
    assert "runtime_query_metrics" in prof
    assert prof["runtime_query_metrics"].get("project_root") == str(tmp_path.resolve())


def test_run_scan_end_to_end_mark_safe_finding(tmp_path: Path) -> None:
    p = tmp_path / "views.py"
    p.write_text(
        "from django.utils.safestring import mark_safe\n"
        "HTML = mark_safe(user_input)\n",
        encoding="utf-8",
    )
    report = run_scan(tmp_path.resolve())
    f = _finding_by_rule(report.findings, "DJG070")
    assert f.severity == "HIGH"
    assert f.path and f.path.replace("\\", "/").endswith("views.py")
    assert "mark_safe" in (f.title or "") or "mark_safe" in (f.message or "").lower()
    assert f.line is not None


def test_run_scan_end_to_end_concurrency_djg052(tmp_path: Path) -> None:
    p = tmp_path / "race.py"
    p.write_text(
        "def go():\n"
        "    for row in M.objects.filter(active=True):\n"
        "        row.x = 1\n"
        "        row.save()\n",
        encoding="utf-8",
    )
    report = run_scan(tmp_path.resolve())
    f = _finding_by_rule(report.findings, "DJG052")
    assert f.severity == "WARN"
    assert "select_for_update" in (f.title or "").lower() or "select_for_update" in (
        f.fix_hint or ""
    ).lower()
    assert f.path and "race.py" in f.path.replace("\\", "/")


def test_run_scan_clean_python_no_djg070(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text(
        "def healthy():\n    return 42\n",
        encoding="utf-8",
    )
    report = run_scan(tmp_path.resolve())
    assert not any(f.rule_id == "DJG070" for f in report.findings)


def test_run_scan_report_dict_round_trip_includes_findings(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text("pickle.loads(blob)\n", encoding="utf-8")
    report = run_scan(tmp_path.resolve())
    data = report.to_dict()
    assert data["mode"] == "scan"
    ids = {x.get("rule_id") for x in data.get("findings", [])}
    assert "DJG072" in ids


def test_run_profile_end_to_end_static_djg045(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def v():\n"
        "    for u in User.objects.all():\n"
        "        print(u.email)\n",
        encoding="utf-8",
    )
    report = run_profile(tmp_path.resolve())
    f = _finding_by_rule(report.findings, "DJG045")
    assert f.severity == "WARN"
    assert "views.py" in (f.path or "").replace("\\", "/")
    assert "Loop variable" in (f.message or "") or "queryset" in (f.message or "").lower()


@pytest.mark.parametrize(
    "snippet,rule_id",
    [
        (
            "from django.utils.safestring import mark_safe\nx = mark_safe(z)\n",
            "DJG070",
        ),
        ("import pickle\npickle.loads(data)\n", "DJG072"),
    ],
)
def test_run_scan_multiple_rules_reachable(tmp_path: Path, snippet: str, rule_id: str) -> None:
    (tmp_path / "t.py").write_text(snippet, encoding="utf-8")
    report = run_scan(tmp_path.resolve())
    assert any(f.rule_id == rule_id for f in report.findings)
