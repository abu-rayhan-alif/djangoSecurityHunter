"""Error handling and negative-path tests (malformed inputs, bad JSON from tools)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

from django_security_hunter.collectors import bandit_runner, semgrep_runner
from django_security_hunter.engine import run_scan
from django_security_hunter.rules.profiling import _read_profile_json


def test_run_scan_survives_syntax_error_python(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def x(\n", encoding="utf-8")
    report = run_scan(tmp_path.resolve())
    assert report.mode == "scan"
    assert isinstance(report.findings, list)


def test_run_scan_survives_invalid_utf8_python(tmp_path: Path) -> None:
    p = tmp_path / "badenc.py"
    p.write_bytes(b"\xff\xfe def ok():\n    return 1\n")
    report = run_scan(tmp_path.resolve())
    assert report.mode == "scan"


def test_run_scan_survives_invalid_utf8_template(tmp_path: Path) -> None:
    (tmp_path / "t.html").write_bytes(b"\xff\xfe{% load static %}\n")
    report = run_scan(tmp_path.resolve())
    assert report.mode == "scan"


def test_bandit_runner_invalid_json_returns_empty_and_meta(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "x.py").write_text("x = 1\n", encoding="utf-8")
    proc = type("P", (), {})()
    proc.stdout = "{ not valid json"
    proc.stderr = ""
    proc.returncode = 1
    with patch("django_security_hunter.collectors.bandit_runner.subprocess.run", return_value=proc):
        findings, meta = bandit_runner.run_bandit(tmp_path)
    assert findings == []
    assert meta.get("reason") == "invalid_json"


def test_semgrep_runner_invalid_json_returns_empty_and_meta(tmp_path: Path) -> None:
    (tmp_path / "y.py").write_text("y = 2\n", encoding="utf-8")
    proc = type("P", (), {})()
    proc.stdout = "not-json-at-all"
    proc.stderr = ""
    proc.returncode = 0
    with patch(
        "django_security_hunter.collectors.semgrep_runner.shutil.which",
        return_value=sys.executable,
    ):
        with patch(
            "django_security_hunter.collectors.semgrep_runner.subprocess.run",
            return_value=proc,
        ):
            findings, meta = semgrep_runner.run_semgrep(tmp_path)
    assert findings == []
    assert meta.get("reason") == "invalid_json"


def test_read_profile_json_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    data = _read_profile_json(missing)
    assert data.get("tests") == []
