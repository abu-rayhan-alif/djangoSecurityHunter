import json
from pathlib import Path

from django_security_hunter.engine import run_profile, run_scan


def test_scan_returns_empty_report_by_default() -> None:
    report = run_scan(Path(".").resolve())
    assert report.mode == "scan"
    assert report.findings == []
    assert report.metadata.get("django_settings_loaded") is False
    assert report.metadata.get("django_settings_skip_reason") == "no_settings_module"
    assert "django_settings_load_error" not in report.metadata
    dumped = json.dumps(report.to_dict())
    assert "django_settings_load_error" not in dumped


def test_profile_returns_empty_report_by_default() -> None:
    report = run_profile(Path(".").resolve())
    assert report.mode == "profile"
    assert report.findings == []

