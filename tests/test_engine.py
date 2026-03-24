from pathlib import Path

from djangoguard.engine import run_profile, run_scan


def test_scan_returns_empty_report_by_default() -> None:
    report = run_scan(Path(".").resolve())
    assert report.mode == "scan"
    assert report.findings == []


def test_profile_returns_empty_report_by_default() -> None:
    report = run_profile(Path(".").resolve())
    assert report.mode == "profile"
    assert report.findings == []
