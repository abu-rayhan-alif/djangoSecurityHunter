import re
from pathlib import Path

from typer.testing import CliRunner

from django_security_hunter.cli import app

runner = CliRunner()

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI_ESCAPE.sub("", s)


def test_scan_console_runs(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", "--format", "console", "--project", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert "django_security_hunter report (scan)" in result.stdout
    assert "Django settings were not loaded" in result.stderr


def test_scan_console_force_color_uses_rich_layout(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--format",
            "console",
            "--project",
            str(tmp_path),
            "--force-color",
            "--threshold",
            "CRITICAL",
        ],
    )
    assert result.exit_code == 0
    # Rich inserts ANSI between styled spans; full phrase is not one substring.
    plain = _strip_ansi(result.stdout)
    assert "django_security_hunter report (scan)" in plain
    # Rich layout: Unicode rounded panels or ASCII box (+---) on legacy Windows consoles.
    assert "╭" in result.stdout or "─" in result.stdout or (
        "+" in plain and "|" in plain
    )


def test_scan_json_runs(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", "--format", "json", "--project", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert '"mode": "scan"' in result.stdout
    assert '"security_score"' in result.stdout
    assert '"security_trend"' in result.stdout


def test_scan_with_settings_requires_gate(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--format",
            "json",
            "--project",
            str(tmp_path),
            "--settings",
            "invalid settings",
        ],
    )
    assert result.exit_code == 2
    assert "Safety gate" in (result.stdout + (result.stderr or ""))


def test_scan_with_settings_allows_with_flag(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--format",
            "json",
            "--project",
            str(tmp_path),
            "--settings",
            "invalid settings",
            "--allow-project-code",
        ],
    )
    assert result.exit_code == 0
    assert '"mode": "scan"' in result.stdout


def test_profile_sarif_runs(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "profile",
            "--format",
            "sarif",
            "--project",
            str(tmp_path),
            "--allow-project-code",
        ],
    )
    assert result.exit_code == 0
    assert '"version": "2.1.0"' in result.stdout


def test_profile_requires_gate(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["profile", "--format", "sarif", "--project", str(tmp_path)]
    )
    assert result.exit_code == 2
    assert "Safety gate" in (result.stdout + (result.stderr or ""))


def test_scan_rejects_invalid_threshold(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--format",
            "console",
            "--project",
            str(tmp_path),
            "--threshold",
            "SUPERBAD",
        ],
    )
    assert result.exit_code != 0
    combined = result.stdout + (result.stderr or "")
    assert "threshold must be one of" in combined

