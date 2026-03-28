from typer.testing import CliRunner

from django_security_hunter.cli import app

runner = CliRunner()


def test_scan_console_runs() -> None:
    result = runner.invoke(app, ["scan", "--format", "console"])
    assert result.exit_code == 0
    assert "django_security_hunter report (scan)" in result.stdout
    assert "Django settings were not loaded" in result.stderr


def test_scan_console_force_color_uses_rich_layout() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--format",
            "console",
            "--force-color",
            "--threshold",
            "CRITICAL",
        ],
    )
    assert result.exit_code == 0
    assert "django_security_hunter report (scan)" in result.stdout
    assert "╭" in result.stdout or "─" in result.stdout


def test_scan_json_runs() -> None:
    result = runner.invoke(app, ["scan", "--format", "json"])
    assert result.exit_code == 0
    assert '"mode": "scan"' in result.stdout


def test_profile_sarif_runs() -> None:
    result = runner.invoke(app, ["profile", "--format", "sarif"])
    assert result.exit_code == 0
    assert '"version": "2.1.0"' in result.stdout


def test_scan_rejects_invalid_threshold() -> None:
    result = runner.invoke(
        app, ["scan", "--format", "console", "--threshold", "SUPERBAD"]
    )
    assert result.exit_code != 0
    combined = result.stdout + (result.stderr or "")
    assert "threshold must be one of" in combined

