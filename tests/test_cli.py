from typer.testing import CliRunner

from djangoguard.cli import app

runner = CliRunner()


def test_scan_console_runs() -> None:
    result = runner.invoke(app, ["scan", "--format", "console"])
    assert result.exit_code == 0
    assert "djangoguard report (scan)" in result.stdout


def test_scan_json_runs() -> None:
    result = runner.invoke(app, ["scan", "--format", "json"])
    assert result.exit_code == 0
    assert '"mode": "scan"' in result.stdout


def test_profile_sarif_runs() -> None:
    result = runner.invoke(app, ["profile", "--format", "sarif"])
    assert result.exit_code == 0
    assert '"version": "2.1.0"' in result.stdout
