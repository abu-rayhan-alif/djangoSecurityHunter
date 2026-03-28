from typer.testing import CliRunner

from djangoguard.cli import app

runner = CliRunner()


def test_scan_console_runs() -> None:
    result = runner.invoke(app, ["scan", "--format", "console"])
    assert result.exit_code == 0
    assert "djangoguard report (scan)" in result.stdout
    assert "Django settings were not loaded" in result.stderr


def test_scan_json_runs() -> None:
    result = runner.invoke(app, ["scan", "--format", "json"])
    assert result.exit_code == 0
    assert '"mode": "scan"' in result.stdout


def test_profile_sarif_runs() -> None:
    result = runner.invoke(app, ["profile", "--format", "sarif"])
    assert result.exit_code == 0
    assert '"version": "2.1.0"' in result.stdout


def test_hello_runs() -> None:
    result = runner.invoke(app, ["hello"])
    assert result.exit_code == 0
    assert "[ 25%]" in result.stdout
    assert "ready" in result.stdout.lower()
    assert "Abu Rayhan Alif" in result.stdout


def test_help_shows_author() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Abu Rayhan Alif" in result.stdout


def test_first_run_thanks_once(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("DJANGOGUARD_NO_THANKS", raising=False)
    monkeypatch.delenv("CI", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    result = runner.invoke(app, ["scan", "--format", "console"])
    assert result.exit_code == 0
    assert "Thanks for using djangoguard" in result.stdout
    assert "Abu Rayhan Alif" in result.stdout

    result2 = runner.invoke(app, ["scan", "--format", "console"])
    assert result2.exit_code == 0
    assert "Thanks for using djangoguard" not in result2.stdout


def test_scan_rejects_invalid_threshold() -> None:
    result = runner.invoke(
        app, ["scan", "--format", "console", "--threshold", "SUPERBAD"]
    )
    assert result.exit_code != 0
    combined = result.stdout + (result.stderr or "")
    assert "threshold must be one of" in combined
