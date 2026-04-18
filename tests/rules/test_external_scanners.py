from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from django_security_hunter.config import GuardConfig
from django_security_hunter.rules.external_scanners import (
    run_bandit_rules,
    run_semgrep_rules,
)


def test_djg061_bandit_parses_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DJANGOGUARD_BANDIT", "1")
    payload = (
        '{"results": [{'
        '"filename": "x.py", "line_number": 3, "issue_text": "use of eval", '
        '"issue_severity": "HIGH", "test_id": "B307"'
        "}]}"
    )
    with patch(
        "django_security_hunter.rules.external_scanners.subprocess.run"
    ) as m:
        m.return_value.stdout = payload
        m.return_value.stderr = ""
        findings = run_bandit_rules(tmp_path, GuardConfig())
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG061"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 3


def test_semgrep_subprocess_drops_unsafe_config_tokens(tmp_path: Path, monkeypatch) -> None:
    """``DJANGOGUARD_SEMGREP_CONFIGS`` must not smuggle extra argv (e.g. ``--help``)."""
    monkeypatch.setenv("DJANGOGUARD_SEMGREP", "1")
    monkeypatch.setenv("DJANGOGUARD_SEMGREP_CONFIGS", "p/python,--help,p/django")
    payload = '{"results": []}'
    with patch(
        "django_security_hunter.rules.external_scanners.shutil.which",
        return_value="/fake/semgrep",
    ):
        with patch(
            "django_security_hunter.rules.external_scanners.subprocess.run"
        ) as m:
            m.return_value.stdout = payload
            m.return_value.stderr = ""
            run_semgrep_rules(tmp_path, GuardConfig())
    cmd = m.call_args[0][0]
    assert "--help" not in cmd
    config_values = [cmd[i + 1] for i, x in enumerate(cmd) if x == "--config"]
    assert config_values == ["p/python", "p/django"]


def test_djg062_semgrep_parses_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DJANGOGUARD_SEMGREP", "1")
    monkeypatch.setenv("PATH", "/bin")  # may not find semgrep
    payload = (
        '{"results": [{'
        '"check_id": "python.lang.eval", "path": "bad.py", '
        '"start": {"line": 2}, '
        '"extra": {"message": "eval is bad", "severity": "ERROR"}'
        "}]}"
    )
    with patch(
        "django_security_hunter.rules.external_scanners.shutil.which",
        return_value="/fake/semgrep",
    ):
        with patch(
            "django_security_hunter.rules.external_scanners.subprocess.run"
        ) as m:
            m.return_value.stdout = payload
            m.return_value.stderr = ""
            findings = run_semgrep_rules(tmp_path, GuardConfig())
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG062"
    assert findings[0].line == 2
