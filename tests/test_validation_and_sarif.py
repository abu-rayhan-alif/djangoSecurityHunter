"""Tests for settings-module validation and SARIF URI hardening."""

from __future__ import annotations

import json
from pathlib import Path

from djsecinspect.collectors.settings_loader import load_settings_context
from djsecinspect.models import Finding, Report
from djsecinspect.output import _sarif_artifact_uri, as_sarif
from djsecinspect.validation import is_valid_django_settings_module


def test_settings_module_rejects_injection_like_values() -> None:
    assert is_valid_django_settings_module("mysite.settings") is True
    assert is_valid_django_settings_module("x") is False
    assert is_valid_django_settings_module("os.anything") is False
    assert is_valid_django_settings_module("a\nimport os") is False
    assert is_valid_django_settings_module("foo-bar.settings") is False
    assert is_valid_django_settings_module("") is False


def test_load_settings_skips_invalid_module() -> None:
    ctx = load_settings_context(Path("."), "bad;evil")
    assert ctx.get("loaded") is False
    assert ctx.get("skip_reason") == "invalid_settings_module"


def test_sarif_strips_remote_scheme_to_filename() -> None:
    assert _sarif_artifact_uri("https://evil.test/path/to/file.py") == "file.py"


def test_sarif_collapses_parent_segments() -> None:
    assert _sarif_artifact_uri("src/../../../etc/passwd") == "etc/passwd"
    assert _sarif_artifact_uri("../secret.txt") == "secret.txt"


def test_sarif_report_has_safe_uris() -> None:
    report = Report(
        mode="scan",
        findings=[
            Finding(
                rule_id="DJG099",
                severity="WARN",
                title="t",
                message="m",
                path="https://x.test/a/b.py",
                line=1,
            )
        ],
    )
    data = json.loads(as_sarif(report))
    loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "b.py"

