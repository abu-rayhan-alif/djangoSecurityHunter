"""DJG-9: stable JSON + SARIF shape."""

from __future__ import annotations

import json

from django_security_hunter.models import Report
from django_security_hunter.output import as_json, as_sarif
from django_security_hunter.package_meta import REPORT_JSON_SCHEMA_VERSION


def test_json_report_includes_schema_and_tool() -> None:
    r = Report(mode="scan", findings=[])
    data = json.loads(as_json(r))
    assert data["schema_version"] == REPORT_JSON_SCHEMA_VERSION
    assert data["tool"]["name"] == "django_security_hunter"
    assert "version" in data["tool"]
    assert data["mode"] == "scan"
    assert data["findings"] == []


def test_sarif_empty_run_is_valid() -> None:
    r = Report(mode="scan", findings=[])
    sarif = json.loads(as_sarif(r))
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_sarif_is_v2_1_with_driver_and_locations() -> None:
    from django_security_hunter.models import Finding

    r = Report(
        mode="scan",
        findings=[
            Finding(
                rule_id="DJG001",
                severity="WARN",
                title="T",
                message="M",
                path="src/x.py",
                line=10,
            )
        ],
    )
    sarif = json.loads(as_sarif(r))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["columnKind"] == "utf16CodeUnits"
    driver = run["tool"]["driver"]
    assert driver["name"] == "django_security_hunter"
    assert "version" in driver
    assert "informationUri" in driver
    assert len(driver["rules"]) == 1
    assert driver["rules"][0]["id"] == "DJG001"
    res = run["results"][0]
    assert res["ruleId"] == "DJG001"
    assert res["ruleIndex"] == 0
    assert "locations" in res
