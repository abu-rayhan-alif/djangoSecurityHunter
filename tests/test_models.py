from djangoguard.models import Finding, Report


def test_finding_coerces_bad_line_to_none() -> None:
    f = Finding(
        rule_id="R",
        severity="WARN",
        title="t",
        message="m",
        line="nope",  # type: ignore[arg-type]
    )
    assert f.line is None


def test_report_has_threshold_with_none_severity() -> None:
    r = Report(
        mode="scan",
        findings=[
            Finding(
                rule_id="X",
                severity=None,  # type: ignore[arg-type]
                title="t",
                message="m",
            )
        ],
    )
    assert not r.has_threshold_hit("WARN")
