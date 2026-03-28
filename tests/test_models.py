from django_security_hunter.models import Finding


def test_finding_coerces_string_line_to_int() -> None:
    f = Finding(
        rule_id="R",
        severity="WARN",
        title="t",
        message="m",
        line="42",  # type: ignore[arg-type]
    )
    assert f.line == 42
    assert f.column is None


def test_finding_drops_invalid_line() -> None:
    f = Finding(
        rule_id="R",
        severity="WARN",
        title="t",
        message="m",
        line="nope",  # type: ignore[arg-type]
    )
    assert f.line is None
