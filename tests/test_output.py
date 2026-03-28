from djangoguard.models import Finding, Report
from djangoguard.output import as_sarif


def test_as_sarif_tolerates_non_numeric_line_column() -> None:
    """Garbage line/column are dropped; SARIF still serializes without crashing."""
    f = Finding(
        rule_id="X",
        severity="WARN",
        title="t",
        message="m",
        path="p.py",
        line="oops",  # type: ignore[arg-type]
        column="bad",  # type: ignore[arg-type]
    )
    assert f.line is None
    assert f.column is None
    report = Report(mode="scan", findings=[f])
    out = as_sarif(report)
    assert "p.py" in out
    assert "startLine" not in out
