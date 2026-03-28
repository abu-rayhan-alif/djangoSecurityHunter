from __future__ import annotations

from django_security_hunter.config import GuardConfig
from django_security_hunter.profile_analysis import (
    PerTestCapture,
    build_profile_findings,
    normalize_sql_signature,
)
from django_security_hunter.rules.profiling import run_profiling_rules


def test_normalize_sql_signature_collapses_literals() -> None:
    a = normalize_sql_signature("SELECT * FROM x WHERE id = 1")
    b = normalize_sql_signature("SELECT * FROM x WHERE id = 99")
    assert a == b


def test_djg040_high_when_many_queries() -> None:
    queries = [{"sql": f"SELECT {i}", "time": "0.001"} for i in range(120)]
    cap = PerTestCapture(nodeid="app/tests/test_x.py::test_foo", queries=queries)
    findings = build_profile_findings(
        [cap],
        query_count_threshold=50,
        db_time_ms_threshold=10_000.0,
    )
    djg040 = [f for f in findings if f.rule_id == "DJG040"]
    assert len(djg040) == 1
    assert djg040[0].severity == "HIGH"


def test_djg041_repeated_signature() -> None:
    sql = "SELECT * FROM book WHERE author_id = 1"
    queries = [{"sql": sql, "time": "0.001"} for _ in range(5)]
    cap = PerTestCapture(nodeid="app/tests/test_n1.py::test_n", queries=queries)
    findings = build_profile_findings(
        [cap],
        query_count_threshold=10_000,
        db_time_ms_threshold=10_000.0,
    )
    assert any(f.rule_id == "DJG041" for f in findings)


def test_djg042_db_time() -> None:
    queries = [{"sql": "SELECT 1", "time": "0.15"}]  # 150ms
    cap = PerTestCapture(nodeid="app/tests/test_slow.py::test_s", queries=queries)
    findings = build_profile_findings(
        [cap],
        query_count_threshold=10_000,
        db_time_ms_threshold=100.0,
    )
    assert any(f.rule_id == "DJG042" for f in findings)


def test_run_profiling_empty_project(tmp_path) -> None:
    cfg = GuardConfig()
    findings, meta = run_profiling_rules(tmp_path.resolve(), cfg, None)
    assert isinstance(findings, list)
    assert "profile_pytest_exit_code" in meta
