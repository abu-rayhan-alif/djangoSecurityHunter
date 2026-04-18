from __future__ import annotations

import json
from pathlib import Path

from django_security_hunter.config import GuardConfig
from django_security_hunter.rules.profiling import (
    _build_profile_summary,
    _read_profile_json,
    _tests_to_findings,
    run_profiling_rules,
)


def test_djg045_loop_queryset_attribute_static_n_plus_one_hint(tmp_path: Path) -> None:
    """DJG045 is the static N+1 heuristic (not DJG041 duplicate SQL from pytest JSON)."""
    p = tmp_path / "views.py"
    p.write_text(
        "def v():\n"
        "    for u in User.objects.all():\n"
        "        print(u.email)\n",
        encoding="utf-8",
    )
    findings, meta = run_profiling_rules(tmp_path)
    assert "profile" in meta
    djg045 = [f for f in findings if f.rule_id == "DJG045"]
    assert len(djg045) == 1
    f = djg045[0]
    assert f.severity == "WARN"
    assert f.path and "views.py" in f.path.replace("\\", "/")
    assert "Loop variable" in (f.message or "")
    assert "email" in (f.message or "")


def test_djg045_not_emitted_for_plain_iterable_loop(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text(
        "def v():\n"
        "    for x in [1, 2, 3]:\n"
        "        print(x)\n",
        encoding="utf-8",
    )
    findings, _meta = run_profiling_rules(tmp_path)
    assert not any(f.rule_id == "DJG045" for f in findings)


def test_djg045_not_emitted_for_queryset_iterator_loop(tmp_path: Path) -> None:
    """``.iterator()`` is a cursor/stream, not a QuerySet — skip N+1 heuristic."""
    (tmp_path / "views.py").write_text(
        "def v():\n"
        "    for u in User.objects.all().iterator():\n"
        "        print(u.email)\n",
        encoding="utf-8",
    )
    findings, _ = run_profiling_rules(tmp_path)
    assert not any(f.rule_id == "DJG045" for f in findings)


def test_profile_summary_top_offenders() -> None:
    cfg = GuardConfig()
    tests = [
        {
            "nodeid": "pkg.test_a",
            "query_count": 99,
            "sql_time_ms": 10.0,
            "duplicate_sql": {},
            "has_django_db": True,
        },
        {
            "nodeid": "pkg.test_b",
            "query_count": 5,
            "sql_time_ms": 200.0,
            "duplicate_sql": {"SELECT ? FROM t": 4},
            "has_django_db": True,
        },
    ]
    s = _build_profile_summary(tests, cfg)
    assert s["top_by_query_count"][0]["nodeid"] == "pkg.test_a"
    assert s["top_by_sql_time_ms"][0]["nodeid"] == "pkg.test_b"
    assert s["duplicate_sql_examples"]


def test_tests_to_findings_djg040_high_query_count(tmp_path: Path) -> None:
    cfg = GuardConfig(query_count_threshold=10)
    tests = [
        {
            "nodeid": "app.tests.test_x",
            "query_count": 50,
            "sql_time_ms": 1.0,
            "duplicate_sql": {},
            "has_django_db": True,
        }
    ]
    findings = _tests_to_findings(tests, cfg)
    djg040 = [f for f in findings if f.rule_id == "DJG040"]
    assert len(djg040) == 1
    assert djg040[0].severity == "HIGH"
    assert "50" in (djg040[0].message or "")
    assert "app.tests.test_x" in (djg040[0].path or "")


def test_tests_to_findings_djg040_warn_not_double_threshold(tmp_path: Path) -> None:
    cfg = GuardConfig(query_count_threshold=10)
    tests = [
        {
            "nodeid": "t1",
            "query_count": 15,
            "sql_time_ms": 0.0,
            "duplicate_sql": {},
            "has_django_db": True,
        }
    ]
    findings = _tests_to_findings(tests, cfg)
    djg040 = [f for f in findings if f.rule_id == "DJG040"]
    assert len(djg040) == 1
    assert djg040[0].severity == "WARN"


def test_tests_to_findings_djg041_duplicate_sql(tmp_path: Path) -> None:
    cfg = GuardConfig()
    tests = [
        {
            "nodeid": "pkg.test_dup",
            "query_count": 1,
            "sql_time_ms": 1.0,
            "duplicate_sql": {"SELECT * FROM users": 5},
            "has_django_db": True,
        }
    ]
    findings = _tests_to_findings(tests, cfg)
    djg041 = [f for f in findings if f.rule_id == "DJG041"]
    assert len(djg041) == 1
    assert djg041[0].severity == "HIGH"
    assert "pkg.test_dup" in (djg041[0].path or "")
    assert "SELECT" in (djg041[0].message or "") or "repeated" in (djg041[0].message or "").lower()


def test_tests_to_findings_djg042_high_sql_time(tmp_path: Path) -> None:
    cfg = GuardConfig(db_time_ms_threshold=50)
    tests = [
        {
            "nodeid": "pkg.test_slow",
            "query_count": 1,
            "sql_time_ms": 400.0,
            "duplicate_sql": {},
            "has_django_db": True,
        }
    ]
    findings = _tests_to_findings(tests, cfg)
    djg042 = [f for f in findings if f.rule_id == "DJG042"]
    assert len(djg042) == 1
    assert djg042[0].severity == "WARN"
    assert "400" in (djg042[0].message or "") or "400.0" in (djg042[0].message or "")


def test_read_profile_json_malformed_returns_empty_tests(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    data = _read_profile_json(bad)
    assert data.get("tests") == []


def test_read_profile_json_valid_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "ok.json"
    payload = {"tests": [{"nodeid": "a", "query_count": 3}]}
    path.write_text(json.dumps(payload), encoding="utf-8")
    data = _read_profile_json(path)
    assert data.get("tests") == [{"nodeid": "a", "query_count": 3}]
