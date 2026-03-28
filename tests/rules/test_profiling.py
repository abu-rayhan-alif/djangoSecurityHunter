from __future__ import annotations

from pathlib import Path

from django_security_hunter.rules.profiling import run_profiling_rules


def test_djg041_loop_queryset_attribute(tmp_path: Path) -> None:
    p = tmp_path / "views.py"
    p.write_text(
        "def v():\n"
        "    for u in User.objects.all():\n"
        "        print(u.email)\n",
        encoding="utf-8",
    )
    findings, meta = run_profiling_rules(tmp_path)
    assert "profile" in meta
    assert any(f.rule_id == "DJG045" for f in findings)


def test_profile_summary_top_offenders() -> None:
    from django_security_hunter.config import GuardConfig
    from django_security_hunter.rules.profiling import _build_profile_summary

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
