"""Pytest hooks for `profile` mode (DJG040–DJG042).

Loaded via `pytest -p django_security_hunter.profile_pytest`."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

_rows: list[dict[str, Any]] = []


def pytest_sessionstart(session: pytest.Session) -> None:
    global _rows
    _rows = []


def _norm_sql(sql: str) -> str:
    s = re.sub(r"\s+", " ", sql.strip())
    s = re.sub(r"\b\d+\b", "?", s)
    return s[:800]


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Any:
    out = os.environ.get("DJANGOGUARD_PROFILE_OUT")
    if not out:
        yield
        return
    try:
        from django.conf import settings
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
    except Exception:
        yield
        return
    if not settings.configured:
        yield
        return

    ctx_mgr = CaptureQueriesContext(connection)
    ctx_mgr.__enter__()
    try:
        yield
    finally:
        ctx_mgr.__exit__(None, None, None)
        captured = ctx_mgr.captured_queries
        norms = [_norm_sql(q.get("sql", "")) for q in captured]
        counts = Counter(norms)
        dupes = {k: v for k, v in counts.items() if v >= 3 and k.strip()}
        sql_ms = 0.0
        for q in captured:
            try:
                sql_ms += float(q.get("time", 0) or 0) * 1000.0
            except (TypeError, ValueError):
                pass
        _rows.append(
            {
                "nodeid": item.nodeid,
                "query_count": len(captured),
                "sql_time_ms": sql_ms,
                "duplicate_sql": dupes,
                "has_django_db": item.get_closest_marker("django_db") is not None,
            }
        )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    out = os.environ.get("DJANGOGUARD_PROFILE_OUT")
    if not out:
        return
    Path(out).write_text(json.dumps({"tests": _rows}), encoding="utf-8")
