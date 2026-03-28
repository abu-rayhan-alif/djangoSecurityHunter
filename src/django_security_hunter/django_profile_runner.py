"""Django ``DiscoverRunner`` fallback for profile mode when ``pytest`` is unavailable.

Run: ``python -m django_security_hunter.django_profile_runner <project_root>``

Requires ``DJANGO_SETTINGS_MODULE`` and ``DJANGOGUARD_PROFILE_OUT`` in the environment.
"""

from __future__ import annotations

import json
import os
import re
import sys
import unittest
from collections import Counter
from pathlib import Path
from typing import Any


def _norm_sql(sql: str) -> str:
    s = re.sub(r"\s+", " ", sql.strip())
    s = re.sub(r"\b\d+\b", "?", s)
    return s[:800]


def _make_profile_result_class(rows_out: list[dict[str, Any]]) -> type[unittest.TextTestResult]:
    class ProfileTextTestResult(unittest.TextTestResult):
        def __init__(self, stream: Any, descriptions: bool, verbosity: int) -> None:
            super().__init__(stream, descriptions, verbosity)
            self._qc: Any = None

        def startTest(self, test: unittest.TestCase) -> None:
            super().startTest(test)
            from django.db import connection
            from django.test.utils import CaptureQueriesContext

            self._qc = CaptureQueriesContext(connection)
            self._qc.__enter__()

        def stopTest(self, test: unittest.TestCase) -> None:
            try:
                if self._qc is not None:
                    self._qc.__exit__(None, None, None)
                    captured = self._qc.captured_queries
                    norms = [_norm_sql(q.get("sql", "")) for q in captured]
                    counts = Counter(norms)
                    dupes = {k: v for k, v in counts.items() if v >= 3 and k.strip()}
                    sql_ms = 0.0
                    for q in captured:
                        try:
                            sql_ms += float(q.get("time", 0) or 0) * 1000.0
                        except (TypeError, ValueError):
                            pass
                    rows_out.append(
                        {
                            "nodeid": test.id(),
                            "query_count": len(captured),
                            "sql_time_ms": sql_ms,
                            "duplicate_sql": dupes,
                            "has_django_db": False,
                        }
                    )
            finally:
                self._qc = None
            super().stopTest(test)

    return ProfileTextTestResult


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv
    if len(argv) < 2:
        print(
            "usage: python -m django_security_hunter.django_profile_runner "
            "<project_root>",
            file=sys.stderr,
        )
        return 2
    project_root = Path(argv[1]).resolve()
    out = os.environ.get("DJANGOGUARD_PROFILE_OUT")
    if not out:
        print("DJANGOGUARD_PROFILE_OUT is required", file=sys.stderr)
        return 2
    settings = os.environ.get("DJANGO_SETTINGS_MODULE")
    if not settings:
        print("DJANGO_SETTINGS_MODULE is required for Django test runner fallback", file=sys.stderr)
        return 2

    sys.path.insert(0, str(project_root))
    os.chdir(project_root)

    import django

    django.setup()

    from django.test.runner import DiscoverRunner

    rows: list[dict[str, Any]] = []
    result_cls = _make_profile_result_class(rows)
    runner = DiscoverRunner(
        verbosity=0,
        interactive=False,
        resultclass=result_cls,
    )
    failures = runner.run_tests([])
    payload = {"tests": rows, "profile_runner": "django"}
    Path(out).write_text(json.dumps(payload), encoding="utf-8")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
