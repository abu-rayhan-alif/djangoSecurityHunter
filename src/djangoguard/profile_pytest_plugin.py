"""Pytest plugin: capture Django DB queries per test for profile mode."""

from __future__ import annotations

from dataclasses import dataclass, field

from djangoguard.profile_analysis import PerTestCapture

_MAX_SQL_CHARS = 8_000
_MAX_QUERIES_PER_TEST = 10_000


@dataclass
class DjangoguardProfilePlugin:
    """Populates ``captures`` with one :class:`PerTestCapture` per completed test."""

    captures: list[PerTestCapture] = field(default_factory=list)

    def pytest_sessionstart(self, session) -> None:
        try:
            from django.db import connections

            for conn in connections.all():
                conn.force_debug_cursor = True
        except Exception:
            pass

    def pytest_runtest_setup(self, item) -> None:
        try:
            from django.db import connections

            item._djangoguard_q_starts = {  # noqa: SLF001
                alias: len(connections[alias].queries) for alias in connections
            }
        except Exception:
            item._djangoguard_q_starts = {}  # noqa: SLF001

    def pytest_runtest_teardown(self, item, nextitem) -> None:  # noqa: ARG002
        chunk: list[dict[str, str]] = []
        try:
            from django.db import connections

            starts = getattr(item, "_djangoguard_q_starts", {})
            for alias in connections:
                conn = connections[alias]
                start = int(starts.get(alias, 0))
                for q in conn.queries[start:]:
                    sql = q.get("sql", "") or ""
                    if len(sql) > _MAX_SQL_CHARS:
                        sql = sql[:_MAX_SQL_CHARS] + "…"
                    chunk.append({"sql": sql, "time": str(q.get("time", "0"))})
                    if len(chunk) >= _MAX_QUERIES_PER_TEST:
                        break
                if len(chunk) >= _MAX_QUERIES_PER_TEST:
                    break
        except Exception:
            chunk = []
        self.captures.append(PerTestCapture(nodeid=item.nodeid, queries=chunk))
