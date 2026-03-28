"""Analyze captured per-test SQL for DJG040–DJG042."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from django_security_hunter.models import Finding

# N+1 heuristic: same normalized shape repeated at least this many times in one test.
_N1_REPEAT_MIN = 4


def normalize_sql_signature(sql: str, max_len: int = 400) -> str:
    """Collapse literals so repeated ORM queries group as one signature."""
    if len(sql) > 50_000:
        sql = sql[:50_000]
    s = " ".join(sql.split())
    s = re.sub(r"\b\d+\b", "?", s)
    s = re.sub(r"'(?:[^']|'')*'", "?", s)
    s = re.sub(r'"(?:[^"]|"")*"', "?", s)
    return s[:max_len]


def nodeid_to_path(nodeid: str) -> str | None:
    if "::" not in nodeid:
        return None
    return nodeid.split("::", 1)[0]


@dataclass
class PerTestCapture:
    nodeid: str
    queries: list[dict[str, str]] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.queries)

    def total_time_ms(self) -> float:
        total = 0.0
        for q in self.queries:
            try:
                total += float(q.get("time", 0)) * 1000.0
            except (TypeError, ValueError):
                continue
        return total

    def signature_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for q in self.queries:
            sig = normalize_sql_signature(q.get("sql", ""))
            out[sig] = out.get(sig, 0) + 1
        return out

    def worst_repeated_signature(self) -> tuple[str, int]:
        counts = self.signature_counts()
        if not counts:
            return ("", 0)
        sig, n = max(counts.items(), key=lambda kv: kv[1])
        return (sig, n)


def build_profile_findings(
    captures: list[PerTestCapture],
    *,
    query_count_threshold: int,
    db_time_ms_threshold: float,
) -> list[Finding]:
    findings: list[Finding] = []
    for cap in captures:
        path = nodeid_to_path(cap.nodeid)
        qc = cap.count
        t_ms = cap.total_time_ms()
        worst_sig, repeat_n = cap.worst_repeated_signature()

        if qc > query_count_threshold:
            sev = (
                "HIGH"
                if qc > max(query_count_threshold * 2, 100)
                else "WARN"
            )
            findings.append(
                Finding(
                    rule_id="DJG040",
                    severity=sev,
                    title="High query count in a single test",
                    message=(
                        f"Test `{cap.nodeid}` executed {qc} SQL queries "
                        f"(threshold {query_count_threshold})."
                    ),
                    path=path,
                    fix_hint=(
                        "Reduce queries with select_related/prefetch_related, "
                        "annotate/aggregate, or smaller test data; check for N+1 loops."
                    ),
                    tags=["performance", "queries"],
                )
            )

        if repeat_n >= _N1_REPEAT_MIN and worst_sig.strip():
            findings.append(
                Finding(
                    rule_id="DJG041",
                    severity="HIGH",
                    title="Repeated SQL signature suggests N+1 queries",
                    message=(
                        f"Test `{cap.nodeid}` ran the same query shape {repeat_n} times. "
                        f"Example signature: {worst_sig[:220]}"
                        + ("…" if len(worst_sig) > 220 else "")
                    ),
                    path=path,
                    fix_hint=(
                        "Use select_related/prefetch_related, bulk operations, or cache "
                        "in-loop lookups; confirm iterators are not triggering lazy loads per row."
                    ),
                    tags=["performance", "n-plus-1"],
                )
            )

        if t_ms > db_time_ms_threshold:
            findings.append(
                Finding(
                    rule_id="DJG042",
                    severity="WARN",
                    title="High total DB time in a single test",
                    message=(
                        f"Test `{cap.nodeid}` spent ~{t_ms:.1f} ms in database time "
                        f"(threshold {db_time_ms_threshold:.0f} ms)."
                    ),
                    path=path,
                    fix_hint=(
                        "Profile slow queries, add indexes, reduce round-trips, "
                        "or use smaller fixtures for this test."
                    ),
                    tags=["performance", "database"],
                )
            )

    return findings


def profile_summary_metadata(
    captures: list[PerTestCapture],
    *,
    pytest_exit_code: int,
    runner: str,
    error: str | None = None,
) -> dict[str, object]:
    """Top offenders and repeated-SQL examples for report metadata / console."""
    meta: dict[str, object] = {
        "profile_runner": runner,
        "profile_pytest_exit_code": pytest_exit_code,
        "profile_tests_observed": len(captures),
        "profile_note": (
            "Captured via pytest; Django's built-in ``manage.py test`` runner is not used. "
            "Install pytest-django and set DJANGO_SETTINGS_MODULE "
            "(or pass --settings) for ORM tests."
        ),
    }
    if error:
        meta["profile_error"] = error

    if not captures:
        return meta

    by_q = sorted(captures, key=lambda c: c.count, reverse=True)[:15]
    meta["profile_top_by_query_count"] = [
        {
            "nodeid": c.nodeid,
            "query_count": c.count,
            "db_time_ms": round(c.total_time_ms(), 2),
            "worst_repeated_signature": c.worst_repeated_signature()[0][:300],
            "repeat_count": c.worst_repeated_signature()[1],
        }
        for c in by_q
    ]

    by_t = sorted(captures, key=lambda c: c.total_time_ms(), reverse=True)[:15]
    meta["profile_top_by_db_time_ms"] = [
        {
            "nodeid": c.nodeid,
            "query_count": c.count,
            "db_time_ms": round(c.total_time_ms(), 2),
        }
        for c in by_t
    ]
    return meta
