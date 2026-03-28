from __future__ import annotations

from pathlib import Path
from typing import Iterable

from django_security_hunter.collectors.concurrency_scan import scan_concurrency_findings
from django_security_hunter.models import Finding

_DJG050_TITLE = "Possible check-then-create race on ORM"
_DJG050_HINT = (
    "Prefer get_or_create / update_or_create, or create inside try/except IntegrityError "
    "after a unique constraint. If you must branch on existence, lock the candidate row "
    "(select_for_update) inside transaction.atomic(), or use an idempotency key for the "
    "whole operation."
)

_DJG051_TITLE = (
    "Multi-step ORM write flow without transaction.atomic() (heuristic)"
)
_DJG051_HINT = (
    "Wrap the sequence in transaction.atomic() so partial updates roll back together. "
    "If reads influence writes, lock those rows with select_for_update() in the same "
    "atomic block."
)

_DJG052_TITLE = "Counter-style field update without F() (heuristic)"
_DJG052_HINT = (
    "Use queryset.update with F('field') (e.g. F('quantity') + 1) for read-modify-write "
    "counters, and/or lock the row with select_for_update() before assigning. "
    "Unique constraints and idempotency keys help prevent duplicate increments under retries."
)


def run_concurrency_rules(project_root: Path) -> Iterable[Finding]:
    findings: list[Finding] = []
    for rule_id, path_s, line, severity, kind in scan_concurrency_findings(project_root):
        if rule_id == "DJG050":
            msg050 = (
                "if queryset.exists(): ... .create() / get_or_create pattern may race with "
                "concurrent creates."
            )
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    title=_DJG050_TITLE,
                    message=msg050,
                    path=path_s,
                    line=line,
                    fix_hint=_DJG050_HINT,
                    tags=["concurrency", "orm"],
                )
            )
        elif rule_id == "DJG051":
            title = _DJG051_TITLE
            message = (
                "This function performs multiple ORM writes without an obvious "
                f"transaction.atomic() guard ({kind.replace('_', ' ')})."
            )
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    message=message,
                    path=path_s,
                    line=line,
                    fix_hint=_DJG051_HINT,
                    tags=["concurrency", "transactions"],
                )
            )
        elif rule_id == "DJG052":
            suffix = " augmented assignment" if "augassign" in kind else ""
            msg052 = (
                f"Stock/counter-like field update{suffix} without F(); may lose updates under "
                "concurrency."
            )
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    title=_DJG052_TITLE,
                    message=msg052,
                    path=path_s,
                    line=line,
                    fix_hint=_DJG052_HINT,
                    tags=["concurrency", "orm"],
                )
            )
    return findings
