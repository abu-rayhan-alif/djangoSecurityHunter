from __future__ import annotations

from pathlib import Path
from typing import Iterable

from django_security_hunter.collectors.model_schema_scan import (
    scan_djg080_natural_key_hits,
    scan_djg081_cascade_hits,
)
from django_security_hunter.models import Finding


def run_static_pattern_rules(project_root: Path) -> Iterable[Finding]:
    """Static analysis: data integrity / DB design (DJG080+) and future DJG-5 rules."""
    findings: list[Finding] = []
    for path, line, sev, model, field, factory in scan_djg080_natural_key_hits(
        project_root
    ):
        findings.append(
            Finding(
                rule_id="DJG080",
                severity=sev,
                title="Natural key / identifier field may lack uniqueness (heuristic)",
                message=(
                    f"Model `{model}` field `{field}` ({factory}) has no unique=True / "
                    "primary_key=True. Duplicate natural keys cause subtle production bugs "
                    "(wrong row updates, flaky lookups)."
                ),
                path=path,
                line=line,
                fix_hint=(
                    f"On `{model}.{field}` add `unique=True`, or in `Meta.constraints` use "
                    f"`UniqueConstraint(fields=['{field}'], "
                    f"name='{model.lower()}_{field.lower()}_uniq')`, then migrate. "
                    "Add a DB index if you need uniqueness + fast lookup.\n"
                ),
            )
        )
    for path, line, model, field, related in scan_djg081_cascade_hits(project_root):
        findings.append(
            Finding(
                rule_id="DJG081",
                severity="WARN",
                title="Risky on_delete=CASCADE toward sensitive-looking related model (heuristic)",
                message=(
                    f"Model `{model}` field `{field}` uses CASCADE to `{related or '?'}`. "
                    "Deletes can cascade into money, identity, or audit-adjacent data."
                ),
                path=path,
                line=line,
                fix_hint=(
                    "Prefer `on_delete=models.PROTECT` or `SET_NULL` where retention matters; "
                    "use soft-delete patterns for audit. Framework joins (ContentType, etc.) "
                    "are ignored by default.\n"
                ),
            )
        )
    return findings
