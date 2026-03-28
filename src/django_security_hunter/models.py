from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .package_meta import REPORT_JSON_SCHEMA_VERSION, package_version


def _coerce_optional_int(value: Any) -> int | None:
    """Normalize line/column to a non-negative int or None (runtime safety)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        value = value.strip()
    try:
        n = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


SEVERITY_ORDER = {
    "INFO": 10,
    "WARN": 20,
    "HIGH": 30,
    "CRITICAL": 40,
}

VALID_SEVERITY_THRESHOLDS = frozenset(SEVERITY_ORDER)


def _normalize_severity_key(severity: object) -> str:
    if severity is None:
        return ""
    return str(severity).strip().upper()


@dataclass(slots=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    path: str | None = None
    line: int | None = None
    column: int | None = None
    fix_hint: str | None = None
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        object.__setattr__(self, "line", _coerce_optional_int(self.line))
        object.__setattr__(self, "column", _coerce_optional_int(self.column))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Report:
    mode: str
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    # Shown on stderr only; omitted from to_dict() / JSON / SARIF (avoids leaking paths).
    settings_load_error_detail: str | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        sorted_findings = self.sorted_findings()
        return {
            "schema_version": REPORT_JSON_SCHEMA_VERSION,
            "tool": {"name": "django_security_hunter", "version": package_version()},
            "mode": self.mode,
            "generated_at": self.generated_at,
            "metadata": self.metadata,
            "findings": [finding.to_dict() for finding in sorted_findings],
        }

    def has_threshold_hit(self, threshold: str) -> bool:
        t = threshold.strip().upper()
        if t not in SEVERITY_ORDER:
            t = "WARN"
        threshold_value = SEVERITY_ORDER[t]
        return any(
            SEVERITY_ORDER.get(_normalize_severity_key(finding.severity), 0)
            >= threshold_value
            for finding in self.findings
        )

    def sorted_findings(self) -> list[Finding]:
        def sort_key(f: Finding) -> tuple[int, str, str, int]:
            severity_value = SEVERITY_ORDER.get(_normalize_severity_key(f.severity), 0)
            # Higher severity first -> negate for descending
            return (
                -severity_value,
                f.rule_id,
                f.path or "",
                f.line or 0,
            )

        return sorted(self.findings, key=sort_key)
