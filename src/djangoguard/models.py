from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


SEVERITY_ORDER = {
    "INFO": 10,
    "WARN": 20,
    "HIGH": 30,
    "CRITICAL": 40,
}

VALID_SEVERITY_THRESHOLDS = frozenset(SEVERITY_ORDER)


def _severity_rank(severity: str) -> int:
    """Numeric rank for ordering and threshold checks (unknown values fail-safe as HIGH)."""
    s = severity.strip().upper()
    return SEVERITY_ORDER.get(s, SEVERITY_ORDER["HIGH"])


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
            _severity_rank(finding.severity) >= threshold_value
            for finding in self.findings
        )

    def sorted_findings(self) -> list[Finding]:
        def sort_key(f: Finding) -> tuple[int, str, str, int]:
            severity_value = _severity_rank(f.severity)
            # Higher severity first -> negate for descending
            return (
                -severity_value,
                f.rule_id,
                f.path or "",
                f.line or 0,
            )

        return sorted(self.findings, key=sort_key)
