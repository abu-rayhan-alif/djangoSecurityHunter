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

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "generated_at": self.generated_at,
            "metadata": self.metadata,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def has_threshold_hit(self, threshold: str) -> bool:
        threshold_value = SEVERITY_ORDER.get(threshold.upper(), SEVERITY_ORDER["WARN"])
        return any(
            SEVERITY_ORDER.get(finding.severity.upper(), 0) >= threshold_value
            for finding in self.findings
        )
