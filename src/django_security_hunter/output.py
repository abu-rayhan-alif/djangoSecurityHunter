from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Report


def _sarif_positive_int(value: object | None, *, default: int = 1) -> int:
    """SARIF requires positive integers; tolerate bad runtime values on Finding."""
    if value is None:
        return default
    try:
        n = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(1, n)


def as_console(report: Report) -> str:
    lines: list[str] = [
        f"django_security_hunter report ({report.mode})",
        f"generated_at: {report.generated_at}",
        f"findings: {len(report.findings)}",
    ]
    findings = report.sorted_findings()
    if not findings:
        lines.append("No findings.")
    else:
        for finding in findings:
            location = ""
            if finding.path:
                location = f" [{finding.path}"
                if finding.line is not None:
                    location += f":{finding.line}"
                location += "]"
            lines.append(
                f"- {finding.severity} {finding.rule_id}: {finding.title}{location}"
            )
            lines.append(f"  {finding.message}")
            if finding.fix_hint:
                lines.append(f"  Fix: {finding.fix_hint}")
    return "\n".join(lines)


def as_json(report: Report) -> str:
    # Strict JSON (no NaN/Infinity) for safe interchange with other tools.
    return json.dumps(report.to_dict(), indent=2, allow_nan=False)


def as_sarif(report: Report) -> str:
    rules: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    results: list[dict[str, Any]] = []

    for finding in report.sorted_findings():
        if finding.rule_id not in seen_ids:
            seen_ids.add(finding.rule_id)
            rules.append(
                {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.message},
                    "help": {"text": finding.fix_hint or "Review and remediate."},
                    "properties": {"severity": finding.severity},
                }
            )

        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": finding.message},
        }
        if finding.path:
            p = Path(finding.path)
            try:
                uri = p.as_uri() if p.is_absolute() else finding.path.replace("\\", "/")
            except ValueError:
                uri = finding.path.replace("\\", "/")
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                }
            }
            if finding.line is not None:
                line = _sarif_positive_int(finding.line)
                col = (
                    _sarif_positive_int(finding.column)
                    if finding.column is not None
                    else 1
                )
                location["physicalLocation"]["region"] = {
                    "startLine": line,
                    "startColumn": col,
                }
            result["locations"] = [location]
        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "django_security_hunter", "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, allow_nan=False)


def _sarif_level(severity: str) -> str:
    normalized = severity.upper()
    if normalized in {"CRITICAL", "HIGH"}:
        return "error"
    if normalized == "WARN":
        return "warning"
    return "note"
