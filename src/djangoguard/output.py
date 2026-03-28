from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Report, SEVERITY_ORDER, _severity_rank


def _sarif_file_uri(path: str) -> str:
    """RFC 3986 file URI for SARIF (avoids raw Windows backslashes in JSON)."""
    try:
        return Path(path).resolve().as_uri()
    except (OSError, ValueError, RuntimeError):
        return path


def as_console(report: Report) -> str:
    lines: list[str] = [
        f"djangoguard report ({report.mode})",
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
    return json.dumps(report.to_dict(), indent=2)


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
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": _sarif_file_uri(finding.path)},
                }
            }
            if finding.line is not None:
                location["physicalLocation"]["region"] = {
                    "startLine": finding.line,
                    "startColumn": finding.column or 1,
                }
            result["locations"] = [location]
        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "djangoguard", "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _sarif_level(severity: str) -> str:
    r = _severity_rank(severity)
    if r >= SEVERITY_ORDER["HIGH"]:
        return "error"
    if r >= SEVERITY_ORDER["WARN"]:
        return "warning"
    return "note"
