from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote, urlsplit

from .models import Report

_SARIF_URI_MAX = 2048


def _sarif_artifact_uri(path: str | None) -> str | None:
    """Normalize paths for SARIF: no path traversal, no remote URL schemes in uri."""
    if path is None:
        return None
    raw = path.strip().replace("\\", "/")
    if not raw:
        return None
    if len(raw) > _SARIF_URI_MAX:
        raw = raw[:_SARIF_URI_MAX]
    low = raw.lower()
    if "://" in low:
        if low.startswith("file:"):
            try:
                u = urlsplit(raw)
                raw = unquote(u.path or "")
            except Exception:
                raw = ""
        else:
            tail = raw.rstrip("/").rsplit("/", 1)[-1]
            tail = tail.split("?", 1)[0].split("#", 1)[0]
            raw = tail or "artifact"
    parts = [p for p in raw.split("/") if p and p != "."]
    safe: list[str] = []
    for p in parts:
        if p == "..":
            if safe:
                safe.pop()
        else:
            safe.append(p)
    out = "/".join(safe)
    return out or None


def as_console(report: Report) -> str:
    lines: list[str] = [
        f"djsecinspect report ({report.mode})",
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
        uri = _sarif_artifact_uri(finding.path)
        if uri:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
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
                "tool": {"driver": {"name": "djsecinspect", "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _sarif_level(severity: str) -> str:
    normalized = severity.upper()
    if normalized in {"CRITICAL", "HIGH"}:
        return "error"
    if normalized == "WARN":
        return "warning"
    return "note"

