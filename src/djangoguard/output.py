from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .models import Report, SEVERITY_ORDER, _severity_rank

_INNER_WIDTH = 60
_TAGLINE = "security · reliability · performance"


def _sarif_file_uri(path: str) -> str:
    try:
        return Path(path).resolve().as_uri()
    except (OSError, ValueError, RuntimeError):
        return path


# ANSI (disabled when color=False or NO_COLOR in cli).
class _A:
    RST = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def _sev_style(sev: str, color: bool) -> tuple[str, str]:
    """(prefix_label, ansi_prefix_for_line)."""
    s = sev.strip().upper()
    if not color:
        return f"[{s}]", ""
    glyph = {"CRITICAL": "!!", "HIGH": ">>", "WARN": "!>", "INFO": ".."}.get(
        s, "??"
    )
    if s == "CRITICAL":
        return f"{glyph} [{s}]", _A.BOLD + _A.RED
    if s == "HIGH":
        return f"{glyph} [{s}]", _A.RED
    if s == "WARN":
        return f"{glyph} [{s}]", _A.YELLOW
    if s == "INFO":
        return f"{glyph} [{s}]", _A.CYAN
    return f">> [{s}]", _A.MAGENTA


def _fit_line(text: str, width: int) -> str:
    if len(text) <= width:
        return text.ljust(width)
    return text[: width - 1] + "…"


def _banner_and_meta(report: Report, color: bool) -> list[str]:
    mode_uc = report.mode.upper()
    w = _INNER_WIDTH
    rule_h = "─" * w if color else "-"
    if color:
        row1 = (
            f"  {_A.BOLD}{_A.CYAN}▶ djangoguard{_A.RST}  "
            f"{_A.MAGENTA}[{mode_uc}]{_A.RST}  "
            f"{_A.DIM}v{__version__}{_A.RST}"
        )
        row2 = f"  {_A.DIM}{_TAGLINE}{_A.RST}"
        top = (
            f"{_A.DIM}╭{rule_h}╮{_A.RST}\n"
            f"{_A.DIM}│{_A.RST}{row1}\n"
            f"{_A.DIM}│{_A.RST}{row2}\n"
            f"{_A.DIM}╰{rule_h}╯{_A.RST}"
        )
    else:
        bar = "+" + "-" * w + "+"
        row1 = _fit_line(f"  > djangoguard  [{mode_uc}]  v{__version__}", w)
        row2 = _fit_line(f"  {_TAGLINE}", w)
        top = f"{bar}\n|{row1}|\n|{row2}|\n{bar}"
    meta = [
        top,
        f"djangoguard report ({report.mode})",
        f"generated_at: {report.generated_at}",
    ]
    return meta


def _severity_summary(findings: list, color: bool) -> str:
    counts = Counter(f.severity.strip().upper() for f in findings)
    parts = [
        f"{k}: {counts[k]}"
        for k in sorted(counts, key=lambda x: -SEVERITY_ORDER.get(x, 0))
    ]
    summary = "summary: " + " | ".join(parts)
    if color:
        return (
            f"{_A.BOLD}findings: {len(findings)}{_A.RST}  "
            f"{_A.DIM}({summary}){_A.RST}"
        )
    return f"findings: {len(findings)}  ({summary})"


def as_console(report: Report, *, color: bool = False) -> str:
    """Human-readable report. Set ``color=True`` when writing to a TTY (see cli)."""
    lines: list[str] = []
    lines.extend(_banner_and_meta(report, color))
    findings = report.sorted_findings()
    if not findings:
        if color:
            lines.append(
                f"{_A.GREEN}No findings.{_A.RST} {_A.DIM}All clear.{_A.RST}"
            )
        else:
            lines.append("No findings.")
    else:
        lines.append(_severity_summary(findings, color))
        sep_w = _INNER_WIDTH + 2
        lines.append(
            "" if not color else f"{_A.DIM}{'·' * (sep_w // 2)}{_A.RST}"
        )
        for finding in findings:
            loc = ""
            if finding.path:
                loc = f" [{finding.path}"
                if finding.line is not None:
                    loc += f":{finding.line}"
                loc += "]"
            label, pre = _sev_style(finding.severity, color)
            rst = _A.RST if color else ""
            head = f"{pre}{label} {finding.rule_id}:{rst} {finding.title}{loc}"
            lines.append(head)
            dim = _A.DIM if color else ""
            lines.append(f"  {dim}{finding.message}{rst}")
            if finding.fix_hint:
                fix_pre = _A.BLUE if color else ""
                lines.append(
                    f"  {fix_pre}Fix:{rst} {dim}{finding.fix_hint.strip()}{rst}"
                )
    lines.append(_console_footer(report, color))
    return "\n".join(lines)


def _console_footer(report: Report, color: bool) -> str:
    label = f" {report.mode} complete "
    fill = max(16, _INNER_WIDTH + 2 - len(label))
    if color:
        return f"{_A.DIM}───{label}{'─' * fill}{_A.RST}"
    return f"---{label}{'-' * fill}"


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
