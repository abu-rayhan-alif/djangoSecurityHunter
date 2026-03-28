from __future__ import annotations

import json
import os
import shutil
import sys
from io import StringIO
from typing import Any, TextIO

from .models import Report


def console_color_preferred(*, force: bool = False, no_color_flag: bool = False) -> bool:
    """Whether styled console output is appropriate (TTY, env, flags)."""
    if no_color_flag:
        return False
    # Explicit CLI flag wins over NO_COLOR (IDEs often set NO_COLOR for subprocesses).
    if force:
        return True
    if os.environ.get("NO_COLOR", "").strip():
        return False
    if os.environ.get("FORCE_COLOR", "").strip() or os.environ.get(
        "CLICOLOR_FORCE", ""
    ).strip():
        return True
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _render_rich_report(console: Any, report: Report) -> None:
    from rich.console import Group
    from rich.panel import Panel
    from rich.text import Text

    title = Text()
    title.append("django_security_hunter report ", style="bold cyan")
    title.append(f"({report.mode})", style="bold white")

    subtitle = f"{report.generated_at} · {len(report.findings)} finding(s)"
    console.print(
        Panel(
            Group(title, Text(subtitle, style="dim")),
            border_style="cyan",
            padding=(0, 1),
        )
    )

    findings = report.sorted_findings()
    if not findings:
        console.print(Text("No findings.", style="bold green"))
        return

    for i, finding in enumerate(findings):
        if i:
            console.print()
        st = _severity_style(finding.severity)
        header = Text()
        header.append(f"{finding.severity} ", style=st)
        header.append(f"{finding.rule_id}", style="bold white")
        header.append(f" · {finding.title}", style="white")
        body: list[Text | str] = [header, Text(finding.message)]
        if finding.path:
            loc_bits = finding.path
            if finding.line is not None:
                loc_bits = f"{finding.path}:{finding.line}"
            body.append(Text(loc_bits, style="dim"))
        if finding.fix_hint:
            body.append(Text(f"Fix: {finding.fix_hint}", style="dim italic"))
        border = st.split()[-1]
        console.print(
            Panel(
                Group(*body),
                border_style=border,
                padding=(0, 1),
            )
        )


def print_console_report(report: Report, *, file: TextIO | None = None) -> None:
    """Print styled report with Rich (Windows-safe: writes via Rich, not pre-built ANSI + echo)."""
    from rich.console import Console

    stream = file if file is not None else sys.stdout
    width = max(60, min(100, shutil.get_terminal_size((100, 24)).columns))
    try:
        is_tty = stream.isatty()
    except (AttributeError, ValueError):
        is_tty = False
    # CliRunner / pipes: not a TTY; Rich would skip rendering unless forced.
    console = Console(
        file=stream,
        width=width,
        soft_wrap=True,
        highlight=False,
        force_terminal=not is_tty,
    )
    _render_rich_report(console, report)


def _as_console_plain(report: Report) -> str:
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


def _severity_style(severity: str) -> str:
    s = severity.upper()
    if s == "CRITICAL":
        return "bold red"
    if s == "HIGH":
        return "red"
    if s == "WARN":
        return "yellow"
    return "cyan"


def _as_console_rich(report: Report) -> str:
    from rich.console import Console

    width = max(60, min(100, shutil.get_terminal_size((100, 24)).columns))
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=width, soft_wrap=True)
    _render_rich_report(console, report)
    return buf.getvalue()


def as_console(report: Report, *, color: bool = True) -> str:
    """Render report for terminal. Plain text when *color* is False (files, pipes)."""
    if not color:
        return _as_console_plain(report)
    return _as_console_rich(report)


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
                    "artifactLocation": {"uri": finding.path},
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
                "tool": {"driver": {"name": "django_security_hunter", "rules": rules}},
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

