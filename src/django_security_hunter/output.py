from __future__ import annotations

import json
import os
import shutil
import sys
from io import StringIO
from typing import Any, TextIO
from urllib.parse import unquote, urlsplit

from .models import Report
from .package_meta import INFORMATION_URI, package_version

_SARIF_URI_MAX = 2048
_SETTINGS_LOAD_README = f"{INFORMATION_URI}#when-django-settings-fail-to-load"


def _cli_panel_box() -> Any:
    # ASCII box: Unicode U+250x borders break on legacy Windows cp1252 consoles.
    from rich import box

    return box.ASCII


def _stream_allows_style(
    stream: TextIO,
    *,
    force: bool = False,
    no_color_flag: bool = False,
) -> bool:
    """Whether Rich styling is appropriate for *stream* (TTY, NO_COLOR, FORCE_COLOR)."""
    if no_color_flag:
        return False
    if force:
        return True
    if os.environ.get("NO_COLOR", "").strip():
        return False
    if os.environ.get("FORCE_COLOR", "").strip() or os.environ.get(
        "CLICOLOR_FORCE", ""
    ).strip():
        return True
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def console_color_preferred(*, force: bool = False, no_color_flag: bool = False) -> bool:
    """Whether styled console output is appropriate for stdout (TTY, env, flags)."""
    return _stream_allows_style(sys.stdout, force=force, no_color_flag=no_color_flag)


def print_django_settings_load_warning(
    report: Report,
    *,
    force_color: bool = False,
    no_color: bool = False,
) -> None:
    """Pretty-print the scan warning when Django settings did not load (stderr)."""
    if report.mode != "scan":
        return
    if report.metadata.get("django_settings_loaded"):
        return

    summary = (
        "Django settings were not loaded; DJG001-DJG012 and DRF settings-based "
        "rules (DJG020-DJG023, DJG025-DJG026) were skipped. "
        "Static analysis of your project files still ran."
    )
    detail_lines: list[str] = []
    if sr := report.metadata.get("django_settings_skip_reason"):
        detail_lines.append(f"Reason: {sr}")
    if err := report.settings_load_error_detail:
        detail_lines.append(err)

    skip = report.metadata.get("django_settings_skip_reason")
    err_detail = (report.settings_load_error_detail or "").lower()
    has_settings_flag = bool(report.metadata.get("settings_module"))

    tip: str | None = None
    if skip == "no_settings_module":
        tip = (
            "Tip: pass `--settings <same-as-manage.py> --allow-project-code` "
            "to check Django and DRF configuration in settings. "
            'If you still have problems, see the README section '
            f'"When Django settings fail to load": {_SETTINGS_LOAD_README}'
        )
    elif has_settings_flag and "secret_key" in err_detail:
        tip = (
            "Tip: export the variable your settings use for SECRET_KEY "
            "(often DJANGO_SECRET_KEY) to a long random value in this terminal, "
            "then run the scan again. "
            'If problems persist, see README '
            f'"When Django settings fail to load": {_SETTINGS_LOAD_README}'
        )
    elif has_settings_flag:
        tip = (
            "Tip: fix the error above, then run the scan again. "
            'If problems persist, see README '
            f'"When Django settings fail to load": {_SETTINGS_LOAD_README}'
        )

    use_rich = _stream_allows_style(
        sys.stderr, force=force_color, no_color_flag=no_color
    )
    if not use_rich:
        chunks: list[str] = [summary]
        if detail_lines:
            chunks.append("\n".join(detail_lines))
        if tip:
            chunks.append(tip)
        print("\n\n".join(chunks), file=sys.stderr)
        return

    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.text import Text

    width = max(60, min(100, shutil.get_terminal_size((100, 24)).columns))
    try:
        stderr_tty = sys.stderr.isatty()
    except (AttributeError, ValueError):
        stderr_tty = False
    console = Console(
        file=sys.stderr,
        width=width,
        soft_wrap=True,
        highlight=False,
        force_terminal=force_color or not stderr_tty,
        legacy_windows=False,
    )

    body_items: list[Any] = [Text(summary, style="white")]
    for line in detail_lines:
        body_items.append(Text(line, style="dim"))
    if tip:
        body_items.append(Text(""))
        tip_line = Text()
        tip_line.append("> ", style="bold cyan")
        tip_line.append(tip, style="cyan")
        body_items.append(tip_line)

    _panel_title = (
        "[bold yellow]Settings[/bold yellow] [dim]|[/dim] "
        "[bold white]not loaded[/bold white]"
    )
    console.print(
        Panel(
            Group(*body_items),
            title=_panel_title,
            title_align="left",
            border_style="yellow",
            box=_cli_panel_box(),
            padding=(0, 1),
        )
    )
    console.print()


def _render_rich_report(console: Any, report: Report) -> None:
    from rich.console import Group
    from rich.panel import Panel
    from rich.text import Text

    title = Text()
    title.append("django_security_hunter report ", style="bold cyan")
    title.append(f"({report.mode})", style="bold white")

    subtitle = f"{report.generated_at} - {len(report.findings)} finding(s)"
    console.print(
        Panel(
            Group(title, Text(subtitle, style="dim")),
            border_style="cyan",
            box=_cli_panel_box(),
            padding=(0, 1),
        )
    )

    if report.mode == "profile":
        _print_profile_summary_rich(console, report)

    findings = report.sorted_findings()
    if not findings:
        console.print(
            Panel(
                Text("No findings - nothing flagged in this run.", style="bold green"),
                border_style="green",
                box=_cli_panel_box(),
                padding=(0, 1),
            )
        )
        return

    for i, finding in enumerate(findings):
        if i:
            console.print()
        st = _severity_style(finding.severity)
        border_style = _severity_panel_border_style(finding.severity)
        header = Text()
        header.append(f"{finding.severity}", style=st)
        header.append(" | ", style="dim")
        header.append(f"{finding.rule_id}", style="bold white")
        header.append(f" - {finding.title}", style="white")
        body: list[Text | str] = [header, Text(finding.message)]
        if finding.path:
            loc_bits = finding.path
            if finding.line is not None:
                loc_bits = f"{finding.path}:{finding.line}"
            loc = Text()
            loc.append("@ ", style="dim")
            loc.append(loc_bits, style="dim cyan")
            body.append(loc)
        if finding.fix_hint:
            fix = Text()
            fix.append("Fix: ", style="bold dim")
            fix.append(finding.fix_hint.strip(), style="dim italic")
            body.append(fix)
        console.print(
            Panel(
                Group(*body),
                border_style=border_style,
                box=_cli_panel_box(),
                padding=(0, 1),
            )
        )


def _print_profile_summary_rich(console: Any, report: Report) -> None:
    from rich.console import Group
    from rich.panel import Panel
    from rich.text import Text

    prof = report.metadata.get("profile")
    if not prof:
        return
    lines: list[Text | str] = [
        Text("Runtime query profile", style="bold cyan"),
        Text(
            f"runner={prof.get('query_runtime', '?')} ; "
            f"tests_profiled={prof.get('tests_profiled', 0)} ; "
            f"thresholds: queries>{prof.get('threshold_query_count', '?')}, "
            f"time>{prof.get('threshold_db_time_ms', '?')}ms",
            style="dim",
        ),
    ]
    tops = prof.get("top_by_query_count") or []
    if tops:
        lines.append(Text("Top by query count:", style="bold white"))
        for row in tops[:5]:
            lines.append(
                Text(
                    f"  * {row.get('nodeid', '?')}: {row.get('query_count', 0)} queries",
                    style="white",
                )
            )
    slow = prof.get("top_by_sql_time_ms") or []
    if slow:
        lines.append(Text("Top by SQL time:", style="bold white"))
        for row in slow[:5]:
            lines.append(
                Text(
                    f"  * {row.get('nodeid', '?')}: {row.get('sql_time_ms', 0):.1f} ms",
                    style="white",
                )
            )
    dup = prof.get("duplicate_sql_examples") or []
    if dup:
        lines.append(Text("Example repeated SQL (normalized):", style="bold white"))
        for row in dup[:5]:
            sig = str(row.get("signature", ""))[:120]
            lines.append(
                Text(
                    f"  * {row.get('repeat_count', 0)}x @ {row.get('nodeid', '?')}: {sig}",
                    style="yellow",
                )
            )
    console.print(
        Panel(
            Group(*lines),
            border_style="blue",
            box=_cli_panel_box(),
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
        legacy_windows=False,
    )
    _render_rich_report(console, report)


def _as_console_plain(report: Report) -> str:
    lines: list[str] = [
        f"django_security_hunter report ({report.mode})",
        f"generated_at: {report.generated_at}",
        f"findings: {len(report.findings)}",
    ]
    if report.mode == "profile":
        prof = report.metadata.get("profile")
        if prof:
            lines.append("")
            lines.append("Runtime query profile:")
            lines.append(f"  runner: {prof.get('query_runtime', '?')}")
            lines.append(f"  tests_profiled: {prof.get('tests_profiled', 0)}")
            for row in (prof.get("top_by_query_count") or [])[:5]:
                lines.append(
                    f"  top_queries: {row.get('nodeid')}: {row.get('query_count')} queries"
                )
            for row in (prof.get("duplicate_sql_examples") or [])[:5]:
                sig = str(row.get("signature", ""))[:100]
                lines.append(
                    f"  duplicate_sql: {row.get('repeat_count')}x @ "
                    f"{row.get('nodeid')}: {sig}"
                )

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


def _severity_panel_border_style(severity: str) -> str:
    """Single Rich color name for Panel borders (avoid splitting compound styles on spaces)."""
    s = severity.upper()
    if s == "CRITICAL":
        return "red"
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
    return json.dumps(report.to_dict(), indent=2, allow_nan=False)


def _sarif_positive_int(value: object | None, *, default: int = 1) -> int:
    """SARIF requires positive integers; tolerate bad runtime values on Finding."""
    if value is None:
        return default
    try:
        n = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(1, n)


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


def as_sarif(report: Report) -> str:
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in report.sorted_findings():
        rid = finding.rule_id
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append(
                {
                    "id": rid,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.message},
                    "help": {"text": finding.fix_hint or "Review and remediate."},
                    "properties": {"severity": str(finding.severity)},
                }
            )

        result: dict[str, Any] = {
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": _sarif_level(finding.severity),
            "message": {"text": finding.message},
        }
        uri = _sarif_artifact_uri(finding.path)
        if uri:
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                }
            }
            if finding.line is not None:
                location["physicalLocation"]["region"] = {
                    "startLine": _sarif_positive_int(finding.line),
                    "startColumn": (
                        _sarif_positive_int(finding.column)
                        if finding.column is not None
                        else 1
                    ),
                }
            result["locations"] = [location]
        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "django_security_hunter",
                        "version": package_version(),
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "columnKind": "utf16CodeUnits",
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, allow_nan=False)


def _sarif_level(severity: object) -> str:
    normalized = str(severity or "").upper()
    if normalized in {"CRITICAL", "HIGH"}:
        return "error"
    if normalized == "WARN":
        return "warning"
    return "note"

