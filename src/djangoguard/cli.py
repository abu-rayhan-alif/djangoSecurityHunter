from __future__ import annotations

from pathlib import Path
import sys

import typer

from .config import load_config
from .engine import run_profile, run_scan
from .output import as_console, as_json, as_sarif

app = typer.Typer(help="Django + DRF Security, Reliability and Performance Inspector")


def _render_report(report, output_format: str) -> str:
    fmt = output_format.lower()
    if fmt == "console":
        return as_console(report)
    if fmt == "json":
        return as_json(report)
    if fmt == "sarif":
        return as_sarif(report)
    raise typer.BadParameter("format must be one of: console, json, sarif")


def _emit(content: str, output: Path | None) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        typer.echo(f"Report written: {output}")
        return
    typer.echo(content)


def _exit_by_threshold(report, threshold: str) -> None:
    if report.has_threshold_hit(threshold):
        raise typer.Exit(code=2)


@app.command()
def scan(
    project: Path = typer.Option(Path("."), "--project", help="Project root path"),
    settings: str | None = typer.Option(
        None, "--settings", help="Django settings module"
    ),
    format: str = typer.Option("console", "--format", help="console|json|sarif"),
    output: Path | None = typer.Option(None, "--output", help="Write report to file"),
    threshold: str | None = typer.Option(
        None, "--threshold", help="INFO|WARN|HIGH|CRITICAL"
    ),
) -> None:
    project_root = project.resolve()
    cfg = load_config(project_root)
    report = run_scan(project_root=project_root, settings_module=settings)
    rendered = _render_report(report, format)
    _emit(rendered, output)
    _exit_by_threshold(report, threshold or cfg.severity_threshold)


@app.command()
def profile(
    project: Path = typer.Option(Path("."), "--project", help="Project root path"),
    settings: str | None = typer.Option(
        None, "--settings", help="Django settings module"
    ),
    format: str = typer.Option("console", "--format", help="console|json|sarif"),
    output: Path | None = typer.Option(None, "--output", help="Write report to file"),
    threshold: str | None = typer.Option(
        None, "--threshold", help="INFO|WARN|HIGH|CRITICAL"
    ),
) -> None:
    project_root = project.resolve()
    cfg = load_config(project_root)
    report = run_profile(project_root=project_root, settings_module=settings)
    rendered = _render_report(report, format)
    _emit(rendered, output)
    _exit_by_threshold(report, threshold or cfg.severity_threshold)


@app.command()
def init(
    project: Path = typer.Option(Path("."), "--project", help="Project root path"),
) -> None:
    project_root = project.resolve()
    target = project_root / "djangoguard.toml"
    if target.exists():
        typer.echo("djangoguard.toml already exists.")
        raise typer.Exit(code=0)

    sample = (
        'severity_threshold = "WARN"\n'
        "query_count_threshold = 50\n"
        "db_time_ms_threshold = 200\n"
    )
    target.write_text(sample, encoding="utf-8")
    typer.echo(f"Created {target}")


def main() -> int:
    app()
    return 0


if __name__ == "__main__":
    sys.exit(main())
