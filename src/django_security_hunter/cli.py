from __future__ import annotations

from pathlib import Path
import sys

import typer

from .config import load_config
from .engine import run_profile, run_scan
from .models import VALID_SEVERITY_THRESHOLDS
from .output import as_console, as_json, as_sarif
from .settings_module import InvalidSettingsModule, normalize_django_settings_module

app = typer.Typer(help="Django + DRF Security, Reliability and Performance Inspector")


def _render_report(report, output_format: str) -> str:
    fmt = output_format.strip().lower()
    if not fmt:
        raise typer.BadParameter("format must be one of: console, json, sarif")
    if fmt == "console":
        return as_console(report)
    if fmt == "json":
        return as_json(report)
    if fmt == "sarif":
        return as_sarif(report)
    raise typer.BadParameter("format must be one of: console, json, sarif")


def _emit(content: str, output: Path | None) -> None:
    if output:
        try:
            out = output.expanduser()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content, encoding="utf-8")
        except OSError as exc:
            raise typer.BadParameter(f"Could not write report file: {exc}") from exc
        typer.echo(f"Report written: {out}")
        return
    typer.echo(content)


def _exit_by_threshold(report, threshold: str) -> None:
    if report.has_threshold_hit(threshold):
        raise typer.Exit(code=2)


def _warn_if_django_settings_not_loaded(report) -> None:
    if report.mode != "scan":
        return
    if report.metadata.get("django_settings_loaded"):
        return
    parts = [
        "Django settings were not loaded; DJG001–DJG012 rules were skipped."
    ]
    if sr := report.metadata.get("django_settings_skip_reason"):
        parts.append(f"Reason: {sr}")
    if err := report.settings_load_error_detail:
        parts.append(err)
    typer.secho(" ".join(parts), fg=typer.colors.YELLOW, err=True)


def _effective_threshold(cli_value: str | None, config_default: str) -> str:
    raw = (cli_value if cli_value is not None else config_default).strip().upper()
    if raw not in VALID_SEVERITY_THRESHOLDS:
        raise typer.BadParameter(
            f"threshold must be one of: {', '.join(sorted(VALID_SEVERITY_THRESHOLDS))}"
        )
    return raw


def _cli_settings_module(settings: str | None) -> str | None:
    try:
        return normalize_django_settings_module(settings)
    except InvalidSettingsModule as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def scan(
    project: Path = typer.Option(Path("."), "--project", help="Project root path"),
    settings: str | None = typer.Option(
        None, "--settings", help="Django settings module"
    ),
    output_format: str = typer.Option(
        "console", "--format", help="console|json|sarif"
    ),
    output: Path | None = typer.Option(None, "--output", help="Write report to file"),
    threshold: str | None = typer.Option(
        None, "--threshold", help="INFO|WARN|HIGH|CRITICAL"
    ),
) -> None:
    project_root = project.expanduser().resolve()
    settings_mod = _cli_settings_module(settings)
    cfg = load_config(project_root)
    eff_threshold = _effective_threshold(threshold, cfg.severity_threshold)
    report = run_scan(project_root=project_root, settings_module=settings_mod)
    _warn_if_django_settings_not_loaded(report)
    rendered = _render_report(report, output_format)
    _emit(rendered, output)
    _exit_by_threshold(report, eff_threshold)


@app.command()
def profile(
    project: Path = typer.Option(Path("."), "--project", help="Project root path"),
    settings: str | None = typer.Option(
        None, "--settings", help="Django settings module"
    ),
    output_format: str = typer.Option(
        "console", "--format", help="console|json|sarif"
    ),
    output: Path | None = typer.Option(None, "--output", help="Write report to file"),
    threshold: str | None = typer.Option(
        None, "--threshold", help="INFO|WARN|HIGH|CRITICAL"
    ),
) -> None:
    project_root = project.expanduser().resolve()
    settings_mod = _cli_settings_module(settings)
    cfg = load_config(project_root)
    eff_threshold = _effective_threshold(threshold, cfg.severity_threshold)
    report = run_profile(project_root=project_root, settings_module=settings_mod)
    rendered = _render_report(report, output_format)
    _emit(rendered, output)
    _exit_by_threshold(report, eff_threshold)


@app.command()
def init(
    project: Path = typer.Option(Path("."), "--project", help="Project root path"),
) -> None:
    project_root = project.expanduser().resolve()
    target = project_root / "django_security_hunter.toml"
    if target.exists():
        typer.echo("django_security_hunter.toml already exists.")
        raise typer.Exit(code=0)

    sample = (
        'severity_threshold = "WARN"\n'
        "query_count_threshold = 50\n"
        "db_time_ms_threshold = 200\n"
    )
    try:
        target.write_text(sample, encoding="utf-8")
    except OSError as exc:
        raise typer.BadParameter(f"Could not create django_security_hunter.toml: {exc}") from exc
    typer.echo(f"Created {target}")


def main() -> int:
    app()
    return 0


if __name__ == "__main__":
    sys.exit(main())
