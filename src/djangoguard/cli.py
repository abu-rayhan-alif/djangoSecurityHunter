from __future__ import annotations

import importlib.metadata
import os
import sys
import time
from pathlib import Path

import typer

from . import __author__, __author_url__, __distribution__, __version__
from .config import load_config
from .engine import run_profile, run_scan
from .models import VALID_SEVERITY_THRESHOLDS
from .output import as_console, as_json, as_sarif

app = typer.Typer(
    help="Django + DRF Security, Reliability and Performance Inspector",
    epilog=f"Author: {__author__}  •  {__author_url__}",
    no_args_is_help=True,
)


def _thanks_flag_path() -> Path:
    return Path.home() / ".cache" / "djangoguard" / "first_run_thanks_v1"


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _maybe_show_first_run_thanks() -> None:
    """Once per machine after install, when user runs any real subcommand (not --help)."""
    if _env_truthy("DJANGOGUARD_NO_THANKS") or _env_truthy("CI"):
        return
    if "--help" in sys.argv or "-h" in sys.argv:
        return
    flag = _thanks_flag_path()
    try:
        if flag.exists():
            return
    except OSError:
        return
    typer.echo("")
    typer.secho("Thanks for using djangoguard!", fg=typer.colors.GREEN)
    typer.echo(f"— {__author__}")
    typer.echo(__author_url__)
    typer.echo("")
    try:
        flag.parent.mkdir(parents=True, exist_ok=True)
        flag.write_text("1", encoding="utf-8")
    except OSError:
        pass


@app.callback()
def _main_callback(ctx: typer.Context) -> None:
    if ctx.resilient_parsing:
        return
    if ctx.invoked_subcommand is None:
        return
    _maybe_show_first_run_thanks()


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


def _warn_if_django_settings_not_loaded(report) -> None:
    if report.mode != "scan":
        return
    if report.metadata.get("django_settings_loaded"):
        return
    parts = [
        "Django settings were not loaded; settings-based rules were skipped."
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
    eff_threshold = _effective_threshold(threshold, cfg.severity_threshold)
    report = run_scan(project_root=project_root, settings_module=settings)
    _warn_if_django_settings_not_loaded(report)
    rendered = _render_report(report, format)
    _emit(rendered, output)
    _exit_by_threshold(report, eff_threshold)


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
    eff_threshold = _effective_threshold(threshold, cfg.severity_threshold)
    report = run_profile(project_root=project_root, settings_module=settings)
    rendered = _render_report(report, format)
    _emit(rendered, output)
    _exit_by_threshold(report, eff_threshold)


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


@app.command()
def hello(
    animate: bool = typer.Option(
        False,
        "--animate",
        "-a",
        help="Pause briefly between each 25%% step (cosmetic only).",
    ),
) -> None:
    """Show install OK + optional 4×25%% style steps.

    pip controls its own download/install UI; wheels do not run custom code during
    ``pip install``. Use this command after install instead.
    """
    try:
        ver = importlib.metadata.version(__distribution__)
    except importlib.metadata.PackageNotFoundError:
        ver = __version__

    stages: tuple[tuple[int, str], ...] = (
        (25, "a----"),
        (50, "l----"),
        (75, "i---"),
        (100, "f---"),
    )
    for pct, label in stages:
        if animate:
            time.sleep(0.2)
        typer.echo(f"[{pct:3d}%] {label}")
    typer.secho(f"djangoguard {ver} — ready.", fg=typer.colors.GREEN)
    typer.echo(f"By {__author__}")
    typer.echo(__author_url__)


def main() -> int:
    app()
    return 0


if __name__ == "__main__":
    sys.exit(main())
