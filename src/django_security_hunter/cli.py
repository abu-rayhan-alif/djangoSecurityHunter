from __future__ import annotations

from pathlib import Path
import sys

import typer

from .config import load_config
from .engine import run_profile, run_scan
from .models import VALID_SEVERITY_THRESHOLDS
from .output import (
    as_console,
    as_json,
    as_sarif,
    console_color_preferred,
    print_console_report,
)

app = typer.Typer(help="Django + DRF Security, Reliability and Performance Inspector")


def _emit_formatted_report(
    report,
    output_format: str,
    output: Path | None,
    *,
    force_color: bool = False,
    no_color: bool = False,
) -> None:
    fmt = output_format.lower()
    if fmt == "console":
        use_rich = output is None and console_color_preferred(
            force=force_color, no_color_flag=no_color
        )
        if use_rich:
            print_console_report(report)
        else:
            _emit(as_console(report, color=False), output)
        return
    if fmt == "json":
        _emit(as_json(report), output)
        return
    if fmt == "sarif":
        _emit(as_sarif(report), output)
        return
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
    force_color: bool = typer.Option(
        False,
        "--force-color",
        help="Use styled console output even when stdout is not a TTY.",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Plain text console output (no panels / colors).",
    ),
) -> None:
    project_root = project.resolve()
    cfg = load_config(project_root)
    eff_threshold = _effective_threshold(threshold, cfg.severity_threshold)
    report = run_scan(
        project_root=project_root, settings_module=settings, cfg=cfg
    )
    _warn_if_django_settings_not_loaded(report)
    _emit_formatted_report(
        report, format, output, force_color=force_color, no_color=no_color
    )
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
    force_color: bool = typer.Option(
        False,
        "--force-color",
        help="Use styled console output even when stdout is not a TTY.",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Plain text console output (no panels / colors).",
    ),
) -> None:
    project_root = project.resolve()
    cfg = load_config(project_root)
    eff_threshold = _effective_threshold(threshold, cfg.severity_threshold)
    report = run_profile(
        project_root=project_root, settings_module=settings, cfg=cfg
    )
    _emit_formatted_report(
        report, format, output, force_color=force_color, no_color=no_color
    )
    _exit_by_threshold(report, eff_threshold)


@app.command()
def init(
    project: Path = typer.Option(Path("."), "--project", help="Project root path"),
) -> None:
    project_root = project.resolve()
    primary = project_root / "djangoguard.toml"
    legacy = project_root / "django_security_hunter.toml"
    if primary.exists():
        typer.echo("djangoguard.toml already exists.")
        raise typer.Exit(code=0)
    if legacy.exists():
        typer.echo(
            "django_security_hunter.toml exists; remove or rename it to create djangoguard.toml."
        )
        raise typer.Exit(code=0)

    sample = (
        '# djangoguard / django-security-hunter\n'
        'severity_threshold = "WARN"\n'
        "query_count_threshold = 50\n"
        "db_time_ms_threshold = 200\n"
        "# Optional:\n"
        '# static_secrets_allowlist = ["PUBLIC_CLIENT_ID"]\n'
        '# model_integrity_ignore_models = ["UserAuditLog"]\n'
        "# djg051_high_save_threshold = 3\n"
        "# pip_audit = true   # run pip-audit during scan (or set env; see README)\n"
        "# bandit = true\n"
        "# semgrep = true\n"
    )
    primary.write_text(sample, encoding="utf-8")
    typer.echo(f"Created {primary}")


def main() -> int:
    app()
    return 0


if __name__ == "__main__":
    sys.exit(main())

