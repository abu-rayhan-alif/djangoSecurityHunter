from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
import sys
import threading

import typer

from .config import GuardConfig, load_config
from .engine import run_profile, run_scan
from .models import VALID_SEVERITY_THRESHOLDS
from .output import as_console, as_json, as_sarif
from .settings_module import InvalidSettingsModule, normalize_django_settings_module

app = typer.Typer(
    help="Django + DRF Security, Reliability and Performance Inspector",
    epilog=(
        "Console reports use a branded header and severity colors on TTYs; "
        "set NO_COLOR=1 to disable. Colors are off when using --output."
    ),
)


def _console_use_color(*, writing_to_file: bool) -> bool:
    """Respect NO_COLOR and TTY; disable colors when piping or ``--output`` file."""
    if writing_to_file:
        return False
    if os.environ.get("NO_COLOR", "").strip():
        return False
    return sys.stdout.isatty()


def _render_report(
    report, output_format: str, *, writing_to_file: bool = False
) -> str:
    fmt = output_format.strip().lower()
    if not fmt:
        raise typer.BadParameter("format must be one of: console, json, sarif")
    if fmt == "console":
        return as_console(
            report,
            color=_console_use_color(writing_to_file=writing_to_file),
        )
    if fmt == "json":
        return as_json(report)
    if fmt == "sarif":
        return as_sarif(report)
    raise typer.BadParameter("format must be one of: console, json, sarif")


def _emit(content: str, output: Path | None) -> None:
    if output:
        try:
            out = output.expanduser()
            resolved = out.resolve()
        except OSError as exc:
            raise typer.BadParameter(f"invalid --output path: {exc}") from exc
        if resolved.exists() and resolved.is_dir():
            raise typer.BadParameter(
                f"--output must be a file path, not a directory: {resolved}"
            )
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_text(content, encoding="utf-8")
        except OSError as exc:
            raise typer.BadParameter(f"Could not write report file: {exc}") from exc
        typer.echo(f"Report written: {resolved}")
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
        if sr == "no_settings_module":
            parts.append(
                "Hint: django_security_hunter scan --project . --settings yourpackage.settings "
                "(or set DJANGO_SETTINGS_MODULE)."
            )
    if err := report.settings_load_error_detail:
        parts.append(err)
    typer.secho(" ".join(parts), fg=typer.colors.YELLOW, err=True)


def _cli_settings_module(settings: str | None) -> str | None:
    try:
        return normalize_django_settings_module(settings)
    except InvalidSettingsModule as exc:
        raise typer.BadParameter(str(exc)) from exc


def _merge_integration_overrides(
    cfg: GuardConfig,
    pip_audit: bool | None,
    bandit: bool | None,
    semgrep: bool | None,
) -> GuardConfig:
    if pip_audit is None and bandit is None and semgrep is None:
        return cfg
    return replace(
        cfg,
        enable_pip_audit=pip_audit if pip_audit is not None else cfg.enable_pip_audit,
        enable_bandit=bandit if bandit is not None else cfg.enable_bandit,
        enable_semgrep=semgrep if semgrep is not None else cfg.enable_semgrep,
    )


def _effective_threshold(cli_value: str | None, config_default: str) -> str:
    raw = (cli_value if cli_value is not None else config_default).strip().upper()
    if raw not in VALID_SEVERITY_THRESHOLDS:
        raise typer.BadParameter(
            f"threshold must be one of: {', '.join(sorted(VALID_SEVERITY_THRESHOLDS))}"
        )
    return raw


_SCAN_STATUS_EN = (
    "Take a coffee-break, we're hunting bugs, security issues & risky patterns in your project"
)

# Raw string: keeps literal backslashes (e.g. \i, \f) for a custom frame sequence, not escapes.
_SPINNER_FRAMES = r"a|/l-\i\f"


def _run_with_scan_status(message: str, fn, *args, **kwargs):
    """Show a small stderr spinner on TTY while ``fn`` runs (English status line)."""
    if not sys.stderr.isatty():
        return fn(*args, **kwargs)
    stop = threading.Event()
    use_dim = not os.environ.get("NO_COLOR", "").strip()
    frames = _SPINNER_FRAMES

    def spin() -> None:
        i = 0
        while not stop.wait(0.09):
            ch = frames[i % len(frames)]
            if use_dim:
                sys.stderr.write(f"\r\x1b[2m{message}… {ch}\x1b[0m ")
            else:
                sys.stderr.write(f"\r{message}… {ch} ")
            sys.stderr.flush()
            i += 1
        pad = max(len(message) + 12, 72)
        sys.stderr.write("\r" + " " * pad + "\r")
        sys.stderr.flush()

    worker = threading.Thread(target=spin, daemon=True)
    worker.start()
    try:
        return fn(*args, **kwargs)
    finally:
        stop.set()
        worker.join(timeout=3.0)


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
    pip_audit: bool | None = typer.Option(
        None,
        "--pip-audit/--no-pip-audit",
        help="Run pip-audit (default: enable_pip_audit in config)",
    ),
    bandit: bool | None = typer.Option(
        None,
        "--bandit/--no-bandit",
        help="Run Bandit (default: enable_bandit in config)",
    ),
    semgrep: bool | None = typer.Option(
        None,
        "--semgrep/--no-semgrep",
        help="Run Semgrep (default: enable_semgrep in config)",
    ),
) -> None:
    project_root = project.expanduser().resolve()
    settings_mod = _cli_settings_module(settings)
    cfg = load_config(project_root)
    eff_cfg = _merge_integration_overrides(cfg, pip_audit, bandit, semgrep)
    eff_threshold = _effective_threshold(threshold, cfg.severity_threshold)
    want_status = (
        output_format.strip().lower() == "console"
        and output is None
        and sys.stderr.isatty()
    )
    if want_status:
        report = _run_with_scan_status(
            _SCAN_STATUS_EN,
            run_scan,
            project_root,
            settings_module=settings_mod,
            cfg=eff_cfg,
        )
    else:
        report = run_scan(
            project_root=project_root,
            settings_module=settings_mod,
            cfg=eff_cfg,
        )
    _warn_if_django_settings_not_loaded(report)
    rendered = _render_report(
        report, output_format, writing_to_file=output is not None
    )
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
    rendered = _render_report(
        report, output_format, writing_to_file=output is not None
    )
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
        "# Optional external scanners (also overridable via CLI flags):\n"
        "enable_pip_audit = false\n"
        "enable_bandit = false\n"
        "enable_semgrep = false\n"
    )
    try:
        target.write_text(sample, encoding="utf-8")
    except OSError as exc:
        raise typer.BadParameter(
            f"Could not create django_security_hunter.toml: {exc}"
        ) from exc
    typer.echo(f"Created {target}")


def main() -> int:
    app()
    return 0


if __name__ == "__main__":
    sys.exit(main())
