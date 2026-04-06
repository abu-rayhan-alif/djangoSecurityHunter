from __future__ import annotations

import json
from pathlib import Path
import sys
from datetime import datetime, timedelta, timezone

import typer

from .config import GuardConfig, load_config
from .engine import run_profile, run_scan
from .models import VALID_SEVERITY_THRESHOLDS
from .output import (
    as_console,
    as_json,
    as_sarif,
    console_color_preferred,
    print_console_report,
    print_django_settings_load_warning,
)

app = typer.Typer(help="Django + DRF Security, Reliability and Performance Inspector")
_DEFAULT_SEVERITY_WEIGHTS = {"INFO": 1, "WARN": 5, "HIGH": 15, "CRITICAL": 40}


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


def _effective_threshold(cli_value: str | None, config_default: str) -> str:
    raw = (cli_value if cli_value is not None else config_default).strip().upper()
    if raw not in VALID_SEVERITY_THRESHOLDS:
        raise typer.BadParameter(
            f"threshold must be one of: {', '.join(sorted(VALID_SEVERITY_THRESHOLDS))}"
        )
    return raw


def _severity_counts(report) -> dict[str, int]:
    counts = {"INFO": 0, "WARN": 0, "HIGH": 0, "CRITICAL": 0}
    for finding in report.findings:
        sev = str(getattr(finding, "severity", "")).strip().upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _weights_from_config(cfg: GuardConfig) -> dict[str, int]:
    return {
        "INFO": max(0, int(cfg.score_weight_info)),
        "WARN": max(0, int(cfg.score_weight_warn)),
        "HIGH": max(0, int(cfg.score_weight_high)),
        "CRITICAL": max(0, int(cfg.score_weight_critical)),
    }


def _security_score(report, cfg: GuardConfig) -> dict[str, object]:
    counts = _severity_counts(report)
    weights = _weights_from_config(cfg)
    penalty = sum(counts[k] * v for k, v in weights.items())
    score = max(0, 100 - penalty)
    return {
        "model": "weighted-v1",
        "score": score,
        "max_score": 100,
        "penalty": penalty,
        "weights": weights or dict(_DEFAULT_SEVERITY_WEIGHTS),
        "counts": counts,
    }


def _parse_iso8601(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _compute_trend_from_history(
    entries: list[dict[str, object]], current_score: int
) -> dict[str, object]:
    if not entries:
        return {
            "direction": "flat",
            "delta": 0,
            "previous_score": None,
            "weekly_delta": None,
        }
    previous = int(entries[-1].get("score", current_score))
    delta = current_score - previous
    direction = "improved" if delta > 0 else "degraded" if delta < 0 else "flat"
    weekly_delta: int | None = None
    now = datetime.now(timezone.utc)
    weekly_cutoff = now - timedelta(days=7)
    for entry in entries:
        ts = str(entry.get("generated_at", ""))
        when = _parse_iso8601(ts)
        if when and when >= weekly_cutoff:
            weekly_delta = current_score - int(entry.get("score", current_score))
            break
    return {
        "direction": direction,
        "delta": delta,
        "previous_score": previous,
        "weekly_delta": weekly_delta,
    }


def _append_trend_history(
    history_file: Path, *, mode: str, generated_at: str, score: int, counts: dict[str, int]
) -> dict[str, object]:
    history: dict[str, object] = {"schema": "djangoguard.trend.v1", "entries": []}
    if history_file.exists():
        try:
            history = json.loads(history_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            history = {"schema": "djangoguard.trend.v1", "entries": []}
    entries = history.get("entries")
    if not isinstance(entries, list):
        entries = []
    prior_same_mode = [
        e
        for e in entries
        if isinstance(e, dict) and str(e.get("mode", "")).strip() == mode
    ]
    trend = _compute_trend_from_history(prior_same_mode, score)
    entries.append(
        {
            "generated_at": generated_at,
            "mode": mode,
            "score": score,
            "counts": counts,
        }
    )
    # Keep history file bounded.
    history["entries"] = entries[-500:]
    history_file.parent.mkdir(parents=True, exist_ok=True)
    history_file.write_text(json.dumps(history, indent=2), encoding="utf-8")
    return trend


def _attach_score_and_trend(
    report, trend_history: Path | None, cfg: GuardConfig
) -> None:
    score = _security_score(report, cfg)
    report.metadata["security_score"] = score
    if trend_history is None:
        report.metadata["security_trend"] = {
            "direction": "flat",
            "delta": 0,
            "previous_score": None,
            "weekly_delta": None,
            "history_file": None,
        }
        return
    try:
        trend = _append_trend_history(
            trend_history,
            mode=report.mode,
            generated_at=report.generated_at,
            score=int(score["score"]),
            counts=dict(score["counts"]),
        )
        trend["history_file"] = str(trend_history)
        report.metadata["security_trend"] = trend
    except OSError:
        report.metadata["security_trend"] = {
            "direction": "flat",
            "delta": 0,
            "previous_score": None,
            "weekly_delta": None,
            "history_file": str(trend_history),
            "status": "history_write_failed",
        }


def _require_project_code_ack(
    *,
    allow_project_code: bool,
    mode: str,
    uses_settings: bool,
) -> None:
    if allow_project_code:
        return
    if mode == "scan" and not uses_settings:
        return
    msg = (
        "Safety gate: this command can execute target project code "
        f"({mode} mode"
    )
    if uses_settings:
        msg += " with Django settings loading"
    msg += "). Re-run with --allow-project-code only for repositories you control."
    typer.secho(msg, fg=typer.colors.YELLOW, err=True)
    raise typer.Exit(code=2)


@app.command()
def scan(
    project: Path = typer.Option(
        Path("."), "--project", "-p", help="Project root path"
    ),
    settings: str | None = typer.Option(
        None, "--settings", "-s", help="Django settings module"
    ),
    output_format: str = typer.Option(
        "console", "--format", "-f", help="console|json|sarif"
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write report to file"
    ),
    threshold: str | None = typer.Option(
        None, "--threshold", "-t", help="INFO|WARN|HIGH|CRITICAL"
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
    allow_project_code: bool = typer.Option(
        False,
        "--allow-project-code",
        "-y",
        help=(
            "Allow loading project code for settings analysis. "
            "Required when --settings is used."
        ),
    ),
    trend_history: Path | None = typer.Option(
        None,
        "--trend-history",
        help=(
            "Optional JSON file to store score history and compute trend deltas "
            "(for example reports/trend.json)."
        ),
    ),
) -> None:
    project_root = project.resolve()
    _require_project_code_ack(
        allow_project_code=allow_project_code,
        mode="scan",
        uses_settings=bool(settings),
    )
    cfg = load_config(project_root)
    eff_threshold = _effective_threshold(threshold, cfg.severity_threshold)
    report = run_scan(
        project_root=project_root, settings_module=settings, cfg=cfg
    )
    _attach_score_and_trend(report, trend_history, cfg)
    print_django_settings_load_warning(
        report, force_color=force_color, no_color=no_color
    )
    _emit_formatted_report(
        report,
        output_format,
        output,
        force_color=force_color,
        no_color=no_color,
    )
    _exit_by_threshold(report, eff_threshold)


@app.command()
def profile(
    project: Path = typer.Option(
        Path("."), "--project", "-p", help="Project root path"
    ),
    settings: str | None = typer.Option(
        None, "--settings", "-s", help="Django settings module"
    ),
    output_format: str = typer.Option(
        "console", "--format", "-f", help="console|json|sarif"
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write report to file"
    ),
    threshold: str | None = typer.Option(
        None, "--threshold", "-t", help="INFO|WARN|HIGH|CRITICAL"
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
    allow_project_code: bool = typer.Option(
        False,
        "--allow-project-code",
        "-y",
        help=(
            "Allow profile mode to run target test code/subprocesses. "
            "Required for profile mode."
        ),
    ),
    trend_history: Path | None = typer.Option(
        None,
        "--trend-history",
        help=(
            "Optional JSON file to store score history and compute trend deltas "
            "(for example reports/trend.json)."
        ),
    ),
) -> None:
    project_root = project.resolve()
    _require_project_code_ack(
        allow_project_code=allow_project_code,
        mode="profile",
        uses_settings=bool(settings),
    )
    cfg = load_config(project_root)
    eff_threshold = _effective_threshold(threshold, cfg.severity_threshold)
    report = run_profile(
        project_root=project_root, settings_module=settings, cfg=cfg
    )
    _attach_score_and_trend(report, trend_history, cfg)
    _emit_formatted_report(
        report,
        output_format,
        output,
        force_color=force_color,
        no_color=no_color,
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
        "# score_weight_info = 1\n"
        "# score_weight_warn = 5\n"
        "# score_weight_high = 15\n"
        "# score_weight_critical = 40\n"
    )
    primary.write_text(sample, encoding="utf-8")
    typer.echo(f"Created {primary}")


def main() -> int:
    app()
    return 0


if __name__ == "__main__":
    sys.exit(main())

