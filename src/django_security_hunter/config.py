from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path
import tomllib

from .models import VALID_SEVERITY_THRESHOLDS

_MAX_TOML_BYTES = 512 * 1024


@dataclass(slots=True)
class GuardConfig:
    severity_threshold: str = "WARN"
    query_count_threshold: int = 50
    db_time_ms_threshold: int = 200


def _safe_int(
    value: object,
    default: int,
    *,
    min_value: int = 0,
    max_value: int = 2**31 - 1,
) -> int:
    try:
        n = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(min_value, min(max_value, n))


def _read_toml(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open("rb") as f:
            data = f.read(_MAX_TOML_BYTES + 1)
    except OSError:
        return {}
    if len(data) > _MAX_TOML_BYTES:
        return {}
    try:
        return tomllib.load(io.BytesIO(data))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return {}


def load_config(project_root: Path) -> GuardConfig:
    pyproject = _read_toml(project_root / "pyproject.toml")
    local = _read_toml(project_root / "django_security_hunter.toml")

    config_data: dict = {}
    tool = pyproject.get("tool")
    if isinstance(tool, dict):
        dg = tool.get("django_security_hunter")
        if isinstance(dg, dict):
            config_data.update(dg)
    if isinstance(local, dict):
        config_data.update(local)

    sev = str(config_data.get("severity_threshold", "WARN")).strip().upper()
    if sev not in VALID_SEVERITY_THRESHOLDS:
        sev = "WARN"

    return GuardConfig(
        severity_threshold=sev,
        query_count_threshold=_safe_int(
            config_data.get("query_count_threshold", 50), 50
        ),
        db_time_ms_threshold=_safe_int(
            config_data.get("db_time_ms_threshold", 200), 200
        ),
    )
