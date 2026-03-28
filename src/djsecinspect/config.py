from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib

from .limits import MAX_TOML_CONFIG_BYTES
from .models import VALID_SEVERITY_THRESHOLDS


@dataclass(slots=True)
class GuardConfig:
    severity_threshold: str = "WARN"
    query_count_threshold: int = 50
    db_time_ms_threshold: int = 200
    enable_pip_audit: bool = False
    enable_bandit: bool = False
    enable_semgrep: bool = False


def _safe_int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _safe_bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("1", "true", "yes", "on"):
            return True
        if s in ("0", "false", "no", "off"):
            return False
    return default


def _read_toml(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        st = path.stat()
    except OSError:
        return {}
    if st.st_size > MAX_TOML_CONFIG_BYTES:
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


def load_config(project_root: Path) -> GuardConfig:
    pyproject = _read_toml(project_root / "pyproject.toml")
    legacy_guard = _read_toml(project_root / "djangoguard.toml")
    legacy_audit = _read_toml(project_root / "djangoaudit.toml")
    local = _read_toml(project_root / "djsecinspect.toml")

    config_data: dict = {}
    tool = pyproject.get("tool") if isinstance(pyproject.get("tool"), dict) else {}
    if isinstance(tool, dict):
        if "djangoguard" in tool:
            config_data.update(tool["djangoguard"])
        if "djangoaudit" in tool:
            config_data.update(tool["djangoaudit"])
        if "djsecinspect" in tool:
            config_data.update(tool["djsecinspect"])
    config_data.update(legacy_guard)
    config_data.update(legacy_audit)
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
        enable_pip_audit=_safe_bool(
            config_data.get("enable_pip_audit", False), False
        ),
        enable_bandit=_safe_bool(config_data.get("enable_bandit", False), False),
        enable_semgrep=_safe_bool(
            config_data.get("enable_semgrep", False), False
        ),
    )

