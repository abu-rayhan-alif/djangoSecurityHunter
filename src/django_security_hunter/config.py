from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import tomllib

from .models import VALID_SEVERITY_THRESHOLDS


def _str_frozenset(value: object) -> frozenset[str]:
    if not value:
        return frozenset()
    if isinstance(value, (list, tuple)):
        return frozenset(str(x).strip() for x in value if str(x).strip())
    return frozenset()


@dataclass(slots=True)
class GuardConfig:
    severity_threshold: str = "WARN"
    query_count_threshold: int = 50
    db_time_ms_threshold: int = 200
    static_secrets_allowlist: frozenset[str] = field(default_factory=frozenset)
    model_integrity_ignore_models: frozenset[str] = field(default_factory=frozenset)
    djg051_high_save_threshold: int = 3
    pip_audit: bool = False
    bandit: bool = False
    semgrep: bool = False


def _safe_int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _safe_bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return default


def _read_toml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


def load_config(project_root: Path) -> GuardConfig:
    pyproject = _read_toml(project_root / "pyproject.toml")
    local_legacy = _read_toml(project_root / "django_security_hunter.toml")
    local_dg = _read_toml(project_root / "djangoguard.toml")

    config_data: dict = {}
    if "tool" in pyproject:
        tool = pyproject["tool"]
        if "django_security_hunter" in tool:
            config_data.update(tool["django_security_hunter"])
        if "djangoguard" in tool:
            config_data.update(tool["djangoguard"])
    config_data.update(local_legacy)
    config_data.update(local_dg)

    sev = str(config_data.get("severity_threshold", "WARN")).strip().upper()
    if sev not in VALID_SEVERITY_THRESHOLDS:
        sev = "WARN"

    high_saves = _safe_int(config_data.get("djg051_high_save_threshold", 3), 3)
    if high_saves < 2:
        high_saves = 3

    return GuardConfig(
        severity_threshold=sev,
        query_count_threshold=_safe_int(
            config_data.get("query_count_threshold", 50), 50
        ),
        db_time_ms_threshold=_safe_int(
            config_data.get("db_time_ms_threshold", 200), 200
        ),
        static_secrets_allowlist=_str_frozenset(
            config_data.get("static_secrets_allowlist")
        ),
        model_integrity_ignore_models=_str_frozenset(
            config_data.get("model_integrity_ignore_models")
        ),
        djg051_high_save_threshold=high_saves,
        pip_audit=_safe_bool(config_data.get("pip_audit", False), False),
        bandit=_safe_bool(config_data.get("bandit", False), False),
        semgrep=_safe_bool(config_data.get("semgrep", False), False),
    )

