from __future__ import annotations

import io
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
import tomllib

from .limits import MAX_TOML_CONFIG_BYTES
from .models import VALID_SEVERITY_THRESHOLDS

logger = logging.getLogger(__name__)


def env_tri_bool(cfg_value: bool, env_key: str) -> bool:
    """Env on/off wins when set; otherwise use *cfg_value* (README integration toggles)."""
    raw = os.environ.get(env_key, "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on"}:
        return True
    return cfg_value


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
    enable_scan_plugins: bool = True
    score_weight_info: int = 1
    score_weight_warn: int = 5
    score_weight_high: int = 15
    score_weight_critical: int = 40


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


def _safe_bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("1", "true", "yes", "on"):
            return True
        if s in ("0", "false", "no", "off"):
            return False
    return default


def _read_toml(path: Path) -> dict:
    if not path.exists():
        logger.debug("No TOML config at %s (defaults apply)", path)
        return {}
    try:
        with path.open("rb") as f:
            data = f.read(MAX_TOML_CONFIG_BYTES + 1)
    except OSError as exc:
        logger.warning("Could not read config file %s: %s", path, exc)
        return {}
    if len(data) > MAX_TOML_CONFIG_BYTES:
        logger.warning(
            "Config file %s exceeds %s bytes; ignoring",
            path,
            MAX_TOML_CONFIG_BYTES,
        )
        return {}
    try:
        return tomllib.load(io.BytesIO(data))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        logger.warning("Invalid TOML in %s: %s", path, exc)
        return {}


def _bool_from_config(
    config_data: dict,
    primary: str,
    alias: str,
    default: bool = False,
) -> bool:
    if primary in config_data:
        return _safe_bool(config_data.get(primary), default)
    if alias in config_data:
        return _safe_bool(config_data.get(alias), default)
    return default


def load_config(project_root: Path) -> GuardConfig:
    root = project_root.resolve()
    pyproject = _read_toml(root / "pyproject.toml")
    local_legacy = _read_toml(root / "django_security_hunter.toml")
    local_dg = _read_toml(root / "djangoguard.toml")

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
        logger.warning(
            "Invalid severity_threshold %r; falling back to WARN",
            config_data.get("severity_threshold"),
        )
        sev = "WARN"

    high_saves = _safe_int(config_data.get("djg051_high_save_threshold", 3), 3)
    if high_saves < 2:
        high_saves = 3

    cfg = GuardConfig(
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
        pip_audit=_bool_from_config(
            config_data, "pip_audit", "enable_pip_audit", False
        ),
        bandit=_bool_from_config(
            config_data, "bandit", "enable_bandit", False
        ),
        semgrep=_bool_from_config(
            config_data, "semgrep", "enable_semgrep", False
        ),
        enable_scan_plugins=_safe_bool(
            config_data.get("enable_scan_plugins", True), True
        ),
        score_weight_info=_safe_int(config_data.get("score_weight_info", 1), 1),
        score_weight_warn=_safe_int(config_data.get("score_weight_warn", 5), 5),
        score_weight_high=_safe_int(config_data.get("score_weight_high", 15), 15),
        score_weight_critical=_safe_int(
            config_data.get("score_weight_critical", 40), 40
        ),
    )
    logger.debug(
        "Loaded GuardConfig for %s (severity_threshold=%s, pip_audit=%s, "
        "bandit=%s, semgrep=%s, enable_scan_plugins=%s)",
        root,
        cfg.severity_threshold,
        cfg.pip_audit,
        cfg.bandit,
        cfg.semgrep,
        cfg.enable_scan_plugins,
    )
    return cfg
