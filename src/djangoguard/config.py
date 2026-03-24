from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib


@dataclass(slots=True)
class GuardConfig:
    severity_threshold: str = "WARN"
    query_count_threshold: int = 50
    db_time_ms_threshold: int = 200


def _read_toml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


def load_config(project_root: Path) -> GuardConfig:
    pyproject = _read_toml(project_root / "pyproject.toml")
    local = _read_toml(project_root / "djangoguard.toml")

    config_data: dict = {}
    if "tool" in pyproject and "djangoguard" in pyproject["tool"]:
        config_data.update(pyproject["tool"]["djangoguard"])
    config_data.update(local)

    return GuardConfig(
        severity_threshold=str(config_data.get("severity_threshold", "WARN")).upper(),
        query_count_threshold=int(config_data.get("query_count_threshold", 50)),
        db_time_ms_threshold=int(config_data.get("db_time_ms_threshold", 200)),
    )
