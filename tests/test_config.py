from __future__ import annotations

from pathlib import Path

from django_security_hunter.config import GuardConfig, _safe_int, load_config


def test_safe_int_valid() -> None:
    assert _safe_int(42, 7) == 42
    assert _safe_int("99", 7) == 99


def test_safe_int_invalid_uses_default() -> None:
    assert _safe_int("nope", 50) == 50
    assert _safe_int(None, 200) == 200


def test_load_config_invalid_severity_fallback_to_warn(tmp_path: Path) -> None:
    cfg_path = tmp_path / "django_security_hunter.toml"
    cfg_path.write_text('severity_threshold = "NOT_A_LEVEL"\n', encoding="utf-8")
    cfg = load_config(tmp_path)
    assert cfg.severity_threshold == "WARN"


def test_load_config_invalid_ints_fallback(tmp_path: Path) -> None:
    cfg_path = tmp_path / "django_security_hunter.toml"
    cfg_path.write_text(
        'query_count_threshold = "bad"\n'
        "db_time_ms_threshold = []\n",
        encoding="utf-8",
    )
    cfg = load_config(tmp_path)
    assert isinstance(cfg, GuardConfig)
    assert cfg.query_count_threshold == 50
    assert cfg.db_time_ms_threshold == 200


