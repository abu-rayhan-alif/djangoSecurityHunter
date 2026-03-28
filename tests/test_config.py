from pathlib import Path

from django_security_hunter.config import GuardConfig, load_config


def test_load_config_skips_malformed_toml(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("not toml {{{", encoding="utf-8")
    cfg = load_config(tmp_path)
    assert cfg.query_count_threshold == 50


def test_load_config_ignores_non_dict_tool_section(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool]\ndjango_security_hunter = "oops"\n',
        encoding="utf-8",
    )
    cfg = load_config(tmp_path)
    assert cfg.severity_threshold == "WARN"


def test_load_config_invalid_severity_fallback_to_warn(tmp_path: Path) -> None:
    cfg_path = tmp_path / "django_security_hunter.toml"
    cfg_path.write_text('severity_threshold = "NOT_A_LEVEL"\n', encoding="utf-8")
    cfg = load_config(tmp_path)
    assert cfg.severity_threshold == "WARN"


def test_safe_int_clamps_huge_value(tmp_path: Path) -> None:
    (tmp_path / "django_security_hunter.toml").write_text(
        "query_count_threshold = 9999999999999999999999999999999\n",
        encoding="utf-8",
    )
    cfg = load_config(tmp_path)
    assert cfg.query_count_threshold == 2**31 - 1


def test_load_config_skips_oversized_pyproject(tmp_path: Path) -> None:
    huge = tmp_path / "pyproject.toml"
    huge.write_bytes(b"#" + b"x" * (600 * 1024))
    cfg = load_config(tmp_path)
    assert isinstance(cfg, GuardConfig)
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
