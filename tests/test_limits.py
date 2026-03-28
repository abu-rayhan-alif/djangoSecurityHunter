"""Tests for config and scanner output size limits."""

from __future__ import annotations

from pathlib import Path

from django_security_hunter.config import GuardConfig, load_config
from django_security_hunter.limits import MAX_TOML_CONFIG_BYTES


def test_oversized_pyproject_toml_is_ignored(tmp_path: Path) -> None:
    huge = tmp_path / "pyproject.toml"
    huge.write_bytes(b"x" * (MAX_TOML_CONFIG_BYTES + 1))
    cfg = load_config(tmp_path)
    assert cfg == GuardConfig()


