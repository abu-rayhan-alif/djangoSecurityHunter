from pathlib import Path

import pytest

from djangoguard.collectors.settings_loader import load_settings_context


def test_load_settings_invalid_explicit_module(tmp_path: Path) -> None:
    ctx = load_settings_context(tmp_path, "evil:settings")
    assert ctx.get("loaded") is False
    assert ctx.get("skip_reason") == "invalid_settings_module"
    assert ctx.get("settings_module") is None


def test_load_settings_invalid_env_module(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DJANGO_SETTINGS_MODULE", "a\nb")
    ctx = load_settings_context(tmp_path, None)
    assert ctx.get("loaded") is False
    assert ctx.get("skip_reason") == "invalid_settings_module"
