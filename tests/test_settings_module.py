import pytest

from djangoguard.settings_module import InvalidSettingsModule, normalize_django_settings_module


def test_normalize_accepts_dotted() -> None:
    assert normalize_django_settings_module("mysite.settings") == "mysite.settings"


def test_normalize_rejects_control_chars() -> None:
    with pytest.raises(InvalidSettingsModule):
        normalize_django_settings_module("a\nb")
