import pytest
import typer

from django_security_hunter.cli import _cli_settings_module, _render_report
from django_security_hunter.models import Report
from django_security_hunter.settings_module import (
    InvalidSettingsModule,
    normalize_django_settings_module,
)


def test_normalize_none_and_blank() -> None:
    assert normalize_django_settings_module(None) is None
    assert normalize_django_settings_module("") is None
    assert normalize_django_settings_module("   ") is None


def test_normalize_accepts_dotted() -> None:
    assert normalize_django_settings_module("mysite.settings") == "mysite.settings"


def test_normalize_rejects_outer_whitespace() -> None:
    with pytest.raises(InvalidSettingsModule):
        normalize_django_settings_module(" foo.bar ")


def test_normalize_rejects_control_chars() -> None:
    with pytest.raises(InvalidSettingsModule):
        normalize_django_settings_module("foo\nbar")
    with pytest.raises(InvalidSettingsModule):
        normalize_django_settings_module("foo\x00bar")


def test_normalize_rejects_invalid_chars() -> None:
    with pytest.raises(InvalidSettingsModule):
        normalize_django_settings_module("foo:bar")
    with pytest.raises(InvalidSettingsModule):
        normalize_django_settings_module("foo/bar")


def test_normalize_rejects_double_dot() -> None:
    with pytest.raises(InvalidSettingsModule):
        normalize_django_settings_module("pkg..settings")


def test_normalize_rejects_non_ascii() -> None:
    with pytest.raises(InvalidSettingsModule):
        normalize_django_settings_module("café.settings")


def test_cli_settings_wraps_as_bad_parameter() -> None:
    with pytest.raises(typer.BadParameter):
        _cli_settings_module("foo\nbar")


def test_render_report_strips_whitespace_format() -> None:
    report = Report(mode="scan", findings=[])
    out = _render_report(report, "  json  ")
    assert '"mode": "scan"' in out


def test_render_report_rejects_blank_format() -> None:
    report = Report(mode="scan", findings=[])
    with pytest.raises(typer.BadParameter):
        _render_report(report, "   ")
