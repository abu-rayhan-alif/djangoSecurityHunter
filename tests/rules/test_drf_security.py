from __future__ import annotations

from django_security_hunter.rules.drf_security import run_drf_security_rules


def _base_ctx(**overrides: object) -> dict:
    ctx = {
        "loaded": True,
        "drf_installed": True,
        "rest_default_permission_classes": [
            "rest_framework.permissions.IsAuthenticated",
        ],
        "rest_default_authentication_classes": [
            "rest_framework.authentication.SessionAuthentication",
        ],
        "rest_default_throttle_classes": [
            "rest_framework.throttling.UserRateThrottle",
        ],
        "rest_default_throttle_rates": {"user": "1000/day"},
        "rest_default_pagination_class": "rest_framework.pagination.PageNumberPagination",
        "rest_page_size": 25,
        "data_upload_max_memory_size": 2_621_440,
    }
    ctx.update(overrides)
    return ctx


def test_drf_skipped_when_settings_not_loaded() -> None:
    assert list(run_drf_security_rules({"loaded": False})) == []


def test_drf_skipped_when_drf_not_installed() -> None:
    assert list(run_drf_security_rules(_base_ctx(drf_installed=False))) == []


def test_djg020_when_allow_any() -> None:
    ctx = _base_ctx(
        rest_default_permission_classes=[
            "rest_framework.permissions.AllowAny",
        ],
    )
    findings = list(run_drf_security_rules(ctx))
    assert any(f.rule_id == "DJG020" for f in findings)


def test_djg020_when_permissions_missing() -> None:
    ctx = _base_ctx(rest_default_permission_classes=[])
    findings = list(run_drf_security_rules(ctx))
    assert any(f.rule_id == "DJG020" for f in findings)


def test_djg021_empty_authentication_classes() -> None:
    ctx = _base_ctx(rest_default_authentication_classes=[])
    findings = list(run_drf_security_rules(ctx))
    assert any(f.rule_id == "DJG021" for f in findings)


def test_djg022_no_throttling() -> None:
    ctx = _base_ctx(
        rest_default_throttle_classes=[],
        rest_default_throttle_rates={},
    )
    findings = list(run_drf_security_rules(ctx))
    assert any(f.rule_id == "DJG022" for f in findings)


def test_djg025_no_pagination() -> None:
    ctx = _base_ctx(
        rest_default_pagination_class=None,
        rest_page_size=None,
    )
    findings = list(run_drf_security_rules(ctx))
    assert any(f.rule_id == "DJG025" for f in findings)


def test_djg026_huge_upload_limit() -> None:
    ctx = _base_ctx(data_upload_max_memory_size=80 * 1024 * 1024)
    findings = list(run_drf_security_rules(ctx))
    assert any(f.rule_id == "DJG026" for f in findings)
