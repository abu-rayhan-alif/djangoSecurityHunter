from __future__ import annotations

from pathlib import Path

from django_security_hunter.rules.drf_auth_urls import run_drf_auth_url_rules


def test_djg023_high_without_throttle(tmp_path: Path) -> None:
    (tmp_path / "urls.py").write_text(
        "from django.urls import path\n"
        "urlpatterns = [path('login/', lambda r: None)]\n",
        encoding="utf-8",
    )
    ctx = {
        "drf_installed": True,
        "rest_default_throttle_classes": [],
        "rest_default_throttle_rates": {},
    }
    findings = run_drf_auth_url_rules(tmp_path, ctx)
    assert any(f.rule_id == "DJG023" and f.severity == "HIGH" for f in findings)


def test_djg023_warn_with_global_throttle(tmp_path: Path) -> None:
    (tmp_path / "urls.py").write_text(
        "from django.urls import path\n"
        "urlpatterns = [path('api/token/', lambda r: None)]\n",
        encoding="utf-8",
    )
    ctx = {
        "drf_installed": True,
        "rest_default_throttle_classes": ["rest_framework.throttling.AnonRateThrottle"],
        "rest_default_throttle_rates": {"anon": "100/hour"},
    }
    findings = run_drf_auth_url_rules(tmp_path, ctx)
    assert any(f.rule_id == "DJG023" and f.severity == "WARN" for f in findings)


def test_djg023_per_view_high_resolved_without_throttle(tmp_path: Path) -> None:
    (tmp_path / "urls.py").write_text(
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [path('login/', views.login_view)]\n",
        encoding="utf-8",
    )
    (tmp_path / "views.py").write_text(
        "def login_view(request):\n"
        "    return None\n",
        encoding="utf-8",
    )
    ctx = {
        "drf_installed": True,
        "rest_default_throttle_classes": [],
        "rest_default_throttle_rates": {},
    }
    findings = run_drf_auth_url_rules(tmp_path, ctx)
    assert any(
        f.rule_id == "DJG023"
        and f.severity == "HIGH"
        and "'login/'" in f.message
        for f in findings
    )


def test_djg023_per_view_ok_with_throttle_decorator(tmp_path: Path) -> None:
    (tmp_path / "urls.py").write_text(
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [path('login/', views.login_view)]\n",
        encoding="utf-8",
    )
    (tmp_path / "views.py").write_text(
        "from rest_framework.decorators import throttle_classes\n"
        "@throttle_classes([])\n"
        "def login_view(request):\n"
        "    return None\n",
        encoding="utf-8",
    )
    ctx = {
        "drf_installed": True,
        "rest_default_throttle_classes": [],
        "rest_default_throttle_rates": {},
    }
    findings = run_drf_auth_url_rules(tmp_path, ctx)
    assert not any(f.rule_id == "DJG023" for f in findings)
