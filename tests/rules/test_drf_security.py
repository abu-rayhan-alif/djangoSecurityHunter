from __future__ import annotations

from pathlib import Path

import pytest

from djangoguard.rules import drf_security as drf_security_rules

_FIXTURE_SCAN_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "drf_scan_empty"


def _ctx(**overrides: object) -> dict:
    base = {
        "loaded": True,
        "debug": False,
        "drf_installed": True,
        "project_root": str(_FIXTURE_SCAN_ROOT),
        "drf_default_permission_classes": [
            "rest_framework.permissions.IsAuthenticated",
        ],
        "drf_default_authentication_classes": [
            "rest_framework.authentication.SessionAuthentication",
        ],
        "drf_default_throttle_classes": [
            "rest_framework.throttling.UserRateThrottle",
        ],
        "drf_default_pagination_class": None,
    }
    base.update(overrides)
    return base


def test_skips_when_settings_not_loaded() -> None:
    findings = list(drf_security_rules.run_drf_security_rules({"loaded": False}))
    assert findings == []


def test_skips_when_drf_not_installed() -> None:
    findings = list(
        drf_security_rules.run_drf_security_rules(_ctx(drf_installed=False))
    )
    assert findings == []


def test_skips_when_debug_true() -> None:
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(debug=True, drf_default_permission_classes=None)
        )
    )
    assert findings == []


def test_djg020_high_when_default_permission_classes_missing() -> None:
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(drf_default_permission_classes=None),
        )
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG020"
    assert findings[0].severity == "HIGH"
    assert "missing" in findings[0].title.lower()


def test_djg020_high_when_default_permission_classes_empty() -> None:
    findings = list(
        drf_security_rules.run_drf_security_rules(_ctx(drf_default_permission_classes=[]))
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG020"
    assert "empty" in findings[0].title.lower()


def test_djg020_high_when_allow_any() -> None:
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(
                drf_default_permission_classes=[
                    "rest_framework.permissions.AllowAny",
                ],
            ),
        )
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG020"
    assert "AllowAny" in findings[0].title


def test_djg020_high_when_allow_any_mixed_with_others() -> None:
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(
                drf_default_permission_classes=[
                    "rest_framework.permissions.IsAuthenticated",
                    "rest_framework.permissions.AllowAny",
                ],
            ),
        )
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG020"


def test_no_finding_when_is_authenticated_only() -> None:
    findings = list(drf_security_rules.run_drf_security_rules(_ctx()))
    assert findings == []


def test_no_finding_when_is_admin_only() -> None:
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(
                drf_default_permission_classes=[
                    "rest_framework.permissions.IsAdminUser",
                ],
            ),
        )
    )
    assert findings == []


def test_djg021_high_when_default_authentication_classes_missing() -> None:
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(drf_default_authentication_classes=None),
        )
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG021"
    assert findings[0].severity == "HIGH"
    assert "AUTHENTICATION" in findings[0].title.upper()


def test_djg020_and_djg021_when_both_defaults_missing() -> None:
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(
                drf_default_permission_classes=None,
                drf_default_authentication_classes=None,
                drf_default_throttle_classes=[
                    "rest_framework.throttling.UserRateThrottle",
                ],
            ),
        )
    )
    ids = {f.rule_id for f in findings}
    assert ids == {"DJG020", "DJG021"}
    assert len(findings) == 2


def test_djg022_warn_when_throttle_classes_missing() -> None:
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(drf_default_throttle_classes=None),
        )
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG022"
    assert findings[0].severity == "WARN"


def test_djg022_warn_when_throttle_classes_empty() -> None:
    findings = list(
        drf_security_rules.run_drf_security_rules(_ctx(drf_default_throttle_classes=[]))
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG022"


def test_djg023_high_when_auth_url_heuristic_and_no_global_throttle(
    tmp_path: Path,
) -> None:
    (tmp_path / "urls.py").write_text(
        "urlpatterns = [path('api/token/', obtain)]\n",
        encoding="utf-8",
    )
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(
                project_root=str(tmp_path),
                drf_default_throttle_classes=None,
            ),
        )
    )
    assert any(f.rule_id == "DJG023" for f in findings)
    djg023 = [f for f in findings if f.rule_id == "DJG023"][0]
    assert djg023.severity == "HIGH"


def test_djg023_not_fired_when_global_throttle_configured(tmp_path: Path) -> None:
    (tmp_path / "urls.py").write_text(
        "urlpatterns = [path('api/token/', obtain)]\n",
        encoding="utf-8",
    )
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(
                project_root=str(tmp_path),
                drf_default_throttle_classes=[
                    "rest_framework.throttling.AnonRateThrottle",
                ],
            ),
        )
    )
    assert not any(f.rule_id == "DJG023" for f in findings)


def test_djg024_high_user_serializer_all_fields(tmp_path: Path) -> None:
    (tmp_path / "serializers.py").write_text(
        "from rest_framework import serializers\n"
        "from django.contrib.auth.models import User\n"
        "class UserSerializer(serializers.ModelSerializer):\n"
        "    class Meta:\n"
        "        model = User\n"
        "        fields = '__all__'\n",
        encoding="utf-8",
    )
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(project_root=str(tmp_path)),
        )
    )
    djg024 = [f for f in findings if f.rule_id == "DJG024"]
    assert len(djg024) == 1
    assert djg024[0].severity == "HIGH"


def test_djg024_warn_profile_serializer(tmp_path: Path) -> None:
    (tmp_path / "serializers.py").write_text(
        "from rest_framework import serializers\n"
        "class ProfileSerializer(serializers.ModelSerializer):\n"
        "    class Meta:\n"
        "        model = Profile\n"
        "        fields = '__all__'\n",
        encoding="utf-8",
    )
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(project_root=str(tmp_path)),
        )
    )
    djg024 = [f for f in findings if f.rule_id == "DJG024"]
    assert len(djg024) == 1
    assert djg024[0].severity == "WARN"


def test_djg025_high_modelviewset_no_global_pagination(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "from rest_framework import viewsets\n"
        "class BookViewSet(viewsets.ModelViewSet):\n"
        "    pass\n",
        encoding="utf-8",
    )
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(
                project_root=str(tmp_path),
                drf_default_pagination_class=None,
            ),
        )
    )
    djg025 = [f for f in findings if f.rule_id == "DJG025"]
    assert len(djg025) == 1
    assert djg025[0].severity == "HIGH"
    assert "PageNumberPagination" in (djg025[0].fix_hint or "")
    assert "DEFAULT_PERMISSION_CLASSES" in (djg025[0].fix_hint or "")


def test_djg025_warn_single_list_api_view(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "from rest_framework import generics\n"
        "class TagList(generics.ListAPIView):\n"
        "    pass\n",
        encoding="utf-8",
    )
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(
                project_root=str(tmp_path),
                drf_default_pagination_class=None,
            ),
        )
    )
    djg025 = [f for f in findings if f.rule_id == "DJG025"]
    assert len(djg025) == 1
    assert djg025[0].severity == "WARN"


def test_djg025_warn_three_router_registers_only(tmp_path: Path) -> None:
    (tmp_path / "urls.py").write_text(
        "router = DefaultRouter()\n"
        "router.register(r'a', A)\n"
        "router.register(r'b', B)\n"
        "router.register(r'c', C)\n",
        encoding="utf-8",
    )
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(
                project_root=str(tmp_path),
                drf_default_pagination_class=None,
            ),
        )
    )
    djg025 = [f for f in findings if f.rule_id == "DJG025"]
    assert len(djg025) == 1
    assert djg025[0].severity == "WARN"


def test_djg025_one_hit_when_class_has_multiple_list_bases(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "from rest_framework import generics\n"
        "from rest_framework.mixins import ListModelMixin\n"
        "class X(ListModelMixin, generics.ListCreateAPIView):\n"
        "    pass\n",
        encoding="utf-8",
    )
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(
                project_root=str(tmp_path),
                drf_default_pagination_class=None,
            ),
        )
    )
    djg025 = [f for f in findings if f.rule_id == "DJG025"]
    assert len(djg025) == 1
    assert djg025[0].severity == "WARN"


def test_djg025_not_fired_when_pagination_configured(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "from rest_framework import viewsets\n"
        "class BookViewSet(viewsets.ModelViewSet):\n"
        "    pass\n",
        encoding="utf-8",
    )
    findings = list(
        drf_security_rules.run_drf_security_rules(
            _ctx(
                project_root=str(tmp_path),
                drf_default_pagination_class=(
                    "rest_framework.pagination.PageNumberPagination"
                ),
            ),
        )
    )
    assert not any(f.rule_id == "DJG025" for f in findings)


def test_static_scan_skips_oversized_py_file(tmp_path: Path) -> None:
    from djangoguard.collectors.drf_static_scan import (
        _MAX_PY_SOURCE_BYTES,
        scan_auth_like_url_hits,
    )

    (tmp_path / "huge.py").write_bytes(b"#" * (_MAX_PY_SOURCE_BYTES + 1))
    (tmp_path / "urls.py").write_text(
        "urlpatterns = [path('api/token/', x)]\n",
        encoding="utf-8",
    )
    hits = scan_auth_like_url_hits(tmp_path)
    assert len(hits) == 1
