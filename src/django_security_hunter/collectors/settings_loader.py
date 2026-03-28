from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from django_security_hunter.settings_module import (
    InvalidSettingsModule,
    normalize_django_settings_module,
)
from django_security_hunter.validation import is_valid_django_settings_module


def _str_list_setting(settings: Any, name: str) -> list[str]:
    raw = getattr(settings, name, None)
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw]
    return [str(raw)]


def _cors_active(settings: Any) -> bool:
    for app in getattr(settings, "INSTALLED_APPS", ()):
        a = str(app).lower()
        if a == "corsheaders" or a.endswith(".corsheaders"):
            return True
    for mw in getattr(settings, "MIDDLEWARE", ()):
        if "corsheaders.middleware" in str(mw).lower():
            return True
    return False


def _hsts_seconds(settings: Any) -> int:
    raw = getattr(settings, "SECURE_HSTS_SECONDS", 0)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _drf_installed(settings: Any) -> bool:
    for app in getattr(settings, "INSTALLED_APPS", ()):
        a = str(app).lower()
        if a == "rest_framework" or a.endswith(".rest_framework"):
            return True
    return False


def _permission_class_to_str(entry: Any) -> str:
    if isinstance(entry, str):
        return entry
    mod = getattr(entry, "__module__", "") or ""
    qual = getattr(entry, "__qualname__", type(entry).__name__)
    return f"{mod}.{qual}" if mod else str(entry)


def _drf_rest_framework_sequence_key(settings: Any, key: str) -> list[str] | None:
    """None = REST_FRAMEWORK or key missing; [] = explicitly empty; else configured."""
    rf = getattr(settings, "REST_FRAMEWORK", None)
    if rf is None:
        return None
    if not isinstance(rf, dict):
        return None
    if key not in rf:
        return None
    raw = rf[key]
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [_permission_class_to_str(x) for x in raw]
    return [_permission_class_to_str(raw)]


def _drf_default_permission_classes(settings: Any) -> list[str] | None:
    return _drf_rest_framework_sequence_key(settings, "DEFAULT_PERMISSION_CLASSES")


def _drf_default_authentication_classes(settings: Any) -> list[str] | None:
    return _drf_rest_framework_sequence_key(settings, "DEFAULT_AUTHENTICATION_CLASSES")


def _drf_default_throttle_classes(settings: Any) -> list[str] | None:
    return _drf_rest_framework_sequence_key(settings, "DEFAULT_THROTTLE_CLASSES")


def _drf_default_pagination_class(settings: Any) -> str | None:
    """None = REST_FRAMEWORK or key missing; '' = explicitly disabled/empty."""
    rf = getattr(settings, "REST_FRAMEWORK", None)
    if rf is None or not isinstance(rf, dict):
        return None
    if "DEFAULT_PAGINATION_CLASS" not in rf:
        return None
    raw = rf["DEFAULT_PAGINATION_CLASS"]
    if raw is None:
        return ""
    if raw == "":
        return ""
    return _permission_class_to_str(raw)


def _drf_page_size(settings: Any) -> int | None:
    rf = getattr(settings, "REST_FRAMEWORK", None)
    if rf is None or not isinstance(rf, dict) or "PAGE_SIZE" not in rf:
        return None
    raw = rf["PAGE_SIZE"]
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _safe_int_setting(settings: Any, name: str, default: int) -> int:
    raw = getattr(settings, name, default)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _allowed_hosts_list(settings: Any) -> list[str]:
    raw = getattr(settings, "ALLOWED_HOSTS", None)
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(h) for h in raw]
    return [str(raw)]


def load_settings_context(project_root: Path, settings_module: str | None) -> dict[str, Any]:
    """Load Django settings via ``DJANGO_SETTINGS_MODULE`` and ``django.setup()``."""
    root = project_root.resolve()
    raw = (
        settings_module
        if settings_module is not None
        else os.environ.get("DJANGO_SETTINGS_MODULE")
    )
    try:
        module = normalize_django_settings_module(raw)
    except InvalidSettingsModule:
        return {
            "project_root": str(root),
            "settings_module": None,
            "loaded": False,
            "skip_reason": "invalid_settings_module",
        }
    base: dict[str, Any] = {
        "project_root": str(root),
        "settings_module": module,
        "loaded": False,
    }
    if not module:
        base["skip_reason"] = "no_settings_module"
        return base

    if not is_valid_django_settings_module(module):
        base["skip_reason"] = "invalid_settings_module"
        return base

    root_str = str(root)
    path_inserted = False
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
        path_inserted = True

    try:
        try:
            import django
            from django.conf import settings

            if settings.configured:
                env_raw = os.environ.get("DJANGO_SETTINGS_MODULE")
                env_module = env_raw.strip() if isinstance(env_raw, str) else None
                if env_module != module:
                    base["skip_reason"] = "django_already_configured"
                    base["load_error"] = (
                        "Django settings are already loaded in this process "
                        f"(DJANGO_SETTINGS_MODULE={env_raw!r}); "
                        f"refusing to use a different module ({module!r}). "
                        "Run django_security_hunter in a fresh process per project, or match "
                        "the already-loaded settings module."
                    )
                    return base
            else:
                os.environ["DJANGO_SETTINGS_MODULE"] = module
                django.setup()

            debug = bool(getattr(settings, "DEBUG", False))
            sk_raw = getattr(settings, "SECRET_KEY", None)
            secret_key = "" if sk_raw is None else str(sk_raw)
            base.update(
                {
                    "loaded": True,
                    "debug": debug,
                    "secret_key": secret_key,
                    "allowed_hosts": _allowed_hosts_list(settings),
                    "secure_ssl_redirect": bool(
                        getattr(settings, "SECURE_SSL_REDIRECT", False)
                    ),
                    "hsts_seconds": _hsts_seconds(settings),
                    "session_cookie_secure": bool(
                        getattr(settings, "SESSION_COOKIE_SECURE", False)
                    ),
                    "csrf_cookie_secure": bool(
                        getattr(settings, "CSRF_COOKIE_SECURE", False)
                    ),
                    "secure_content_type_nosniff": bool(
                        getattr(settings, "SECURE_CONTENT_TYPE_NOSNIFF", True)
                    ),
                    "x_frame_options": str(
                        getattr(settings, "X_FRAME_OPTIONS", "DENY") or ""
                    ),
                    "csrf_trusted_origins": _str_list_setting(
                        settings, "CSRF_TRUSTED_ORIGINS"
                    ),
                    "cors_active": _cors_active(settings),
                    "cors_allow_all_origins": bool(
                        getattr(settings, "CORS_ALLOW_ALL_ORIGINS", False)
                    ),
                    "cors_allowed_origins": _str_list_setting(
                        settings, "CORS_ALLOWED_ORIGINS"
                    ),
                    "cors_allowed_origin_regexes": _str_list_setting(
                        settings, "CORS_ALLOWED_ORIGIN_REGEXES"
                    ),
                    "drf_installed": _drf_installed(settings),
                    "drf_default_permission_classes": _drf_default_permission_classes(
                        settings
                    ),
                    "drf_default_authentication_classes": (
                        _drf_default_authentication_classes(settings)
                    ),
                    "drf_default_throttle_classes": _drf_default_throttle_classes(
                        settings
                    ),
                    "drf_default_pagination_class": _drf_default_pagination_class(
                        settings
                    ),
                    "drf_page_size": _drf_page_size(settings),
                    "data_upload_max_memory_size": _safe_int_setting(
                        settings,
                        "DATA_UPLOAD_MAX_MEMORY_SIZE",
                        2_621_440,
                    ),
                    "file_upload_max_memory_size": _safe_int_setting(
                        settings,
                        "FILE_UPLOAD_MAX_MEMORY_SIZE",
                        2_621_440,
                    ),
                    "data_upload_max_number_fields": _safe_int_setting(
                        settings,
                        "DATA_UPLOAD_MAX_NUMBER_FIELDS",
                        1_000,
                    ),
                }
            )
            return base
        except Exception as exc:
            base["load_error"] = str(exc)
            return base
    finally:
        if path_inserted:
            try:
                sys.path.remove(root_str)
            except ValueError:
                pass


