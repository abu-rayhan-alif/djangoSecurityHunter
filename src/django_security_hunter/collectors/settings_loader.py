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

            if not settings.configured:
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


