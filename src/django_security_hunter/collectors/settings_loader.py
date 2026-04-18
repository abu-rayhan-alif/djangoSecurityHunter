from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

from django_security_hunter.validation import is_valid_django_settings_module

logger = logging.getLogger(__name__)


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


def _cls_repr(obj: Any) -> str:
    if isinstance(obj, str):
        return obj
    mod = getattr(obj, "__module__", None)
    name = getattr(obj, "__name__", None)
    if mod and name:
        return f"{mod}.{name}"
    return str(obj)


def _rest_framework_lists(settings: Any) -> dict[str, Any]:
    rf = getattr(settings, "REST_FRAMEWORK", None)
    if not isinstance(rf, dict):
        return {
            "rest_default_permission_classes": [],
            "rest_default_authentication_classes": [],
            "rest_default_throttle_classes": [],
            "rest_default_throttle_rates": {},
            "rest_default_pagination_class": None,
            "rest_page_size": None,
        }
    perms = rf.get("DEFAULT_PERMISSION_CLASSES")
    auths = rf.get("DEFAULT_AUTHENTICATION_CLASSES")
    throttles = rf.get("DEFAULT_THROTTLE_CLASSES")
    rates = rf.get("DEFAULT_THROTTLE_RATES")
    pag = rf.get("DEFAULT_PAGINATION_CLASS")
    page_size = rf.get("PAGE_SIZE")

    def _as_seq(v: Any) -> list[Any]:
        if isinstance(v, (list, tuple)):
            return list(v)
        return [v] if v is not None else []

    return {
        "rest_default_permission_classes": [_cls_repr(x) for x in _as_seq(perms)],
        "rest_default_authentication_classes": [_cls_repr(x) for x in _as_seq(auths)],
        "rest_default_throttle_classes": [_cls_repr(x) for x in _as_seq(throttles)],
        "rest_default_throttle_rates": dict(rates) if isinstance(rates, dict) else {},
        "rest_default_pagination_class": _cls_repr(pag) if pag is not None else None,
        "rest_page_size": page_size,
    }


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
    module = settings_module or os.environ.get("DJANGO_SETTINGS_MODULE")
    base: dict[str, Any] = {
        "project_root": str(root),
        "settings_module": module,
        "loaded": False,
    }
    if not module:
        base["skip_reason"] = "no_settings_module"
        logger.debug("Django settings skipped: no_settings_module (project_root=%s)", root)
        return base

    if not is_valid_django_settings_module(module):
        logger.warning(
            "Invalid Django settings module string %r; skipping settings load",
            module,
        )
        return {
            "project_root": str(root),
            "settings_module": None,
            "loaded": False,
            "skip_reason": "invalid_settings_module",
        }

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
                    "drf_installed": _drf_installed(settings),
                    "data_upload_max_memory_size": getattr(
                        settings, "DATA_UPLOAD_MAX_MEMORY_SIZE", None
                    ),
                    **_rest_framework_lists(settings),
                }
            )
            logger.debug(
                "Django settings loaded successfully (module=%s, project_root=%s)",
                module,
                root,
            )
            return base
        except ModuleNotFoundError as exc:
            hint = ""
            if exc.name in ("django", "Django"):
                hint = " Install Django in this environment or run without --settings."
            logger.warning(
                "Django settings load failed: missing module %r (%s).%s",
                exc.name,
                exc,
                hint,
            )
            base["load_error"] = str(exc)
            base["load_error_kind"] = "module_not_found"
            return base
        except Exception as exc:
            logger.warning(
                "Django settings failed to load (module=%s): %s",
                module,
                exc,
            )
            base["load_error"] = str(exc)
            return base
    finally:
        if path_inserted:
            try:
                sys.path.remove(root_str)
            except ValueError:
                logger.debug(
                    "sys.path cleanup: %s was not in sys.path (already removed)",
                    root_str,
                )
