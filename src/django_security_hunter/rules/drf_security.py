from __future__ import annotations

from typing import Any, Iterable

from django_security_hunter.models import Finding


def _djg020_permissions(ctx: dict[str, Any]) -> list[Finding]:
    perms: list[str] = ctx.get("rest_default_permission_classes") or []
    if not perms:
        return [
            Finding(
                rule_id="DJG020",
                severity="HIGH",
                title="DRF DEFAULT_PERMISSION_CLASSES not configured",
                message=(
                    "REST_FRAMEWORK does not set DEFAULT_PERMISSION_CLASSES. "
                    "DRF may default to permissive behavior; API views can be exposed "
                    "without explicit authentication."
                ),
                fix_hint=(
                    "Set strict defaults, e.g.:\n\n"
                    "REST_FRAMEWORK = {\n"
                    '    "DEFAULT_PERMISSION_CLASSES": [\n'
                    '        "rest_framework.permissions.IsAuthenticated",\n'
                    "    ],\n"
                    "}\n"
                ),
            )
        ]
    if any("AllowAny" in p for p in perms):
        return [
            Finding(
                rule_id="DJG020",
                severity="HIGH",
                title="DRF DEFAULT_PERMISSION_CLASSES includes AllowAny",
                message=(
                    "Global AllowAny means unauthenticated clients can reach any view "
                    "that does not override permissions."
                ),
                fix_hint=(
                    "Use IsAuthenticated or custom restrictive classes by default; "
                    "override only on specific public endpoints.\n"
                ),
            )
        ]
    return []


def _djg021_authentication(ctx: dict[str, Any]) -> list[Finding]:
    auth: list[str] = ctx.get("rest_default_authentication_classes") or []
    if auth == []:
        return [
            Finding(
                rule_id="DJG021",
                severity="HIGH",
                title="DRF DEFAULT_AUTHENTICATION_CLASSES is empty",
                message=(
                    "An empty authentication class list disables DRF authentication "
                    "for views using default settings."
                ),
                fix_hint=(
                    "Configure explicit classes in REST_FRAMEWORK, e.g.:\n\n"
                    "REST_FRAMEWORK = {\n"
                    '    "DEFAULT_AUTHENTICATION_CLASSES": [\n'
                    '        "rest_framework.authentication.SessionAuthentication",\n'
                    '        "rest_framework.authentication.TokenAuthentication",\n'
                    "    ],\n"
                    "}\n"
                ),
            )
        ]
    return []


def _djg022_throttling(ctx: dict[str, Any]) -> list[Finding]:
    classes: list[str] = ctx.get("rest_default_throttle_classes") or []
    rates: dict[str, Any] = ctx.get("rest_default_throttle_rates") or {}
    if classes or rates:
        return []
    return [
        Finding(
            rule_id="DJG022",
            severity="WARN",
            title="DRF throttling not configured",
            message=(
                "DEFAULT_THROTTLE_CLASSES and DEFAULT_THROTTLE_RATES are unset. "
                "Public or authenticated APIs may be abused without rate limits."
            ),
            fix_hint=(
                "Enable throttling in REST_FRAMEWORK, e.g.:\n\n"
                "REST_FRAMEWORK = {\n"
                '    "DEFAULT_THROTTLE_CLASSES": [\n'
                '        "rest_framework.throttling.AnonRateThrottle",\n'
                '        "rest_framework.throttling.UserRateThrottle",\n'
                "    ],\n"
                '    "DEFAULT_THROTTLE_RATES": {"anon": "100/hour", "user": "1000/hour"},\n'
                "}\n"
            ),
        )
    ]


def _djg025_pagination(ctx: dict[str, Any]) -> list[Finding]:
    pag = ctx.get("rest_default_pagination_class")
    page_size = ctx.get("rest_page_size")
    if pag or page_size is not None:
        return []
    return [
        Finding(
            rule_id="DJG025",
            severity="WARN",
            title="DRF default pagination not configured",
            message=(
                "No DEFAULT_PAGINATION_CLASS or PAGE_SIZE in REST_FRAMEWORK. "
                "List endpoints may return unbounded result sets."
            ),
            fix_hint=(
                "Use PageNumberPagination or CursorPagination with PAGE_SIZE, e.g.:\n\n"
                'REST_FRAMEWORK = {"PAGE_SIZE": 50, '
                '"DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination"}\n'
            ),
        )
    ]


def _djg026_upload_limit(ctx: dict[str, Any]) -> list[Finding]:
    raw = ctx.get("data_upload_max_memory_size")
    if raw is None:
        return []
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return []
    # 50 MiB
    if n <= 50 * 1024 * 1024:
        return []
    return [
        Finding(
            rule_id="DJG026",
            severity="WARN",
            title="DATA_UPLOAD_MAX_MEMORY_SIZE is very large",
            message=(
                f"DATA_UPLOAD_MAX_MEMORY_SIZE is {n} bytes (~{n // (1024 * 1024)} MiB). "
                "Large in-memory uploads increase DoS and memory pressure risk."
            ),
            fix_hint=(
                "Lower the limit or reject huge bodies at the proxy; stream large uploads "
                "to disk/object storage instead.\n"
            ),
        )
    ]


def run_drf_security_rules(ctx: dict[str, Any]) -> Iterable[Finding]:
    if not ctx.get("loaded") or not ctx.get("drf_installed"):
        return []
    findings: list[Finding] = []
    findings.extend(_djg020_permissions(ctx))
    findings.extend(_djg021_authentication(ctx))
    findings.extend(_djg022_throttling(ctx))
    findings.extend(_djg025_pagination(ctx))
    findings.extend(_djg026_upload_limit(ctx))
    return findings
