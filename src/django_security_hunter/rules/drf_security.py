from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from django_security_hunter.collectors.drf_static_scan import (
    scan_auth_like_url_hits,
    scan_drf_list_endpoint_hits,
    scan_serializers_fields_all_sensitive,
)
from django_security_hunter.models import Finding


def _is_allow_any_permission(class_str: str) -> bool:
    s = class_str.lower().replace(" ", "")
    return "allowany" in s


def _djg023_auth_like_routes_without_global_throttle(ctx: dict[str, Any]) -> list[Finding]:
    throttle = ctx.get("drf_default_throttle_classes")
    if throttle is not None and len(throttle) > 0:
        return []
    root = Path(ctx.get("project_root") or ".")
    hits = scan_auth_like_url_hits(root)
    if not hits:
        return []
    sample = "; ".join(f"{p}:{ln}" for p, ln, _ in hits[:5])
    if len(hits) > 5:
        sample += f" (+{len(hits) - 5} more)"
    first_path, first_line, _ = hits[0]
    return [
        Finding(
            rule_id="DJG023",
            severity="HIGH",
            title="Auth-like URL routes with no global throttling (heuristic)",
            message=(
                f"Heuristic: {len(hits)} line(s) look like login/token/password/auth routes "
                f"while DEFAULT_THROTTLE_CLASSES is unset or empty — brute-force risk. "
                f"Examples: {sample}"
            ),
            path=first_path,
            line=first_line,
            fix_hint=(
                "Enable global throttling and/or add throttle_classes on these views, "
                "e.g. AnonRateThrottle for obtain_token / login routes.\n"
            ),
        )
    ]


def _djg024_serializers_all_fields_sensitive(ctx: dict[str, Any]) -> list[Finding]:
    root = Path(ctx.get("project_root") or ".")
    rows = scan_serializers_fields_all_sensitive(root)
    findings: list[Finding] = []
    for file, line, class_name, model_hint, sev in rows:
        findings.append(
            Finding(
                rule_id="DJG024",
                severity=sev,
                title="Serializer uses fields='__all__' on a likely-sensitive model",
                message=(
                    f"{class_name} sets Meta.fields = '__all__' "
                    f"(model={model_hint or 'unknown'}); all DB columns may be exposed."
                ),
                path=file,
                line=line,
                fix_hint=(
                    "Prefer explicit `fields` or `exclude` for models that can hold "
                    "PII, credentials, or payment data.\n"
                ),
            )
        )
    return findings


_REST_FRAMEWORK_SNIPPET_WITH_PAGINATION = (
    "REST_FRAMEWORK = {\n"
    '    "DEFAULT_PERMISSION_CLASSES": [\n'
    '        "rest_framework.permissions.IsAuthenticated",\n'
    "    ],\n"
    '    "DEFAULT_AUTHENTICATION_CLASSES": [\n'
    '        "rest_framework.authentication.SessionAuthentication",\n'
    "    ],\n"
    '    "DEFAULT_THROTTLE_CLASSES": [\n'
    '        "rest_framework.throttling.UserRateThrottle",\n'
    '        "rest_framework.throttling.AnonRateThrottle",\n'
    "    ],\n"
    '    "DEFAULT_THROTTLE_RATES": {"user": "1000/day", "anon": "100/day"},\n'
    '    "DEFAULT_PAGINATION_CLASS": '
    '"rest_framework.pagination.PageNumberPagination",\n'
    '    "PAGE_SIZE": 20,\n'
    "}\n"
)


def _pagination_configured(ctx: dict[str, Any]) -> bool:
    raw = ctx.get("drf_default_pagination_class")
    if raw is None:
        return False
    if isinstance(raw, str) and raw.strip() == "":
        return False
    return True


def _djg025_list_endpoints_without_pagination(ctx: dict[str, Any]) -> list[Finding]:
    if _pagination_configured(ctx):
        return []
    root = Path(ctx.get("project_root") or ".")
    hits = scan_drf_list_endpoint_hits(root)
    if not hits:
        return []
    high_kinds = frozenset({"MODEL_VIEWSET", "READONLY_VIEWSET"})
    non_router = [h for h in hits if h[3] != "ROUTER_REGISTER"]
    router_only = len(non_router) == 0

    if any(h[3] in high_kinds for h in hits):
        severity = "HIGH"
    elif len(non_router) >= 3:
        severity = "HIGH"
    elif len(hits) >= 3 and not router_only:
        severity = "HIGH"
    else:
        # e.g. only router.register lines (weak signal) or few list-style classes
        severity = "WARN"
    sample = "; ".join(f"{p}:{ln}:{name}" for p, ln, name, _ in hits[:5])
    if len(hits) > 5:
        sample += f" (+{len(hits) - 5} more)"
    first_path, first_line, _, _ = hits[0]
    return [
        Finding(
            rule_id="DJG025",
            severity=severity,
            title="List-style API endpoints with no global DRF pagination (heuristic)",
            message=(
                "Heuristic: DEFAULT_PAGINATION_CLASS is unset or empty in REST_FRAMEWORK, "
                f"while static analysis found {len(hits)} possible list/router registrations "
                f"({', '.join(sorted({h[3] for h in hits}))}). "
                "Limitations: misses manual pagination, per-view pagination_class, "
                "non-DRF routers, and dynamic view assembly; may include tests and dead code."
            ),
            path=first_path,
            line=first_line,
            fix_hint=(
                "Enable default pagination and tune page size; align with permission, "
                "authentication, and throttling defaults:\n\n"
                + _REST_FRAMEWORK_SNIPPET_WITH_PAGINATION
            ),
        )
    ]


def run_drf_security_rules(ctx: dict[str, Any]) -> Iterable[Finding]:
    """DRF security checks (require Django settings context)."""
    if not ctx.get("loaded"):
        return []
    if not ctx.get("drf_installed"):
        return []
    if ctx.get("debug"):
        return []

    findings: list[Finding] = []

    perms = ctx.get("drf_default_permission_classes")
    if perms is None:
        findings.append(
            Finding(
                rule_id="DJG020",
                severity="HIGH",
                title="DEFAULT_PERMISSION_CLASSES missing (DRF defaults to AllowAny)",
                message=(
                    "REST_FRAMEWORK does not set DEFAULT_PERMISSION_CLASSES. "
                    "Django REST Framework then defaults to AllowAny, exposing "
                    "views unless each view sets permission_classes."
                ),
                fix_hint=(
                    "Set explicit defaults in settings, e.g.:\n\n"
                    "REST_FRAMEWORK = {\n"
                    '    "DEFAULT_PERMISSION_CLASSES": [\n'
                    '        "rest_framework.permissions.IsAuthenticated",\n'
                    "    ],\n"
                    "}\n"
                ),
            )
        )
    elif len(perms) == 0:
        findings.append(
            Finding(
                rule_id="DJG020",
                severity="HIGH",
                title="DEFAULT_PERMISSION_CLASSES is empty",
                message=(
                    "DEFAULT_PERMISSION_CLASSES is set to an empty sequence, which "
                    "is effectively permissive and can leave API endpoints unprotected."
                ),
                fix_hint=(
                    "Use at least one permission class, e.g. IsAuthenticated or "
                    "DjangoModelPermissions.\n"
                ),
            )
        )
    elif any(_is_allow_any_permission(p) for p in perms):
        findings.append(
            Finding(
                rule_id="DJG020",
                severity="HIGH",
                title="DEFAULT_PERMISSION_CLASSES includes AllowAny",
                message=(
                    "rest_framework.permissions.AllowAny allows unauthenticated "
                    "access to any view that does not override permission_classes."
                ),
                fix_hint=(
                    "Replace AllowAny with a restrictive default (e.g. IsAuthenticated) "
                    "and opt-in to AllowAny only on specific public views.\n"
                ),
            )
        )

    auth = ctx.get("drf_default_authentication_classes")
    if auth is None:
        findings.append(
            Finding(
                rule_id="DJG021",
                severity="HIGH",
                title="DEFAULT_AUTHENTICATION_CLASSES missing",
                message=(
                    "REST_FRAMEWORK does not set DEFAULT_AUTHENTICATION_CLASSES. "
                    "Without explicit defaults, authentication behavior relies on "
                    "DRF built-ins and per-view classes, which is easy to misconfigure."
                ),
                fix_hint=(
                    "Declare authentication explicitly, e.g.:\n\n"
                    "REST_FRAMEWORK = {\n"
                    '    "DEFAULT_AUTHENTICATION_CLASSES": [\n'
                    '        "rest_framework.authentication.SessionAuthentication",\n'
                    '        "rest_framework.authentication.TokenAuthentication",\n'
                    "    ],\n"
                    "}\n"
                ),
            )
        )

    throttle = ctx.get("drf_default_throttle_classes")
    if throttle is None or len(throttle) == 0:
        findings.append(
            Finding(
                rule_id="DJG022",
                severity="WARN",
                title="API throttling disabled globally",
                message=(
                    "DEFAULT_THROTTLE_CLASSES is missing or empty, so no global "
                    "rate limiting applies unless each view sets throttle_classes."
                ),
                fix_hint=(
                    "Enable default throttling and rates, e.g.:\n\n"
                    "REST_FRAMEWORK = {\n"
                    '    "DEFAULT_THROTTLE_CLASSES": [\n'
                    '        "rest_framework.throttling.UserRateThrottle",\n'
                    '        "rest_framework.throttling.AnonRateThrottle",\n'
                    "    ],\n"
                    '    "DEFAULT_THROTTLE_RATES": {"user": "1000/day", "anon": "100/day"},\n'
                    "}\n"
                ),
            )
        )

    findings.extend(_djg023_auth_like_routes_without_global_throttle(ctx))
    findings.extend(_djg024_serializers_all_fields_sensitive(ctx))
    findings.extend(_djg025_list_endpoints_without_pagination(ctx))

    return findings
