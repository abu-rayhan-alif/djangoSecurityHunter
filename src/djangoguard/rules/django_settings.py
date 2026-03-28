from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from djangoguard.collectors.settings_loader import load_settings_context
from djangoguard.models import Finding

_MIN_SECRET_KEY_LEN = 40

# One year — common production minimum / HSTS preload guidance
_HSTS_RECOMMENDED_SECONDS = 31_536_000

_WEAK_SECRET_KEYS = frozenset(
    {
        "changeme",
        "secret",
        "password",
        "admin",
        "test",
        "django",
    }
)


def _djg001_debug(ctx: dict) -> list[Finding]:
    if not ctx.get("debug"):
        return []
    return [
        Finding(
            rule_id="DJG001",
            severity="CRITICAL",
            title="DEBUG is enabled",
            message=(
                "Django DEBUG=True is unsafe in production: verbose errors leak "
                "implementation details and may expose secrets."
            ),
            fix_hint=(
                "Use an environment flag and default to False in production.\n\n"
                'DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() in '
                '("1", "true", "yes")\n'
            ),
        )
    ]


def _djg002_secret_key(ctx: dict) -> list[Finding]:
    key = (ctx.get("secret_key") or "").strip()
    reason: str | None = None
    if not key:
        reason = "SECRET_KEY is empty or not set."
    elif len(key) < _MIN_SECRET_KEY_LEN:
        reason = (
            f"SECRET_KEY is too short ({len(key)} characters). "
            f"Use a long, unpredictable value (typically {_MIN_SECRET_KEY_LEN}+ characters)."
        )
    elif key.startswith("django-insecure-"):
        reason = (
            "SECRET_KEY uses Django's insecure development prefix (django-insecure-). "
            "Generate a unique secret for each environment and load it from the environment "
            "or a secrets manager, not from source control."
        )
    elif key.casefold() in _WEAK_SECRET_KEYS:
        reason = "SECRET_KEY is a common placeholder value and is trivial to guess."
    elif len(key) > 5 and len(set(key)) == 1:
        reason = "SECRET_KEY has no entropy (repeated single character)."

    if reason is None:
        return []
    return [
        Finding(
            rule_id="DJG002",
            severity="HIGH",
            title="SECRET_KEY is hardcoded or suspicious (weak / dev-style)",
            message=(
                "A weak or development-style SECRET_KEY lets attackers forge sessions "
                "and signed tokens. " + reason
            ),
            fix_hint=(
                "Generate a strong secret and inject it at runtime, e.g.:\n\n"
                'SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]\n\n'
                "Never commit production secrets to the repository."
            ),
        )
    ]


def _djg003_allowed_hosts(ctx: dict) -> list[Finding]:
    raw = ctx.get("allowed_hosts")
    hosts: list[str] = list(raw) if isinstance(raw, list) else []
    has_wildcard = any(h.strip() == "*" for h in hosts)
    is_empty = len(hosts) == 0

    if not is_empty and not has_wildcard:
        return []

    parts: list[str] = []
    if is_empty:
        parts.append(
            "ALLOWED_HOSTS is empty, so Django rejects hosts in production and the "
            "deployment is easy to misconfigure."
        )
    if has_wildcard:
        parts.append(
            "ALLOWED_HOSTS contains '*', which accepts any Host header and enables "
            "HTTP Host header attacks and cache poisoning."
        )
    message = " ".join(parts)

    return [
        Finding(
            rule_id="DJG003",
            severity="HIGH",
            title="ALLOWED_HOSTS is wildcard or empty",
            message=message,
            fix_hint=(
                "List explicit hostnames (and your service domain), e.g.:\n\n"
                'ALLOWED_HOSTS = ["api.example.com", "www.example.com"]\n\n'
                "Derive from environment in production; never use ['*'] outside local DEBUG."
            ),
        )
    ]


def _djg004_secure_ssl_redirect(ctx: dict) -> list[Finding]:
    if ctx.get("debug"):
        return []
    if ctx.get("secure_ssl_redirect"):
        return []
    return [
        Finding(
            rule_id="DJG004",
            severity="HIGH",
            title="SECURE_SSL_REDIRECT is false or missing",
            message=(
                "HTTP requests are not redirected to HTTPS, so sessions and cookies may "
                "travel over cleartext. SECURE_SSL_REDIRECT is False or unset (Django "
                "defaults to False)."
            ),
            fix_hint=(
                "Enable when the app is served over HTTPS (or TLS terminates at a proxy):\n\n"
                'SECURE_SSL_REDIRECT = True\n'
                'SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")\n'
            ),
        )
    ]


def _coerce_hsts_seconds(ctx: dict) -> int:
    raw = ctx.get("hsts_seconds")
    if raw is None:
        return 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _djg005_hsts_seconds(ctx: dict) -> list[Finding]:
    if ctx.get("debug"):
        return []
    seconds = _coerce_hsts_seconds(ctx)
    if seconds <= 0:
        return [
            Finding(
                rule_id="DJG005",
                severity="HIGH",
                title="SECURE_HSTS_SECONDS missing or zero",
                message=(
                    "Strict-Transport-Security is not sent (Django default is 0), so browsers "
                    "will not remember to use HTTPS only for this site."
                ),
                fix_hint=(
                    "Set a long max-age once the site is fully HTTPS-only, e.g.:\n\n"
                    "SECURE_HSTS_SECONDS = 31536000  # 1 year\n"
                    "SECURE_HSTS_INCLUDE_SUBDOMAINS = True\n"
                    "SECURE_HSTS_PRELOAD = True  # optional; requires correct rollout\n"
                ),
            )
        ]
    if seconds < _HSTS_RECOMMENDED_SECONDS:
        return [
            Finding(
                rule_id="DJG005",
                severity="WARN",
                title="SECURE_HSTS_SECONDS is low",
                message=(
                    f"SECURE_HSTS_SECONDS is {seconds} seconds; many deployments use at "
                    f"least {_HSTS_RECOMMENDED_SECONDS} (one year) for production and "
                    "preload eligibility."
                ),
                fix_hint=(
                    "Increase gradually after verifying HTTPS everywhere:\n\n"
                    "SECURE_HSTS_SECONDS = 31536000\n"
                ),
            )
        ]
    return []


def _djg006_session_cookie_secure(ctx: dict) -> list[Finding]:
    if ctx.get("debug"):
        return []
    if ctx.get("session_cookie_secure"):
        return []
    return [
        Finding(
            rule_id="DJG006",
            severity="HIGH",
            title="SESSION_COOKIE_SECURE is false or missing",
            message=(
                "The session cookie can be sent over HTTP, exposing session IDs to "
                "network attackers. SESSION_COOKIE_SECURE is False or unset (Django "
                "defaults to False)."
            ),
            fix_hint=(
                "Enable when the site is served over HTTPS:\n\n"
                "SESSION_COOKIE_SECURE = True\n"
            ),
        )
    ]


def _djg007_csrf_cookie_secure(ctx: dict) -> list[Finding]:
    if ctx.get("debug"):
        return []
    if ctx.get("csrf_cookie_secure"):
        return []
    return [
        Finding(
            rule_id="DJG007",
            severity="HIGH",
            title="CSRF_COOKIE_SECURE is false or missing",
            message=(
                "The CSRF cookie can be sent over HTTP, weakening CSRF protection on "
                "mixed or downgraded connections. CSRF_COOKIE_SECURE is False or unset "
                "(Django defaults to False)."
            ),
            fix_hint=(
                "Enable when the site is served over HTTPS:\n\n"
                "CSRF_COOKIE_SECURE = True\n"
            ),
        )
    ]


def _djg008_content_type_nosniff(ctx: dict) -> list[Finding]:
    if ctx.get("debug"):
        return []
    if ctx.get("secure_content_type_nosniff"):
        return []
    return [
        Finding(
            rule_id="DJG008",
            severity="WARN",
            title="SECURE_CONTENT_TYPE_NOSNIFF is disabled or missing",
            message=(
                "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff "
                "responses and increase XSS risk. SECURE_CONTENT_TYPE_NOSNIFF is False "
                "or unset."
            ),
            fix_hint=(
                "Enable Django's SecurityMiddleware behavior:\n\n"
                "SECURE_CONTENT_TYPE_NOSNIFF = True\n"
            ),
        )
    ]


def _djg009_x_frame_options(ctx: dict) -> list[Finding]:
    if ctx.get("debug"):
        return []
    raw = ctx.get("x_frame_options")
    v = str(raw).strip().upper() if raw is not None else ""
    if v == "DENY":
        return []
    if not v or v == "ALLOWALL" or v in {"SAMEORIGIN", "EXEMPT"}:
        label = v or "empty"
        return [
            Finding(
                rule_id="DJG009",
                severity="WARN",
                title="X_FRAME_OPTIONS is missing or weak",
                message=(
                    f"Clickjacking protection is weak: X_FRAME_OPTIONS is {label!s}. "
                    "Prefer DENY unless you intentionally embed this app in frames."
                ),
                fix_hint=(
                    "Use the strictest policy that fits your UX:\n\n"
                    'X_FRAME_OPTIONS = "DENY"\n'
                ),
            )
        ]
    return [
        Finding(
            rule_id="DJG009",
            severity="WARN",
            title="X_FRAME_OPTIONS is missing or weak",
            message=(
                f"Unrecognized X_FRAME_OPTIONS value {raw!r}; verify clickjacking "
                "middleware behavior."
            ),
            fix_hint='Use "DENY" or "SAMEORIGIN" explicitly.\n',
        )
    ]


def _csrf_origin_local_http_ok(origin: str) -> bool:
    lo = origin.lower().rstrip("/")
    for prefix in ("http://localhost", "http://127.0.0.1", "http://[::1]"):
        if lo == prefix or lo.startswith(prefix + ":") or lo.startswith(prefix + "/"):
            return True
    return False


def _csrf_origin_trailing_path_slash(origin: str) -> bool:
    try:
        p = urlparse(origin)
    except ValueError:
        return False
    return bool(p.scheme and p.netloc and p.path == "/")


def _djg010_csrf_trusted_origins(ctx: dict) -> list[Finding]:
    if ctx.get("debug"):
        return []
    raw = ctx.get("csrf_trusted_origins")
    origins: list[str] = list(raw) if isinstance(raw, list) else []
    high_bits: list[str] = []
    warn_bits: list[str] = []
    for o in origins:
        s = o.strip()
        if not s:
            warn_bits.append("empty CSRF_TRUSTED_ORIGINS entry")
            continue
        if "*" in s:
            high_bits.append(f"wildcard in origin {s!r}")
        if not s.startswith(("http://", "https://")):
            warn_bits.append(f"{s!r} must be a full origin with scheme")
            continue
        if s.startswith("http://") and not _csrf_origin_local_http_ok(s):
            warn_bits.append(f"non-HTTPS origin {s!r} is risky in production")
        if _csrf_origin_trailing_path_slash(s):
            warn_bits.append(f"{s!r} should not end with a trailing slash (no path)")
    if not high_bits and not warn_bits:
        return []
    severity = "HIGH" if high_bits else "WARN"
    parts = high_bits + warn_bits
    return [
        Finding(
            rule_id="DJG010",
            severity=severity,
            title="CSRF_TRUSTED_ORIGINS is misconfigured",
            message="Issues: " + "; ".join(parts),
            fix_hint=(
                "Use full HTTPS origins without paths, e.g.:\n\n"
                'CSRF_TRUSTED_ORIGINS = ["https://app.example.com"]\n'
            ),
        )
    ]


def _djg011_cors_allow_all(ctx: dict) -> list[Finding]:
    if ctx.get("debug") or not ctx.get("cors_active"):
        return []
    if not ctx.get("cors_allow_all_origins"):
        return []
    return [
        Finding(
            rule_id="DJG011",
            severity="HIGH",
            title="CORS_ALLOW_ALL_ORIGINS is True (django-cors-headers)",
            message=(
                "Any website can read responses from this API in the browser, which "
                "often leaks private data. CORS_ALLOW_ALL_ORIGINS must be False in "
                "production when django-cors-headers is active."
            ),
            fix_hint=(
                "Replace with an explicit allow-list:\n\n"
                'CORS_ALLOW_ALL_ORIGINS = False\n'
                'CORS_ALLOWED_ORIGINS = ["https://app.example.com"]\n'
            ),
        )
    ]


def _cors_regex_overly_permissive(pattern: str) -> bool:
    p = pattern.strip()
    if not p:
        return False
    core = p.strip("^$")
    if core in {".*", ".+", "*"}:
        return True
    if p in {"^.*$", "^.+$", ".*", ".+"}:
        return True
    return False


def _cors_origin_permissive(origin: str) -> bool:
    s = origin.strip()
    return s == "*" or "*" in s


def _djg012_cors_permissive_allowlist(ctx: dict) -> list[Finding]:
    if ctx.get("debug") or not ctx.get("cors_active"):
        return []
    if ctx.get("cors_allow_all_origins"):
        return []
    origins_raw = ctx.get("cors_allowed_origins")
    origins: list[str] = list(origins_raw) if isinstance(origins_raw, list) else []
    regex_raw = ctx.get("cors_allowed_origin_regexes")
    regexes: list[str] = list(regex_raw) if isinstance(regex_raw, list) else []
    high_bits: list[str] = []
    warn_bits: list[str] = []
    for o in origins:
        if _cors_origin_permissive(o):
            high_bits.append(f"overly broad CORS_ALLOWED_ORIGINS entry {o!r}")
        elif o.strip().startswith("http://") and not _csrf_origin_local_http_ok(o):
            warn_bits.append(f"HTTP (non-local) origin {o!r} in CORS_ALLOWED_ORIGINS")
    for rx in regexes:
        if _cors_regex_overly_permissive(rx):
            high_bits.append(f"overly permissive CORS regex {rx!r}")
    if not high_bits and not warn_bits:
        return []
    severity = "HIGH" if high_bits else "WARN"
    parts = high_bits + warn_bits
    return [
        Finding(
            rule_id="DJG012",
            severity=severity,
            title="CORS allow-list or regexes are too permissive",
            message="Issues: " + "; ".join(parts),
            fix_hint=(
                "Prefer explicit https:// origins and tight regexes; avoid wildcards "
                "and catch-all patterns.\n"
            ),
        )
    ]


def run_django_settings_scan(
    project_root: Path, settings_module: str | None = None
) -> tuple[list[Finding], dict[str, Any]]:
    ctx = load_settings_context(project_root, settings_module)
    if not ctx.get("loaded"):
        return [], ctx
    findings: list[Finding] = []
    findings.extend(_djg001_debug(ctx))
    findings.extend(_djg002_secret_key(ctx))
    findings.extend(_djg003_allowed_hosts(ctx))
    findings.extend(_djg004_secure_ssl_redirect(ctx))
    findings.extend(_djg005_hsts_seconds(ctx))
    findings.extend(_djg006_session_cookie_secure(ctx))
    findings.extend(_djg007_csrf_cookie_secure(ctx))
    findings.extend(_djg008_content_type_nosniff(ctx))
    findings.extend(_djg009_x_frame_options(ctx))
    findings.extend(_djg010_csrf_trusted_origins(ctx))
    findings.extend(_djg011_cors_allow_all(ctx))
    findings.extend(_djg012_cors_permissive_allowlist(ctx))
    ctx.pop("secret_key", None)
    return findings, ctx


def run_django_settings_rules(
    project_root: Path, settings_module: str | None = None
) -> Iterable[Finding]:
    findings, _ = run_django_settings_scan(project_root, settings_module)
    return findings
