"""Package identity for JSON/SARIF outputs (DJG-9)."""

from __future__ import annotations

# Bump only when the JSON report shape changes incompatibly.
REPORT_JSON_SCHEMA_VERSION = "django_security_hunter.report.v1"

# Repository / docs home for SARIF tool driver and README links.
INFORMATION_URI = "https://github.com/abu-rayhan-alif/djangoGuard"


def package_version() -> str:
    try:
        from importlib.metadata import version

        return version("django-security-hunter")
    except Exception:
        return "0.1.0"
