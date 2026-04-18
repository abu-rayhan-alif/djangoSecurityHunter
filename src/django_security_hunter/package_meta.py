"""Package identity for JSON/SARIF outputs (DJG-9)."""

from __future__ import annotations

# When importlib.metadata is unavailable (editable run without install), match pyproject.
_FALLBACK_PACKAGE_VERSION = "0.5.0"

# Bump only when the JSON report shape changes incompatibly.
REPORT_JSON_SCHEMA_VERSION = "django_security_hunter.report.v1"

# Repository / docs home for SARIF tool driver and README links.
INFORMATION_URI = "https://github.com/abu-rayhan-alif/djangoSecurityHunter"


def package_version() -> str:
    try:
        from importlib.metadata import version

        return version("django-security-hunter")
    except Exception:
        try:
            from django_security_hunter import __version__

            return str(__version__)
        except Exception:
            return _FALLBACK_PACKAGE_VERSION
