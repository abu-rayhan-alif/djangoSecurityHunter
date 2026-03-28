from __future__ import annotations

from django_security_hunter.models import Report
from django_security_hunter.output import as_sarif


def write_sarif(report: Report) -> str:
    return as_sarif(report)

