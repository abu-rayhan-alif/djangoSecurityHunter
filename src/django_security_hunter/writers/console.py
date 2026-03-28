from __future__ import annotations

from django_security_hunter.models import Report
from django_security_hunter.output import as_console


def write_console(report: Report) -> str:
    return as_console(report)


