from __future__ import annotations

from djangoguard.models import Report
from djangoguard.output import as_console


def write_console(report: Report) -> str:
    return as_console(report)

