from __future__ import annotations

from djsecinspect.models import Report
from djsecinspect.output import as_console


def write_console(report: Report) -> str:
    return as_console(report)


