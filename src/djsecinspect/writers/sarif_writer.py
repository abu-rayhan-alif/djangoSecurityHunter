from __future__ import annotations

from djsecinspect.models import Report
from djsecinspect.output import as_sarif


def write_sarif(report: Report) -> str:
    return as_sarif(report)


