from __future__ import annotations

from djangoguard.models import Report
from djangoguard.output import as_sarif


def write_sarif(report: Report) -> str:
    return as_sarif(report)

