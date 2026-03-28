from __future__ import annotations

from djsecinspect.models import Report
from djsecinspect.output import as_json


def write_json(report: Report) -> str:
    return as_json(report)


