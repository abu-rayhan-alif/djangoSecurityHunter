from __future__ import annotations

from djangoguard.models import Report
from djangoguard.output import as_json


def write_json(report: Report) -> str:
    return as_json(report)

