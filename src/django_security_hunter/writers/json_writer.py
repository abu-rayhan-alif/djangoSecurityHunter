from __future__ import annotations

from django_security_hunter.models import Report
from django_security_hunter.output import as_json


def write_json(report: Report) -> str:
    return as_json(report)



