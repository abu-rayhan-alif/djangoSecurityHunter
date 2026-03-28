from __future__ import annotations

from pathlib import Path

from .models import Report
from .rules.concurrency import run_concurrency_rules
from .rules.django_settings import run_django_settings_rules
from .rules.drf_security import run_drf_security_rules
from .rules.profiling import run_profiling_rules
from .rules.static_patterns import run_static_pattern_rules


def run_scan(project_root: Path, settings_module: str | None = None) -> Report:
    findings = []
    findings.extend(run_django_settings_rules(project_root, settings_module))
    findings.extend(run_drf_security_rules())
    findings.extend(run_static_pattern_rules())
    findings.extend(run_concurrency_rules())

    metadata = {
        "project_root": str(project_root),
        "settings_module": settings_module,
        "runner": "django-settings-scan",
    }
    return Report(mode="scan", metadata=metadata, findings=findings)


def run_profile(project_root: Path, settings_module: str | None = None) -> Report:
    findings = []
    findings.extend(run_profiling_rules())

    metadata = {
        "project_root": str(project_root),
        "settings_module": settings_module,
        "runner": "runtime-profile-skeleton",
    }
    return Report(mode="profile", metadata=metadata, findings=findings)
