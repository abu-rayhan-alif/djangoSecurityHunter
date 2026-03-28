from __future__ import annotations

from pathlib import Path

from .config import GuardConfig, load_config
from .models import Report
from .rules.concurrency import run_concurrency_rules
from .rules.django_settings import run_django_settings_scan
from .rules.drf_security import run_drf_security_rules
from .rules.external_integrations import run_external_integration_findings
from .rules.profiling import run_profiling_rules
from .rules.static_patterns import run_static_pattern_rules


def run_scan(
    project_root: Path,
    settings_module: str | None = None,
    cfg: GuardConfig | None = None,
) -> Report:
    cfg = cfg or load_config(project_root)
    findings = []
    dj_findings, dj_ctx = run_django_settings_scan(project_root, settings_module)
    findings.extend(dj_findings)
    findings.extend(run_drf_security_rules())
    findings.extend(run_static_pattern_rules())
    findings.extend(run_concurrency_rules())

    ext_findings, integrations_meta = run_external_integration_findings(
        project_root, cfg
    )
    findings.extend(ext_findings)

    metadata: dict = {
        "project_root": str(project_root),
        "settings_module": settings_module,
        "runner": "django-settings-scan",
        "django_settings_loaded": bool(dj_ctx.get("loaded")),
        "integrations": integrations_meta,
    }
    err_detail: str | None = None
    if not dj_ctx.get("loaded"):
        if sr := dj_ctx.get("skip_reason"):
            metadata["django_settings_skip_reason"] = sr
        if err := dj_ctx.get("load_error"):
            err_detail = str(err).replace("\n", " ").strip()[:400]

    return Report(
        mode="scan",
        metadata=metadata,
        findings=findings,
        settings_load_error_detail=err_detail,
    )


def run_profile(project_root: Path, settings_module: str | None = None) -> Report:
    findings = []
    findings.extend(run_profiling_rules())

    metadata = {
        "project_root": str(project_root),
        "settings_module": settings_module,
        "runner": "runtime-profile-skeleton",
    }
    return Report(mode="profile", metadata=metadata, findings=findings)
