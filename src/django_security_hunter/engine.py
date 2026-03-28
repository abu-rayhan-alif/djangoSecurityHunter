from __future__ import annotations

from pathlib import Path

from .config import GuardConfig, load_config
from .models import Report
from .rules.concurrency import run_concurrency_rules
from .rules.dependency_audit import run_dependency_audit_rules
from .rules.django_settings import run_django_settings_scan
from .rules.authz_heuristics import run_authz_heuristic_rules
from .rules.drf_auth_urls import run_drf_auth_url_rules
from .rules.drf_security import run_drf_security_rules
from .rules.external_scanners import run_external_scanner_rules
from .rules.model_integrity import run_model_integrity_rules
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
    findings.extend(run_drf_security_rules(dj_ctx))
    findings.extend(run_drf_auth_url_rules(project_root, dj_ctx))
    findings.extend(run_authz_heuristic_rules(project_root))
    findings.extend(run_static_pattern_rules(project_root, cfg))
    findings.extend(run_model_integrity_rules(project_root, cfg))
    findings.extend(run_concurrency_rules(project_root, cfg))
    findings.extend(run_dependency_audit_rules(project_root, cfg))
    findings.extend(run_external_scanner_rules(project_root, cfg))

    metadata: dict = {
        "project_root": str(project_root),
        "settings_module": settings_module,
        "runner": "django-settings-scan",
        "django_settings_loaded": bool(dj_ctx.get("loaded")),
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


def run_profile(
    project_root: Path,
    settings_module: str | None = None,
    cfg: GuardConfig | None = None,
) -> Report:
    cfg = cfg or load_config(project_root)
    findings, profile_bundle = run_profiling_rules(project_root, settings_module, cfg)
    profile = profile_bundle.get("profile") or {}
    runtime = profile.get("query_runtime", "none")

    metadata: dict = {
        "project_root": str(project_root),
        "settings_module": settings_module,
        "runner": f"profile-static+{runtime}",
    }
    metadata.update(profile_bundle)
    return Report(mode="profile", metadata=metadata, findings=findings)
