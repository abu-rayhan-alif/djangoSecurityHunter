from __future__ import annotations

from pathlib import Path
from typing import Iterable

from django_security_hunter.collectors.deserialization_static_scan import (
    scan_insecure_deserialization_hits,
)
from django_security_hunter.collectors.model_schema_scan import (
    scan_djg080_natural_key_hits,
    scan_djg081_cascade_hits,
)
from django_security_hunter.collectors.secrets_and_logging_scan import (
    scan_hardcoded_secret_hits,
    scan_sensitive_logging_hits,
)
from django_security_hunter.collectors.ssrf_static_scan import scan_ssrf_risk_hits
from django_security_hunter.collectors.xss_static_scan import scan_xss_risk_hits
from django_security_hunter.models import Finding


def run_static_pattern_rules(project_root: Path) -> Iterable[Finding]:
    """Static security (DJG070+) and data-integrity heuristics (DJG080+)."""
    findings: list[Finding] = []
    for path, line, kind, detail in scan_xss_risk_hits(project_root):
        findings.append(
            Finding(
                rule_id="DJG070",
                severity="HIGH",
                title="XSS-risky pattern (mark_safe, SafeString, |safe, autoescape off)",
                message=(
                    f"Heuristic: {detail} ({kind}). "
                    "Marking strings safe or disabling autoescape can allow XSS if "
                    "content is user-controlled."
                ),
                path=path,
                line=line,
                fix_hint=(
                    "Prefer django.utils.html.escape(), format_html(), or default "
                    "template autoescaping; never pass untrusted input through "
                    "mark_safe / |safe / autoescape off.\n"
                ),
            )
        )
    for path, line, sev, kind, label in scan_ssrf_risk_hits(project_root):
        findings.append(
            Finding(
                rule_id="DJG071",
                severity=sev,
                title="SSRF risk: dynamic URL passed to requests/httpx (heuristic)",
                message=(
                    f"Heuristic: {label} called with non-literal URL ({kind}). "
                    "Outbound requests to arbitrary URLs can enable SSRF if the URL "
                    "is user-controlled."
                ),
                path=path,
                line=line,
                fix_hint=(
                    "Allowlist permitted hosts/schemes, block private/link-local IPs, "
                    "and avoid passing user-controlled URLs directly to HTTP clients.\n"
                ),
            )
        )
    for path, line, kind, label in scan_insecure_deserialization_hits(project_root):
        findings.append(
            Finding(
                rule_id="DJG072",
                severity="HIGH",
                title="Insecure deserialization (pickle/yaml)",
                message=(
                    f"Heuristic: {label} ({kind}). "
                    "Deserializing untrusted data with pickle or unsafe YAML loaders "
                    "can lead to arbitrary code execution."
                ),
                path=path,
                line=line,
                fix_hint=(
                    "Avoid pickle on untrusted bytes; use json/msgpack with schema "
                    "validation. For YAML, use yaml.safe_load or yaml.load(..., "
                    "Loader=yaml.SafeLoader).\n"
                ),
            )
        )
    for path, line, kind in scan_sensitive_logging_hits(project_root):
        findings.append(
            Finding(
                rule_id="DJG073",
                severity="HIGH",
                title="Sensitive data may be logged (heuristic)",
                message=(
                    f"Heuristic: logging call ({kind}) references identifiers that "
                    "often hold secrets (password, token, api key, etc.). "
                    "Secrets in logs can leak via log aggregation and backups."
                ),
                path=path,
                line=line,
                fix_hint=(
                    "Log only non-sensitive correlation IDs; redact or omit credential "
                    "fields; use structured logging with allowlisted keys; never log "
                    "headers such as Authorization or Cookie.\n"
                ),
            )
        )
    for path, line, sev, kind in scan_hardcoded_secret_hits(project_root):
        findings.append(
            Finding(
                rule_id="DJG074",
                severity=sev,
                title="Possible hardcoded secret in string literal (heuristic)",
                message=(
                    f"Heuristic match ({kind}). "
                    "Embedding credentials in source risks repository leaks and "
                    "bypasses secret rotation."
                ),
                path=path,
                line=line,
                fix_hint=(
                    "Load secrets from environment variables or a managed secret store "
                    "(e.g. vault); rotate exposed keys; add patterns to .gitignore "
                    "only after removal from history.\n"
                ),
            )
        )
    for path, line, sev, model, field, factory in scan_djg080_natural_key_hits(
        project_root
    ):
        findings.append(
            Finding(
                rule_id="DJG080",
                severity=sev,
                title="Natural key / identifier field may lack uniqueness (heuristic)",
                message=(
                    f"Model `{model}` field `{field}` ({factory}) has no unique=True / "
                    "primary_key=True. Duplicate natural keys cause subtle production bugs "
                    "(wrong row updates, flaky lookups)."
                ),
                path=path,
                line=line,
                fix_hint=(
                    f"On `{model}.{field}` add `unique=True`, or in `Meta.constraints` use "
                    f"`UniqueConstraint(fields=['{field}'], "
                    f"name='{model.lower()}_{field.lower()}_uniq')`, then migrate. "
                    "Add a DB index if you need uniqueness + fast lookup.\n"
                ),
            )
        )
    for path, line, model, field, related in scan_djg081_cascade_hits(project_root):
        findings.append(
            Finding(
                rule_id="DJG081",
                severity="WARN",
                title="Risky on_delete=CASCADE toward sensitive-looking related model (heuristic)",
                message=(
                    f"Model `{model}` field `{field}` uses CASCADE to `{related or '?'}`. "
                    "Deletes can cascade into money, identity, or audit-adjacent data."
                ),
                path=path,
                line=line,
                fix_hint=(
                    "Prefer `on_delete=models.PROTECT` or `SET_NULL` where retention matters; "
                    "use soft-delete patterns for audit. Framework joins (ContentType, etc.) "
                    "are ignored by default.\n"
                ),
            )
        )
    return findings
