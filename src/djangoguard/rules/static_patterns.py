from __future__ import annotations

from pathlib import Path
from typing import Iterable

from djangoguard.collectors.deserialization_static_scan import (
    scan_insecure_deserialization_hits,
)
from djangoguard.collectors.secrets_and_logging_scan import (
    scan_hardcoded_secret_hits,
    scan_sensitive_logging_hits,
)
from djangoguard.collectors.ssrf_static_scan import scan_ssrf_risk_hits
from djangoguard.collectors.xss_static_scan import scan_xss_risk_hits
from djangoguard.models import Finding


def run_static_pattern_rules(project_root: Path) -> Iterable[Finding]:
    """Static security patterns (DJG070+)."""
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
    return findings

