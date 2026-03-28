from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable

from django_security_hunter.collectors.ast_scanner import iter_python_files
from django_security_hunter.config import GuardConfig
from django_security_hunter.models import Finding

# Heuristic “natural key” style field names that usually need uniqueness.
_NATURAL_FIELD_NAMES = frozenset(
    {
        "email",
        "slug",
        "username",
        "external_id",
        "sku",
        "code",
        "iban",
        "phone",
        "national_id",
    }
)

_FIELD_CALL_NAMES = frozenset(
    {"CharField", "EmailField", "SlugField", "TextField", "URLField"}
)

_AUDITISH_SUBSTR = ("Audit", "History", "Log", "Trail", "Event")


def _model_class_bases(bases: list[ast.expr]) -> bool:
    for b in bases:
        if isinstance(b, ast.Name) and b.id == "Model":
            return True
        if isinstance(b, ast.Attribute) and b.attr == "Model":
            return True
    return False


def _call_name(fn: ast.expr) -> str | None:
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return None


def _keyword_bool(call: ast.Call, name: str) -> bool | None:
    for kw in call.keywords:
        if kw.arg != name:
            continue
        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, bool):
            return kw.value.value
        if isinstance(kw.value, ast.Name):
            if kw.value.id in {"True", "False"}:
                return kw.value.id == "True"
    return None


def _is_cascade_on_delete(kw: ast.keyword) -> bool:
    if kw.arg != "on_delete":
        return False
    v = kw.value
    if isinstance(v, ast.Attribute) and v.attr == "CASCADE":
        return True
    return False


def _auditish_model(name: str) -> bool:
    return any(s in name for s in _AUDITISH_SUBSTR)


def run_model_integrity_rules(
    project_root: Path, cfg: GuardConfig | None = None
) -> Iterable[Finding]:
    """DJG080 / DJG081 — schema heuristics from model definitions."""
    cfg = cfg or GuardConfig()
    ignore_models = cfg.model_integrity_ignore_models
    findings: list[Finding] = []
    root = project_root.resolve()
    for path in iter_python_files(project_root):
        if "models" not in path.parts and path.name != "models.py":
            continue
        try:
            src = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            tree = ast.parse(src, filename=str(path))
        except SyntaxError:
            continue
        rel = str(path.relative_to(root))
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            if not _model_class_bases(node.bases):
                continue
            model_name = node.name
            for stmt in node.body:
                if not isinstance(stmt, ast.Assign):
                    continue
                for target in stmt.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    fname = target.id
                    val = stmt.value
                    if not isinstance(val, ast.Call):
                        continue
                    cname = _call_name(val.func)
                    if cname in _FIELD_CALL_NAMES and fname in _NATURAL_FIELD_NAMES:
                        uq = _keyword_bool(val, "unique")
                        if uq is True:
                            continue
                        findings.append(
                            Finding(
                                rule_id="DJG080",
                                severity="WARN",
                                title=f"Natural-key-like field {fname!r} may need unique=True",
                                message=(
                                    f"Model {model_name!r} defines {fname!r} as a "
                                    f"{_field_label(cname)} without unique=True; duplicates "
                                    "often cause subtle production bugs."
                                ),
                                path=rel,
                                line=stmt.lineno,
                                fix_hint=(
                                    "Add unique=True, a UniqueConstraint, or document why "
                                    "duplicates are safe.\n"
                                ),
                            )
                        )
                    if (
                        cname == "ForeignKey"
                        and _auditish_model(model_name)
                        and model_name not in ignore_models
                    ):
                        for kw in val.keywords:
                            if _is_cascade_on_delete(kw):
                                findings.append(
                                    Finding(
                                        rule_id="DJG081",
                                        severity="WARN",
                                        title="CASCADE FK on audit-ish model",
                                        message=(
                                            f"Model {model_name!r} field {fname!r} uses "
                                            "on_delete=CASCADE; cascading deletes on "
                                            "audit/log-style tables can destroy evidence."
                                        ),
                                        path=rel,
                                        line=stmt.lineno,
                                        fix_hint=(
                                            "Prefer PROTECT, SET_NULL, or a soft-delete strategy "
                                            "for audit data.\n"
                                        ),
                                    )
                                )
                                break
    return findings


def _field_label(cname: str) -> str:
    return cname.replace("Field", " field").lower()
