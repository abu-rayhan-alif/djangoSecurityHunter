from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable

from django_security_hunter.collectors.ast_scanner import iter_python_files
from django_security_hunter.models import Finding


def _expr_is_allow_any(node: ast.expr) -> bool:
    if isinstance(node, ast.Name) and node.id == "AllowAny":
        return True
    if isinstance(node, ast.Attribute) and node.attr == "AllowAny":
        return True
    return False


def _iterable_contains_allow_any(node: ast.expr) -> bool:
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(_expr_is_allow_any(elt) for elt in node.elts)
    if _expr_is_allow_any(node):
        return True
    return False


def _class_looks_like_drf_view(bases: list[ast.expr]) -> bool:
    for b in bases:
        name = ""
        if isinstance(b, ast.Name):
            name = b.id
        elif isinstance(b, ast.Attribute):
            name = b.attr
        else:
            continue
        if "APIView" in name or name.endswith("ViewSet") or "GenericAPIView" in name:
            return True
    return False


def _scan_classdef(node: ast.ClassDef, rel: str, findings: list[Finding]) -> None:
    if not _class_looks_like_drf_view(node.bases):
        return
    for stmt in node.body:
        if not isinstance(stmt, ast.Assign):
            continue
        for target in stmt.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id != "permission_classes":
                continue
            if _iterable_contains_allow_any(stmt.value):
                findings.append(
                    Finding(
                        rule_id="DJG027",
                        severity="WARN",
                        title="DRF view sets permission_classes to AllowAny",
                        message=(
                            f"Class {node.name!r} uses AllowAny; unauthenticated clients may "
                            "access this endpoint unless other layers enforce auth."
                        ),
                        path=rel,
                        line=stmt.lineno,
                        fix_hint=(
                            "Use IsAuthenticated, custom permissions, or document as intentionally "
                            "public; avoid accidental AllowAny on sensitive routes.\n"
                        ),
                    )
                )
                return


def run_authz_heuristic_rules(project_root: Path) -> Iterable[Finding]:
    """Best-effort DRF per-view AllowAny detection (not a full authorization audit)."""
    findings: list[Finding] = []
    root = project_root.resolve()
    for path in iter_python_files(project_root):
        try:
            src = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            tree = ast.parse(src, filename=str(path))
        except SyntaxError:
            continue
        rel = str(path.relative_to(root))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                _scan_classdef(node, rel, findings)
    return findings
