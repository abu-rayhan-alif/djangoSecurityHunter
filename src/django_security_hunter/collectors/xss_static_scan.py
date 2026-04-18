from __future__ import annotations

import ast
import re
from pathlib import Path

from django_security_hunter.collectors.project_files import (
    iter_project_glob,
    read_py_source,
)

_RE_TEMPLATE_SAFE = re.compile(r"\|\s*safe\b")
_RE_AUTOESCAPE_OFF = re.compile(r"\{%\s*autoescape\s+off\s*%\}", re.IGNORECASE)


def _xss_risk_call_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name) and func.id in ("mark_safe", "SafeString"):
        return func.id
    if isinstance(func, ast.Attribute) and func.attr in ("mark_safe", "SafeString"):
        return func.attr
    return None


def scan_xss_risk_hits(project_root: Path) -> list[tuple[str, int, str, str]]:
    """(file, 1-based line, kind id, short label) for XSS-risk heuristics."""
    hits: list[tuple[str, int, str, str]] = []

    for py_path in iter_project_glob(project_root, "*.py"):
        if "migrations" in py_path.parts:
            continue
        source = read_py_source(py_path)
        if source is None:
            continue
        try:
            tree = ast.parse(source, filename=str(py_path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _xss_risk_call_name(node.func)
            if not name:
                continue
            hits.append(
                (
                    str(py_path),
                    node.lineno,
                    f"python_{name.lower()}",
                    name,
                )
            )

    for pattern in ("*.html", "*.htm", "*.djhtml"):
        for tpl_path in iter_project_glob(project_root, pattern):
            text = read_py_source(tpl_path)
            if text is None:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if _RE_TEMPLATE_SAFE.search(line):
                    hits.append(
                        (
                            str(tpl_path),
                            lineno,
                            "template_filter_safe",
                            "|safe",
                        )
                    )
                if _RE_AUTOESCAPE_OFF.search(line):
                    hits.append(
                        (
                            str(tpl_path),
                            lineno,
                            "template_autoescape_off",
                            "{% autoescape off %}",
                        )
                    )

    return hits
