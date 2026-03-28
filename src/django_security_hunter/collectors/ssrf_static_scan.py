from __future__ import annotations

import ast
from pathlib import Path

from django_security_hunter.collectors.drf_static_scan import (
    _iter_project_glob,
    _read_py_source,
)

_HTTP_METHODS = frozenset(
    {"get", "post", "put", "delete", "patch", "head", "options", "request"}
)

# Django/DRF request surface often tied to user input.
_REQUEST_LIKE_ATTRS = frozenset({"GET", "POST", "FILES", "data", "query_params", "body"})

# Variable names that often carry user-supplied or external URLs.
_HIGH_HINT_NAMES = frozenset(
    {
        "webhook_url",
        "callback_url",
        "redirect_uri",
        "redirect_url",
        "target_url",
        "user_url",
        "external_url",
        "fetch_url",
        "destination_url",
    }
)


def _requests_httpx_http_call(func: ast.expr) -> tuple[str, str] | None:
    """Return ``(library, method)`` for ``requests.*`` / ``httpx.*`` HTTP helpers."""
    if not isinstance(func, ast.Attribute):
        return None
    if func.attr not in _HTTP_METHODS:
        return None
    if not isinstance(func.value, ast.Name):
        return None
    if func.value.id not in ("requests", "httpx"):
        return None
    return (func.value.id, func.attr)


def _url_expression(call: ast.Call, method: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == "url":
            return kw.value
    if method == "request":
        if len(call.args) >= 2:
            return call.args[1]
        return None
    if len(call.args) >= 1:
        return call.args[0]
    return None


def _is_static_url_literal(node: ast.expr) -> bool:
    """True if URL is a fixed string (no interpolation from variables)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                return False
        return True
    return False


def _url_expr_high_risk(node: ast.expr) -> bool:
    """Heuristic: URL likely user-controlled or externally supplied."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in _HIGH_HINT_NAMES:
            return True
        if not isinstance(child, ast.Attribute):
            continue
        if child.attr not in _REQUEST_LIKE_ATTRS:
            continue
        base = child.value
        if isinstance(base, ast.Name) and base.id in ("request", "req"):
            return True
        if isinstance(base, ast.Attribute) and base.attr == "request":
            return True
    return False


def scan_ssrf_risk_hits(
    project_root: Path,
) -> list[tuple[str, int, str, str, str]]:
    """(file, line, severity, kind id, label) for SSRF-style outbound HTTP heuristics."""
    hits: list[tuple[str, int, str, str, str]] = []

    for py_path in _iter_project_glob(project_root, "*.py"):
        if "migrations" in py_path.parts:
            continue
        source = _read_py_source(py_path)
        if source is None:
            continue
        try:
            tree = ast.parse(source, filename=str(py_path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            parsed = _requests_httpx_http_call(node.func)
            if not parsed:
                continue
            lib, method = parsed
            url_expr = _url_expression(node, method)
            if url_expr is None:
                continue
            if _is_static_url_literal(url_expr):
                continue
            sev = "HIGH" if _url_expr_high_risk(url_expr) else "WARN"
            label = f"{lib}.{method}"
            kind = f"{lib}_{method}_dynamic_url"
            hits.append((str(py_path), node.lineno, sev, kind, label))

    return hits
