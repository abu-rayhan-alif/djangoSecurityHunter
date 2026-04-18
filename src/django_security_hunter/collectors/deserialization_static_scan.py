from __future__ import annotations

import ast
from pathlib import Path

from django_security_hunter.collectors.project_files import (
    iter_project_glob,
    read_py_source,
)

_SAFE_LOADER_ATTRS = frozenset({"SafeLoader", "CSafeLoader"})


def _is_safe_loader_expr(node: ast.expr) -> bool:
    if isinstance(node, ast.Name) and node.id in _SAFE_LOADER_ATTRS:
        return True
    if isinstance(node, ast.Attribute) and node.attr in _SAFE_LOADER_ATTRS:
        return True
    return False


def _yaml_load_uses_safe_loader(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "Loader" and _is_safe_loader_expr(kw.value):
            return True
    if len(call.args) >= 2 and _is_safe_loader_expr(call.args[1]):
        return True
    return False


def _insecure_deserialization_hit(
    node: ast.Call,
) -> tuple[str, str] | None:
    """
    Return ``(kind_id, label)`` if this call is a risky deserialization, else None.
    Only matches explicit ``pickle.*`` / ``yaml.*`` attribute calls (no import aliases).
    """
    func = node.func
    if not isinstance(func, ast.Attribute):
        return None
    if not isinstance(func.value, ast.Name):
        return None
    mod = func.value.id
    name = func.attr

    if mod == "pickle" and name in ("load", "loads"):
        return (f"pickle_{name}", f"pickle.{name}")

    if mod != "yaml":
        return None

    if name in ("safe_load", "safe_load_all"):
        return None
    if name in ("unsafe_load", "unsafe_load_all"):
        return (f"yaml_{name}", f"yaml.{name}")
    if name in ("load", "load_all"):
        if _yaml_load_uses_safe_loader(node):
            return None
        return (f"yaml_{name}_unsafe_loader", f"yaml.{name}")

    return None


def scan_insecure_deserialization_hits(
    project_root: Path,
) -> list[tuple[str, int, str, str]]:
    """(file, line, kind id, label) for insecure deserialization patterns."""
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
            hit = _insecure_deserialization_hit(node)
            if hit:
                kind, label = hit
                hits.append((str(py_path), node.lineno, kind, label))

    return hits
