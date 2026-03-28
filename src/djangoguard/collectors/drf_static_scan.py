from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable

# Per-file cap to limit memory use on pathological huge .py files (DoS hardening).
_MAX_PY_SOURCE_BYTES = 2 * 1024 * 1024  # 2 MiB


def _read_py_source(path: Path) -> str | None:
    """Read UTF-8 Python source, or None if missing, oversized, or invalid UTF-8."""
    try:
        with path.open("rb") as f:
            data = f.read(_MAX_PY_SOURCE_BYTES + 1)
    except OSError:
        return None
    if len(data) > _MAX_PY_SOURCE_BYTES:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".venv",
        "venv",
        "node_modules",
        ".eggs",
        ".tox",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
    }
)


def _line_looks_like_auth_url(line: str) -> bool:
    s = line.strip()
    if "path(" not in s and "re_path(" not in s:
        return False
    low = s.lower()
    for needle in (
        "token",
        "login",
        "logout",
        "password",
        "reset",
        "obtain",
        "jwt",
        "oauth",
        "/auth",
        "auth/",
        "authenticate",
    ):
        if needle in low:
            return True
    return False


# Model names / substrings that suggest sensitive data with fields="__all__"
_SENSITIVE_HIGH = re.compile(
    r"(user|password|token|secret|payment|card|credential|oauth|session|auth|mfa|otp)",
    re.IGNORECASE,
)
_SENSITIVE_WARN = re.compile(
    r"(profile|account|customer|subscription|billing|address|wallet)",
    re.IGNORECASE,
)


def _iter_project_glob(project_root: Path, pattern: str) -> Iterable[Path]:
    """Yield files matching ``pattern`` under project_root (symlink-safe, skips junk dirs)."""
    root = project_root.resolve()
    for p in root.rglob(pattern):
        try:
            resolved = p.resolve()
        except OSError:
            continue
        try:
            if not resolved.is_relative_to(root):
                continue
        except ValueError:
            continue
        if "site-packages" in resolved.parts:
            continue
        if any(part in _SKIP_DIR_NAMES for part in resolved.parts):
            continue
        yield resolved


def _iter_project_py_files(project_root: Path) -> Iterable[Path]:
    """Yield *.py files under project_root only (resolved paths; skips symlink escapes)."""
    yield from _iter_project_glob(project_root, "*.py")


def scan_auth_like_url_hits(project_root: Path) -> list[tuple[str, int, str]]:
    """(file path, 1-based line, stripped line) for auth-like URL registrations."""
    hits: list[tuple[str, int, str]] = []
    for py_path in _iter_project_py_files(project_root):
        text = _read_py_source(py_path)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _line_looks_like_auth_url(line):
                hits.append((str(py_path), lineno, line.strip()[:500]))
    return hits


def _assign_target_names(stmt: ast.Assign) -> list[str]:
    names: list[str] = []
    for t in stmt.targets:
        if isinstance(t, ast.Name):
            names.append(t.id)
    return names


def _str_constant_value(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _expr_simple_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id
    return None


def _meta_fields_all_and_model(meta: ast.ClassDef) -> tuple[bool, str | None]:
    fields_all = False
    model_hint: str | None = None
    for stmt in meta.body:
        if isinstance(stmt, ast.Assign):
            names = _assign_target_names(stmt)
            if "fields" in names:
                val = _str_constant_value(stmt.value)
                if val == "__all__":
                    fields_all = True
            if "model" in names:
                model_hint = _expr_simple_name(stmt.value)
    return fields_all, model_hint


def scan_serializers_fields_all_sensitive(
    project_root: Path,
) -> list[tuple[str, int, str, str, str]]:
    """file, line, class_name, model_hint, severity (HIGH|WARN)."""
    results: list[tuple[str, int, str, str, str]] = []
    for py_path in _iter_project_py_files(project_root):
        if "migrations" in py_path.parts:
            continue
        source = _read_py_source(py_path)
        if source is None:
            continue
        try:
            tree = ast.parse(source, filename=str(py_path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or not node.name.endswith(
                "Serializer"
            ):
                continue
            for item in node.body:
                if not isinstance(item, ast.ClassDef) or item.name != "Meta":
                    continue
                fa, model_hint = _meta_fields_all_and_model(item)
                if not fa:
                    continue
                mh = model_hint or ""
                sev: str | None = None
                if _SENSITIVE_HIGH.search(mh) or _SENSITIVE_HIGH.search(node.name):
                    sev = "HIGH"
                elif _SENSITIVE_WARN.search(mh) or _SENSITIVE_WARN.search(node.name):
                    sev = "WARN"
                if sev:
                    results.append(
                        (
                            str(py_path),
                            node.lineno,
                            node.name,
                            mh,
                            sev,
                        )
                    )
    return results


_LIST_BASE_TO_KIND: dict[str, str] = {
    "ModelViewSet": "MODEL_VIEWSET",
    "ReadOnlyModelViewSet": "READONLY_VIEWSET",
    "ListAPIView": "LIST_API",
    "ListCreateAPIView": "LIST_CREATE",
    "ListModelMixin": "LIST_MIXIN",
}

# Strongest base wins when a class lists multiple list-style bases (avoid double-counting).
_LIST_KIND_PRIORITY: dict[str, int] = {
    "MODEL_VIEWSET": 50,
    "READONLY_VIEWSET": 40,
    "LIST_CREATE": 30,
    "LIST_API": 20,
    "LIST_MIXIN": 10,
}


def _class_base_tail(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _line_looks_like_router_register(line: str) -> bool:
    s = line.strip()
    if ".register(" not in s:
        return False
    low = s.lower()
    return "router" in low


def _best_list_kind_for_classdef(classdef: ast.ClassDef) -> str | None:
    best: str | None = None
    best_pri = -1
    for base in classdef.bases:
        tail = _class_base_tail(base)
        if not tail:
            continue
        kind = _LIST_BASE_TO_KIND.get(tail)
        if not kind:
            continue
        pri = _LIST_KIND_PRIORITY.get(kind, 0)
        if pri > best_pri:
            best_pri = pri
            best = kind
    return best


def scan_drf_list_endpoint_hits(
    project_root: Path,
) -> list[tuple[str, int, str, str]]:
    """file, 1-based line, class_or_router, kind (MODEL_VIEWSET|...|ROUTER_REGISTER)."""
    hits: list[tuple[str, int, str, str]] = []
    for py_path in _iter_project_py_files(project_root):
        if "migrations" in py_path.parts:
            continue
        text = _read_py_source(py_path)
        if text is None:
            continue
        resolved = str(py_path)
        tree: ast.AST | None = None
        try:
            tree = ast.parse(text, filename=str(py_path))
        except (SyntaxError, UnicodeDecodeError):
            tree = None

        if tree is not None:
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                kind = _best_list_kind_for_classdef(node)
                if kind:
                    hits.append((resolved, node.lineno, node.name, kind))

        for lineno, line in enumerate(text.splitlines(), start=1):
            if _line_looks_like_router_register(line):
                label = "router_register"
                hits.append((resolved, lineno, label, "ROUTER_REGISTER"))

    return hits
