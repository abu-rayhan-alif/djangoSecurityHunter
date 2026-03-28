"""Heuristic Django model schema checks (natural keys, on_delete=CASCADE)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from django_security_hunter.collectors.project_files import (
    iter_project_py_files,
    read_py_source,
)

# --- DJG080: natural key / identifier fields without uniqueness ---

_HIGH_NATURAL_FIELD = re.compile(
    r"(^|_)(email|slug|username)$|_email$|_slug$|^email$|^slug$|^username$",
    re.IGNORECASE,
)

_WARN_NATURAL_SUBSTR = (
    "external_id",
    "externalid",
    "reference_id",
    "client_reference",
    "api_key",
    "public_id",
    "sku",
)

_FIELD_TYPES_STRICT = frozenset(
    {"EmailField", "SlugField"}
)


def _call_bool_kw(call: ast.Call, name: str) -> bool | None:
    """True / False if set, None if absent."""
    for kw in call.keywords:
        if kw.arg != name:
            continue
        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, bool):
            return kw.value.value
    return None


def _field_is_explicitly_unique(call: ast.Call) -> bool:
    if _call_bool_kw(call, "primary_key") is True:
        return True
    if _call_bool_kw(call, "unique") is True:
        return True
    return False


def _field_factory_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _djg080_severity_for_charlike(
    field_name: str, factory: str | None
) -> str | None:
    if factory in _FIELD_TYPES_STRICT:
        return "HIGH"
    if factory not in ("CharField", "TextField", "UUIDField"):
        return None
    fn = field_name.lower()
    if _HIGH_NATURAL_FIELD.search(field_name) or fn in (
        "email",
        "slug",
        "username",
    ):
        return "HIGH"
    for sub in _WARN_NATURAL_SUBSTR:
        if sub in fn:
            return "WARN"
    if factory == "UUIDField":
        return "WARN"
    return None


def _class_inherits_model(class_node: ast.ClassDef) -> bool:
    for base in class_node.bases:
        if isinstance(base, ast.Attribute) and base.attr == "Model":
            return True
        if isinstance(base, ast.Name) and base.id == "Model":
            return True
    return False


def _class_meta_abstract(class_node: ast.ClassDef) -> bool:
    for node in class_node.body:
        if not isinstance(node, ast.ClassDef) or node.name != "Meta":
            continue
        for stmt in node.body:
            if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
                continue
            if not isinstance(stmt.targets[0], ast.Name):
                continue
            if stmt.targets[0].id != "abstract":
                continue
            if isinstance(stmt.value, ast.Constant) and stmt.value.value is True:
                return True
    return False


def _iter_model_field_assignments(
    class_node: ast.ClassDef,
) -> list[tuple[str, ast.Call, int]]:
    out: list[tuple[str, ast.Call, int]] = []
    for node in class_node.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            if isinstance(t, ast.Name) and isinstance(node.value, ast.Call):
                out.append((t.id, node.value, node.lineno))
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and isinstance(node.value, ast.Call)
        ):
            out.append((node.target.id, node.value, node.lineno))
    return out


def scan_djg080_natural_key_hits(project_root: Path) -> list[tuple[str, int, str, str, str, str]]:
    """path, line, severity, model, field, factory."""
    hits: list[tuple[str, int, str, str, str, str]] = []
    for py_path in iter_project_py_files(project_root):
        source = read_py_source(py_path)
        if source is None:
            continue
        try:
            tree = ast.parse(source, filename=str(py_path))
        except SyntaxError:
            continue
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            if not _class_inherits_model(node):
                continue
            if _class_meta_abstract(node):
                continue
            for fname, call, lineno in _iter_model_field_assignments(node):
                factory = _field_factory_name(call) or ""
                if _field_is_explicitly_unique(call):
                    continue
                sev = _djg080_severity_for_charlike(fname, factory)
                if not sev:
                    continue
                hits.append(
                    (
                        str(py_path),
                        lineno,
                        sev,
                        node.name,
                        fname,
                        factory,
                    )
                )
    return hits


# --- DJG081: CASCADE toward critical / high-value related models ---

_CASCADE_RELATED_SUBSTR = (
    "payment",
    "order",
    "invoice",
    "subscription",
    "transaction",
    "wallet",
    "payout",
    "refund",
    "account",
    "user",
    "customer",
    "audit",
)

# Related model hints to skip (framework / generic joins).
_DJG081_IGNORE_RELATED = frozenset(
    {
        "contenttype",
        "contenttypes",
        "permission",
        "group",
        "session",
        "migration",
    }
)


def _first_arg_string(call: ast.Call) -> str:
    if not call.args:
        return ""
    a0 = call.args[0]
    if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
        return a0.value
    if isinstance(a0, ast.Name):
        return a0.id
    if isinstance(a0, ast.Attribute):
        parts: list[str] = []
        cur: ast.expr = a0
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _is_cascade_on_delete(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg != "on_delete":
            continue
        val = kw.value
        if isinstance(val, ast.Attribute) and val.attr == "CASCADE":
            return True
        if isinstance(val, ast.Name) and val.id == "CASCADE":
            return True
    return False


def _djg081_related_tokens(related: str) -> frozenset[str]:
    """Split model path like ``app.Model`` into lowercase tokens (avoids ``order``⊂``ordering``)."""
    low = related.lower().replace('"', "").replace("'", "")
    parts = re.split(r"[\s._]+", low)
    return frozenset(p for p in parts if p)


def _djg081_related_is_flaggable(related: str) -> bool:
    low = related.lower().replace('"', "").replace("'", "")
    if not low:
        return False
    for ign in _DJG081_IGNORE_RELATED:
        if ign in low:
            return False
    tokens = _djg081_related_tokens(related)
    return any(s in tokens for s in _CASCADE_RELATED_SUBSTR)


def scan_djg081_cascade_hits(project_root: Path) -> list[tuple[str, int, str, str, str]]:
    """path, line, model, field, related_hint."""
    hits: list[tuple[str, int, str, str, str]] = []
    for py_path in iter_project_py_files(project_root):
        source = read_py_source(py_path)
        if source is None:
            continue
        try:
            tree = ast.parse(source, filename=str(py_path))
        except SyntaxError:
            continue
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            if not _class_inherits_model(node):
                continue
            if _class_meta_abstract(node):
                continue
            for fname, call, lineno in _iter_model_field_assignments(node):
                fac = _field_factory_name(call) or ""
                if fac not in ("ForeignKey", "OneToOneField"):
                    continue
                if not _is_cascade_on_delete(call):
                    continue
                rel = _first_arg_string(call)
                if not _djg081_related_is_flaggable(rel):
                    continue
                hits.append((str(py_path), lineno, node.name, fname, rel))
    return hits
