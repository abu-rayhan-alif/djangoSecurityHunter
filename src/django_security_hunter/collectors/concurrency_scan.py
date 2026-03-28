"""Heuristics for ORM concurrency / transaction discipline (DJG050–DJG052)."""

from __future__ import annotations

import ast
from pathlib import Path

from django_security_hunter.collectors.project_files import iter_project_py_files, read_py_source

_STOCK_LIKE_FIELDS = frozenset(
    {
        "quantity",
        "stock",
        "slots",
        "balance",
        "inventory",
        "counter",
        "available",
        "reserved",
        "seat_count",
        "quota",
        "remaining",
    }
)


def _chain_has_objects(expr: ast.expr) -> bool:
    cur: ast.expr | None = expr
    while isinstance(cur, ast.Attribute):
        if cur.attr == "objects":
            return True
        cur = cur.value
    return False


def _is_queryset_exists(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "exists":
        return False
    return _looks_like_orm_queryset_expr(call.func.value)


def _is_orm_create_like(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr not in ("create", "get_or_create", "update_or_create"):
        return False
    return _chain_has_objects(call.func.value)


def _is_orm_bulk_write(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr not in ("bulk_create", "bulk_update"):
        return False
    return _chain_has_objects(call.func.value)


def _is_queryset_update_or_delete(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr not in ("update", "delete"):
        return False
    v = call.func.value
    return _looks_like_orm_queryset_expr(v)


def _looks_like_orm_queryset_expr(expr: ast.expr) -> bool:
    if _chain_has_objects(expr):
        return True
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        return _looks_like_orm_queryset_expr(expr.func.value)
    return False


def _is_instance_save(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "save":
        return False
    v = call.func.value
    if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute):
        if v.func.attr in ("open", "write_text", "mkdir", "makedirs"):
            return False
    return True


def _count_orm_writes_in_function(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    n = 0
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        if (
            _is_orm_create_like(node)
            or _is_orm_bulk_write(node)
            or _is_queryset_update_or_delete(node)
            or _is_instance_save(node)
        ):
            n += 1
    return n


def _function_has_atomic_guard(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for deco in fn.decorator_list:
        if _expr_is_atomic(deco):
            return True
        if isinstance(deco, ast.Call) and _expr_is_atomic(deco.func):
            return True
    for node in ast.walk(fn):
        if isinstance(node, ast.With):
            for item in node.items:
                if _expr_is_atomic(item.context_expr):
                    return True
    return False


def _expr_is_atomic(expr: ast.expr) -> bool:
    if isinstance(expr, ast.Name) and expr.id == "atomic":
        return True
    if isinstance(expr, ast.Attribute) and expr.attr == "atomic":
        return True
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        if expr.func.attr == "atomic":
            return True
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
        if expr.func.id == "atomic":
            return True
    return False


def _suite_has_create(stmts: list[ast.stmt]) -> bool:
    for s in stmts:
        for n in ast.walk(s):
            if isinstance(n, ast.Call) and _is_orm_create_like(n):
                return True
    return False


def _if_check_exists_then_create(node: ast.If, following: list[ast.stmt]) -> bool:
    if not any(
        isinstance(sub, ast.Call) and _is_queryset_exists(sub) for sub in ast.walk(node.test)
    ):
        return False
    if _suite_has_create(node.body) or _suite_has_create(node.orelse):
        return True
    return any(_suite_has_create([s]) for s in following)


def _parents_in_function(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}

    def visit(n: ast.AST, par: ast.AST | None) -> None:
        if par is not None:
            parents[n] = par
        for c in ast.iter_child_nodes(n):
            if isinstance(c, ast.AST):
                visit(c, n)

    visit(fn, None)
    return parents


def _stmt_list_containing(parent: ast.AST, stmt: ast.stmt) -> list[ast.stmt] | None:
    for name in ("body", "orelse", "finalbody"):
        if hasattr(parent, name):
            block = getattr(parent, name)
            if isinstance(block, list) and stmt in block:
                return block
    if isinstance(parent, ast.Try):
        for h in parent.handlers:
            if stmt in h.body:
                return h.body
    if isinstance(parent, ast.Match):
        for case in parent.cases:
            if stmt in case.body:
                return case.body
    return None


def _following_stmts(stmt: ast.stmt, parents: dict[ast.AST, ast.AST]) -> list[ast.stmt]:
    parent = parents.get(stmt)
    if parent is None:
        return []
    block = _stmt_list_containing(parent, stmt)
    if block is None:
        return []
    try:
        idx = block.index(stmt)
    except ValueError:
        return []
    return block[idx + 1:]


def _tree_has_f_call(root: ast.AST) -> bool:
    for n in ast.walk(root):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "F":
            return True
    return False


def _field_name_from_target(t: ast.expr) -> str | None:
    if isinstance(t, ast.Attribute):
        return t.attr.lower()
    if isinstance(t, ast.Name):
        return t.id.lower()
    return None


def _assign_stock_risk(node: ast.Assign | ast.AugAssign) -> bool:
    if isinstance(node, ast.AugAssign):
        name = _field_name_from_target(node.target)
        if name not in _STOCK_LIKE_FIELDS:
            return False
        return not _tree_has_f_call(node.value)

    for t in node.targets:
        name = _field_name_from_target(t)
        if name not in _STOCK_LIKE_FIELDS:
            continue
        if _tree_has_f_call(node.value):
            continue
        if isinstance(node.value, ast.BinOp):
            return True
        if isinstance(node.value, ast.Call):
            if not _tree_has_f_call(node.value):
                return True
    return False


def scan_concurrency_findings(project_root: Path) -> list[tuple[str, str, int, str, str]]:
    """(rule_id, path, line, severity, message_or_kind)."""
    hits: list[tuple[str, str, int, str, str]] = []
    for py_path in iter_project_py_files(project_root):
        src = read_py_source(py_path)
        if src is None:
            continue
        try:
            tree = ast.parse(src, filename=str(py_path))
        except SyntaxError:
            continue
        path_s = str(py_path)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                hits.extend(_scan_function(node, path_s))
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        hits.extend(_scan_function(item, path_s))
    return hits


def _scan_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef, path_s: str
) -> list[tuple[str, str, int, str, str]]:
    out: list[tuple[str, str, int, str, str]] = []
    parents = _parents_in_function(fn)
    for child in ast.walk(fn):
        if isinstance(child, ast.If) and _if_check_exists_then_create(
            child, _following_stmts(child, parents)
        ):
            out.append(
                (
                    "DJG050",
                    path_s,
                    child.lineno,
                    "WARN",
                    "check_then_create",
                )
            )

    writes = _count_orm_writes_in_function(fn)
    if writes >= 2 and not _function_has_atomic_guard(fn):
        out.append(
            (
                "DJG051",
                path_s,
                fn.lineno,
                "HIGH" if writes >= 3 else "WARN",
                f"{writes}_orm_writes_no_atomic",
            )
        )

    for child in ast.walk(fn):
        if isinstance(child, ast.Assign):
            if _assign_stock_risk(child):
                out.append(
                    (
                        "DJG052",
                        path_s,
                        child.lineno,
                        "WARN",
                        "stock_like_assign_no_f",
                    )
                )
        elif isinstance(child, ast.AugAssign):
            if _assign_stock_risk(child):
                out.append(
                    (
                        "DJG052",
                        path_s,
                        child.lineno,
                        "WARN",
                        "stock_like_augassign_no_f",
                    )
                )
    return out
