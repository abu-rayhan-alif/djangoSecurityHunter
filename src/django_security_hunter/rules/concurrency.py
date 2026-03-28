from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable

from django_security_hunter.collectors.ast_scanner import iter_python_files
from django_security_hunter.config import GuardConfig
from django_security_hunter.models import Finding


def _for_loop_target_names(node: ast.expr) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Tuple):
        out: set[str] = set()
        for elt in node.elts:
            out |= _for_loop_target_names(elt)
        return out
    return set()


def _is_f_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id == "F":
            return True
        if isinstance(fn, ast.Attribute) and fn.attr == "F":
            return True
    return False


def _chain_has_objects_manager(expr: ast.expr) -> bool:
    cur: ast.expr | None = expr
    while isinstance(cur, ast.Call):
        fn = cur.func
        if isinstance(fn, ast.Attribute):
            if fn.attr == "objects":
                return True
            cur = fn.value
            continue
        break
    return isinstance(cur, ast.Attribute) and cur.attr == "objects"


def _orm_queryset_iter_terminal(expr: ast.expr) -> str | None:
    cur: ast.expr | None = expr
    last: str | None = None
    while isinstance(cur, ast.Call):
        fn = cur.func
        if isinstance(fn, ast.Attribute):
            last = fn.attr
            cur = fn.value
            continue
        break
    if last not in {"all", "filter", "exclude", "iterator"}:
        return None
    return last if _chain_has_objects_manager(expr) else None


def _chain_has_select_for_update(expr: ast.expr) -> bool:
    cur: ast.expr | None = expr
    while isinstance(cur, ast.Call):
        fn = cur.func
        if isinstance(fn, ast.Attribute):
            if fn.attr == "select_for_update":
                return True
            cur = fn.value
            continue
        break
    return False


def _expr_has_binop_without_f(node: ast.expr) -> bool:
    if not any(isinstance(n, ast.BinOp) for n in ast.walk(node)):
        return False
    return not any(_is_f_call(n) for n in ast.walk(node))


def _expr_chain_contains_objects(expr: ast.expr) -> bool:
    seen: set[int] = set()
    cur: ast.expr | None = expr
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, ast.Attribute):
            if cur.attr == "objects":
                return True
            cur = cur.value
            continue
        if isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            cur = cur.func.value
            continue
        break
    return False


def _call_is_orm_get(node: ast.Call) -> bool:
    fn = node.func
    if not isinstance(fn, ast.Attribute) or fn.attr != "get":
        return False
    return _expr_chain_contains_objects(fn.value)


def _body_has_orm_get(stmts: list[ast.stmt]) -> bool:
    for st in stmts:
        for n in ast.walk(st):
            if isinstance(n, ast.Call) and _call_is_orm_get(n):
                return True
    return False


def _djg050_fix_hint() -> str:
    return (
        "Use get_or_create with a unique constraint, "
        "or IntegrityError handling, or select_for_update inside transaction.atomic(). "
        "For HTTP APIs, idempotency keys help make retries safe without duplicate rows.\n"
    )


def _djg052_scan_for(
    node: ast.For, rel_path: str, findings: list[Finding], enclosing: set[str]
) -> None:
    names = _for_loop_target_names(node.target) | enclosing
    if _orm_queryset_iter_terminal(node.iter) and not _chain_has_select_for_update(
        node.iter
    ):
        _djg052_scan_save_in_loop_body(node, rel_path, findings, names)
    for stmt in node.body:
        if isinstance(stmt, ast.For):
            _djg052_scan_for(stmt, rel_path, findings, names)
        else:
            _djg052_scan_statement(stmt, rel_path, findings, names)
    for stmt in node.orelse:
        if isinstance(stmt, ast.For):
            _djg052_scan_for(stmt, rel_path, findings, names)
        else:
            _djg052_scan_statement(stmt, rel_path, findings, names)


def _djg052_scan_save_in_loop_body(
    for_node: ast.For,
    rel_path: str,
    findings: list[Finding],
    loop_names: set[str],
) -> None:
    for stmt in for_node.body + for_node.orelse:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.For):
                continue
            if not isinstance(sub, ast.Call) or not isinstance(sub.func, ast.Attribute):
                continue
            if sub.func.attr != "save":
                continue
            if not isinstance(sub.func.value, ast.Name):
                continue
            if sub.func.value.id not in loop_names:
                continue
            findings.append(
                Finding(
                    rule_id="DJG052",
                    severity="WARN",
                    title="save() in ORM loop without select_for_update()",
                    message=(
                        "Iterating a queryset and calling .save() on each row without "
                        "select_for_update() can race with concurrent writers."
                    ),
                    path=rel_path,
                    line=sub.lineno,
                    fix_hint=(
                        "Use queryset.select_for_update() inside transaction.atomic(), or "
                        "bulk_update / F() patterns.\n"
                    ),
                )
            )
            return


def _djg052_scan_statement(
    stmt: ast.stmt, rel_path: str, findings: list[Finding], loop_names: set[str]
) -> None:
    for sub in ast.walk(stmt):
        if isinstance(sub, ast.For):
            continue
        if not isinstance(sub, ast.AugAssign) or not isinstance(sub.op, ast.Add):
            continue
        tgt = sub.target
        if not isinstance(tgt, ast.Attribute):
            continue
        if not isinstance(tgt.value, ast.Name) or tgt.value.id not in loop_names:
            continue
        if _is_f_call(sub.value):
            continue
        findings.append(
            Finding(
                rule_id="DJG052",
                severity="WARN",
                title="Increment on loop variable attribute without F()",
                message=(
                    "A loop updates an attribute on an ORM instance with +=; concurrent "
                    "workers can race. Prefer F() updates, select_for_update(), or atomic SQL."
                ),
                path=rel_path,
                line=sub.lineno,
                fix_hint=(
                    "Use queryset.update(count=F('count') + 1) or select_for_update inside "
                    "transaction.atomic().\n"
                ),
            )
        )


def _djg052_scan_update_binop_without_f(
    tree: ast.AST, rel_path: str, findings: list[Finding]
) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "update":
            continue
        for kw in node.keywords:
            if kw.arg is None:
                continue
            if _expr_has_binop_without_f(kw.value):
                findings.append(
                    Finding(
                        rule_id="DJG052",
                        severity="WARN",
                        title="QuerySet.update() with arithmetic may need F()",
                        message=(
                            f"Keyword {kw.arg!r} uses a binary expression without F(); "
                            "concurrent updates can lose increments."
                        ),
                        path=rel_path,
                        line=node.lineno,
                        fix_hint=(
                            "Use F('field') in update expressions, e.g. "
                            "Model.objects.filter(...).update(n=F('n') + 1).\n"
                        ),
                    )
                )
                break


def _run_djg052_on_tree(tree: ast.AST, rel_path: str, findings: list[Finding]) -> None:
    _djg052_scan_update_binop_without_f(tree, rel_path, findings)
    for stmt in getattr(tree, "body", []):
        _djg052_walk_stmt(stmt, rel_path, findings, set())


def _djg052_walk_stmt(
    stmt: ast.stmt, rel_path: str, findings: list[Finding], enclosing: set[str]
) -> None:
    if isinstance(stmt, ast.For):
        _djg052_scan_for(stmt, rel_path, findings, enclosing)
        return
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for s in stmt.body:
            _djg052_walk_stmt(s, rel_path, findings, enclosing)
        return
    if isinstance(stmt, ast.ClassDef):
        for s in stmt.body:
            _djg052_walk_stmt(s, rel_path, findings, enclosing)
        return
    if isinstance(stmt, ast.If):
        for s in stmt.body:
            _djg052_walk_stmt(s, rel_path, findings, enclosing)
        for s in stmt.orelse:
            _djg052_walk_stmt(s, rel_path, findings, enclosing)
        return
    if isinstance(stmt, ast.With):
        for s in stmt.body:
            _djg052_walk_stmt(s, rel_path, findings, enclosing)
        for s in stmt.orelse:
            _djg052_walk_stmt(s, rel_path, findings, enclosing)
        return
    if isinstance(stmt, ast.Try):
        for s in stmt.body:
            _djg052_walk_stmt(s, rel_path, findings, enclosing)
        for h in stmt.handlers:
            for s in h.body:
                _djg052_walk_stmt(s, rel_path, findings, enclosing)
        for s in stmt.orelse + stmt.finalbody:
            _djg052_walk_stmt(s, rel_path, findings, enclosing)
        return
    if isinstance(stmt, ast.Match):
        for case in stmt.cases:
            for s in case.body:
                _djg052_walk_stmt(s, rel_path, findings, enclosing)
        return


def _is_atomic_context_expr(expr: ast.expr) -> bool:
    if not isinstance(expr, ast.Call):
        return False
    fn = expr.func
    if isinstance(fn, ast.Attribute) and fn.attr == "atomic":
        if isinstance(fn.value, ast.Name) and fn.value.id == "transaction":
            return True
        if isinstance(fn.value, ast.Attribute) and fn.value.attr == "transaction":
            return True
    if isinstance(fn, ast.Name) and fn.id == "atomic":
        return True
    return False


def _block_has_transaction_atomic(stmts: list[ast.stmt]) -> bool:
    for st in stmts:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(st, ast.With):
            for item in st.items:
                if _is_atomic_context_expr(item.context_expr):
                    return True
            if _block_has_transaction_atomic(st.body):
                return True
            if _block_has_transaction_atomic(st.orelse):
                return True
        elif isinstance(st, ast.If):
            if _block_has_transaction_atomic(st.body) or _block_has_transaction_atomic(
                st.orelse
            ):
                return True
        elif isinstance(st, (ast.For, ast.While)):
            if _block_has_transaction_atomic(st.body + st.orelse):
                return True
        elif isinstance(st, ast.Try):
            parts = list(st.body) + list(st.orelse) + list(st.finalbody)
            for h in st.handlers:
                parts.extend(h.body)
            if _block_has_transaction_atomic(parts):
                return True
        elif isinstance(st, ast.Match):
            for case in st.cases:
                if _block_has_transaction_atomic(case.body):
                    return True
        elif isinstance(st, ast.ClassDef):
            for it in st.body:
                if isinstance(it, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if _function_has_transaction_atomic(it):
                        return True
    return False


def _function_has_transaction_atomic(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return _block_has_transaction_atomic(list(fn.body))


def _count_saves_in_stmt_list(stmts: list[ast.stmt]) -> int:
    n = 0
    for st in stmts:
        n += _count_saves_in_stmt(st)
    return n


def _count_saves_in_stmt(st: ast.stmt) -> int:
    if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return 0
    if isinstance(st, ast.If):
        return _count_saves_in_stmt_list(st.body) + _count_saves_in_stmt_list(st.orelse)
    if isinstance(st, ast.With):
        return _count_saves_in_stmt_list(st.body) + _count_saves_in_stmt_list(st.orelse)
    if isinstance(st, (ast.For, ast.While)):
        return _count_saves_in_stmt_list(st.body) + _count_saves_in_stmt_list(st.orelse)
    if isinstance(st, ast.Try):
        total = _count_saves_in_stmt_list(st.body)
        total += _count_saves_in_stmt_list(st.orelse)
        total += _count_saves_in_stmt_list(st.finalbody)
        for h in st.handlers:
            total += _count_saves_in_stmt_list(h.body)
        return total
    if isinstance(st, ast.Match):
        total = 0
        for case in st.cases:
            total += _count_saves_in_stmt_list(case.body)
        return total
    n = 0
    for sub in ast.walk(st):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
            if sub.func.attr == "save":
                n += 1
    return n


def _djg051_for_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    rel: str,
    high_threshold: int,
) -> list[Finding]:
    n = _count_saves_in_stmt_list(list(fn.body))
    if n < 2:
        return []
    if _function_has_transaction_atomic(fn):
        return []
    sev = "HIGH" if n >= high_threshold else "WARN"
    return [
        Finding(
            rule_id="DJG051",
            severity=sev,
            title="Multiple .save() calls without transaction.atomic",
            message=(
                f"Function {fn.name!r} has {n} .save() calls with no transaction.atomic() "
                "in this function; partial writes may leave inconsistent state on errors."
            ),
            path=rel,
            line=fn.lineno,
            fix_hint=(
                "Group related writes in transaction.atomic(); consider bulk operations. "
                "Use idempotency keys for external side effects.\n"
            ),
        )
    ]


def _iter_functions(tree: ast.AST) -> Iterable[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _djg051_scan_tree(tree: ast.AST, rel: str, high_threshold: int) -> list[Finding]:
    findings: list[Finding] = []
    for fn in _iter_functions(tree):
        findings.extend(_djg051_for_function(fn, rel, high_threshold))
    return findings


class _ConcurrencyVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str, findings: list[Finding]) -> None:
        self.rel_path = rel_path
        self.findings = findings

    def visit_If(self, node: ast.If) -> None:
        if _if_has_exists_call(node.test):
            for branch in (node.body, node.orelse):
                if (
                    branch
                    and _stmts_have_objects_create(branch)
                    and not _stmts_have_get_or_create(branch)
                ):
                    self.findings.append(
                        Finding(
                            rule_id="DJG050",
                            severity="WARN",
                            title="Possible check-then-act race (exists + create)",
                            message=(
                                "Pattern uses .exists() (or similar) near .objects.create() "
                                "without atomic DB constraint; concurrent requests can "
                                "duplicate rows."
                            ),
                            path=self.rel_path,
                            line=node.lineno,
                            fix_hint=_djg050_fix_hint(),
                        )
                    )
                    break
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        if _body_has_orm_get(node.body):
            for h in node.handlers:
                if (
                    h.body
                    and _stmts_have_objects_create(h.body)
                    and not _stmts_have_get_or_create(h.body)
                ):
                    self.findings.append(
                        Finding(
                            rule_id="DJG050",
                            severity="WARN",
                            title="Possible check-then-act race (get + create in try/except)",
                            message=(
                                "Pattern uses .get() in try with .objects.create() in except; "
                                "concurrent requests can still create duplicates."
                            ),
                            path=self.rel_path,
                            line=node.lineno,
                            fix_hint=_djg050_fix_hint(),
                        )
                    )
                    break
        self.generic_visit(node)


def _if_has_exists_call(node: ast.expr) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if n.func.attr == "exists":
                return True
    return False


def _stmts_have_objects_create(stmts: list[ast.stmt]) -> bool:
    for stmt in stmts:
        for n in ast.walk(stmt):
            if not isinstance(n, ast.Call):
                continue
            fn = n.func
            if not isinstance(fn, ast.Attribute) or fn.attr != "create":
                continue
            if isinstance(fn.value, ast.Attribute) and fn.value.attr == "objects":
                return True
    return False


def _stmts_have_get_or_create(stmts: list[ast.stmt]) -> bool:
    for stmt in stmts:
        for n in ast.walk(stmt):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                if n.func.attr == "get_or_create":
                    return True
    return False


def run_concurrency_rules(
    project_root: Path, cfg: GuardConfig | None = None
) -> Iterable[Finding]:
    cfg = cfg or GuardConfig()
    findings: list[Finding] = []
    root = project_root.resolve()
    high_th = max(2, cfg.djg051_high_save_threshold)
    for path in iter_python_files(project_root):
        rel = str(path.relative_to(root))
        try:
            src = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            tree = ast.parse(src, filename=str(path))
        except SyntaxError:
            continue
        findings.extend(_djg051_scan_tree(tree, rel, high_th))
        _run_djg052_on_tree(tree, rel, findings)
        _ConcurrencyVisitor(rel, findings).visit(tree)
    return findings
