from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from django_security_hunter.models import Finding

_AUTH_PATH_RE = re.compile(
    r"(login|signin|sign-in|logout|token|password|reset|oauth|refresh|auth|register|signup)",
    re.IGNORECASE,
)

_MAX_ROUTE_FINDINGS = 15


@dataclass
class _AuthRoute:
    pattern: str
    lineno: int
    view_expr: ast.expr


def _urls_py_files(project_root: Path) -> list[Path]:
    out: list[Path] = []
    root = project_root.resolve()
    if not root.is_dir():
        return out
    for p in root.rglob("*.py"):
        if p.name != "urls.py":
            continue
        parts = p.parts
        if ".venv" in parts or "venv" in parts or "node_modules" in parts:
            continue
        out.append(p)
    return sorted(out)


def _unwrap_as_view(node: ast.expr) -> ast.expr:
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr == "as_view":
            return fn.value
    return node


def _collect_auth_routes(tree: ast.AST, urls_file: Path) -> list[_AuthRoute]:
    routes: list[_AuthRoute] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = None
        if isinstance(fn, ast.Name):
            name = fn.id
        elif isinstance(fn, ast.Attribute):
            name = fn.attr
        if name not in {"path", "re_path"}:
            continue
        if len(node.args) < 2:
            continue
        pat = node.args[0]
        if not isinstance(pat, ast.Constant) or not isinstance(pat.value, str):
            continue
        if not _AUTH_PATH_RE.search(pat.value):
            continue
        view_expr = _unwrap_as_view(node.args[1])
        routes.append(_AuthRoute(pat.value, node.lineno, view_expr))
    return routes


def _ast_mentions_throttle(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and "throttle" in sub.id.lower():
            return True
        if isinstance(sub, ast.Attribute) and "throttle" in sub.attr.lower():
            return True
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if "throttle" in sub.value.lower():
                return True
    return False


def _class_or_func_has_throttle(node: ast.FunctionDef | ast.ClassDef) -> bool:
    for d in node.decorator_list:
        if _ast_mentions_throttle(d):
            return True
    if isinstance(node, ast.ClassDef):
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name) and "throttle" in t.id.lower():
                        return True
    return False


def _parse_module(path: Path) -> ast.AST | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return None


def _find_def_in_module(
    tree: ast.AST, name: str
) -> ast.FunctionDef | ast.ClassDef | None:
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
        if isinstance(n, ast.ClassDef) and n.name == name:
            return n
    return None


def _resolve_views_file(urls_file: Path) -> Path | None:
    cand = urls_file.parent / "views.py"
    return cand if cand.exists() else None


def _split_view_string(ref: str) -> tuple[str, str] | None:
    if not ref or ":" in ref:
        return None
    if ref.count(".") < 1:
        return None
    mod, _, attr = ref.rpartition(".")
    if not mod or not attr:
        return None
    return mod, attr


def _module_path_to_file(project_root: Path, module: str) -> Path | None:
    parts = module.split(".")
    if len(parts) < 1:
        return None
    rel = project_root.joinpath(*parts[:-1], f"{parts[-1]}.py")
    if rel.is_file():
        return rel
    rel2 = project_root.joinpath(*parts, "__init__.py")
    if rel2.is_file():
        return rel2
    return None


def _view_throttle_status(
    view_expr: ast.expr,
    urls_tree: ast.AST,
    urls_file: Path,
    project_root: Path,
) -> Literal["throttled", "not_throttled", "unknown"]:
    if isinstance(view_expr, ast.Lambda):
        return "unknown"

    if isinstance(view_expr, ast.Constant) and isinstance(view_expr.value, str):
        sp = _split_view_string(view_expr.value)
        if not sp:
            return "unknown"
        mod, attr = sp
        py = _module_path_to_file(project_root.resolve(), mod)
        if not py:
            return "unknown"
        mtree = _parse_module(py)
        if not mtree:
            return "unknown"
        node = _find_def_in_module(mtree, attr)
        if node is None:
            return "unknown"
        return "throttled" if _class_or_func_has_throttle(node) else "not_throttled"

    views_py = _resolve_views_file(urls_file)
    if views_py is None:
        return "unknown"

    vtree = _parse_module(views_py)
    if not vtree:
        return "unknown"

    if isinstance(view_expr, ast.Name):
        node = _find_def_in_module(vtree, view_expr.id)
        if node is None:
            return "unknown"
        return "throttled" if _class_or_func_has_throttle(node) else "not_throttled"

    if isinstance(view_expr, ast.Attribute):
        if isinstance(view_expr.value, ast.Name) and view_expr.value.id == "views":
            node = _find_def_in_module(vtree, view_expr.attr)
            if node is None:
                return "unknown"
            return "throttled" if _class_or_func_has_throttle(node) else "not_throttled"

    return "unknown"


def run_drf_auth_url_rules(
    project_root: Path, ctx: dict[str, Any]
) -> list[Finding]:
    """DJG023 — auth-like routes: prefer per-view throttle; fall back to global DRF settings."""
    if not ctx.get("drf_installed"):
        return []
    root = project_root.resolve()
    rows: list[tuple[_AuthRoute, Path, Literal["throttled", "not_throttled", "unknown"]]] = []

    for urls_path in _urls_py_files(root):
        tree = _parse_module(urls_path)
        if not tree:
            continue
        for route in _collect_auth_routes(tree, urls_path):
            st = _view_throttle_status(route.view_expr, tree, urls_path, root)
            rows.append((route, urls_path, st))
            if len(rows) >= _MAX_ROUTE_FINDINGS:
                break
        if len(rows) >= _MAX_ROUTE_FINDINGS:
            break

    if not rows:
        return []

    classes: list[str] = ctx.get("rest_default_throttle_classes") or []
    rates: dict[str, Any] = ctx.get("rest_default_throttle_rates") or {}
    has_global_throttle = bool(classes) and bool(rates)

    unknown_count = sum(1 for _, _, s in rows if s == "unknown")
    findings: list[Finding] = []

    for route, urls_path, st in rows:
        if st != "not_throttled":
            continue
        rel = str(urls_path.relative_to(root))
        findings.append(
            Finding(
                rule_id="DJG023",
                severity="HIGH",
                title="Auth-like route without view-level throttling",
                message=(
                    f"Route {route.pattern!r} ({rel}:{route.lineno}) maps to a resolvable "
                    "view/class with no obvious DRF throttle_classes / throttle_scope."
                ),
                path=rel,
                line=route.lineno,
                fix_hint=(
                    "Add @throttle_classes([ScopedRateThrottle]) or set throttle_scope / "
                    "throttle_classes on the API view class.\n"
                ),
            )
        )

    if findings and unknown_count:
        if not has_global_throttle:
            findings.append(
                Finding(
                    rule_id="DJG023",
                    severity="HIGH",
                    title="Auth-like routes: some views could not be verified",
                    message=(
                        f"{unknown_count} additional auth-style route(s) use lambdas or "
                        "dynamic views; global DRF throttling is not configured."
                    ),
                    path="urls.py",
                    fix_hint=(
                        "Use named importable views and/or enable DEFAULT_THROTTLE_* in "
                        "REST_FRAMEWORK.\n"
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    rule_id="DJG023",
                    severity="WARN",
                    title="Auth-like routes: per-view throttle not verified",
                    message=(
                        f"{unknown_count} route(s) could not be statically resolved. "
                        "Global throttling is set — still review auth endpoints."
                    ),
                    path="urls.py",
                    fix_hint=(
                        "Replace lambda views with named views and add strict "
                        "ScopedRateThrottle on login/token/password paths.\n"
                    ),
                )
            )
        return findings

    if findings:
        return findings

    if unknown_count:
        if not has_global_throttle:
            findings.append(
                Finding(
                    rule_id="DJG023",
                    severity="HIGH",
                    title="Auth-like URL patterns without verifiable throttling",
                    message=(
                        f"{unknown_count} auth-style route(s) use lambdas or views we could "
                        "not resolve, and global DRF throttling is not configured."
                    ),
                    path="urls.py",
                    fix_hint=(
                        "Use importable views (not lambdas) and/or enable DEFAULT_THROTTLE_* "
                        "in REST_FRAMEWORK.\n"
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    rule_id="DJG023",
                    severity="WARN",
                    title="Auth-like routes: per-view throttle not verified",
                    message=(
                        f"{unknown_count} route(s) could not be statically resolved (lambda or "
                        "dynamic view). Global throttling is set — still review auth endpoints."
                    ),
                    path="urls.py",
                    fix_hint=(
                        "Replace lambda views with named views and add strict ScopedRateThrottle "
                        "on login/token/password paths.\n"
                    ),
                )
            )
        return findings

    return findings


def project_has_auth_like_url_patterns(project_root: Path) -> bool:
    root = project_root.resolve()
    for urls_path in _urls_py_files(root):
        tree = _parse_module(urls_path)
        if tree and _collect_auth_routes(tree, urls_path):
            return True
    return False
