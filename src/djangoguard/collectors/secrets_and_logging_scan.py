from __future__ import annotations

import ast
import re
from pathlib import Path

from djangoguard.collectors.drf_static_scan import (
    _iter_project_glob,
    _read_py_source,
)

# Heuristic scans: skip test trees and fixture dirs to cut false positives (sample secrets).
_SKIP_PATH_PARTS = frozenset({"migrations", "tests", "fixtures"})


def _skip_secrets_scan_path(py_path: Path) -> bool:
    return any(p in _SKIP_PATH_PARTS for p in py_path.parts)

_LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "critical", "exception", "log"}
)

# Variable / attribute fragments that suggest credential-bearing values.
_SENSITIVE_NAME_PARTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "bearer",
    "credential",
    "authorization",
    "private_key",
    "access_key",
    "client_secret",
    "csrf",
)

_FALSE_NAME_POSITIVE = frozenset(
    {
        "author",
        "authority",
        "authors",
        "authentic",
        "authentication",
        "authenticator",
    }
)


def _identifier_sensitive(name: str) -> bool:
    lower = name.lower()
    if lower in _FALSE_NAME_POSITIVE:
        return False
    for part in _SENSITIVE_NAME_PARTS:
        if part in lower:
            return True
    return False


def _expr_references_sensitive_name(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and _identifier_sensitive(child.id):
            return True
        if isinstance(child, ast.Attribute) and _identifier_sensitive(child.attr):
            return True
    return False


def _is_logger_call(func: ast.expr) -> bool:
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in _LOG_METHODS:
        return False
    val = func.value
    if isinstance(val, ast.Name):
        return val.id in ("logging", "logger", "LOGGER", "log", "_logger")
    if isinstance(val, ast.Attribute) and val.attr in ("logger", "log"):
        return True
    return False


def _logging_call_args(call: ast.Call) -> list[ast.expr]:
    out: list[ast.expr] = list(call.args)
    for kw in call.keywords:
        out.append(kw.value)
    return out


def _logging_call_may_leak_secrets(call: ast.Call) -> str | None:
    """Return a short reason if this looks like logging of sensitive data."""
    if not _is_logger_call(call.func):
        return None
    for arg in _logging_call_args(call):
        if _expr_references_sensitive_name(arg):
            return "log_call_sensitive_identifier"
    return None


# --- Hardcoded secrets (DJG074) ---

# Skip obvious placeholders and documentation snippets.
_LITERAL_ALLOWLIST = re.compile(
    r"(^|\b)(example|changeme|placeholder|your[-_]?key|not[-_]?a[-_]?real|"
    r"xxxx|xxx|test[-_]?only|dummy|sample|lorem|ipsum|redacted|insert|replace|"
    r"todo|fixme|\*\*\*|passwordhere|secretkeyhere)(\b|$)",
    re.I,
)

# HIGH-confidence shapes (narrow; reduce noise).
_RE_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_RE_STRIPE_SECRET = re.compile(r"\bsk_(live|test)_[0-9a-zA-Z]{20,}\b")
_RE_GH_CLASSIC = re.compile(r"\bghp_[0-9a-zA-Z]{36,}\b")
_RE_GH_FINE = re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{20,}\b")
_RE_SLACK = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")
_RE_PEM_PRIVATE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

# WARN: long opaque blobs (heuristic).
_RE_BEARER = re.compile(r"Bearer\s+[A-Za-z0-9._+/=-]{24,}")
_RE_LONG_B64ISH = re.compile(r"\b[A-Za-z0-9+/]{40}={0,2}\b")

# Skip WARN regexes on huge literals (HIGH patterns stay; file read is already capped).
_MAX_WARN_LITERAL_CHARS = 8192


def _literal_skipped_by_allowlist(s: str) -> bool:
    if len(s) < 10:
        return True
    if _LITERAL_ALLOWLIST.search(s):
        return True
    low = s.strip().lower()
    if low in ("true", "false", "null", "none"):
        return True
    return False


def _classify_hardcoded_secret(text: str) -> str | None:
    """Return severity 'HIGH'|'WARN' or None if no match."""
    if _literal_skipped_by_allowlist(text):
        return None
    n = len(text)
    if _RE_AWS_ACCESS_KEY.search(text):
        return "HIGH"
    if _RE_STRIPE_SECRET.search(text):
        return "HIGH"
    if _RE_GH_CLASSIC.search(text) or _RE_GH_FINE.search(text):
        return "HIGH"
    if _RE_SLACK.search(text):
        return "HIGH"
    if _RE_PEM_PRIVATE.search(text):
        return "HIGH"
    # Looser heuristics: avoid scanning multi‑KiB blobs (DoS hardening on regex work).
    if n > _MAX_WARN_LITERAL_CHARS:
        return None
    if _RE_BEARER.search(text):
        return "WARN"
    if n >= 48 and _RE_LONG_B64ISH.search(text):
        return "WARN"
    return None


def _scan_string_constants(tree: ast.AST) -> list[tuple[int, str, str]]:
    """(lineno, severity, kind) for risky string literals."""
    hits: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            sev = _classify_hardcoded_secret(node.value)
            if sev:
                kind = f"string_literal_{sev.lower()}"
                hits.append((node.lineno, sev, kind))
    return hits


def scan_sensitive_logging_hits(project_root: Path) -> list[tuple[str, int, str]]:
    """(file, line, kind) for DJG073."""
    hits: list[tuple[str, int, str]] = []
    for py_path in _iter_project_glob(project_root, "*.py"):
        if _skip_secrets_scan_path(py_path):
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
            reason = _logging_call_may_leak_secrets(node)
            if reason:
                hits.append((str(py_path), node.lineno, reason))
    return hits


def scan_hardcoded_secret_hits(
    project_root: Path,
) -> list[tuple[str, int, str, str]]:
    """(file, line, severity, kind) for DJG074."""
    hits: list[tuple[str, int, str, str]] = []
    for py_path in _iter_project_glob(project_root, "*.py"):
        if _skip_secrets_scan_path(py_path):
            continue
        source = _read_py_source(py_path)
        if source is None:
            continue
        try:
            tree = ast.parse(source, filename=str(py_path))
        except SyntaxError:
            continue
        seen: set[tuple[int, str]] = set()
        for lineno, sev, kind in _scan_string_constants(tree):
            key = (lineno, kind)
            if key in seen:
                continue
            seen.add(key)
            hits.append((str(py_path), lineno, sev, kind))
    return hits
