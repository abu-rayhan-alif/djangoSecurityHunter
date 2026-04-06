from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable

from django_security_hunter.collectors.ast_scanner import (
    iter_html_template_files,
    iter_python_files,
)
from django_security_hunter.config import GuardConfig
from django_security_hunter.models import Finding

_TEMPLATE_PIPE_SAFE_RE = re.compile(r"\|\s*safe\b")
_TEMPLATE_AUTOESCAPE_OFF_RE = re.compile(r"\{%\s*autoescape\s+off\s*%\}")

_SECRET_NAME_RE = re.compile(
    r"^(SECRET|API_KEY|PASSWORD|AUTH_TOKEN|ACCESS_TOKEN|PRIVATE_KEY|BEARER)_?",
    re.IGNORECASE,
)

# DJG024: bump to HIGH when serializer class name suggests auth/payment-style models
_SENSITIVE_SERIALIZER_NAME_RE = re.compile(
    r"(User|Account|Auth|Token|Credential|Payment|Secret|Profile|Customer|Subscriber|Admin)"
    r"(Serializer)?$",
    re.IGNORECASE,
)

# DJG073: log *template* strings that mention credentials. Use boundary-aware
# patterns (not bare substrings) and allow known-safe operational phrasing to cut FPs.
_DJG073_SAFE_MESSAGE_RE = re.compile(
    r"(?i)(?:"
    r"password\s+reset|reset\s+password|forgot\s+password|reset\s+email|password\s+reset\s+email|"
    r"denying\s+token|"
    r"registered\s+(?:refresh|access)[-\s]token|"
    r"set\s+[A-Z][A-Z0-9_]*_API_URL\b|"
    r"(?:refresh|access)[-\s]token.{0,160}?"
    r"(?:blacklist|redis|issuance|cleanup|invalid|unavail|fail|init|register|removed|denying|expired)|"
    r"(?:blacklist|redis|cleanup\s+scan).{0,120}?(?:refresh|access)[-\s]token"
    r")",
)

_DJG073_SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bpassword\b|\bpasswd\b", re.I),
    re.compile(r"\bsecret\b", re.I),
    re.compile(r"\btoken\b", re.I),
    re.compile(r"\bapi[_-]?key\b|\bapikey\b", re.I),
    re.compile(r"authorization\s*:", re.I),
    # Opaque-looking value after Bearer (skip "bearer authentication …" phrasing).
    re.compile(
        r"\bbearer\s+(?!authentication\b)[A-Za-z0-9+/=_-]{8,}", re.I
    ),
)


def _joined_str_has_interpolation(node: ast.JoinedStr) -> bool:
    return any(isinstance(v, ast.FormattedValue) for v in node.values)


def _sql_arg_taint_severity(node: ast.expr) -> str | None:
    """Return HIGH/WARN if *node* is not a safe static SQL literal; else None.

    Safe: plain string constant (including ``%s`` placeholders with params).
    HIGH: f-strings, ``%`` formatting, ``.format``, non-trivial string concat.
    WARN: variable/attribute/call (SQL built elsewhere—may still use parameters).
    """
    if isinstance(node, ast.Constant):
        return None if isinstance(node.value, str) else "WARN"

    if isinstance(node, ast.JoinedStr):
        return "HIGH" if _joined_str_has_interpolation(node) else None

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return "HIGH"

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return "HIGH"
        if isinstance(node.func, ast.Name) and node.func.id == "format":
            return "HIGH"
        return "WARN"

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        lc = isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)
        rc = isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)
        if lc and rc:
            return None
        return "HIGH"

    if isinstance(node, ast.BinOp):
        return "WARN"

    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return "WARN"

    return "WARN"


class _StaticVisitor(ast.NodeVisitor):
    def __init__(
        self,
        rel_path: str,
        findings: list[Finding],
        static_secrets_allowlist: frozenset[str],
    ) -> None:
        self.rel_path = rel_path
        self.findings = findings
        self._secret_allow = static_secrets_allowlist

    def _add(
        self,
        rule_id: str,
        severity: str,
        title: str,
        message: str,
        fix_hint: str,
        line: int,
    ) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                title=title,
                message=message,
                path=self.rel_path,
                line=line,
                fix_hint=fix_hint,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        self._check_mark_safe(node)
        self._check_safe_string(node)
        self._check_pickle_marshal(node)
        self._check_yaml_load(node)
        self._check_eval_exec(node)
        self._check_http_get_ssrf(node)
        self._check_logging_leak(node)
        self._check_sql_injection_heuristic(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_hardcoded_secret_assign(node)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._check_serializer_all_fields(node)
        self.generic_visit(node)

    def _check_mark_safe(self, node: ast.Call) -> None:
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id == "mark_safe":
            pass
        elif isinstance(fn, ast.Attribute) and fn.attr == "mark_safe":
            pass
        else:
            return
        self._add(
            "DJG070",
            "HIGH",
            "mark_safe used",
            (
                "mark_safe disables HTML escaping and is a common XSS foot-gun "
                "when combined with user-controlled strings."
            ),
            (
                "Prefer django.utils.html.format_html() for small HTML snippets with "
                "escaped interpolations; use template auto-escaping. If unavoidable, sanitize with "
                "a vetted HTML cleaner.\n"
            ),
            node.lineno,
        )

    def _check_safe_string(self, node: ast.Call) -> None:
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id == "SafeString":
            pass
        elif isinstance(fn, ast.Attribute) and fn.attr == "SafeString":
            pass
        else:
            return
        self._add(
            "DJG070",
            "HIGH",
            "SafeString used",
            (
                "SafeString marks content as safe for HTML output; combined with user input "
                "it is equivalent to disabling escaping (XSS risk)."
            ),
            (
                "Avoid wrapping untrusted strings. Prefer format_html() or templates with "
                "default auto-escaping.\n"
            ),
            node.lineno,
        )

    def _check_pickle_marshal(self, node: ast.Call) -> None:
        fn = node.func
        if not isinstance(fn, ast.Attribute):
            return
        if fn.attr not in {"loads", "load"}:
            return
        base = fn.value
        name = ""
        if isinstance(base, ast.Name):
            name = base.id
        elif isinstance(base, ast.Attribute):
            name = base.attr
        if name in {"pickle", "_pickle"} and fn.attr in {"loads", "load"}:
            self._add(
                "DJG072",
                "HIGH",
                "Insecure deserialization (pickle)",
                (
                    "pickle can execute arbitrary code when loading untrusted "
                    "data."
                ),
                (
                    "Use JSON, msgpack, or explicit safe schemas instead of "
                    "pickle for untrusted input.\n"
                ),
                node.lineno,
            )
        if name == "marshal" and fn.attr == "loads":
            self._add(
                "DJG072",
                "HIGH",
                "marshal.loads used",
                "marshal is not a safe interchange format for untrusted data.",
                "Avoid marshal for externally sourced payloads.\n",
                node.lineno,
            )

    def _check_yaml_load(self, node: ast.Call) -> None:
        fn = node.func
        if not isinstance(fn, ast.Attribute) or fn.attr != "load":
            return
        val = fn.value
        if not (isinstance(val, ast.Name) and val.id == "yaml"):
            return
        safe = False
        for kw in node.keywords:
            if kw.arg == "Loader":
                if isinstance(kw.value, ast.Attribute) and kw.value.attr in (
                    "SafeLoader",
                    "CSafeLoader",
                ):
                    safe = True
                elif isinstance(kw.value, ast.Name) and "Safe" in kw.value.id:
                    safe = True
        if not safe and node.args:
            self._add(
                "DJG072",
                "HIGH",
                "Unsafe yaml.load",
                "yaml.load without SafeLoader can execute arbitrary objects.",
                (
                    "Use yaml.safe_load() or yaml.load(..., "
                    "Loader=yaml.SafeLoader).\n"
                ),
                node.lineno,
            )

    def _check_sql_injection_heuristic(self, node: ast.Call) -> None:
        """DJG075 — best-effort SQL injection patterns (not full taint analysis)."""
        fn = node.func
        check_arg0 = False
        is_manager_raw = False

        if isinstance(fn, ast.Name) and fn.id == "RawSQL":
            check_arg0 = True
        elif isinstance(fn, ast.Attribute):
            if fn.attr in ("execute", "executemany"):
                check_arg0 = True
            elif fn.attr == "raw" and isinstance(fn.value, ast.Attribute):
                if fn.value.attr == "objects":
                    is_manager_raw = True
                    check_arg0 = True

        if not check_arg0 or not node.args:
            return

        sev = _sql_arg_taint_severity(node.args[0])
        if sev is None:
            return

        if is_manager_raw:
            ctx = "ORM .objects.raw()"
        elif isinstance(fn, ast.Name) and fn.id == "RawSQL":
            ctx = "RawSQL()"
        elif isinstance(fn, ast.Attribute):
            ctx = f".{fn.attr}()"
        else:
            ctx = "SQL API"

        self._add(
            "DJG075",
            sev,
            "Possible SQL injection (dynamic SQL string)",
            (
                f"{ctx} receives a non-literal SQL fragment; string formatting or "
                "concatenation with untrusted data can lead to SQL injection. "
                "This rule is heuristic and may false-positive."
            ),
            (
                "Use the ORM, or cursor.execute() with a fixed SQL string and a "
                "separate parameter sequence (%s placeholders); never interpolate "
                "untrusted data into the SQL text.\n"
            ),
            node.lineno,
        )

    def _check_eval_exec(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            self._add(
                "DJG072",
                "HIGH",
                f"{node.func.id}() used",
                (
                    f"{node.func.id} executes arbitrary Python code and must "
                    "not process untrusted input."
                ),
                "Remove or replace with a safe parser or allow-list.\n",
                node.lineno,
            )

    def _check_http_get_ssrf(self, node: ast.Call) -> None:
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr == "get":
            if isinstance(fn.value, ast.Name) and fn.value.id in {"requests", "httpx"}:
                if not node.args:
                    return
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    return
                self._add(
                    "DJG071",
                    "WARN",
                    "HTTP client get() with non-literal URL",
                    (
                        f"{fn.value.id}.get() may fetch user-controlled URLs "
                        "(SSRF / open redirect)."
                    ),
                    (
                        "Validate URLs against an allow-list; block private/"
                        "link-local IPs.\n"
                    ),
                    node.lineno,
                )

    def _check_logging_leak(self, node: ast.Call) -> None:
        fn = node.func
        method_names = {
            "debug",
            "info",
            "warning",
            "warn",
            "error",
            "exception",
            "critical",
        }
        if isinstance(fn, ast.Attribute) and fn.attr in method_names:
            pass
        elif isinstance(fn, ast.Name) and fn.id in {
            "debug",
            "info",
            "warning",
            "warn",
            "error",
            "critical",
        }:
            pass
        else:
            return
        if not node.args:
            return
        text = self._string_preview(node.args[0])
        if not text:
            return
        if _DJG073_SAFE_MESSAGE_RE.search(text):
            return
        if not any(p.search(text) for p in _DJG073_SENSITIVE_PATTERNS):
            return
        self._add(
            "DJG073",
            "HIGH",
            "Possible sensitive data in log message",
            f"Log call may emit sensitive keywords in: {text[:120]!r}...",
            "Redact secrets; never log passwords, tokens, or raw Authorization headers.\n",
            node.lineno,
        )

    @staticmethod
    def _string_preview(node: ast.expr) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return ""

    def _check_hardcoded_secret_assign(self, node: ast.Assign) -> None:
        if not isinstance(node.value, ast.Constant) or not isinstance(
            node.value.value, str
        ):
            return
        val = node.value.value
        if len(val) < 8:
            return
        for t in node.targets:
            if not isinstance(t, ast.Name):
                continue
            if t.id in self._secret_allow:
                continue
            if _SECRET_NAME_RE.match(t.id):
                self._add(
                    "DJG074",
                    "WARN",
                    "Hardcoded secret-like assignment",
                    (
                        f"Variable {t.id!r} is assigned a long string literal; "
                        "may be a committed secret."
                    ),
                    "Load secrets from the environment or a secrets manager.\n",
                    node.lineno,
                )

    def _check_serializer_all_fields(self, node: ast.ClassDef) -> None:
        if not any(self._looks_like_serializer_base(b) for b in node.bases):
            return
        for stmt in node.body:
            if isinstance(stmt, ast.ClassDef) and stmt.name == "Meta":
                for inner in stmt.body:
                    if not isinstance(inner, ast.Assign):
                        continue
                    for target in inner.targets:
                        if isinstance(target, ast.Name) and target.id == "fields":
                            v = inner.value
                            if isinstance(v, ast.Constant) and v.value == "__all__":
                                sev = (
                                    "HIGH"
                                    if _SENSITIVE_SERIALIZER_NAME_RE.search(node.name)
                                    else "WARN"
                                )
                                self._add(
                                    "DJG024",
                                    sev,
                                    'DRF serializer uses fields = "__all__"',
                                    (
                                        f"Class {node.name!r} exposes every model field; "
                                        "hidden or internal fields may leak via the API."
                                    ),
                                    (
                                        "Replace Meta.fields = \"__all__\" with an "
                                        "explicit tuple/list of safe fields, or use "
                                        "Meta.exclude for known-private fields.\n"
                                    ),
                                    inner.lineno,
                                )

    @staticmethod
    def _looks_like_serializer_base(node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id.endswith("Serializer")
        if isinstance(node, ast.Attribute):
            return node.attr.endswith("Serializer")
        return False


def _scan_html_templates(project_root: Path, findings: list[Finding]) -> None:
    root = project_root.resolve()
    for path in iter_html_template_files(project_root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = str(path.relative_to(root))
        for i, line in enumerate(text.splitlines(), start=1):
            if _TEMPLATE_PIPE_SAFE_RE.search(line):
                findings.append(
                    Finding(
                        rule_id="DJG070",
                        severity="HIGH",
                        title="Template filter |safe disables HTML escaping",
                        message=(
                            f"Line may mark template output as safe; verify no user-controlled "
                            f"data flows into this expression ({rel}:{i})."
                        ),
                        path=rel,
                        line=i,
                        fix_hint=(
                            "Remove |safe where possible; sanitize HTML with a vetted library "
                            "or use format_html in Python views.\n"
                        ),
                    )
                )
            if _TEMPLATE_AUTOESCAPE_OFF_RE.search(line):
                findings.append(
                    Finding(
                        rule_id="DJG070",
                        severity="WARN",
                        title="Template autoescape disabled",
                        message=(
                            "{% autoescape off %} turns off HTML escaping for following content; "
                            "review for XSS."
                        ),
                        path=rel,
                        line=i,
                        fix_hint="Prefer default autoescaping; scope any exceptions narrowly.\n",
                    )
                )


def run_static_pattern_rules(
    project_root: Path, cfg: GuardConfig | None = None
) -> Iterable[Finding]:
    cfg = cfg or GuardConfig()
    allow = cfg.static_secrets_allowlist
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
        _StaticVisitor(rel, findings, allow).visit(tree)
    _scan_html_templates(project_root, findings)
    return findings
