"""Input validation for security-sensitive CLI / loader paths."""

from __future__ import annotations

import re

# Django settings module: dotted Python identifiers (at least one dot).
_SETTINGS_MODULE_RE = re.compile(
    r"\A[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+\Z"
)
_MAX_SETTINGS_MODULE_LEN = 200
_BLOCKED_ROOT_MODULES = frozenset(
    {
        "builtins",
        "code",
        "importlib",
        "os",
        "pty",
        "shutil",
        "subprocess",
        "sys",
    }
)


def is_valid_django_settings_module(name: str | None) -> bool:
    """Return True if ``name`` looks like a safe Django ``DJANGO_SETTINGS_MODULE`` value."""
    if not name or not isinstance(name, str):
        return False
    s = name.strip()
    if not s or len(s) > _MAX_SETTINGS_MODULE_LEN:
        return False
    if "\x00" in s or "\n" in s or "\r" in s:
        return False
    if not _SETTINGS_MODULE_RE.fullmatch(s):
        return False
    root = s.split(".", 1)[0]
    if root in _BLOCKED_ROOT_MODULES:
        return False
    return True
