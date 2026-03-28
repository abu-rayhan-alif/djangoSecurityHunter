"""Walk project Python files with size/skip rules (shared static scanners)."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

_MAX_PY_SOURCE_BYTES = 2 * 1024 * 1024  # 2 MiB

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
        "migrations",
        "tests",
        "fixtures",
    }
)


def read_py_source(path: Path) -> str | None:
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


def iter_project_py_files(project_root: Path) -> Iterable[Path]:
    """Yield ``*.py`` under project_root (resolved; skips junk dirs; symlink-safe)."""
    root = project_root.resolve()
    for p in root.rglob("*.py"):
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
