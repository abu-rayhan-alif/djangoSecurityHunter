"""Walk project files with size/skip rules for static collectors.

Canonical imports for new scanners (do **not** re-export these from other collector modules):

- ``read_py_source`` — bounded UTF-8 read of a single ``.py`` (or text) file
- ``iter_project_glob`` — arbitrary glob under the project with junk-dir skips
- ``iter_project_py_files`` — ``*.py`` with stricter skips (migrations/tests/fixtures)
- ``iter_project_py_skip_migrations`` — ``*.py`` with glob skips only, excluding any path
  segment named ``migrations`` (DRF serializers / URL scans)
"""

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

# Wider walk for static scanners that skip migrations/tests per-file themselves.
_SKIP_DIR_NAMES_GLOB = frozenset(
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
    yield from iter_project_glob(project_root, "*.py", skip_names=_SKIP_DIR_NAMES)


def iter_project_py_skip_migrations(project_root: Path) -> Iterable[Path]:
    """Yield ``*.py`` like ``iter_project_glob``, dropping files under a ``migrations`` dir."""
    for p in iter_project_glob(project_root, "*.py"):
        if "migrations" in p.parts:
            continue
        yield p


def iter_project_glob(
    project_root: Path,
    pattern: str,
    *,
    skip_names: frozenset[str] | None = None,
) -> Iterable[Path]:
    """Yield files matching *pattern* under *project_root* (symlink-safe; skips junk dirs)."""
    names = skip_names if skip_names is not None else _SKIP_DIR_NAMES_GLOB
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
        if any(part in names for part in resolved.parts):
            continue
        yield resolved
