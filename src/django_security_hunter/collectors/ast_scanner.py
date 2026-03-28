from __future__ import annotations

from pathlib import Path

_EXCLUDE_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        ".tox",
        ".eggs",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        ".pytest_cache",
        "htmlcov",
        ".mypy_cache",
        ".ruff_cache",
    }
)


def iter_python_files(project_root: Path) -> list[Path]:
    """Python files under *project_root*, skipping deps and migrations."""
    root = project_root.resolve()
    out: list[Path] = []
    if not root.is_dir():
        return out
    for path in root.rglob("*.py"):
        parts = path.parts
        if "migrations" in parts:
            continue
        if _EXCLUDE_DIR_NAMES.intersection(parts):
            continue
        try:
            path.relative_to(root)
        except ValueError:
            continue
        out.append(path)
    return sorted(out)


def iter_html_template_files(project_root: Path) -> list[Path]:
    """Django/HTML templates under *project_root* (for ``|safe`` and similar scans)."""
    root = project_root.resolve()
    out: list[Path] = []
    if not root.is_dir():
        return out
    for path in root.rglob("*.html"):
        parts = path.parts
        if "migrations" in parts:
            continue
        if _EXCLUDE_DIR_NAMES.intersection(parts):
            continue
        try:
            path.relative_to(root)
        except ValueError:
            continue
        out.append(path)
    return sorted(out)


def collect_python_files(project_root: Path) -> dict[str, object]:
    files = iter_python_files(project_root)
    return {"project_root": str(project_root.resolve()), "python_files": [str(p) for p in files]}
