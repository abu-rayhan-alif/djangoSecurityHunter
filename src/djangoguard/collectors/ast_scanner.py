from __future__ import annotations

from pathlib import Path
from typing import Any


def collect_python_files(project_root: Path) -> dict[str, Any]:
    """Placeholder AST collector for static code pattern rules."""
    return {"project_root": str(project_root), "python_files": []}

