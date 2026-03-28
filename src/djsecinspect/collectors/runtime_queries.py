from __future__ import annotations

from pathlib import Path
from typing import Any


def collect_runtime_query_metrics(project_root: Path) -> dict[str, Any]:
    """Placeholder runtime collector for DJG-8 profile mode."""
    return {"project_root": str(project_root), "tests": []}

