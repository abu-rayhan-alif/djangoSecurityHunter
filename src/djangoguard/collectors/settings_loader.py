from __future__ import annotations

from pathlib import Path
from typing import Any


def load_settings_context(project_root: Path, settings_module: str | None) -> dict[str, Any]:
    """Placeholder settings collector for DJG-3 and DJG-4."""
    return {
        "project_root": str(project_root),
        "settings_module": settings_module,
    }

