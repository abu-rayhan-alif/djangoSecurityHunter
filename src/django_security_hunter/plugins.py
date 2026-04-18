"""Entry-point discovery for third-party scan plugins (extensibility without forking)."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable, Mapping
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from django_security_hunter.config import GuardConfig
from django_security_hunter.models import Finding

logger = logging.getLogger(__name__)

# Third-party packages register callables under this group in pyproject.toml, e.g.:
# [project.entry-points."django_security_hunter.scan_plugins"]
# my_pack = "my_package.plugin:run_custom_scan"
SCAN_PLUGINS_GROUP = "django_security_hunter.scan_plugins"


@runtime_checkable
class ScanPlugin(Protocol):
    """Callable invoked for each ``scan`` after built-in rules (same process, same report)."""

    def __call__(
        self,
        project_root: Path,
        cfg: GuardConfig,
        django_settings_context: Mapping[str, Any],
    ) -> Iterable[Finding]:
        ...


def scan_plugins_enabled(cfg: GuardConfig) -> bool:
    """TOML ``enable_scan_plugins`` unless ``DJANGO_SECURITY_HUNTER_PLUGINS`` overrides."""
    raw = os.environ.get("DJANGO_SECURITY_HUNTER_PLUGINS", "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    return cfg.enable_scan_plugins


def _iter_scan_plugin_entry_points() -> Iterable[EntryPoint]:
    return entry_points(group=SCAN_PLUGINS_GROUP)


def run_scan_plugins(
    project_root: Path,
    cfg: GuardConfig,
    django_settings_context: Mapping[str, Any],
) -> tuple[list[Finding], dict[str, Any]]:
    """Load and run all registered scan plugins; failures are isolated per plugin."""
    if not scan_plugins_enabled(cfg):
        return [], {
            "enabled": False,
            "status": "skipped",
            "reason": "disabled_by_config_or_env",
        }

    root = project_root.resolve()
    findings: list[Finding] = []
    plugin_records: list[dict[str, Any]] = []

    for ep in _iter_scan_plugin_entry_points():
        name = ep.name
        try:
            fn = ep.load()
        except Exception as exc:
            logger.warning("Failed to load scan plugin %r: %s", name, exc)
            plugin_records.append(
                {"name": name, "status": "load_error", "error": str(exc)[:500]}
            )
            continue

        if not callable(fn):
            logger.warning("Scan plugin %r is not callable", name)
            plugin_records.append(
                {"name": name, "status": "error", "error": "entry_point_not_callable"}
            )
            continue

        try:
            out = fn(root, cfg, django_settings_context)
        except Exception as exc:
            logger.warning("Scan plugin %r raised: %s", name, exc)
            plugin_records.append(
                {"name": name, "status": "error", "error": str(exc)[:500]}
            )
            continue

        batch: list[Finding] = []
        try:
            for f in out:
                if isinstance(f, Finding):
                    batch.append(f)
        except Exception as exc:
            logger.warning("Scan plugin %r iteration failed: %s", name, exc)
            plugin_records.append(
                {"name": name, "status": "error", "error": str(exc)[:500]}
            )
            continue

        findings.extend(batch)
        plugin_records.append(
            {"name": name, "status": "ok", "findings": len(batch)}
        )
        logger.debug(
            "Scan plugin %r contributed %s findings",
            name,
            len(batch),
        )

    meta: dict[str, Any] = {
        "enabled": True,
        "entry_point_group": SCAN_PLUGINS_GROUP,
        "plugins": plugin_records,
        "total_findings": len(findings),
    }
    return findings, meta
