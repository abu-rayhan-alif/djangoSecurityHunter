"""Run pytest with the django_security_hunter profile plugin and return captures."""

from __future__ import annotations

import os
from pathlib import Path

from django_security_hunter.profile_analysis import PerTestCapture
from django_security_hunter.profile_pytest_plugin import DjangoSecurityHunterProfilePlugin
from django_security_hunter.settings_module import (
    InvalidSettingsModule,
    normalize_django_settings_module,
)


def run_pytest_profile_capture(
    project_root: Path,
    settings_module: str | None,
) -> tuple[list[PerTestCapture], int, str | None]:
    """Execute pytest from ``project_root`` and return per-test query captures.

    Returns ``(captures, pytest_exit_code, error_message)``.
    """
    try:
        import pytest
    except ImportError:
        return [], 2, "pytest is not installed"

    try:
        settings_mod = normalize_django_settings_module(settings_module)
    except InvalidSettingsModule as exc:
        return [], 2, str(exc)

    root = project_root.resolve()
    tests_dir = root / "tests"
    if tests_dir.is_dir():
        test_targets: list[str] = [str(tests_dir)]
    else:
        test_targets = [str(root)]

    args: list[str] = []
    try:
        import pytest_django  # noqa: F401, PLC0415

        args.extend(["-p", "pytest_django"])
    except ImportError:
        pass

    args.extend(
        [
            *test_targets,
            "-q",
            "--tb=no",
            "--no-header",
        ]
    )

    plugin = DjangoSecurityHunterProfilePlugin()
    prev_settings = os.environ.get("DJANGO_SETTINGS_MODULE")
    prev_cwd = os.getcwd()
    try:
        os.chdir(root)
        if settings_mod:
            os.environ["DJANGO_SETTINGS_MODULE"] = settings_mod
        code = pytest.main(args, plugins=[plugin])
    except OSError as exc:
        return [], 2, str(exc)
    finally:
        try:
            os.chdir(prev_cwd)
        except OSError:
            pass
        if settings_mod:
            if prev_settings is None:
                os.environ.pop("DJANGO_SETTINGS_MODULE", None)
            else:
                os.environ["DJANGO_SETTINGS_MODULE"] = prev_settings

    return plugin.captures, int(code), None
