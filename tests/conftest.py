"""Test suite defaults."""

from __future__ import annotations

import os

# Skip nested `pytest` subprocess during `run_profile` (engine/unit tests).
os.environ.setdefault("DJANGOGUARD_SKIP_PYTEST_PROFILE", "1")
