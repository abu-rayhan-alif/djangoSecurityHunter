from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _suppress_first_run_thanks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep CLI test output stable; opt in per test for thanks banner."""
    monkeypatch.setenv("DJANGOGUARD_NO_THANKS", "1")
