from __future__ import annotations

from pathlib import Path

from django_security_hunter.collectors.project_files import (
    iter_project_py_skip_migrations,
)


def test_iter_project_py_skip_migrations(tmp_path: Path) -> None:
    mig = tmp_path / "app" / "migrations"
    mig.mkdir(parents=True)
    (mig / "0001_initial.py").write_text("x=1\n", encoding="utf-8")
    (tmp_path / "app" / "models.py").write_text("y=2\n", encoding="utf-8")
    paths = {p.relative_to(tmp_path.resolve()) for p in iter_project_py_skip_migrations(tmp_path)}
    assert Path("app/models.py") in paths
    assert Path("app/migrations/0001_initial.py") not in paths
