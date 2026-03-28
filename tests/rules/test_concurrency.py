from __future__ import annotations

from pathlib import Path

from django_security_hunter.config import GuardConfig
from django_security_hunter.rules.concurrency import run_concurrency_rules


def test_djg050_exists_then_create(tmp_path: Path) -> None:
    p = tmp_path / "race.py"
    p.write_text(
        "def f():\n"
        "    if not M.objects.filter(x=1).exists():\n"
        "        M.objects.create(x=1)\n",
        encoding="utf-8",
    )
    findings = list(run_concurrency_rules(tmp_path))
    assert any(f.rule_id == "DJG050" for f in findings)


def test_djg052_increment_without_f(tmp_path: Path) -> None:
    p = tmp_path / "inc.py"
    p.write_text(
        "def go(qs):\n"
        "    for row in qs:\n"
        "        row.count += 1\n",
        encoding="utf-8",
    )
    findings = list(run_concurrency_rules(tmp_path))
    assert any(f.rule_id == "DJG052" for f in findings)


def test_djg052_save_in_loop_without_lock(tmp_path: Path) -> None:
    p = tmp_path / "loop_save.py"
    p.write_text(
        "def go():\n"
        "    for row in M.objects.filter(active=True):\n"
        "        row.x = 1\n"
        "        row.save()\n",
        encoding="utf-8",
    )
    findings = list(run_concurrency_rules(tmp_path))
    assert any(
        f.rule_id == "DJG052" and "select_for_update" in (f.title or "") for f in findings
    )


def test_djg052_update_binop_without_f(tmp_path: Path) -> None:
    p = tmp_path / "upd.py"
    p.write_text(
        "def bump():\n"
        "    M.objects.filter(pk=1).update(n=1 + 1)\n",
        encoding="utf-8",
    )
    findings = list(run_concurrency_rules(tmp_path))
    assert any(
        f.rule_id == "DJG052" and "update()" in (f.title or "").lower() for f in findings
    )


def test_djg051_multi_save(tmp_path: Path) -> None:
    p = tmp_path / "saves.py"
    p.write_text(
        "class X:\n"
        "    def go(self, a, b):\n"
        "        a.save()\n"
        "        b.save()\n",
        encoding="utf-8",
    )
    findings = list(run_concurrency_rules(tmp_path))
    assert any(f.rule_id == "DJG051" and f.severity == "WARN" for f in findings)


def test_djg051_high_when_many_saves(tmp_path: Path) -> None:
    p = tmp_path / "many.py"
    p.write_text(
        "def go(a, b, c):\n"
        "    a.save()\n"
        "    b.save()\n"
        "    c.save()\n",
        encoding="utf-8",
    )
    cfg = GuardConfig(djg051_high_save_threshold=3)
    findings = list(run_concurrency_rules(tmp_path, cfg))
    assert any(f.rule_id == "DJG051" and f.severity == "HIGH" for f in findings)


def test_djg050_try_get_then_create(tmp_path: Path) -> None:
    p = tmp_path / "race2.py"
    p.write_text(
        "def f():\n"
        "    try:\n"
        "        M.objects.get(pk=1)\n"
        "    except Exception:\n"
        "        M.objects.create(pk=1)\n",
        encoding="utf-8",
    )
    findings = list(run_concurrency_rules(tmp_path))
    assert any(
        f.rule_id == "DJG050" and "get" in (f.title or "").lower() for f in findings
    )


def test_djg051_with_block_no_crash(tmp_path: Path) -> None:
    """ast.With has no orelse; walker must not assume If/For shape."""
    p = tmp_path / "ctx.py"
    p.write_text(
        "def go(a, b):\n"
        "    with open('x'):\n"
        "        a.save()\n"
        "        b.save()\n",
        encoding="utf-8",
    )
    findings = list(run_concurrency_rules(tmp_path))
    assert any(f.rule_id == "DJG051" for f in findings)
