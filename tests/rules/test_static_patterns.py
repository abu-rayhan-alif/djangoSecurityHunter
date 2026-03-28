from pathlib import Path

from djangoguard.rules.static_patterns import run_static_pattern_rules


def test_static_patterns_empty_without_models(tmp_path: Path) -> None:
    assert list(run_static_pattern_rules(tmp_path)) == []


def test_djg080_email_field_not_unique_high(tmp_path: Path) -> None:
    (tmp_path / "models.py").write_text(
        "from django.db import models\n"
        "class Profile(models.Model):\n"
        "    email = models.EmailField()\n",
        encoding="utf-8",
    )
    fs = [f for f in run_static_pattern_rules(tmp_path) if f.rule_id == "DJG080"]
    assert len(fs) == 1
    assert fs[0].severity == "HIGH"
    assert "Profile" in fs[0].message
    assert "email" in fs[0].message
    assert "unique=True" in fs[0].fix_hint
    assert "UniqueConstraint" in fs[0].fix_hint


def test_djg080_unique_true_skipped(tmp_path: Path) -> None:
    (tmp_path / "models.py").write_text(
        "from django.db import models\n"
        "class Profile(models.Model):\n"
        "    email = models.EmailField(unique=True)\n",
        encoding="utf-8",
    )
    assert [f.rule_id for f in run_static_pattern_rules(tmp_path)] == []


def test_djg081_cascade_to_order_warn(tmp_path: Path) -> None:
    (tmp_path / "models.py").write_text(
        "from django.db import models\n"
        "class Line(models.Model):\n"
        "    order = models.ForeignKey('Order', on_delete=models.CASCADE)\n",
        encoding="utf-8",
    )
    fs = [f for f in run_static_pattern_rules(tmp_path) if f.rule_id == "DJG081"]
    assert len(fs) == 1
    assert fs[0].severity == "WARN"
    assert "Line" in fs[0].message
    assert "PROTECT" in fs[0].fix_hint


def test_djg081_no_false_positive_ordering_token(tmp_path: Path) -> None:
    """``order`` must not match inside ``ordering`` (substring heuristic bug)."""
    (tmp_path / "models.py").write_text(
        "from django.db import models\n"
        "class X(models.Model):\n"
        "    prio = models.ForeignKey('shop.ordering.Priority', on_delete=models.CASCADE)\n",
        encoding="utf-8",
    )
    assert [f.rule_id for f in run_static_pattern_rules(tmp_path)] == []


def test_djg081_ignores_contenttype(tmp_path: Path) -> None:
    (tmp_path / "models.py").write_text(
        "from django.db import models\n"
        "class X(models.Model):\n"
        "    ct = models.ForeignKey('contenttypes.ContentType', on_delete=models.CASCADE)\n",
        encoding="utf-8",
    )
    assert [f.rule_id for f in run_static_pattern_rules(tmp_path)] == []
