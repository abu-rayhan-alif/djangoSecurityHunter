from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from django_security_hunter.rules.concurrency import run_concurrency_rules


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_djg050_check_then_create(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "svc/risky.py",
        dedent(
            """
            from django.db import models

            class Thing(models.Model):
                pass

            def ensure():
                if Thing.objects.filter(pk=1).exists():
                    pass
                Thing.objects.create(pk=1)
            """
        ),
    )
    findings = [f for f in run_concurrency_rules(tmp_path) if f.rule_id == "DJG050"]
    assert len(findings) == 1
    assert findings[0].line == 8
    assert findings[0].severity == "WARN"
    assert findings[0].fix_hint


def test_djg050_body_has_create_inside_if(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "svc/risky2.py",
        dedent(
            """
            from django.db import models

            class Thing(models.Model):
                pass

            def ensure():
                if Thing.objects.filter(name="a").exists():
                    Thing.objects.create(name="a")
            """
        ),
    )
    findings = [f for f in run_concurrency_rules(tmp_path) if f.rule_id == "DJG050"]
    assert len(findings) == 1


def test_djg051_multi_writes_warn(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "svc/writes.py",
        dedent(
            """
            from django.db import models

            class A(models.Model):
                pass

            class B(models.Model):
                pass

            def flow():
                a = A()
                a.save()
                B.objects.create()
            """
        ),
    )
    findings = [f for f in run_concurrency_rules(tmp_path) if f.rule_id == "DJG051"]
    assert len(findings) == 1
    assert findings[0].severity == "WARN"


def test_djg051_three_writes_high(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "svc/writes3.py",
        dedent(
            """
            from django.db import models

            class A(models.Model):
                pass

            def flow():
                A.objects.create()
                A.objects.create()
                A.objects.create()
            """
        ),
    )
    findings = [f for f in run_concurrency_rules(tmp_path) if f.rule_id == "DJG051"]
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_djg051_skips_when_atomic_context(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "svc/atomic_ctx.py",
        dedent(
            """
            from django.db import models, transaction

            class A(models.Model):
                pass

            def flow():
                with transaction.atomic():
                    a = A()
                    a.save()
                    A.objects.create()
            """
        ),
    )
    findings = [f for f in run_concurrency_rules(tmp_path) if f.rule_id == "DJG051"]
    assert findings == []


def test_djg051_skips_when_atomic_decorator(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "svc/atomic_deco.py",
        dedent(
            """
            from django.db import models, transaction

            class A(models.Model):
                pass

            @transaction.atomic
            def flow():
                a = A()
                a.save()
                A.objects.create()
            """
        ),
    )
    findings = [f for f in run_concurrency_rules(tmp_path) if f.rule_id == "DJG051"]
    assert findings == []


def test_djg052_counter_without_f(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "svc/stock.py",
        dedent(
            """
            from django.db import models

            class Lot(models.Model):
                quantity = models.IntegerField()

            def dec(lot):
                lot.quantity = lot.quantity - 1
                lot.save()
            """
        ),
    )
    findings = [f for f in run_concurrency_rules(tmp_path) if f.rule_id == "DJG052"]
    assert len(findings) >= 1
    assert any(f.line == 8 for f in findings)


def test_djg052_allows_f_expression(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "svc/stock_f.py",
        dedent(
            """
            from django.db import models
            from django.db.models import F

            class Lot(models.Model):
                quantity = models.IntegerField()

            def bump(lot):
                lot.quantity = F("quantity") + 1
                lot.save()
            """
        ),
    )
    findings = [f for f in run_concurrency_rules(tmp_path) if f.rule_id == "DJG052"]
    assert findings == []


def test_djg052_augassign(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "svc/aug.py",
        dedent(
            """
            from django.db import models

            class Lot(models.Model):
                balance = models.IntegerField()

            def inc(lot):
                lot.balance += 1
            """
        ),
    )
    findings = [f for f in run_concurrency_rules(tmp_path) if f.rule_id == "DJG052"]
    assert len(findings) == 1
