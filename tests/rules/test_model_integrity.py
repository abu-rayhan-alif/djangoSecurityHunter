from __future__ import annotations

from pathlib import Path

from django_security_hunter.config import GuardConfig
from django_security_hunter.rules.model_integrity import run_model_integrity_rules


def test_djg080_natural_key_not_unique(tmp_path: Path) -> None:
    p = tmp_path / "models.py"
    p.write_text(
        "from django.db import models\n"
        "class M(models.Model):\n"
        "    email = models.EmailField()\n",
        encoding="utf-8",
    )
    findings = list(run_model_integrity_rules(tmp_path))
    assert any(f.rule_id == "DJG080" for f in findings)


def test_djg081_cascade_on_auditish_model(tmp_path: Path) -> None:
    p = tmp_path / "models.py"
    p.write_text(
        "from django.db import models\n"
        "class UserAuditLog(models.Model):\n"
        "    user = models.ForeignKey('User', on_delete=models.CASCADE)\n",
        encoding="utf-8",
    )
    findings = list(run_model_integrity_rules(tmp_path))
    assert any(f.rule_id == "DJG081" for f in findings)
    assert any(
        f.rule_id == "DJG081" and "'user'" in f.message for f in findings
    )


def test_djg081_respects_model_ignore_list(tmp_path: Path) -> None:
    p = tmp_path / "models.py"
    p.write_text(
        "from django.db import models\n"
        "class UserAuditLog(models.Model):\n"
        "    user = models.ForeignKey('User', on_delete=models.CASCADE)\n",
        encoding="utf-8",
    )
    cfg = GuardConfig(model_integrity_ignore_models=frozenset(["UserAuditLog"]))
    findings = list(run_model_integrity_rules(tmp_path, cfg))
    assert not any(f.rule_id == "DJG081" for f in findings)
