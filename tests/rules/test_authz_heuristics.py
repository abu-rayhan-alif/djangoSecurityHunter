from __future__ import annotations

from pathlib import Path

from django_security_hunter.rules.authz_heuristics import run_authz_heuristic_rules


def test_djg027_allow_any_on_viewset(tmp_path: Path) -> None:
    p = tmp_path / "views.py"
    p.write_text(
        "from rest_framework import viewsets\n"
        "from rest_framework.permissions import AllowAny\n"
        "class U(viewsets.ModelViewSet):\n"
        "    permission_classes = [AllowAny]\n",
        encoding="utf-8",
    )
    findings = list(run_authz_heuristic_rules(tmp_path))
    assert any(f.rule_id == "DJG027" for f in findings)


def test_djg027_clean_view(tmp_path: Path) -> None:
    p = tmp_path / "views.py"
    p.write_text(
        "from rest_framework import viewsets\n"
        "from rest_framework.permissions import IsAuthenticated\n"
        "class U(viewsets.ModelViewSet):\n"
        "    permission_classes = [IsAuthenticated]\n",
        encoding="utf-8",
    )
    assert not list(run_authz_heuristic_rules(tmp_path))
