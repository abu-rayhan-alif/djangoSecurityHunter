from __future__ import annotations

from pathlib import Path

from django_security_hunter.config import GuardConfig
from django_security_hunter.rules.static_patterns import run_static_pattern_rules


def test_mark_safe_finding(tmp_path: Path) -> None:
    p = tmp_path / "bad.py"
    p.write_text(
        "from django.utils.safestring import mark_safe\n"
        "x = mark_safe(user_input)\n",
        encoding="utf-8",
    )
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(f.rule_id == "DJG070" for f in findings)


def test_pickle_loads_finding(tmp_path: Path) -> None:
    p = tmp_path / "bad.py"
    p.write_text("import pickle\npickle.loads(blob)\n", encoding="utf-8")
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(f.rule_id == "DJG072" for f in findings)


def test_serializer_all_fields(tmp_path: Path) -> None:
    p = tmp_path / "ser.py"
    p.write_text(
        "from rest_framework import serializers\n"
        "class M(serializers.ModelSerializer):\n"
        "    class Meta:\n"
        "        model = object\n"
        '        fields = "__all__"\n',
        encoding="utf-8",
    )
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(f.rule_id == "DJG024" and f.severity == "WARN" for f in findings)


def test_serializer_all_fields_high_on_sensitive_name(tmp_path: Path) -> None:
    p = tmp_path / "ser.py"
    p.write_text(
        "from rest_framework import serializers\n"
        "class UserSerializer(serializers.ModelSerializer):\n"
        "    class Meta:\n"
        "        model = object\n"
        '        fields = "__all__"\n',
        encoding="utf-8",
    )
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(f.rule_id == "DJG024" and f.severity == "HIGH" for f in findings)


def test_clean_file_no_findings(tmp_path: Path) -> None:
    p = tmp_path / "ok.py"
    p.write_text("def f():\n    return 1\n", encoding="utf-8")
    assert list(run_static_pattern_rules(tmp_path)) == []


def test_djg074_static_secrets_allowlist(tmp_path: Path) -> None:
    p = tmp_path / "keys.py"
    p.write_text('API_KEY = "12345678901234567890"\n', encoding="utf-8")
    cfg = GuardConfig(static_secrets_allowlist=frozenset(["API_KEY"]))
    findings = list(run_static_pattern_rules(tmp_path, cfg))
    assert not any(f.rule_id == "DJG074" for f in findings)


def test_djg070_safe_string(tmp_path: Path) -> None:
    p = tmp_path / "xss.py"
    p.write_text(
        "from django.utils.safestring import SafeString\n"
        "x = SafeString('<b>hi</b>')\n",
        encoding="utf-8",
    )
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(
        f.rule_id == "DJG070" and "SafeString" in (f.title or "") for f in findings
    )


def test_djg070_template_pipe_safe(tmp_path: Path) -> None:
    tdir = tmp_path / "templates"
    tdir.mkdir()
    (tdir / "x.html").write_text("<div>{{ body|safe }}</div>\n", encoding="utf-8")
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(
        f.rule_id == "DJG070" and "|safe" in (f.title or "").lower() for f in findings
    )


def test_djg070_template_autoescape_off(tmp_path: Path) -> None:
    tdir = tmp_path / "templates"
    tdir.mkdir()
    (tdir / "y.html").write_text("{% autoescape off %}{{ x }}{% endautoescape %}\n")
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(
        f.rule_id == "DJG070" and "autoescape" in (f.title or "").lower()
        for f in findings
    )


def test_djg075_execute_fstring_high(tmp_path: Path) -> None:
    p = tmp_path / "sql.py"
    p.write_text(
        "def run(c, uid):\n"
        '    c.execute(f"SELECT * FROM u WHERE id={uid}")\n',
        encoding="utf-8",
    )
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(f.rule_id == "DJG075" and f.severity == "HIGH" for f in findings)


def test_djg075_execute_literal_ignored(tmp_path: Path) -> None:
    p = tmp_path / "ok_sql.py"
    p.write_text(
        'def run(c, uid):\n'
        '    c.execute("SELECT * FROM u WHERE id=%s", [uid])\n',
        encoding="utf-8",
    )
    assert not any(f.rule_id == "DJG075" for f in run_static_pattern_rules(tmp_path))


def test_djg075_objects_raw_mod_high(tmp_path: Path) -> None:
    p = tmp_path / "raw_orm.py"
    p.write_text(
        "class Entry:\n"
        "    objects = None\n\n"
        'def bad(table):\n'
        '    Entry.objects.raw("SELECT * FROM %s" % table)\n',
        encoding="utf-8",
    )
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(f.rule_id == "DJG075" and f.severity == "HIGH" for f in findings)


def test_djg075_rawsql_name_high(tmp_path: Path) -> None:
    p = tmp_path / "expr.py"
    p.write_text(
        "def q(x):\n"
        '    return RawSQL(f"SELECT col FROM t WHERE id={x}", [])\n',
        encoding="utf-8",
    )
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(f.rule_id == "DJG075" for f in findings)


def test_djg073_no_finding_operational_token_logs(tmp_path: Path) -> None:
    p = tmp_path / "ops.py"
    p.write_text(
        'import logging\nlog = logging.getLogger("x")\n'
        'log.error("Redis refresh-token blacklist connection failed: %s", err)\n'
        'log.warning("Admin password reset email failed for %s: %s", a, b)\n'
        'log.info("Registered refresh token issuance: user_id=%s", uid)\n'
        'log.info("Set BD_SMS_API_URL to enable SMS; got: %s", msg)\n',
        encoding="utf-8",
    )
    findings = list(run_static_pattern_rules(tmp_path))
    assert not any(f.rule_id == "DJG073" for f in findings)


def test_djg073_finding_raw_password_in_message(tmp_path: Path) -> None:
    p = tmp_path / "leak.py"
    p.write_text(
        'import logging\nlog = logging.getLogger("x")\n'
        'log.info("User password is %s for uid %s", password, uid)\n',
        encoding="utf-8",
    )
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(f.rule_id == "DJG073" for f in findings)


def test_djg073_finding_authorization_header_literal(tmp_path: Path) -> None:
    p = tmp_path / "hdr.py"
    p.write_text(
        'import logging\nlog = logging.getLogger("x")\n'
        'log.debug("request headers: authorization: %s", h)\n',
        encoding="utf-8",
    )
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(f.rule_id == "DJG073" for f in findings)


def test_djg075_execute_variable_warn(tmp_path: Path) -> None:
    p = tmp_path / "dyn.py"
    p.write_text(
        "def run(c, sql, params):\n"
        "    c.execute(sql, params)\n",
        encoding="utf-8",
    )
    findings = list(run_static_pattern_rules(tmp_path))
    assert any(f.rule_id == "DJG075" and f.severity == "WARN" for f in findings)
