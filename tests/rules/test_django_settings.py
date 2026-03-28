from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from django_security_hunter.rules import django_settings as django_settings_rules

_GOOD_SECRET_KEY = "".join(f"{i:02x}" for i in range(25))  # 50 hex chars, mixed
_GOOD_ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
_GOOD_HSTS_SECONDS = 31_536_000


def _ctx(**overrides: object) -> dict:
    base = {
        "loaded": True,
        "settings_module": "x",
        "secret_key": _GOOD_SECRET_KEY,
        "allowed_hosts": _GOOD_ALLOWED_HOSTS,
        "secure_ssl_redirect": True,
        "hsts_seconds": _GOOD_HSTS_SECONDS,
        "session_cookie_secure": True,
        "csrf_cookie_secure": True,
        "secure_content_type_nosniff": True,
        "x_frame_options": "DENY",
        "csrf_trusted_origins": [],
        "cors_active": False,
        "cors_allow_all_origins": False,
        "cors_allowed_origins": [],
        "cors_allowed_origin_regexes": [],
        "data_upload_max_memory_size": 2_621_440,
        "file_upload_max_memory_size": 2_621_440,
        "data_upload_max_number_fields": 1_000,
    }
    base.update(overrides)
    return base


def test_djg001_finding_when_debug_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=True),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG001"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].fix_hint


def test_no_finding_when_debug_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert findings == []


def test_djg002_django_insecure_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(
            debug=False,
            secret_key="django-insecure-" + "a" * 40,
        ),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG002"]
    assert findings[0].severity == "HIGH"


def test_djg002_too_short(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False, secret_key="short"),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG002"]


def test_djg002_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False, secret_key=""),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG002"]


def test_djg001_and_djg002_when_both_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(
            debug=True,
            secret_key="django-insecure-" + "b" * 40,
        ),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    ids = {f.rule_id for f in findings}
    assert ids == {"DJG001", "DJG002"}


def test_djg003_allowed_hosts_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False, allowed_hosts=[]),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG003"]
    assert findings[0].severity == "HIGH"


def test_djg003_allowed_hosts_wildcard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False, allowed_hosts=["*"]),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG003"]


def test_djg003_wildcard_alongside_other_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False, allowed_hosts=["api.example.com", "*"]),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG003"]


def test_djg004_when_debug_false_and_ssl_redirect_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False, secure_ssl_redirect=False),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG004"]
    assert findings[0].severity == "HIGH"


def test_djg004_skipped_when_debug_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=True, secure_ssl_redirect=False),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG001"]


def test_djg004_when_secure_ssl_redirect_key_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(debug=False)
    del ctx["secure_ssl_redirect"]
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: ctx,
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG004"]


def test_djg005_high_when_hsts_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False, hsts_seconds=0),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG005"]
    assert findings[0].severity == "HIGH"


def test_djg005_warn_when_hsts_low(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False, hsts_seconds=86400),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG005"]
    assert findings[0].severity == "WARN"


def test_djg005_skipped_when_debug_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=True, hsts_seconds=0),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG001"]


def test_djg005_when_hsts_key_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _ctx(debug=False)
    del ctx["hsts_seconds"]
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: ctx,
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG005"]
    assert findings[0].severity == "HIGH"


def test_djg006_session_cookie_insecure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False, session_cookie_secure=False),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG006"]
    assert findings[0].severity == "HIGH"


def test_djg007_csrf_cookie_insecure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False, csrf_cookie_secure=False),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG007"]
    assert findings[0].severity == "HIGH"


def test_djg006_and_djg007_when_both_insecure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(
            debug=False,
            session_cookie_secure=False,
            csrf_cookie_secure=False,
        ),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG006", "DJG007"]


def test_djg006_skipped_when_debug_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=True, session_cookie_secure=False),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG001"]


def test_djg008_when_nosniff_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False, secure_content_type_nosniff=False),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG008"]


def test_djg009_when_x_frame_sameorigin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False, x_frame_options="SAMEORIGIN"),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG009"]


def test_djg010_high_on_wildcard_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(
            debug=False,
            csrf_trusted_origins=["https://*.example.com"],
        ),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG010"]
    assert findings[0].severity == "HIGH"


def test_djg010_warn_on_http_production_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(
            debug=False,
            csrf_trusted_origins=["http://api.evil.com"],
        ),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG010"]
    assert findings[0].severity == "WARN"


def test_djg011_cors_allow_all_when_active(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(
            debug=False,
            cors_active=True,
            cors_allow_all_origins=True,
        ),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG011"]


def test_djg012_cors_catch_all_regex(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(
            debug=False,
            cors_active=True,
            cors_allow_all_origins=False,
            cors_allowed_origin_regexes=["^.*$"],
        ),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG012"]
    assert findings[0].severity == "HIGH"


def test_djg012_cors_http_origin_warn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(
            debug=False,
            cors_active=True,
            cors_allow_all_origins=False,
            cors_allowed_origins=["http://api.example.com"],
        ),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert [f.rule_id for f in findings] == ["DJG012"]
    assert findings[0].severity == "WARN"


def test_djg026_warn_when_upload_limits_high(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(
            debug=False,
            data_upload_max_memory_size=20 * 1024 * 1024,
        ),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    djg026 = [f for f in findings if f.rule_id == "DJG026"]
    assert len(djg026) == 1
    assert djg026[0].severity == "WARN"
    assert "DATA_UPLOAD_MAX_MEMORY_SIZE" in djg026[0].message
    assert "DATA_UPLOAD_MAX_MEMORY_SIZE =" in (djg026[0].fix_hint or "")


def test_djg026_no_finding_when_limits_conservative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: _ctx(debug=False),
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), "x"))
    assert not any(f.rule_id == "DJG026" for f in findings)


def test_skips_when_settings_not_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        django_settings_rules,
        "load_settings_context",
        lambda _p, _s: {"loaded": False, "skip_reason": "no_settings_module"},
    )
    findings = list(django_settings_rules.run_django_settings_rules(Path("."), None))
    assert findings == []


def test_scan_fixture_project_reports_djg001() -> None:
    repo = Path(__file__).resolve().parents[2]
    fix = repo / "tests" / "fixtures" / "djg001_proj"
    src = repo / "src"
    env = os.environ.copy()
    extra = os.pathsep.join([str(src), str(fix)])
    env["PYTHONPATH"] = extra + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

    code = f"""
from pathlib import Path
from django_security_hunter.engine import run_scan
root = Path({str(fix)!r})
report = run_scan(root, "mysite.settings")
ids = [f.rule_id for f in report.findings]
assert "DJG001" in ids, ids
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        cwd=str(repo),
        check=False,
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr

