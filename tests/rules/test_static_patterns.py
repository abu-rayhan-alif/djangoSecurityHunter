from pathlib import Path

from djangoguard.rules.static_patterns import run_static_pattern_rules


def test_djg070_empty_project(tmp_path: Path) -> None:
    assert list(run_static_pattern_rules(tmp_path)) == []


def test_djg070_detects_mark_safe_and_template_safe(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "from django.utils.safestring import SafeString\n"
        "from django.utils.safestring import mark_safe\n"
        "def f(x):\n"
        "    return mark_safe(x)\n"
        "def g(x):\n"
        "    return SafeString(x)\n",
        encoding="utf-8",
    )
    tpl = tmp_path / "templates"
    tpl.mkdir()
    (tpl / "x.html").write_text("{{ body|safe }}\n", encoding="utf-8")
    (tpl / "y.html").write_text("{% autoescape off %}\n", encoding="utf-8")

    findings = list(run_static_pattern_rules(tmp_path))
    ids = [f.rule_id for f in findings]
    assert ids.count("DJG070") == 4
    assert all(f.severity == "HIGH" for f in findings if f.rule_id == "DJG070")


def test_djg071_skips_literal_url(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import requests\n"
        "def ping():\n"
        "    return requests.get('https://api.example.com/v1/status')\n",
        encoding="utf-8",
    )
    assert [f.rule_id for f in run_static_pattern_rules(tmp_path)] == []


def test_djg071_warns_dynamic_url(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import requests\n"
        "def fetch(endpoint):\n"
        "    return requests.get(endpoint)\n",
        encoding="utf-8",
    )
    findings = list(run_static_pattern_rules(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG071"
    assert findings[0].severity == "WARN"


def test_djg071_high_when_url_from_request(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "import httpx\n"
        "def proxy(request):\n"
        "    return httpx.get(request.GET['target'])\n",
        encoding="utf-8",
    )
    findings = [f for f in run_static_pattern_rules(tmp_path) if f.rule_id == "DJG071"]
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_djg071_high_webhook_name_hint(tmp_path: Path) -> None:
    (tmp_path / "hooks.py").write_text(
        "import requests\n"
        "def notify(webhook_url):\n"
        "    return requests.post(webhook_url, json={})\n",
        encoding="utf-8",
    )
    findings = [f for f in run_static_pattern_rules(tmp_path) if f.rule_id == "DJG071"]
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_djg072_pickle_loads(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text(
        "import pickle\n"
        "def f(b):\n"
        "    return pickle.loads(b)\n",
        encoding="utf-8",
    )
    findings = [f for f in run_static_pattern_rules(tmp_path) if f.rule_id == "DJG072"]
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "pickle" in findings[0].message


def test_djg072_yaml_load_without_safe_loader(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text(
        "import yaml\n"
        "def f(s):\n"
        "    return yaml.load(s)\n",
        encoding="utf-8",
    )
    findings = [f for f in run_static_pattern_rules(tmp_path) if f.rule_id == "DJG072"]
    assert len(findings) == 1


def test_djg072_yaml_load_with_safe_loader_kwarg(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text(
        "import yaml\n"
        "def f(s):\n"
        "    return yaml.load(s, Loader=yaml.SafeLoader)\n",
        encoding="utf-8",
    )
    assert [f.rule_id for f in run_static_pattern_rules(tmp_path)] == []


def test_djg072_yaml_load_with_safe_loader_positional(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text(
        "import yaml\n"
        "def f(s):\n"
        "    return yaml.load(s, yaml.SafeLoader)\n",
        encoding="utf-8",
    )
    assert [f.rule_id for f in run_static_pattern_rules(tmp_path)] == []


def test_djg072_yaml_load_with_csafeloader(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text(
        "import yaml\n"
        "def f(s):\n"
        "    return yaml.load(s, Loader=yaml.CSafeLoader)\n",
        encoding="utf-8",
    )
    assert [f.rule_id for f in run_static_pattern_rules(tmp_path)] == []


def test_djg072_yaml_unsafe_load(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text(
        "import yaml\n"
        "def f(s):\n"
        "    return yaml.unsafe_load(s)\n",
        encoding="utf-8",
    )
    findings = [f for f in run_static_pattern_rules(tmp_path) if f.rule_id == "DJG072"]
    assert len(findings) == 1


def test_djg072_yaml_safe_load_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text(
        "import yaml\n"
        "def f(s):\n"
        "    return yaml.safe_load(s)\n",
        encoding="utf-8",
    )
    assert [f.rule_id for f in run_static_pattern_rules(tmp_path)] == []


def test_djg073_logs_sensitive_identifier(tmp_path: Path) -> None:
    (tmp_path / "log.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def f(access_token):\n"
        "    logger.info(access_token)\n",
        encoding="utf-8",
    )
    findings = [f for f in run_static_pattern_rules(tmp_path) if f.rule_id == "DJG073"]
    assert len(findings) == 1
    assert findings[0].line == 4
    assert findings[0].path.endswith("log.py")
    assert findings[0].fix_hint
    assert "redact" in findings[0].fix_hint.lower()


def test_djg073_no_hit_for_literal_only(tmp_path: Path) -> None:
    (tmp_path / "log.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def f():\n"
        '    logger.info("hello")\n',
        encoding="utf-8",
    )
    assert [f for f in run_static_pattern_rules(tmp_path) if f.rule_id == "DJG073"] == []


def test_djg074_high_aws_like_key(tmp_path: Path) -> None:
    (tmp_path / "cfg.py").write_text(
        'KEY = "AKIAIOSFODNN7EXAMPLE"\n',
        encoding="utf-8",
    )
    findings = [f for f in run_static_pattern_rules(tmp_path) if f.rule_id == "DJG074"]
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 1


def test_djg074_allowlist_placeholder(tmp_path: Path) -> None:
    (tmp_path / "cfg.py").write_text(
        'API_KEY = "changeme"\n',
        encoding="utf-8",
    )
    assert [f for f in run_static_pattern_rules(tmp_path) if f.rule_id == "DJG074"] == []


def test_djg074_warn_bearer_literal(tmp_path: Path) -> None:
    (tmp_path / "cfg.py").write_text(
        'H = "Bearer xxxxxxxxxxxxxxxxxxxxxxxx"\n',
        encoding="utf-8",
    )
    findings = [f for f in run_static_pattern_rules(tmp_path) if f.rule_id == "DJG074"]
    assert len(findings) == 1
    assert findings[0].severity == "WARN"
