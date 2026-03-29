<div align="center">

<pre>
 ____    ____    _   _ 
|  _ \  / ___|  | | | |
| | | | \___ \  | |_| |
| |_| |  ___) | |  _  |
|____/  |____/  |_| |_|
</pre>

**django-security-hunter**

### Security, reliability & performance for Django APIs

Static and config checks · optional query profiling · **SARIF** for GitHub Code Scanning

[![PyPI](https://img.shields.io/pypi/v/django-security-hunter.svg?style=flat-square&label=PyPI)](https://pypi.org/project/django-security-hunter/)
[![Python](https://img.shields.io/pypi/pyversions/django-security-hunter.svg?style=flat-square&label=Python)](https://pypi.org/project/django-security-hunter/)
[![License](https://img.shields.io/badge/License-MIT-0d1117?style=flat-square&labelColor=30363d)](https://github.com/abu-rayhan-alif/djangoSecurityHunter/blob/main/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/abu-rayhan-alif/djangoSecurityHunter/ci.yml?style=flat-square&label=CI&logo=github)](https://github.com/abu-rayhan-alif/djangoSecurityHunter/actions/workflows/ci.yml)

**Install:** `pip install django-security-hunter` · **CLI:** `django_security_hunter` or `djangoguard`

[Install & run](#install-and-run) · [At a glance](#at-a-glance-what-gets-checked) · [Quick start](#quick-start) · [CI](#use-in-github--gitlab-ci) · [Rules](docs/rules.md) · [**GitHub** (star / contribute)](https://github.com/abu-rayhan-alif/djangoSecurityHunter) · [Issues](https://github.com/abu-rayhan-alif/djangoSecurityHunter/issues)

Maintained by [Abu Rayhan Alif](https://github.com/abu-rayhan-alif)

</div>

> [!TIP]
> **New here?** Use [Install and run](#install-and-run) below, then [Quick start](#quick-start) and [CI](#use-in-github--gitlab-ci) when you automate.

---

## Install and run

This package is a **standalone CLI** (it does **not** register a `manage.py` subcommand). From your **Django project root** (the directory that contains `manage.py`):

```bash
pip install django-security-hunter
django_security_hunter scan --project . --settings yourproject.settings --format console
```

Replace `yourproject.settings` with the same module you use for `DJANGO_SETTINGS_MODULE` (for example `config.settings` or `mysite.settings`). Omitting `--settings` still runs many file-based checks, but **Django settings rules** (e.g. `DEBUG`, `SECRET_KEY`, `ALLOWED_HOSTS`, HTTPS cookies) are skipped.

**Shorthand CLI name:** `djangoguard` (same program).

**Optional:** write reports to disk as JSON or SARIF (for GitHub Code Scanning):

```bash
django_security_hunter scan --project . --settings yourproject.settings --format json --output reports/scan.json
django_security_hunter scan --project . --settings yourproject.settings --format sarif --output reports/scan.sarif
```

PyPI **Project links** (Homepage, Source, Issues, Documentation, Changelog) come from `[project.urls]` in `pyproject.toml` and point at this repo so you can **star**, **fork**, or **open PRs** on GitHub.

---

## At a glance: what gets checked

High-level checklist of what the scanner looks for (details and rule IDs: **[docs/rules.md](docs/rules.md)** and [What it finds](#what-it-finds)):

**Django production settings**

- `DEBUG`, `SECRET_KEY`, `ALLOWED_HOSTS`
- HTTPS redirect, HSTS, secure session / CSRF cookies
- `SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS`
- `CSRF_TRUSTED_ORIGINS`, CORS configuration (`CORS_ALLOW_ALL_ORIGINS`, allowlists)
- Very large request / upload limits (DoS-style misconfiguration)

**Django REST Framework**

- Default permission and authentication classes (e.g. missing vs `AllowAny`)
- Throttling disabled or weak for auth-like routes (`urls.py` heuristics)
- Serializers with `fields = "__all__"` (extra scrutiny on sensitive-looking serializer names)
- Global list pagination and upload-related settings
- Per-view `AllowAny` on DRF-style classes (review hint, not full authz proof)

**Static analysis (Python + templates)**

- XSS-prone patterns (`mark_safe`, `SafeString`, disabling template auto-escaping)
- SSRF-style outbound HTTP when the URL is not a fixed string (heuristic)
- Risky deserialization and `eval` / `exec`
- Secrets in logging calls and hardcoded secret-like names
- **SQL injection hints (heuristic):** non-literal SQL passed to `execute` / `executemany`, `RawSQL(...)`, or `Model.objects.raw(...)` (**DJG075**)

**Models, concurrency, performance**

- Natural-key / identifier fields without uniqueness; risky `CASCADE` edges
- Race-prone ORM patterns, missing `transaction.atomic`, counters without `F()` / locking
- Per-test query count, repeated SQL shapes, DB time (profile mode); static N+1-style hints

**Optional integrations**

- **pip-audit** (vulnerable dependencies), **Bandit**, **Semgrep** (enable in config or environment)

---

<details>
<summary><strong>Contents</strong></summary>

- [Install and run](#install-and-run)
- [At a glance: what gets checked](#at-a-glance-what-gets-checked)
- [Why django_security_hunter](#why-django_security_hunter)
- [What it finds](#what-it-finds)
- [Features](#features)
- [Documentation](#documentation)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Environment variables](#environment-variables)
- [Configuration](#configuration)
- [CLI options](#cli-options)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [Use in GitHub / GitLab CI](#use-in-github--gitlab-ci)
- [Docker](#docker)
- [Security notes](#security-notes)
- [Limitations](#limitations)
- [Roadmap](#roadmap--future-work)
- [Contributing](#contributing)
- [License](#license)

</details>

---

## Why django_security_hunter

AI-assisted coding speeds up delivery but can hide risky backend patterns. This tool gives **fast, actionable feedback** in the editor and in **CI**, before code ships.

## What it finds

`django-security-hunter` combines **loaded Django settings** (when you pass `--settings`), **static analysis** of Python and HTML templates, optional **pytest-based query profiling**, and optional **pip-audit / Bandit / Semgrep**. Findings use stable rule IDs (**DJG001** … **DJG062**); the full catalog with severities and fix hints is in **[docs/rules.md](docs/rules.md)**.

Below is what each area is meant to catch. Most rules are **heuristic**—useful for triage, not a substitute for manual review or penetration testing.

### Django settings (`settings.py` and related)

| Topic | Examples (rule IDs) |
|------|----------------------|
| **Production safety** | `DEBUG=True`, weak or hardcoded `SECRET_KEY`, empty / wildcard `ALLOWED_HOSTS` (**DJG001–DJG003**) |
| **HTTPS & cookies** | Missing or weak `SECURE_SSL_REDIRECT`, HSTS, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` (**DJG004–DJG007**) |
| **Browser hardening** | `SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS` (**DJG008–DJG009**) |
| **CSRF & CORS** | Over-broad `CSRF_TRUSTED_ORIGINS`, `CORS_ALLOW_ALL_ORIGINS`, loose CORS allowlists (**DJG010–DJG012**) |
| **Upload / DoS-style limits** | Very large `DATA_UPLOAD_MAX_MEMORY_SIZE` / related Django limits (**DJG026**, also checked from settings) |

### Django REST Framework (API surface)

| Topic | Examples (rule IDs) |
|------|----------------------|
| **Defaults too open** | Missing or `AllowAny` default permissions; missing default authentication classes (**DJG020–DJG021**) |
| **Abuse & discovery** | Throttling disabled globally; auth-like URL patterns without matching throttle discipline (**DJG022–DJG023**) |
| **Data exposure** | `Meta.fields = "__all__"` on serializers—**escalated** when the serializer name looks sensitive (e.g. user/payment-style) (**DJG024**) |
| **Operational limits** | No global list pagination; very large upload settings (**DJG025–DJG026**) |
| **Per-view permissions** | DRF-style classes that list `AllowAny`—**review only**, not full object-level authz (**DJG027**) |

### Static code patterns (`.py` and templates)

| Topic | Examples (rule IDs) |
|------|----------------------|
| **XSS-style footguns** | `mark_safe`, `SafeString`, templates that force raw HTML (`safe` filter, `{% autoescape off %}`) (**DJG070**) |
| **SSRF-style calls** | `requests` / `httpx` `.get()` (and similar) where the URL is not a constant string—**heuristic** (**DJG071**) |
| **Unsafe deserialization & code execution** | `pickle` / `marshal`, unsafe YAML loaders, `eval` / `exec` (**DJG072**) |
| **Secrets in logs** | Logging calls that likely include passwords, tokens, or `Authorization` (**DJG073**) |
| **Hardcoded secrets** | Assignments to names like `SECRET_*`, `API_KEY`, `PASSWORD`, etc. (**DJG074**) |
| **SQL injection (heuristic)** | f-strings, `%` / `.format` on SQL text, or variable SQL as the first argument to `.execute()` / `.executemany()`, `RawSQL()`, or `*.objects.raw()` (**DJG075**) |

### Models, concurrency, and performance

| Topic | Examples (rule IDs) |
|------|----------------------|
| **Schema hints** | Identifier-like fields without uniqueness; risky `on_delete=CASCADE` toward sensitive-related models (**DJG080–DJG081**) |
| **Concurrency** | Check-then-create races, writes outside `transaction.atomic`, counter updates without `F()` / locking hints (**DJG050–DJG052**) |
| **ORM / SQL behaviour** | High query counts, repeated SQL shapes, or high DB time **per test** (profile mode); static loop/queryset N+1-style hints (**DJG040–DJG042**, **DJG045**) |

### Dependencies and external scanners (optional)

| Tool | Role |
|------|------|
| **pip-audit** | Known vulnerable dependencies (**DJG060**) |
| **Bandit** | Broader Python security issues reported by Bandit (**DJG061**) |
| **Semgrep** | Community / custom rules (e.g. Django/Python packs)—can surface **additional** issue classes (**DJG062**) |

### What is *not* a built-in guarantee

- **SQL injection:** **DJG075** is **heuristic** (syntax-level only): it does **not** trace data from request to database. Safe uses like `cursor.execute(sql, params)` where `sql` is built in a trusted module may still **WARN**. For deeper coverage, use the ORM, parameterized queries, and optional **Semgrep** / **Bandit** rulesets.
- **Authorization:** **DJG027** flags permissive DRF permissions; it does **not** prove or disprove object-level access control.
- **False positives / negatives:** documented per rule in [docs/rules.md](docs/rules.md); tune `--threshold` and optional scanners for your risk appetite.

## Features

| | Area | What you get |
|---|------|----------------|
| 🔍 | **Scan** | Django settings (DJG001–DJG012), DRF defaults & URLs (DJG020–DJG027), static AST rules (DJG024, DJG050–052, DJG070–075, DJG080–081) |
| ⚡ | **Profile** | Pytest-driven query counts, duplicate SQL hints, DB time (DJG040–DJG042); static N+1-style hints (DJG045) |
| 📄 | **Reports** | `console` (Rich when TTY), stable **JSON** (`schema_version`), **SARIF 2.1.0** for Code Scanning |
| 🔌 | **Integrations** | Optional **pip-audit** (DJG060), **Bandit** (DJG061), **Semgrep** (DJG062) via config or env |
| ✓ | **CI** | Exit code `2` when findings meet `--threshold` |

## Documentation

| Doc | Link |
|-----|------|
| Rule catalog | [docs/rules.md](docs/rules.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| GitHub Code Scanning & SARIF | [docs/github_code_scanning.md](docs/github_code_scanning.md) |

## Requirements

- **Python** 3.11+
- **Django** 4.2+ (declared dependency)
- **Profile mode**: `pytest` in the target project; `pytest-django` recommended for ORM tests

## Installation

**PyPI**

```bash
pip install django-security-hunter
```

- **Import name:** `django_security_hunter`
- **CLI:** `django_security_hunter` or `djangoguard` (same entry point)

**From source** (folder name can match your clone):

```bash
git clone https://github.com/abu-rayhan-alif/djangoSecurityHunter.git django-security-hunter
cd django-security-hunter
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux / macOS
# source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick start

**You need:** a terminal, Python 3.11+, and a Django project folder that contains `manage.py`.

1. **Install the tool**

   ```bash
   pip install django-security-hunter
   ```

2. **Go to your project root** (same folder as `manage.py`).

3. **Run a scan** — replace `mysite.settings` with your real settings module (the same string you use for `DJANGO_SETTINGS_MODULE`):

   ```bash
   django_security_hunter scan --project . --settings mysite.settings --format console
   ```

   Without `--settings`, many checks still run on your Python files, but **Django settings checks** (e.g. `DEBUG`, `SECRET_KEY`, `ALLOWED_HOSTS`) are skipped.

4. **Save a report to a file** (optional):

   ```bash
   django_security_hunter scan --project . --settings mysite.settings --format json --output reports/scan.json
   django_security_hunter scan --project . --settings mysite.settings --format sarif --output reports/scan.sarif
   ```

5. **Fail CI when something serious is found** — add `--threshold HIGH` (or `WARN` / `CRITICAL`). If any finding is at or above that level, the command exits with code `2`.

   ```bash
   django_security_hunter scan --project . --settings mysite.settings --threshold HIGH --format console
   ```

## Commands

### `django_security_hunter scan`

Static and configuration analysis; writes a report in the chosen format.

### `django_security_hunter profile`

Static heuristics (e.g. DJG045) plus, by default, a nested **`pytest`** run with **`django_security_hunter.profile_pytest`**, recording per-test **query count**, **SQL time**, and **repeated SQL signatures** (DJG040–DJG042 / DJG041). Thresholds: `query_count_threshold`, `db_time_ms_threshold` in config.

```bash
django_security_hunter profile --project . --settings mysite.settings --format console
```

### `django_security_hunter init`

Creates **`djangoguard.toml`** with defaults (skipped if `djangoguard.toml` or legacy `django_security_hunter.toml` already exists).

## Environment variables

| Variable | Purpose |
|----------|---------|
| `DJANGO_SECURITY_HUNTER_PIP_AUDIT` | `1`/`true`/`on` runs pip-audit (**DJG060**); `0`/`false`/`off` forces off |
| `DJANGOGUARD_BANDIT` | Same pattern for Bandit (**DJG061**); needs `bandit` installed |
| `DJANGOGUARD_SEMGREP` | Same for Semgrep (**DJG062**); needs `semgrep` on `PATH` |
| `DJANGOGUARD_SEMGREP_CONFIGS` | Comma-separated Semgrep configs (default `p/python,p/django`) |
| `DJANGOGUARD_SKIP_PYTEST_PROFILE` | `1` skips nested pytest in `profile` (e.g. this repo’s tests) |
| `DJANGOGUARD_PROFILE_DJANGO_DB_ONLY` | `1` — only DJG040–042 for `@pytest.mark.django_db` tests |
| `DJANGOGUARD_PROFILE_DJANGO_FALLBACK` | `1` — if pytest yields no rows, try Django `DiscoverRunner` |

If unset for pip-audit/Bandit/Semgrep, use `pip_audit` / `bandit` / `semgrep` in `djangoguard.toml` or `enable_*` aliases (see [Configuration](#configuration)).

## Configuration

**Files (later overrides earlier)**

1. `pyproject.toml` → `[tool.django_security_hunter]`
2. `pyproject.toml` → `[tool.djangoguard]`
3. `django_security_hunter.toml` in project root
4. `djangoguard.toml` in project root (highest precedence)

**Example**

```toml
severity_threshold = "WARN"
query_count_threshold = 50
db_time_ms_threshold = 200
# pip_audit = true
# bandit = true
# semgrep = true
# Legacy aliases also work: enable_pip_audit, enable_bandit, enable_semgrep
```

## CLI options

| Option | Description |
|--------|-------------|
| `--project` | Project root (default: current directory) |
| `--settings` | Django settings module (e.g. `mysite.settings`) |
| `--format` | `console` · `json` · `sarif` |
| `--output` | Write report to file (UTF-8) |
| `--threshold` | `INFO` · `WARN` · `HIGH` · `CRITICAL` — exit `2` if any finding ≥ threshold |
| `--force-color` / `--no-color` | Console styling (when supported) |

## Rule highlights

| Rule ID | Severity | Topic |
|---------|----------|--------|
| DJG001 | CRITICAL | `DEBUG=True` in production settings |
| DJG002 | HIGH | Suspicious `SECRET_KEY` |
| DJG020 | HIGH | DRF default permissions / `AllowAny` |
| DJG040–DJG042 | WARN/HIGH | Profile: queries, duplicates, DB time |
| DJG070 | HIGH | XSS-related patterns (e.g. `mark_safe`) |
| DJG075 | HIGH/WARN | Heuristic SQL injection patterns (`execute`/`raw`/`RawSQL` with dynamic SQL) |

Full list: **[docs/rules.md](docs/rules.md)**.

## Output formats

- **Console** — human-readable; Rich panels on a TTY when enabled.
- **JSON** — includes `schema_version`: `django_security_hunter.report.v1` for stable parsing.
- **SARIF** — v2.1.0, GitHub-friendly (`columnKind`, safe artifact URIs).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--threshold` |
| `2` | One or more findings at or above threshold |

## Use in GitHub / GitLab CI

> [!NOTE]
> `pip install` only installs the command-line tool. It does **not** create `.github/workflows` or `.gitlab-ci.yml` for you. You copy a small YAML file once, then every push can run the scan automatically.

### This repository (developers of django-security-hunter)

Our own CI is in [`.github/workflows/ci.yml`](.github/workflows/ci.yml). For SARIF and the Security tab, see [docs/github_code_scanning.md](docs/github_code_scanning.md).

### Your Django project on GitHub Actions

Do this **in your app’s GitHub repo** (not in this tool’s repo):

1. Create the folder `.github/workflows/` if it does not exist.
2. Copy [`examples/ci/github-actions-django-app.yml`](examples/ci/github-actions-django-app.yml) into that folder, e.g. as `django-security-hunter.yml`.
3. Open the file and change **`yourproject.settings`** to your real settings module (e.g. `config.settings`).
4. If the job needs your dependencies, uncomment the `pip install -r requirements.txt` line (or add your install steps).
5. Commit and push. Check the **Actions** tab — the workflow should run on push and pull requests.
6. **Optional — block bad PRs:** In GitHub → **Settings → Branches → Branch protection**, add a rule and enable **Require status checks**, then select this workflow’s check.

### Your Django project on GitLab

1. Copy [`examples/ci/gitlab-ci.yml`](examples/ci/gitlab-ci.yml) to the **root** of your repo as `.gitlab-ci.yml`.
2. Change **`yourproject.settings`** to your real settings module.
3. Commit and push. Open **CI/CD → Pipelines** to see the job.

### Where the example files live

The YAML templates are in this repository under [`examples/ci/`](examples/ci/). They are **not** bundled inside the PyPI wheel; people usually copy them from GitHub or from a checkout of this repo.

## Docker

```bash
docker build -t django_security_hunter:local .
docker run --rm django_security_hunter:local django_security_hunter scan --project /app --format console
```

```bash
docker compose run --rm django_security_hunter django_security_hunter scan --project /app --format console
```

## Security notes

- The tool **reads your project files** and may **spawn subprocesses** (pytest, pip-audit, Bandit, Semgrep) when enabled. Use it on **trusted trees**; review CI secrets and third-party scanner configs.
- **SARIF / JSON** paths are normalized to reduce odd `uri` values in reports.
- **Settings module** names are validated before `django.setup()` to reduce injection-style mistakes.
- Automated scans (Bandit, etc.) report **Low** findings for expected `subprocess` use; there is **no `shell=True`** in those call sites.

## Limitations

- Several rules are **heuristic** (false positives possible). **DJG027** is not a full object-level authorization audit.
- **Bandit / Semgrep** are optional; first Semgrep run may fetch rule packs.
- **Profile** quality depends on pytest coverage and Django DB tests where relevant.

## Roadmap / future work

- Deeper URLconf → view resolution and richer authz modeling
- Per-rule toggles in config
- Richer runtime evidence where tests allow

## Contributing

1. Open an issue for large changes  
2. Add tests for new rules  
3. Keep rule IDs stable and documented in `docs/rules.md`  
4. Include `fix_hint` on findings  

## License

MIT
