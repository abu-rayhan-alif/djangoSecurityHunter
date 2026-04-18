<div align="center">

<pre>
 ____    ____    _   _ 
|  _ \  / ___|  | | | |
| | | | \___ \  | |_| |
| |_| |  ___) | |  _  |
|____/  |____/  |_| |_|
</pre>

**django_security_hunter**

<sub>PyPI install name: `django-security-hunter` (hyphens) — same package.</sub>

### Security, reliability & performance for Django APIs

Static and config checks · optional query profiling · **SARIF** for GitHub Code Scanning

[![PyPI](https://img.shields.io/pypi/v/django-security-hunter.svg?style=flat-square&label=PyPI)](https://pypi.org/project/django-security-hunter/)
[![Python](https://img.shields.io/pypi/pyversions/django-security-hunter.svg?style=flat-square&label=Python)](https://pypi.org/project/django-security-hunter/)
[![License](https://img.shields.io/badge/License-MIT-0d1117?style=flat-square&labelColor=30363d)](https://github.com/abu-rayhan-alif/djangoSecurityHunter/blob/main/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/abu-rayhan-alif/djangoSecurityHunter/ci.yml?style=flat-square&label=CI&logo=github)](https://github.com/abu-rayhan-alif/djangoSecurityHunter/actions/workflows/ci.yml)
[![Security Policy](https://img.shields.io/badge/Security-Policy-1f6feb?style=flat-square)](https://github.com/abu-rayhan-alif/djangoSecurityHunter/blob/main/SECURITY.md)
[![GitHub Action](https://img.shields.io/badge/GitHub-Action-2088FF?style=flat-square&logo=github)](https://github.com/marketplace/actions/django-security-hunter)

**Install:** `pip install django-security-hunter` · **Import / CLI:** `django_security_hunter`

[Menu](#menu) · [Quick install](#quick-install) · [GitHub Action](#github-action) · [Install & run](#install-and-run) · [Quick start](#quick-start) · [At a glance](#at-a-glance-what-gets-checked) · [CI](#use-in-github--gitlab-ci) · [Rules](docs/rules.md) · [**GitHub** (star / contribute)](https://github.com/abu-rayhan-alif/djangoSecurityHunter) · [“Django settings were not loaded” — how to fix](#when-django-settings-fail-to-load) · [Issues](https://github.com/abu-rayhan-alif/djangoSecurityHunter/issues)

Maintained by [Abu Rayhan Alif](https://github.com/abu-rayhan-alif)

</div>

## GitHub Action

**[Django Security Hunter](https://github.com/marketplace/actions/django-security-hunter)** on the GitHub Marketplace — fast, automated security and performance inspector for Django and DRF.

**Installation:** copy and paste into your workflow `.yml` (for example under `jobs.<job_id>.steps`):

```yaml
- name: Django Security Hunter
  uses: abu-rayhan-alif/djangoSecurityHunter@v0.5.0
```

Learn more in **[abu-rayhan-alif/djangoSecurityHunter](https://github.com/abu-rayhan-alif/djangoSecurityHunter)** and in [Use in GitHub / GitLab CI](#use-in-github--gitlab-ci).

---

> [!TIP]
> **New here?** Start from **[Quick install](#quick-install)** (copy-paste only), then [Install and run](#install-and-run) for flags & safety, [Quick start](#quick-start) for a numbered walkthrough, and [CI](#use-in-github--gitlab-ci) when you automate.

> [!IMPORTANT]
> **Why teams choose this tool:** one CLI for Django+DRF checks, CI-friendly exit codes, and SARIF output for GitHub Security tab visibility.

---

## Menu

Jump by topic — each link jumps to **one focused section** (GitHub only renders a single scrolling page; use this list like a side nav).

### Get running

- **[Quick install](#quick-install)** — only install + one scan command (copy-paste)
- **[GitHub Action](#github-action)** — Marketplace workflow snippet
- **[Install and run](#install-and-run)** — what the CLI expects, `--allow-project-code`, JSON/SARIF
- **[Quick start](#quick-start)** — numbered walkthrough (first-time)
- **[Installation](#installation)** — PyPI + clone / editable install

### Learn what it checks

- **[At a glance: what gets checked](#at-a-glance-what-gets-checked)** — short checklist
- **[Why django_security_hunter](#why-django_security_hunter)** — motivation
- **[What it finds](#what-it-finds)** — tables by area / rule IDs
- **[Features](#features)** — capability overview
- **[Documentation](#documentation)** · [Requirements](#requirements)

### CLI & config

- **[Commands](#commands)** · **[CLI options](#cli-options)** · **[“Settings not loaded” — fix](#when-django-settings-fail-to-load)** · **[Configuration](#configuration)** · **[Environment variables](#environment-variables)** · **[Rule highlights](#rule-highlights)**

### Output, CI, Docker

- **[Output formats](#output-formats)** · **[Exit codes](#exit-codes)**
- **[Use in GitHub / GitLab CI](#use-in-github--gitlab-ci)** · **[Docker](#docker)**

### Project & safety

- **[Security notes](#security-notes)** · **[Limitations](#limitations)** · **[Roadmap / future work](#roadmap--future-work)** · **[Contributing](#contributing)** · **[License](#license)**

**Related docs:** [Rules (full catalog)](docs/rules.md) · [Architecture](docs/architecture.md) · [GitHub Code Scanning & SARIF](docs/github_code_scanning.md)

---

## Quick install

From your **Django project root** (folder with `manage.py`). Replace `yourproject.settings` with the same value as `DJANGO_SETTINGS_MODULE`.

```bash
pip install django-security-hunter
django_security_hunter scan --project . --settings yourproject.settings --allow-project-code --format console
```

Short flags:

```bash
django_security_hunter scan -p . -s yourproject.settings -y -f console
```

Next: [Install and run](#install-and-run) (flags & safety), [Quick start](#quick-start) (step-by-step), or [GitHub Action](#github-action) (CI).

---

## Install and run

This package is a **standalone CLI** (it does **not** register a `manage.py` subcommand). **Minimal commands** are in [Quick install](#quick-install) above.

`--allow-project-code` confirms that you allow the tool to load and execute project code paths (for example, Django settings import side effects). Use it only for repositories you trust/control.

Replace `yourproject.settings` with the same module you use for `DJANGO_SETTINGS_MODULE` (for example `config.settings` or `mysite.settings`). Omitting `--settings` still runs many file-based checks, but **Django settings rules** (e.g. `DEBUG`, `SECRET_KEY`, `ALLOWED_HOSTS`, HTTPS cookies) are skipped.

**Optional:** write reports to disk as JSON or SARIF (for GitHub Code Scanning):

```bash
django_security_hunter scan --project . --settings yourproject.settings --allow-project-code --format json --output reports/scan.json
django_security_hunter scan --project . --settings yourproject.settings --allow-project-code --format sarif --output reports/scan.sarif
```

### When Django settings fail to load

> **TL;DR** · The scan **did run** on your files. · You only **miss** rules that read live Django settings (`DEBUG`, `SECRET_KEY`, `REST_FRAMEWORK`, …). · **Fastest fix:** use the **same secrets/env** you use for `runserver` (often export `DJANGO_SECRET_KEY`), or pass a CI-only settings module with a placeholder key.

#### Typical terminal output

You may see lines like this on **stderr** (yellow + cyan “Tip”):

```text
Django settings were not loaded; DJG001–DJG012 and DRF settings-based rules …
The SECRET_KEY setting must not be empty.
Tip: export the variable your settings use for SECRET_KEY …
```

That is **not a crash** — it means Django refused to finish booting, so those rule groups were skipped.

#### In plain English

| | |
|--|--|
| **What went wrong** | The CLI calls `django.setup()` when you use `--settings`. Django (and your `settings.py`) may require env vars that are missing in **this** terminal (very often `SECRET_KEY`). |
| **What you still get** | Code/template static checks (e.g. XSS hints, SQL-shape hints, many DJG02x/07x rules). |
| **What you miss until fixed** | Anything that needs loaded settings: **DJG001–DJG012**, **DJG020–DJG023**, **DJG025–DJG026**. |

#### Fix checklist

1. **Match `manage.py`**  
   Use the **same** `--settings` module string as `DJANGO_SETTINGS_MODULE` (e.g. `mysite.settings`, `config.settings`).

2. **Allow imports**  
   Keep **`--allow-project-code`** (`-y`) when using `--settings` (see [Install and run](#install-and-run)).

3. **Set a non-empty `SECRET_KEY` in the environment** before scanning — match whatever your settings module reads (common names: `DJANGO_SECRET_KEY`, `SECRET_KEY`). Use a disposable value for local or CI scans only; do not commit real production secrets.

   **bash / macOS / Linux**

   ```bash
   export DJANGO_SECRET_KEY="local-scan-only-not-for-production-$(openssl rand -hex 24)"
   django_security_hunter scan --project . --settings yourproject.settings --allow-project-code --format console
   ```

   **PowerShell**

   ```powershell
   $env:DJANGO_SECRET_KEY = "local-scan-only-not-for-production-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
   django_security_hunter scan --project . --settings yourproject.settings --allow-project-code --format console
   ```

   If you normally use **`.env`**, load it in that shell first (e.g. `source .env` with a tool you trust, or copy the needed lines into `export` / `$env:…`).

4. **CI / scan-only settings (optional)**  
   Add something like **`settings_ci.py`** with a long placeholder `SECRET_KEY` used **only** for scans, then:  
   `--settings yourproject.settings_ci`.

#### Still stuck?

Double-check `PYTHONPATH` / project layout if the settings module imports app packages, and that you are scanning from the same directory you use for `manage.py`.

PyPI **Project links** (Homepage, Source, Issues, Documentation, Changelog) come from `[project.urls]` in `pyproject.toml` and point at this repo so you can **star**, **fork**, or **open PRs** on GitHub.

---

## Quick start

**You need:** a terminal, Python 3.11+, and a Django project folder that contains `manage.py`.

1. **Install the tool**

   ```bash
   pip install django-security-hunter
   ```

2. **Go to your project root** (same folder as `manage.py`).

3. **Run a scan** — replace `mysite.settings` with your real settings module (the same string you use for `DJANGO_SETTINGS_MODULE`):

   ```bash
   django_security_hunter scan --project . --settings mysite.settings --allow-project-code --format console
   ```

   Without `--settings`, many checks still run on your Python files, but **Django settings checks** (e.g. `DEBUG`, `SECRET_KEY`, `ALLOWED_HOSTS`) are skipped.

4. **Save a report to a file** (optional):

   ```bash
   django_security_hunter scan --project . --settings mysite.settings --allow-project-code --format json --output reports/scan.json
   django_security_hunter scan --project . --settings mysite.settings --allow-project-code --format sarif --output reports/scan.sarif
   ```

5. **Fail CI when something serious is found** — add `--threshold HIGH` (or `WARN` / `CRITICAL`). If any finding is at or above that level, the command exits with code `2`.

   ```bash
   django_security_hunter scan --project . --settings mysite.settings --allow-project-code --threshold HIGH --format console
   ```

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

## Why django_security_hunter

AI-assisted coding speeds up delivery but can hide risky backend patterns. This tool gives **fast, actionable feedback** in the editor and in **CI**, before code ships.

## What it finds

`django_security_hunter` combines **loaded Django settings** (when you pass `--settings`), **static analysis** of Python and HTML templates, optional **pytest-based query profiling**, and optional **pip-audit / Bandit / Semgrep**. Findings use stable rule IDs (**DJG001** … **DJG062**); the full catalog with severities and fix hints is in **[docs/rules.md](docs/rules.md)**.

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

**Feature cards (quick view)**

- **Secure-by-default checks**: Django settings, DRF defaults, static security patterns, and model integrity hints in one run.
- **CI-ready output**: human console output for devs and SARIF for GitHub Security tab workflows.
- **Performance visibility**: profile mode surfaces query count, duplicate SQL, and DB time hotspots.
- **Extensible scanning**: optional `pip-audit`, Bandit, and Semgrep integration when teams need deeper coverage.

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
- **CLI:** `django_security_hunter`

**From source** (folder name can match your clone):

```bash
git clone https://github.com/abu-rayhan-alif/djangoSecurityHunter.git django_security_hunter
cd django_security_hunter
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux / macOS
# source .venv/bin/activate
pip install -e ".[dev]"
```

## Commands

### `django_security_hunter scan`

Static and configuration analysis; writes a report in the chosen format.

### `django_security_hunter profile`

Static heuristics (e.g. DJG045) plus, by default, a nested **`pytest`** run with **`django_security_hunter.profile_pytest`**, recording per-test **query count**, **SQL time**, and **repeated SQL signatures** (DJG040–DJG042 / DJG041). Thresholds: `query_count_threshold`, `db_time_ms_threshold` in config.

```bash
django_security_hunter profile --project . --settings mysite.settings --allow-project-code --format console
```

Short form:

```bash
django_security_hunter profile -p . -s mysite.settings -y -f console
```

### `django_security_hunter init`

Creates **`djangoguard.toml`** with defaults (skipped if `djangoguard.toml` or legacy `django_security_hunter.toml` already exists).

## Environment variables

| Variable | Purpose |
|----------|---------|
| `DJANGO_SECURITY_HUNTER_PIP_AUDIT` | `1`/`true`/`on` runs pip-audit (**DJG060**); `0`/`false`/`off` forces off |
| `DJANGOGUARD_BANDIT` | Same pattern for Bandit (**DJG061**); needs `bandit` installed |
| `DJANGOGUARD_SEMGREP` | Same for Semgrep (**DJG062**); needs `semgrep` on `PATH` |
| `DJANGOGUARD_SEMGREP_CONFIGS` | Comma-separated Semgrep `--config` values (default `p/python,p/django`); tokens starting with `-` or containing control characters are skipped (see logs) |
| `DJANGOGUARD_SKIP_PYTEST_PROFILE` | `1` skips nested pytest in `profile` (e.g. this repo’s tests) |
| `DJANGOGUARD_PROFILE_DJANGO_DB_ONLY` | `1` — only DJG040–042 for `@pytest.mark.django_db` tests |
| `DJANGOGUARD_PROFILE_DJANGO_FALLBACK` | `1` — if pytest yields no rows, try Django `DiscoverRunner` |
| `DJANGO_SECURITY_HUNTER_PLUGINS` | `0`/`off` disables third-party scan plugins (`importlib.metadata` entry points in group `django_security_hunter.scan_plugins`); `1`/`on` forces them on regardless of TOML `enable_scan_plugins` |

For **pip-audit, Bandit, and Semgrep**, setting the matching env var to **`1` / `true` / `on` or `0` / `false` / `off`** overrides TOML for that tool; if the env var is unset, use `pip_audit` / `bandit` / `semgrep` (or legacy `enable_*`) in `djangoguard.toml` / `pyproject.toml` ([Configuration](#configuration)).

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
# enable_scan_plugins = true
# score_weight_info = 1
# score_weight_warn = 5
# score_weight_high = 15
# score_weight_critical = 40
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
| `--allow-project-code` | Required for `profile`, and for `scan` when `--settings` is used (acknowledges code execution risk) |
| `--trend-history` | Optional JSON file path to persist score history and include trend deltas in report metadata |

Short aliases: `-p` (`--project`), `-s` (`--settings`), `-f` (`--format`), `-o` (`--output`), `-t` (`--threshold`), `-y` (`--allow-project-code`).

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

### This repository (developers of django_security_hunter)

Our own CI is in [`.github/workflows/ci.yml`](.github/workflows/ci.yml). For SARIF and the Security tab, see [docs/github_code_scanning.md](docs/github_code_scanning.md).

### Your Django project on GitHub Actions

Do this **in your app’s GitHub repo** (not in this tool’s repo):

1. Create the folder `.github/workflows/` if it does not exist.
2. Copy [`examples/ci/github-actions-django-app.yml`](examples/ci/github-actions-django-app.yml) into that folder, e.g. as `django_security_hunter.yml`.
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
docker run --rm django_security_hunter:local scan --project /app --format console
```

```bash
docker compose run --rm django_security_hunter scan --project /app --format console
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
