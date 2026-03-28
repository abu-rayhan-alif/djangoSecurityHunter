# django_security_hunter

[![PyPI version](https://img.shields.io/pypi/v/django-security-hunter.svg)](https://pypi.org/project/django-security-hunter/)
[![Python versions](https://img.shields.io/pypi/pyversions/django-security-hunter.svg)](https://pypi.org/project/django-security-hunter/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/abu-rayhan-alif/djangoGuard/blob/main/LICENSE)
[![CI](https://github.com/abu-rayhan-alif/djangoGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/abu-rayhan-alif/djangoGuard/actions/workflows/ci.yml)

**Django + DRF security, reliability, and performance inspector** — static and config checks, optional runtime query profiling, SARIF for GitHub Code Scanning.

---

## Contents

- [Why use it](#why-django_security_hunter)
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
- [GitHub Actions](#github-actions-integration)
- [Docker](#docker)
- [Security notes](#security-notes)
- [Limitations](#limitations)
- [Roadmap](#roadmap--future-work)
- [Contributing](#contributing)
- [License](#license)

---

## Why django_security_hunter

AI-assisted coding speeds up delivery but can hide risky backend patterns. This tool gives **fast, actionable feedback** in the editor and in **CI**, before code ships.

## Features

| Area | What you get |
|------|----------------|
| **Scan** | Django settings (DJG001–DJG012), DRF defaults & URLs (DJG020–DJG027), static AST rules (DJG024, DJG050–052, DJG070–074, DJG080–081) |
| **Profile** | Pytest-driven query counts, duplicate SQL hints, DB time (DJG040–DJG042); static N+1-style hints (DJG045) |
| **Reports** | `console` (Rich when TTY), stable **JSON** (`schema_version`), **SARIF 2.1.0** for Code Scanning |
| **Integrations** | Optional **pip-audit** (DJG060), **Bandit** (DJG061), **Semgrep** (DJG062) via config or env |
| **CI** | Exit code `2` when findings meet `--threshold` |

## Documentation

- [Rule catalog](docs/rules.md)
- [Architecture](docs/architecture.md)
- [GitHub Code Scanning & SARIF](docs/github_code_scanning.md)

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
git clone https://github.com/abu-rayhan-alif/djangoGuard.git django-security-hunter
cd django-security-hunter
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux / macOS
# source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick start

1. Open a terminal in your **Django project root** (directory with `manage.py`).
2. Run:

```bash
django_security_hunter scan --project . --format console
```

**Django settings rules** (DJG001–DJG012, DJG020–DJG026, …) need a settings module:

```bash
django_security_hunter scan --project . --settings yourproject.settings --format console
```

**JSON / SARIF**

```bash
django_security_hunter scan --project . --format json --output reports/django_security_hunter.json
django_security_hunter scan --project . --format sarif --output reports/django_security_hunter.sarif
```

## Commands

### `django_security_hunter scan`

Static and configuration analysis; writes a report in the chosen format.

### `django_security_hunter profile`

Static heuristics (e.g. DJG045) plus, by default, a nested **`pytest`** run with **`django_security_hunter.profile_pytest`**, recording per-test **query count**, **SQL time**, and **repeated SQL signatures** (DJG040–DJG042 / DJG041). Thresholds: `query_count_threshold`, `db_time_ms_threshold` in config.

```bash
django_security_hunter profile --project . --settings yourproject.settings --format console
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

## GitHub Actions integration

Workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — install, test, SARIF scan, upload to Code Scanning.

More detail: [docs/github_code_scanning.md](docs/github_code_scanning.md).

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
