# django_security_hunter

Django + DRF Security, Reliability, and Performance Inspector.

`django_security_hunter` helps backend teams catch risky patterns early: security misconfigurations, authorization gaps, abuse-protection weaknesses, API correctness issues, and performance/reliability smells.

## Why django_security_hunter

AI-assisted coding improves speed, but it can also introduce hidden backend risks.  
`django_security_hunter` gives fast, actionable feedback during development and in CI before code reaches production.

## Features

- Static and configuration scanning for Django + DRF projects
- `profile` mode: nested `pytest` run with query capture (DJG040–DJG042) plus static query/N+1 hints (DJG045)
- Output formats: `console`, `json`, `sarif`
- CI-friendly exit codes by severity threshold
- GitHub Security integration through SARIF

## Documentation

- [Rule Catalog](docs/rules.md)
- [Architecture Overview](docs/architecture.md)
- [GitHub Code Scanning & PR checks (SARIF)](docs/github_code_scanning.md)

## Installation

From PyPI:

```bash
pip install django-security-hunter
```

Python package: import name **`django_security_hunter`**.  
CLI commands: **`django_security_hunter`** or **`djangoguard`** (same entrypoint).

From source (clone into a folder name that matches the project):

```bash
git clone https://github.com/abu-rayhan-alif/djangoGuard.git django-security-hunter
cd django-security-hunter
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -e .[dev]
```

## Quick Start

1. Open a terminal **in your Django project root** (the directory that contains `manage.py`).
2. Run:

```bash
django_security_hunter scan --project . --format console
```

To load Django settings-based rules (DJG001–DJG012), pass your settings module:

```bash
django_security_hunter scan --project . --settings yourproject.settings --format console
```

Other examples:

```bash
django_security_hunter scan --project . --format json --output reports/django_security_hunter.json
django_security_hunter scan --project . --format sarif --output reports/django_security_hunter.sarif
```

## Commands

### `django_security_hunter scan`

Runs static/config analysis and emits a report.

### `django_security_hunter profile`

Runs profiling rules: static heuristics (e.g. DJG045) and, unless disabled, a nested **`pytest`** invocation with the **`django_security_hunter.profile_pytest`** plugin. That records per-test **query count**, **cumulative SQL time**, and **repeated SQL signatures** (DJG040 / DJG042 / DJG041). Thresholds come from config (`query_count_threshold`, `db_time_ms_threshold`). Requires `pytest` on the project; for Django DB tests, `pytest-django` is recommended.

Example:

```bash
django_security_hunter profile --project . --settings yourproject.settings --format console
```

### `django_security_hunter init`

Creates **`djangoguard.toml`** in the project root with default thresholds (skips if `djangoguard.toml` or legacy `django_security_hunter.toml` already exists).

## Environment variables

- `DJANGO_SECURITY_HUNTER_PIP_AUDIT` — during `scan`, run `pip-audit` for **DJG060** when set to `1`/`true`/`on` (needs `pip-audit` installed; slower, may need network). Set to `0`/`false`/`off` to **force off** (overrides `pip_audit` in config). If unset, use the `pip_audit` boolean in `djangoguard.toml` / `[tool.djangoguard]`.
- `DJANGOGUARD_SKIP_PYTEST_PROFILE=1` — skip the nested `pytest` subprocess during `profile` (used by this repo’s own tests; unset in CI if you rely on **DJG040–DJG042**).
- `DJANGOGUARD_PROFILE_DJANGO_DB_ONLY=1` — during `profile`, only emit **DJG040–DJG042** for tests that carry the `@pytest.mark.django_db` marker (reduces noise from non-DB tests).
- `DJANGOGUARD_PROFILE_DJANGO_FALLBACK=1` — if `pytest` runs but records **no** test rows, run **`python -m django_security_hunter.django_profile_runner`** (Django `DiscoverRunner`) instead. If `pytest` is **not** installed, the Django runner is used automatically when `--settings` / `DJANGO_SETTINGS_MODULE` is set.
- `DJANGOGUARD_BANDIT` — `1`/`true` runs **[Bandit](https://github.com/PyCQA/bandit)** during `scan` (**DJG061**); `0`/`false` forces off. If unset, use `bandit = true` in config. Requires `pip install bandit`.
- `DJANGOGUARD_SEMGREP` — same pattern for **[Semgrep](https://semgrep.dev/)** (**DJG062**); needs the `semgrep` CLI on `PATH`. Optional: `DJANGOGUARD_SEMGREP_CONFIGS` (comma-separated rule packs, default `p/python,p/django`).

## Configuration files

- Preferred: **`djangoguard.toml`** or **`pyproject.toml`** → `[tool.djangoguard]`
- Legacy (still read): **`django_security_hunter.toml`**, **`[tool.django_security_hunter]`** (merged first; `djangoguard` values override).

## CLI Options

- `--project` Project root path
- `--settings` Django settings module (example: `config.settings`)
- `--format` `console | json | sarif`
- `--output` Output file path
- `--threshold` `INFO | WARN | HIGH | CRITICAL`

## Configuration

Values are merged in this order (later wins):

1. `pyproject.toml` → `[tool.django_security_hunter]`
2. `pyproject.toml` → `[tool.djangoguard]` (overrides the block above)
3. `django_security_hunter.toml` in the project root
4. `djangoguard.toml` in the project root (highest precedence)

Use either TOML file or `pyproject.toml` sections; you do not need both.

Example (`djangoguard.toml` or `[tool.djangoguard]` in `pyproject.toml`):

```toml
severity_threshold = "WARN"
query_count_threshold = 50
db_time_ms_threshold = 200
# pip_audit = true   # enable pip-audit during scan (optional; can use env instead)
```

## Rule Catalog (V1 Target)

| Rule ID | Severity | Description |
|---|---|---|
| DJG001 | CRITICAL | `DEBUG=True` in production |
| DJG002 | HIGH | Suspicious/hardcoded `SECRET_KEY` |
| DJG020 | HIGH | DRF default permissions missing or `AllowAny` |
| DJG040 | WARN/HIGH | Query count per test above threshold |
| DJG041 | HIGH | Repeated query signature indicates N+1 |
| DJG070 | HIGH | Risky XSS usage patterns detected |

> Full rules and implementation progress can be maintained in `docs/rules.md`.

## Output Formats

### Console

Human-readable output for local development.

### JSON

Stable schema for automation and custom dashboards.

### SARIF

SARIF v2.1.0 output for **GitHub Code Scanning** (upload in Actions → Security tab and check run annotations on PRs).

## Exit Codes

- `0`: No findings at or above threshold
- `2`: One or more findings at or above threshold

## GitHub Actions Integration

Workflow file: `.github/workflows/ci.yml`

On every push and pull request:
- installs dependencies
- runs tests
- generates SARIF report
- uploads SARIF to GitHub Security

Details (PR checks, Code Scanning, SARIF upload): [docs/github_code_scanning.md](docs/github_code_scanning.md).

## Docker

Build and run:

```bash
docker build -t django_security_hunter:local .
docker run --rm django_security_hunter:local django_security_hunter scan --project /app --format console
```

Using Docker Compose:

```bash
docker compose run --rm django_security_hunter django_security_hunter scan --project /app --format console
```

## Limitations

- Some rules are heuristic and may produce false positives (**DJG027** per-view `AllowAny` is not a full authorization audit).
- **Bandit** / **Semgrep** are optional; install tools separately; first Semgrep run may download rule packs.
- Runtime profiling depends on project test coverage quality.
- Rule precision improves with project-specific tuning and allowlists.

## Roadmap / future work

- Deeper URLconf → view resolution and richer authz modeling (beyond heuristics + **DJG027**)
- Per-rule toggles in config (beyond global flags)
- Richer runtime evidence (sampling, slow-query attribution) where tests permit

## Contributing

Contributions are welcome.

Please follow these guidelines:
1. Open an issue for major changes
2. Add tests for every new rule
3. Keep rule IDs stable and documented
4. Include remediation hints with findings

## License

MIT

