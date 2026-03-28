# djangoguard

Django + DRF Security, Reliability, and Performance Inspector.

`djangoguard` helps backend teams catch risky patterns early: security misconfigurations, authorization gaps, abuse-protection weaknesses, API correctness issues, and performance/reliability smells.

## Why djangoguard

AI-assisted coding improves speed, but it can also introduce hidden backend risks.  
`djangoguard` gives fast, actionable feedback during development and in CI before code reaches production.

## Features

- Static and configuration scanning for Django + DRF projects
- Runtime **profile** mode: pytest-driven DB query capture (DJG040–DJG042)
- **Output formats:** `console`, `json`, `sarif` (SARIF **v2.1.0** for GitHub Code Scanning)
- **Stable JSON report schema** (`schema_version`: `djangoguard.report.v1`)
- CI-friendly exit codes by severity threshold
- GitHub Actions: scan + SARIF upload (see below)

## Documentation

- [Rule catalog](docs/rules.md)
- [Architecture](docs/architecture.md)

## Installation

From the repository:

```bash
git clone https://github.com/abu-rayhan-alif/djangoGuard.git
cd djangoGuard
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux/macOS
# source .venv/bin/activate
pip install -e ".[dev]"
```

The `djangoguard` CLI is installed via `[project.scripts]` in `pyproject.toml`.

## Quick start

```bash
# Human-readable (default)
djangoguard scan --project . --format console

# Machine-readable JSON (stable schema: see schema_version in output)
djangoguard scan --project . --format json --output reports/djangoguard.json

# SARIF for GitHub Code Scanning / PR annotations
djangoguard scan --project . --format sarif --output reports/djangoguard.sarif

# Django settings module (needed for DJG001–DJG012 when settings can be loaded)
djangoguard scan --project . --settings mysite.settings --format json
```

### Profile mode (runtime DB query analysis)

```bash
djangoguard profile --project . --format json --output reports/profile.json
```

Uses **pytest** (and **pytest-django** if installed) against `tests/` (or project root). Set `DJANGO_SETTINGS_MODULE` or pass `--settings` for Django ORM tests.

## Commands

| Command | Purpose |
|--------|---------|
| `djangoguard scan` | Static/config + rules that need project files or Django settings |
| `djangoguard profile` | Pytest run with per-test SQL capture (query count, N+1 heuristic, DB time) |
| `djangoguard init` | Create a starter `djangoguard.toml` in `--project` |

## CLI options

| Option | Description |
|--------|-------------|
| `--project` | Project root path (default: current directory) |
| `--settings` | Django settings module (e.g. `mysite.settings`); validated dotted name |
| `--format` | `console` \| `json` \| `sarif` |
| `--output` | Write report to this file (UTF-8) |
| `--threshold` | Exit code `2` if any finding ≥ this severity: `INFO` \| `WARN` \| `HIGH` \| `CRITICAL` |

Exit codes: `0` = no findings at/above threshold; `2` = threshold hit; other codes = CLI/config errors.

## Configuration

Loaded in order:

1. `[tool.djangoguard]` in `pyproject.toml`
2. `djangoguard.toml` in the project root (overrides)

Example `djangoguard.toml`:

```toml
severity_threshold = "WARN"
query_count_threshold = 50
db_time_ms_threshold = 200
```

Use `djangoguard init` to generate this file.

## JSON report schema (stable)

Every JSON report includes:

- `schema_version` — `djangoguard.report.v1` (bump only on incompatible changes)
- `tool` — `{ "name": "djangoguard", "version": "<package version>" }`
- `mode` — `scan` \| `profile`
- `generated_at` — ISO 8601 UTC timestamp
- `metadata` — run metadata (project root, runner, Django load status, profile stats, …)
- `findings` — sorted list of `{ rule_id, severity, title, message, path?, line?, column?, fix_hint?, tags, references }`

Parse `schema_version` before relying on field shapes.

## SARIF (v2.1.0)

- Emits `$schema` for SARIF 2.1.0, `version: "2.1.0"`, `runs[].columnKind: utf16CodeUnits` (GitHub-friendly).
- `tool.driver` includes `name`, `version`, `informationUri`, and `rules` (rule metadata).
- Each result includes `ruleId`, `ruleIndex`, `level`, `message`, and `locations` when `path` is present.

Upload in GitHub Actions with `github/codeql-action/upload-sarif` (see workflow below). Code Scanning must be enabled for the repository.

## Rule list (summary)

| Range | Topic |
|------|--------|
| DJG001–DJG012 | Django settings security (DEBUG, SECRET_KEY, HTTPS, cookies, CORS, …) |
| DJG020+ | DRF defaults, auth, throttling, serializers (see `docs/rules.md`) |
| DJG040–DJG042 | Profile: query count, N+1-style repeats, DB time per test |
| DJG050–DJG052 | Concurrency / `transaction.atomic` heuristics (static) |
| DJG070+ | Static security patterns (XSS, SSRF, deserialization, secrets in logs) |

Full table: **[docs/rules.md](docs/rules.md)**.

## GitHub Actions (scan + SARIF upload)

Minimal snippet (adjust branches and Python version as needed):

```yaml
name: djangoguard

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install
        run: |
          pip install -e ".[dev]"

      - name: Run djangoguard SARIF
        run: |
          mkdir -p reports
          djangoguard scan --project . --format sarif --output reports/djangoguard.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: reports/djangoguard.sarif
        # If Code Scanning is not enabled, allow the job to pass:
        # continue-on-error: true
```

The repository includes a fuller workflow in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (tests, lint, SARIF).

## Docker

```bash
docker build -t djangoguard:local .
docker run --rm djangoguard:local djangoguard scan --project /app --format console
```

## Limitations

- Rules that load Django settings need a valid `--settings` or `DJANGO_SETTINGS_MODULE`.
- Heuristic rules (concurrency, static patterns) can false-positive; tune thresholds and review findings.
- Profile mode depends on pytest and meaningful Django/ORM test coverage.
- SARIF upload requires GitHub **Code Scanning** (Advanced Security) where applicable.

## Contributing

1. Open an issue for large changes  
2. Add tests for new rules  
3. Keep rule IDs stable and document them in `docs/rules.md`  
4. Include remediation hints (`fix_hint`) on findings  

## License

MIT
