# djangoguard

Django + DRF Security, Reliability, and Performance Inspector.

`djangoguard` helps backend teams catch risky patterns early: security misconfigurations, authorization gaps, abuse-protection weaknesses, API correctness issues, and performance/reliability smells.

## Why djangoguard

AI-assisted coding improves speed, but it can also introduce hidden backend risks.  
`djangoguard` gives fast, actionable feedback during development and in CI before code reaches production.

## Features

- Static and configuration scanning for Django + DRF projects
- Runtime profiling mode scaffold for query explosion / N+1 detection
- Output formats: `console`, `json`, `sarif`
- CI-friendly exit codes by severity threshold
- GitHub Security integration through SARIF

## Documentation

- [Rule Catalog](docs/rules.md)
- [Architecture Overview](docs/architecture.md)

## Installation

### From PyPI

The package is published under the name **`django-guard-inspector`** (PyPI blocks names too similar to existing projects).

```bash
pip install django-guard-inspector
```

After install, the CLI command is still **`djangoguard`** (and `import djangoguard` in Python).

Requires **Python 3.11+** and a Django project when you run `scan` with `--settings`.

### From source (development)

```bash
git clone https://github.com/abu-rayhan-alif/djangoGuard.git
cd djangoGuard
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Quick Start

```bash
djangoguard scan --project . --format console
djangoguard scan --project . --format json --output reports/djangoguard.json
djangoguard scan --project . --format sarif --output reports/djangoguard.sarif
```

With Django settings (recommended for full rule coverage):

```bash
djangoguard scan --project . --settings mysite.settings --format console
```

## Commands

### `djangoguard scan`

Runs static/config analysis and emits a report.

### `djangoguard profile`

Runs runtime-oriented profiling checks (currently scaffolded in v0.1).

### `djangoguard init`

Creates a default `djangoguard.toml` file in the target project.

### `djangoguard hello`

Optional post-install check; prints version and author info.

The first time you run any command (e.g. `scan`) after install, a short “Thanks for using djangoguard” message may appear once per machine (skipped in CI or if `DJANGOGUARD_NO_THANKS=1`).

## CLI Options

- `--project` Project root path
- `--settings` Django settings module (example: `config.settings`)
- `--format` `console | json | sarif`
- `--output` Output file path
- `--threshold` `INFO | WARN | HIGH | CRITICAL`

## Configuration

Configuration is loaded in this order:

1. `djangoguard.toml` (project override)
2. `pyproject.toml` → `[tool.djangoguard]`

Example:

```toml
severity_threshold = "WARN"
query_count_threshold = 50
db_time_ms_threshold = 200
```

## Rule catalog (summary)

| Range | Focus |
|--------|--------|
| **DJG001–DJG012** | Django settings: DEBUG, `SECRET_KEY`, `ALLOWED_HOSTS`, HTTPS/HSTS, cookies, headers, CSRF/CORS |
| **DJG026** | HTTP upload / request size limits (best-effort) |
| **DJG020–DJG025** | DRF: defaults, auth-like URLs, serializers, pagination (heuristics where noted) |

Detailed IDs, severities, and remediation text: **[docs/rules.md](docs/rules.md)** (some “planned” rows there may lag behind the code; the scanner is the source of truth).

## Output Formats

### Console

Human-readable output for local development.

### JSON

Stable schema for automation and custom dashboards.

### SARIF

SARIF v2.1.0 output for GitHub PR annotations and Security tab integration.

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

## Docker

Build and run:

```bash
docker build -t djangoguard:local .
docker run --rm djangoguard:local djangoguard scan --project /app --format console
```

Using Docker Compose:

```bash
docker compose run --rm djangoguard djangoguard scan --project /app --format console
```

## Limitations

- Some rules are heuristic and may produce false positives
- Runtime profiling depends on project test coverage quality
- Rule precision improves with project-specific tuning and allowlists

## Roadmap

- Static code pattern rules (XSS / SSRF / deserialization / secrets in code) — see `docs/rules.md` (DJG-5+)
- Concurrency and atomicity heuristics (`DJG050+`)
- Runtime N+1 and DB-time evidence (`DJG040+`)
- Optional dependency vulnerability integrations

## Contributing

Contributions are welcome.

Please follow these guidelines:

1. Open an issue for major changes
2. Add tests for every new rule
3. Keep rule IDs stable and documented
4. Include remediation hints with findings

## License

MIT
