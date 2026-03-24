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

From source (recommended for now):

```bash
git clone <your-repo-url>
cd djangoguard
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -e .[dev]
```

## Quick Start

```bash
djangoguard scan --project . --format console
djangoguard scan --project . --format json --output reports/djangoguard.json
djangoguard scan --project . --format sarif --output reports/djangoguard.sarif
```

## Commands

### `djangoguard scan`

Runs static/config analysis and emits a report.

### `djangoguard profile`

Runs runtime-oriented profiling checks (currently scaffolded in v0.1).

### `djangoguard init`

Creates a default `djangoguard.toml` file in the target project.

## CLI Options

- `--project` Project root path
- `--settings` Django settings module (example: `config.settings`)
- `--format` `console | json | sarif`
- `--output` Output file path
- `--threshold` `INFO | WARN | HIGH | CRITICAL`

## Configuration

Configuration is loaded in this order:
1. `djangoguard.toml` (project override)
2. `pyproject.toml` -> `[tool.djangoguard]`

Example:

```toml
severity_threshold = "WARN"
query_count_threshold = 50
db_time_ms_threshold = 200
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

- Some future rules are heuristic and may produce false positives
- Runtime profiling depends on project test coverage quality
- Rule precision improves with project-specific tuning and allowlists

## Roadmap

- Django settings hardening rules (`DJG001-DJG012`)
- DRF auth/permission/throttle checks (`DJG020+`)
- Static code pattern rules (XSS/SSRF/deserialization/secrets)
- Concurrency and atomicity heuristics (`DJG050+`)
- Runtime N+1 and DB-time evidence improvements (`DJG040+`)
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
