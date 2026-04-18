# django_security_hunter Architecture

This document explains the current architecture of `django_security_hunter` and the intended evolution path for V1.

## Goals

- Fast feedback for Django + DRF projects
- Deterministic, CI-friendly scanning behavior
- Stable report schema across output formats
- Extensible rule system for security, reliability, and performance checks

## High-Level Components

1. **CLI Layer** (`src/django_security_hunter/cli.py`)
   - Parses command-line arguments (`scan`, `profile`, `init`)
   - Loads configuration and threshold values
   - Runs engine mode and dispatches output writer
   - Returns CI-friendly exit codes

2. **Configuration Layer** (`src/django_security_hunter/config.py`)
   - Reads `pyproject.toml` (`[tool.django_security_hunter]`)
   - Reads `django_security_hunter.toml` project override
   - Produces a normalized runtime config object

3. **Engine Layer** (`src/django_security_hunter/engine.py`)
   - Owns execution flow for `scan` and `profile`
   - Builds report metadata
   - Runs built-in rule modules, optional external scanners, then **scan plugins** (entry points)

4. **Domain Model Layer** (`src/django_security_hunter/models.py`)
   - Defines `Finding` schema and `Report` aggregate
   - Provides deterministic threshold evaluation for exit behavior

5. **Output Layer** (`src/django_security_hunter/output.py`)
   - Converts report into:
     - Console output
     - JSON output
     - SARIF v2.1.0 output

## Execution Flow

### `scan` mode

1. User runs `django_security_hunter scan ...`
2. CLI resolves project root and settings module input
3. Config is loaded from TOML sources
4. Engine executes scan pipeline
5. Report is serialized into selected format
6. Threshold check sets process exit code (`0` or `2`)

### `profile` mode

1. User runs `django_security_hunter profile ...`
2. CLI and config flow are identical to `scan`
3. Engine executes profiling pipeline (runtime collectors)
4. Writers serialize findings
5. Threshold check applies the same CI gating behavior

## Data Contracts

## Finding Model

Core fields:
- `rule_id`
- `severity` (`INFO/WARN/HIGH/CRITICAL`)
- `title`
- `message`

Optional fields:
- `path`, `line`, `column`
- `fix_hint`
- `tags`
- `references`

## Report Model

- `mode` (`scan` or `profile`)
- `generated_at` (UTC ISO-8601)
- `metadata` (execution context)
- `findings` (ordered list)

## Ordering and Determinism

Deterministic behavior is critical for CI and SARIF diffs.

Recommended engine guarantees:
1. Stable rule registration order
2. Stable finding sort key:
   - severity rank (desc)
   - rule ID (asc)
   - path (asc)
   - line (asc)
3. Stable metadata keys where possible

## Output Pipeline

The output layer is intentionally decoupled from the engine:

- Engine returns one canonical `Report`
- Writers project that report into different representations

Advantages:
- JSON remains schema source-of-truth
- SARIF mapping is explicit and testable
- Console formatting can evolve without changing rule logic

## Exit Code Semantics

`django_security_hunter` uses severity threshold gating:

- Exit `0`: no findings at/above threshold
- Exit `2`: one or more findings at/above threshold

This supports strict CI policies while allowing lower-severity findings to remain visible.

## CI and Security Integration

GitHub Actions workflow:
- install package
- run tests
- generate SARIF (`django_security_hunter scan --format sarif`)
- upload SARIF to GitHub Security

This enables:
- PR-level annotations
- Security dashboard tracking
- auditable scanning in pipeline history

## Planned Rule Engine Expansion

For V1 implementation, the engine can evolve to this structure:

1. **Rule Registry**
   - Central list of rule classes/functions
   - Registry metadata: rule ID, category, default severity

2. **Scan Context**
   - Project root
   - parsed settings
   - source code index
   - optional heuristics cache

3. **Collectors**
   - Settings collector
   - AST collector
   - Regex/pattern collector
   - Runtime query collector (`profile`)

4. **Rule Executors**
   - Pure functions where possible
   - Context in, list of findings out
   - No writer/CLI concerns inside rules

5. **Post-processors**
   - Deduplication
   - Severity normalization
   - Final sorting

## Scan plugins (entry points)

Third-party packages can extend `scan` **without forking** by registering a callable under the
`importlib.metadata` group **`django_security_hunter.scan_plugins`**.

### Registration (consumer project)

In the plugin distribution’s `pyproject.toml`:

```toml
[project.entry-points."django_security_hunter.scan_plugins"]
my_rules = "my_package.plugin:run_scan"
```

The callable must be importable and have this shape:

- **Arguments:** `(project_root: Path, cfg: GuardConfig, django_settings_context: Mapping[str, Any])`
- **Returns:** iterable of `Finding` (same model as built-in rules)

Plugins run **after** built-in rules and external integrations (Bandit / Semgrep / pip-audit from config).
Each plugin is isolated: load failures and exceptions are recorded under `metadata["scan_plugins"]`
and do not abort the scan.

### Disabling plugins

- Config: `[tool.django_security_hunter] enable_scan_plugins = false`
- Environment: `DJANGO_SECURITY_HUNTER_PLUGINS=0` (or `false` / `no` / `off`)

### Optional follow-ups

- Explicit local path loading from config (not implemented)
- Richer plugin metadata (version pins, config schema) — evolve as needed

## Testing Strategy

1. **Unit Tests**
   - rule functions
   - severity/threshold behavior
   - config precedence

2. **Golden Output Tests**
   - JSON snapshot consistency
   - SARIF structural validation

3. **Integration Tests**
   - sample Django projects as fixtures
   - scan/profile command behavior

4. **Cross-Platform CI**
   - Linux + Windows compatibility checks

## Performance Considerations

- Minimize filesystem passes by sharing indexed file data across rules
- Cache parsed AST per file when multiple rules use it
- Prefer lazy imports for heavy optional runtime integrations
- Keep default scan fast; allow deep mode through explicit flags later

## Versioning and Backward Compatibility

- Rule IDs are stable and never repurposed
- JSON schema should be versioned on breaking changes
- SARIF output should preserve compatible field mappings across releases
- Deprecated rules should remain documented with migration notes

## Current State

Current repository status:
- CLI, config loading, report schema, and output formatting (console / JSON / SARIF in ``output.py``) are implemented
- Engine runs the full built-in rule pipeline, optional external scanners, and optional **scan plugins**
- CI, Docker, tests, and documentation baseline are in place

This allows incremental ticket-by-ticket implementation while preserving stable public interfaces.

