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
   - Executes registered rules (current skeleton returns empty findings)

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

## Future Plugin Design (Proposed)

To support external rule packs and optional integrations:

### Plugin Interface

Each plugin provides:
- plugin ID and version
- list of rule definitions
- optional config schema
- engine compatibility version

### Discovery Options

1. Python entry points (`django_security_hunter.rules`)
2. Explicit local path loading from config
3. Built-in + external hybrid registry

### Safety Rules

- Plugins should run in-process with strict exception boundaries
- Rule exceptions should not crash the full scan
- Plugin failures should produce diagnostics in metadata

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
- CLI, config loading, report schema, and writers are implemented
- Engine is scaffolded and ready for rule integration
- CI, Docker, tests, and documentation baseline are in place

This allows incremental ticket-by-ticket implementation while preserving stable public interfaces.

