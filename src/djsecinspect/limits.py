"""Resource limits for config I/O and external scanner subprocess output."""

from __future__ import annotations

# pyproject / djsecinspect.toml — refuse pathological configs
MAX_TOML_CONFIG_BYTES = 512 * 1024

# pip-audit / Bandit / Semgrep JSON stdout — cap before json.loads and parsing
MAX_SCANNER_JSON_BYTES = 32 * 1024 * 1024

# Avoid CPU/memory blowups on malicious or broken tool output
MAX_FINDINGS_PER_SCANNER = 5000

