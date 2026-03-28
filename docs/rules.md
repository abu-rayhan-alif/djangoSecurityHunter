# djsecinspect Rule Catalog

This document defines the rule IDs, severities, purpose, and remediation guidance for `djsecinspect`.

## Severity Model

- `INFO`: Informational finding; no immediate risk
- `WARN`: Potential weakness; review recommended
- `HIGH`: Significant security/reliability/performance risk
- `CRITICAL`: Severe risk that should block release

## Rule Status

- `planned`: Rule is designed but not yet implemented
- `in_progress`: Rule implementation has started
- `implemented`: Rule is active in scanner output

---

## Django Settings Security Rules (DJG-3)

| Rule ID | Severity | Status | Description | Typical Fix |
|---|---|---|---|---|
| DJG001 | CRITICAL | planned | `DEBUG=True` in production settings | Set `DEBUG = False` for production |
| DJG002 | HIGH | planned | Hardcoded/suspicious `SECRET_KEY` | Load from environment/secret manager |
| DJG003 | HIGH | planned | `ALLOWED_HOSTS` wildcard or empty | Set explicit production host allowlist |
| DJG004 | HIGH | planned | `SECURE_SSL_REDIRECT` missing/false | Enable `SECURE_SSL_REDIRECT = True` |
| DJG005 | WARN/HIGH | planned | `SECURE_HSTS_SECONDS` missing/too low | Set strong HSTS and preload strategy |
| DJG006 | HIGH | planned | `SESSION_COOKIE_SECURE=False` | Set `SESSION_COOKIE_SECURE = True` |
| DJG007 | HIGH | planned | `CSRF_COOKIE_SECURE=False` | Set `CSRF_COOKIE_SECURE = True` |
| DJG008 | WARN | planned | `SECURE_CONTENT_TYPE_NOSNIFF` missing | Enable `SECURE_CONTENT_TYPE_NOSNIFF = True` |
| DJG009 | WARN | planned | `X_FRAME_OPTIONS` missing/weak | Use `X_FRAME_OPTIONS = "DENY"` or strict value |
| DJG010 | WARN/HIGH | planned | `CSRF_TRUSTED_ORIGINS` misconfigured | Restrict to known HTTPS origins |
| DJG011 | HIGH | planned | `CORS_ALLOW_ALL_ORIGINS=True` | Disable allow-all and use explicit origins |
| DJG012 | WARN/HIGH | planned | Overly permissive CORS allowlist/regex | Tighten CORS patterns and origins |

---

## DRF Auth, Permission, Throttling, Validation Rules (DJG-4)

| Rule ID | Severity | Status | Description | Typical Fix |
|---|---|---|---|---|
| DJG020 | HIGH | planned | `DEFAULT_PERMISSION_CLASSES` missing or `AllowAny` | Set strict defaults (e.g., `IsAuthenticated`) |
| DJG021 | HIGH | planned | `DEFAULT_AUTHENTICATION_CLASSES` missing | Define authentication backends explicitly |
| DJG022 | WARN | planned | Throttling disabled globally | Configure DRF throttle classes/rates |
| DJG023 | HIGH | planned | Auth endpoints not throttled | Add aggressive throttle on login/token/reset routes |
| DJG024 | WARN/HIGH | planned | Serializer uses `fields="__all__"` on likely-sensitive models | Enumerate explicit safe fields |
| DJG025 | WARN/HIGH | planned | Missing pagination on list endpoints | Configure global pagination or per-view pagination |
| DJG026 | WARN | planned | Request size limit missing/too high | Set request/body size guardrails |

---

## Runtime Profiling and Query Analysis Rules (DJG-8)

| Rule ID | Severity | Status | Description | Typical Fix |
|---|---|---|---|---|
| DJG040 | WARN/HIGH | planned | Query count per test exceeds threshold | Optimize ORM usage and prefetch strategy |
| DJG041 | HIGH | planned | Repeated SQL signature suggests N+1 | Add `select_related` / `prefetch_related` |
| DJG042 | WARN | planned | DB time per test exceeds threshold | Reduce heavy queries and add indexes |

---

## Concurrency and Atomicity Heuristics (DJG-7)

| Rule ID | Severity | Status | Description | Typical Fix |
|---|---|---|---|---|
| DJG050 | WARN | planned | Check-then-create race pattern | Use atomic `get_or_create`, unique constraints |
| DJG051 | WARN/HIGH | planned | Multi-step writes without `transaction.atomic()` | Wrap writes in explicit transaction blocks |
| DJG052 | WARN | planned | Counter/stock updates without locking hints | Use `F()` updates and `select_for_update()` |

---

## Static Code Security Pattern Rules (DJG-5)

| Rule ID | Severity | Status | Description | Typical Fix |
|---|---|---|---|---|
| DJG070 | HIGH | planned | Risky XSS patterns (`mark_safe`, unsafe template usage) | Escape output and avoid unsafe rendering |
| DJG071 | WARN/HIGH | planned | SSRF risk in outbound requests with user URLs | Add URL allowlist and egress restrictions |
| DJG072 | HIGH | planned | Insecure deserialization (`pickle`, unsafe `yaml.load`) | Use safe parsers/loaders |
| DJG073 | HIGH | planned | Sensitive data logging (password/token/authorization) | Redact secrets in logs |
| DJG074 | WARN/HIGH | planned | Hardcoded secret-like literals | Move to env vars/secrets manager |

---

## Data Integrity and DB Design Rules (DJG-6)

| Rule ID | Severity | Status | Description | Typical Fix |
|---|---|---|---|---|
| DJG080 | WARN/HIGH | planned | Natural key fields missing uniqueness | Add `unique=True` or unique constraint/index |
| DJG081 | WARN | planned | Risky `on_delete=CASCADE` in critical/audit models | Use safer delete strategy and review data retention |

---

## Dependency and External Scanner Integration Rules (DJG-11)

Enable tools via `enable_pip_audit`, `enable_bandit`, or `enable_semgrep` in config, or CLI flags `--pip-audit`, `--bandit`, `--semgrep` (and `--no-*` to force off). Requires the corresponding CLI on `PATH` / `python -m` where applicable.

| Rule ID | Severity | Status | Description | Typical Fix |
|---|---|---|---|---|
| DJG060 | HIGH/CRITICAL | implemented | `pip-audit` reports high/critical vulnerable dependency | Upgrade/pin to fixed versions; re-lock deps |
| DJG061 | INFO–HIGH | implemented | Bandit finding (`python -m bandit`) | Address per Bandit test ID or narrow `# nosec` with rationale |
| DJG062 | INFO–HIGH | implemented | Semgrep finding (`semgrep scan --config=p/python`) | Fix per rule message or document false-positive suppressions |

---

## Design Principles for Rule Authors

1. Rule IDs are stable and never reused for different semantics.
2. Every finding should include a remediation hint.
3. Heuristic rules should document known false positive/negative scenarios.
4. Findings should include location metadata (`path`, `line`, `column`) whenever available.
5. CI behavior must remain deterministic for the same input and configuration.

## Notes on Heuristics

Some rules intentionally use best-effort heuristics.  
Heuristic results should be interpreted with engineering judgment and confirmed manually before major architectural changes.

