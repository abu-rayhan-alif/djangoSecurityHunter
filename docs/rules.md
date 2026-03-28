# django_security_hunter Rule Catalog

This document defines the rule IDs, severities, purpose, and remediation guidance for `django_security_hunter`.

## Severity Model

- `INFO`: Informational finding; no immediate risk
- `WARN`: Potential weakness; review recommended
- `HIGH`: Significant security/reliability/performance risk
- `CRITICAL`: Severe risk that should block release

## Rule Status

- `planned`: Rule is designed but not yet implemented
- `in_progress`: Rule implementation has started
- `implemented`: Rule is active in scanner output

### What the package implements today

| Area | Rule IDs | Notes |
|------|-----------|--------|
| Django settings | DJG001–DJG012 | Requires `--settings` / `DJANGO_SETTINGS_MODULE` so Django loads. |
| DRF config | DJG020–DJG027 | `REST_FRAMEWORK` + upload limits; **DJG023** inspects `urls.py` for auth-like paths vs throttling; **DJG027** is a per-view `AllowAny` heuristic (not full object-level authz). |
| Static AST scan | DJG024, DJG070–DJG074 | Scans project `*.py` (excludes `migrations/`, venvs, etc.). |
| Model / schema hints | DJG080–DJG081 | `models.py` / `*/models/*.py` heuristics. |
| Concurrency heuristics | DJG050–DJG052 | Includes `+=` on loop-bound ORM rows without `F()`. |
| Query / performance | DJG040–DJG042, DJG045 | **DJG040–042**: `profile` + `pytest -p django_security_hunter.profile_pytest`. **DJG045**: static loop/queryset hint (N+1-style). |
| Dependencies | DJG060 | `pip_audit` in config and/or env; `pip-audit` CLI. |
| CLI / config | — | Command **`djangoguard`**; config **`djangoguard.toml`** / `[tool.djangoguard]` (legacy names supported). |

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
| DJG020 | HIGH | implemented | `DEFAULT_PERMISSION_CLASSES` missing or `AllowAny` | Set strict defaults (e.g., `IsAuthenticated`); finding includes `REST_FRAMEWORK` snippet |
| DJG021 | HIGH | implemented | `DEFAULT_AUTHENTICATION_CLASSES` missing / empty | Explicit auth classes in `REST_FRAMEWORK` (snippet in finding) |
| DJG022 | WARN | implemented | Throttling disabled globally (no classes and no rates) | `DEFAULT_THROTTLE_*` snippet in finding |
| DJG023 | HIGH/WARN | implemented | Auth-like URL paths vs throttling (static `urls.py` + view resolve) | Per-route + global heuristics; see below |
| DJG024 | WARN/HIGH | implemented | `Meta.fields = "__all__"` on DRF serializers | **HIGH** if serializer class name matches sensitive tokens (User, Token, Payment, …); else **WARN** |
| DJG025 | WARN | implemented | No global list pagination (`PAGE_SIZE` / `DEFAULT_PAGINATION_CLASS`) | Snippet in finding; does not analyze per-view `pagination_class` |
| DJG026 | WARN | implemented | `DATA_UPLOAD_MAX_MEMORY_SIZE` very large (\> 50 MiB) | Does **not** flag “unset” (Django default applies) |
| DJG027 | WARN | implemented | DRF-like view class lists `AllowAny` in `permission_classes` | Review endpoint; use stricter permissions or object-level checks as appropriate |

### DJG-4 heuristics and limitations

- **Requires Django settings**: DJG020–022, DJG025–026 read `REST_FRAMEWORK` and related settings after `django.setup()` (same as DJG001–012). If settings are not loaded, these rules do not run.
- **DRF must be installed**: `rest_framework` in `INSTALLED_APPS`; otherwise DJG020–022 / DJG025–026 are skipped.
- **DJG023**: Scans `**/urls.py` for path patterns whose string looks like auth (login, token, password, oauth, …). Resolves `views.py` in the same package or dotted view strings under the project root when possible; lambdas/unresolved views fall back to global throttle settings. May false-negative on dynamic URLconf or includes; may false-positive if throttling is enforced only in middleware or upstream.
- **DJG024**: AST-only; matches classes whose bases look like `*Serializer`. Does not resolve `Meta.model` to a `models.py` symbol; sensitivity uses **serializer class name** regex as a proxy.
- **DJG025**: **Global** `REST_FRAMEWORK` pagination only. Views that define their own pagination without globals are not verified.
- **DJG026**: Best-effort; only warns when the numeric setting exceeds an internal threshold. Use reverse proxies and `DATA_UPLOAD_MAX_NUMBER_FIELDS` / streaming uploads for defense in depth.

Finding `fix_hint` fields are meant to be copy-paste starting points; adjust class paths and rates to your project.

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

## Dependency and External Scanner Integration Rules (DJG-11, Optional)

| Rule ID | Severity | Status | Description | Typical Fix |
|---|---|---|---|---|
| DJG060 | HIGH / CRITICAL | implemented | `pip-audit` when `pip_audit = true` in config and/or env (see README) | Upgrade or replace vulnerable package; **CRITICAL** when CVSS score ≥ 9.0 (best-effort) |
| DJG061 | HIGH / WARN / INFO | implemented | [Bandit](https://github.com/PyCQA/bandit) JSON when `bandit = true` and/or `DJANGOGUARD_BANDIT` (requires `bandit` installed) | Follow Bandit rule guidance; tune excludes in Bandit config if needed |
| DJG062 | varies | implemented | [Semgrep](https://semgrep.dev/) JSON when `semgrep = true` and/or `DJANGOGUARD_SEMGREP` (requires `semgrep` on `PATH`; optional `DJANGOGUARD_SEMGREP_CONFIGS`) | Fix or suppress per Semgrep; align packs with your stack |

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

