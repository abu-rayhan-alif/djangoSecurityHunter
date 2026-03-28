from django_security_hunter.rules.profiling import run_profiling_rules


def test_profiling_rule_placeholder_returns_list() -> None:
    findings = list(run_profiling_rules())
    assert findings == []



