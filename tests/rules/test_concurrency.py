from django_security_hunter.rules.concurrency import run_concurrency_rules


def test_concurrency_rule_placeholder_returns_list() -> None:
    findings = list(run_concurrency_rules())
    assert findings == []



