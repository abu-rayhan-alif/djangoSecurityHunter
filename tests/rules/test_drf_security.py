from djsecinspect.rules.drf_security import run_drf_security_rules


def test_drf_security_rule_placeholder_returns_list() -> None:
    findings = list(run_drf_security_rules())
    assert findings == []


