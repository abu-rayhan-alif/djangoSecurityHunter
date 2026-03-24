from djangoguard.rules.static_patterns import run_static_pattern_rules


def test_static_pattern_rule_placeholder_returns_list() -> None:
    findings = list(run_static_pattern_rules())
    assert findings == []

