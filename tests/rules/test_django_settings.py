from djangoguard.rules.django_settings import run_django_settings_rules


def test_django_settings_rule_placeholder_returns_list() -> None:
    findings = list(run_django_settings_rules())
    assert findings == []

