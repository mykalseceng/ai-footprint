import inspect

from ai_footprint import rules


def test_every_rule_function_is_registered():
    defined = {
        fn for name, fn in inspect.getmembers(rules, inspect.isfunction) if name.startswith("rule_")
    }
    registered = {r.fn for r in rules.TOOL_RULES} | {r.fn for r in rules.HOST_RULES}
    assert defined == registered


def test_every_rule_id_has_a_label():
    ids = [r.id for r in rules.TOOL_RULES] + [r.id for r in rules.HOST_RULES]
    assert all(rules._label(rule_id) != rule_id for rule_id in ids)
