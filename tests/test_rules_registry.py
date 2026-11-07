import inspect

from ai_footprint import checks
from ai_footprint.checks import (
    base,
    local_code,
    machine,
    other_accounts,
    provider_copies,
    steering,
    stolen_token,
)

CHECK_MODULES = (local_code, machine, other_accounts, provider_copies, steering, stolen_token)


def test_every_rule_function_is_registered():
    defined = {
        fn
        for module in CHECK_MODULES
        for name, fn in inspect.getmembers(module, inspect.isfunction)
        if name.startswith("rule_") and fn.__module__ == module.__name__
    }
    registered = {r.fn for r in checks.TOOL_RULES} | {r.fn for r in checks.HOST_RULES}
    assert defined == registered


def test_every_rule_id_has_a_label():
    ids = [r.id for r in checks.TOOL_RULES] + [r.id for r in checks.HOST_RULES]
    assert all(base.label_for(rule_id) != rule_id for rule_id in ids)
