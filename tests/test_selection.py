import pytest

from ai_footprint.cli import SelectionError, select_tools
from ai_footprint.model import ToolPresence

PRESENT = [
    ToolPresence("claude", "Claude Code", installed=True),
    ToolPresence("codex", "Codex CLI", installed=False),
    ToolPresence("opencode", "OpenCode", installed=True),
]


def never_ask(prompt: str) -> str:
    raise AssertionError(f"should not prompt: {prompt}")


def test_named_tools_run_in_registry_order():
    assert select_tools(["opencode", "claude"], PRESENT, ask=never_ask) == ["claude", "opencode"]


def test_all_means_every_installed_tool():
    assert select_tools(["all"], PRESENT, ask=never_ask) == ["claude", "opencode"]


def test_no_names_without_a_terminal_runs_everything_installed():
    assert select_tools([], PRESENT, ask=None) == ["claude", "opencode"]


def test_uninstalled_tool_is_rejected_with_what_is_installed():
    with pytest.raises(SelectionError, match="codex not installed; installed: claude, opencode"):
        select_tools(["codex"], PRESENT, ask=never_ask)


def test_unknown_tool_is_rejected():
    with pytest.raises(SelectionError, match="unknown tool"):
        select_tools(["cursor"], PRESENT, ask=never_ask)


def test_nothing_installed_is_an_error():
    empty = [ToolPresence(p.name, p.display_name, installed=False) for p in PRESENT]
    with pytest.raises(SelectionError, match="none of the supported tools"):
        select_tools([], empty, ask=None)


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ("", ["claude", "opencode"]),
        ("all", ["claude", "opencode"]),
        ("2", ["opencode"]),
        ("opencode, 1", ["opencode", "claude"]),
    ],
)
def test_prompt_answers(answer: str, expected: list[str]):
    prompts: list[str] = []

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        return answer

    assert select_tools([], PRESENT, ask=ask) == expected
    assert "1) Claude Code (claude)" in prompts[0]
    assert "Codex" not in prompts[0]


def test_prompt_rejects_choices_not_listed():
    with pytest.raises(SelectionError, match="not one of the listed choices"):
        select_tools([], PRESENT, ask=lambda _prompt: "9")
