"""Profiles load strictly, roots resolve against the audited home, remedies fill templates."""

import tomllib
from pathlib import Path

import pytest

from ai_footprint.harnesses import base, registry
from ai_footprint.harnesses.base import Harness, RemedyContext
from ai_footprint.harnesses.common import Context
from ai_footprint.harnesses.profile import Profile, ProfileError, Remedy, parse
from ai_footprint.model import ToolPresence, ToolReport
from tests.conftest import FakeSystem

MINIMAL = """
name = "demo"
display_name = "Demo"
binaries = ["demo"]
process = "(^|/)demo(\\\\s|$)"
presence = ["{home}"]
roots = { home = { env = "DEMO_HOME", default = "~/.demo" } }
"""


def load(extra: str = "") -> Profile:
    return parse("demo/profile.toml", tomllib.loads(MINIMAL + extra))


def demo_harness(profile: Profile) -> Harness:
    def collect(ctx: Context, found: ToolPresence) -> ToolReport:
        del ctx
        return ToolReport(name="demo", display_name="Demo", installed=found.installed)

    return Harness(profile=profile, collect_fn=collect)


def context(home: Path, env: dict[str, str] | None = None) -> Context:
    system = FakeSystem()
    system.env.update(env or {})
    return Context(home=home, system=system, now=0)


def test_every_registered_profile_loads_and_matches_its_package():
    harnesses = registry()
    assert list(harnesses) == sorted(harnesses)
    for name, harness in harnesses.items():
        assert harness.profile.name == name
        assert harness.profile.binaries
        assert harness.claims


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ('surprise = "x"\n', "unknown key(s) surprise"),
        ('[[artifacts]]\nlabel = "x"\npath = "/abs"\ncategory = "config"\n', "must start with"),
        ('[[artifacts]]\nlabel = "x"\npath = "{home}/x"\ncategory = "secret"\n', "not one of"),
        (
            '[remedies.require-approval]\nsummary = "s"\ncommands = [{ run = "a", manual = "b" }]',
            "exactly one of run",
        ),
        ('[remedies.unknown-fix]\nsummary = "s"\ncommands = []\n', "not one of"),
        (
            '[[features]]\nkind = "env"\nname = "X"\nsummary = "s"\n'
            '[[features]]\nkind = "env"\nname = "X"\nsummary = "t"\n',
            "duplicate feature env:X",
        ),
        ('capabilities = ["telepathy"]\n', "not one of"),
    ],
)
def test_malformed_profiles_name_the_file_and_the_problem(extra: str, message: str):
    with pytest.raises(ProfileError, match=r"demo/profile\.toml") as raised:
        load(extra)
    assert message in str(raised.value)


def test_a_missing_required_key_is_named():
    raw = tomllib.loads(MINIMAL)
    del raw["process"]
    with pytest.raises(ProfileError, match="missing key"):
        parse("demo/profile.toml", raw)


def test_roots_use_the_audited_home_unless_the_environment_moves_them(tmp_path: Path):
    profile = load()
    assert base.resolve_roots(context(tmp_path), profile) == {"home": tmp_path / ".demo"}
    moved = base.resolve_roots(context(tmp_path, {"DEMO_HOME": "~/elsewhere"}), profile)
    assert moved == {"home": tmp_path / "elsewhere"}


def test_a_root_child_is_appended_to_the_base(tmp_path: Path):
    raw = tomllib.loads(MINIMAL)
    raw["roots"]["data"] = {"env": "XDG_DATA_HOME", "default": "~/.local/share", "child": "d"}
    profile = parse("demo/profile.toml", raw)
    roots = base.resolve_roots(context(tmp_path, {"XDG_DATA_HOME": "/xdg"}), profile)
    assert roots["data"] == Path("/xdg/d")


def test_only_existing_artifacts_are_reported_in_profile_order(tmp_path: Path):
    profile = load(
        '[[artifacts]]\nlabel = "B"\npath = "{home}/b.json"\ncategory = "config"\n'
        '[[artifacts]]\nlabel = "Missing"\npath = "{home}/gone"\ncategory = "log"\n'
        '[[artifacts]]\nlabel = "A"\npath = "{home}/a"\ncategory = "session"\n'
    )
    (tmp_path / ".demo" / "a").mkdir(parents=True)
    (tmp_path / ".demo" / "b.json").write_text("{}")
    assert [a.label for a in base.artifacts(context(tmp_path), profile)] == ["B", "A"]


def test_presence_is_a_data_folder_or_a_binary(tmp_path: Path):
    harness = demo_harness(load())
    assert not harness.detect(context(tmp_path)).installed
    (tmp_path / ".demo").mkdir()
    assert harness.detect(context(tmp_path)).installed


def test_remedy_templates_quote_run_arguments_but_not_manual_steps(tmp_path: Path):
    harness = demo_harness(
        load(
            "[remedies.remove-mcp]\n"
            'summary = "Remove it"\n'
            "commands = [\n"
            '  { run = "demo mcp remove $name", help = ["mcp", "remove"] },\n'
            '  { manual = "Or delete $name from the config", markers = ["mcpServers"] },\n'
            "]\n"
        )
    )
    fix = harness.remedy(Remedy.REMOVE_MCP, RemedyContext("darwin", tmp_path), name="a b; rm")
    assert fix is not None
    run, manual = fix.commands
    assert run.text == "demo mcp remove 'a b; rm'"
    assert run.help_probe == ("demo", "mcp", "remove")
    assert not run.markers and not run.marker_tool
    assert manual.text == "Or delete a b; rm from the config"
    assert manual.manual and manual.marker_tool == "demo"


def test_a_tool_without_a_remedy_returns_none(tmp_path: Path):
    harness = demo_harness(load())
    assert harness.remedy(Remedy.STOP_DAEMONS, RemedyContext("darwin", tmp_path)) is None


def test_a_template_placeholder_the_check_did_not_pass_fails_loudly(tmp_path: Path):
    harness = demo_harness(
        load('[remedies.remove-mcp]\nsummary = "s"\ncommands = [{ run = "demo rm $name" }]\n')
    )
    with pytest.raises(KeyError):
        harness.remedy(Remedy.REMOVE_MCP, RemedyContext("darwin", tmp_path))


def test_code_remedies_take_precedence_over_templates(tmp_path: Path):
    claude = registry()["claude"]
    fix = claude.remedy(Remedy.REQUIRE_APPROVAL, RemedyContext("linux", tmp_path))
    assert fix is not None
    assert "/etc/claude-code" in fix.commands[0].text
    trust = claude.remedy(Remedy.WITHDRAW_TRUST, RemedyContext("darwin", tmp_path))
    assert trust is not None
    assert trust.commands[0].markers == ("hasTrustDialogAccepted",)
