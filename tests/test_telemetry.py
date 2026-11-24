"""Usage data: switch precedence, binary gating, other tools' logins and the two checks."""

import json
import tomllib
from pathlib import Path

import pytest

from ai_footprint import checks
from ai_footprint.checks import needs, provider_copies
from ai_footprint.harnesses import telemetry
from ai_footprint.harnesses.claude import account as claude_account
from ai_footprint.harnesses.codex import account as codex_account
from ai_footprint.harnesses.common import Context
from ai_footprint.harnesses.profile import Profile, parse
from ai_footprint.model import (
    OTHER_TOOL_LOGIN,
    USAGE,
    AccountNote,
    BinaryInfo,
    HostReport,
    ToolReport,
)
from tests.conftest import FakeSystem, bundle_markers

PROFILE = """
name = "demo"
display_name = "Demo"
binaries = ["demo"]
process = "demo"
presence = ["{home}"]
roots = { home = { default = "~/.demo" } }

[[telemetry]]
label = "Usage events"
host = "ingest.example.com"
sends = "counts"
identity = "a hash of another tool's account id"
default = "on"
markers = ["usage-marker"]
switches = [
  { name = "DEMO_OFFLINE", off = ["*"] },
  { name = "DEMO_TELEMETRY", on = ["1", "true"], off = ["*"] },
  { name = "telemetry.enabled", on = ["true"], off = ["false"] },
]

[[telemetry.reads]]
tool = "codex"
path = "~/.codex/auth.json"
fields = ["tokens.account_id", "tokens.id_token"]
sends = "a hash of the workspace id"
marker = "reads-marker"
"""
SECRET = "acct-not-for-the-report"


def demo() -> Profile:
    return parse("demo/profile.toml", tomllib.loads(PROFILE))


def context(home: Path, env: dict[str, str] | None = None) -> Context:
    system = FakeSystem()
    system.env.update(env or {})
    return Context(home=home, system=system, now=0, scan=False)


def installed(home: Path, markers: list[str], name: str = "demo") -> ToolReport:
    binary = home / "demo-bin"
    binary.write_bytes(b"\0".join(m.encode() for m in markers))
    report = ToolReport(name=name, display_name="Demo", installed=True)
    report.binaries = [BinaryInfo(path=str(binary), resolved=str(binary))]
    return report


def codex_login(home: Path, tokens: dict[str, str]) -> None:
    (home / ".codex").mkdir(exist_ok=True)
    (home / ".codex" / "auth.json").write_text(json.dumps({"tokens": tokens}))


def decided(env: dict[str, str], config: dict | None = None) -> telemetry.State:
    [stream] = demo().telemetry
    values = telemetry.read_values(demo(), [("env", env), ("config", config or {})])
    return telemetry.state(stream, values)


def test_unset_switches_leave_the_default():
    assert decided({}) == telemetry.State(on=True)


def test_the_first_switch_that_is_set_decides():
    state = decided({"DEMO_OFFLINE": "0", "DEMO_TELEMETRY": "1"})
    assert not state.on
    assert state.switch == "DEMO_OFFLINE"


@pytest.mark.parametrize(
    ("value", "on"), [("1", True), ("TRUE", True), ("0", False), ("maybe", False)]
)
def test_on_values_are_tried_before_a_wildcard_off(value: str, on: bool):
    assert decided({"DEMO_TELEMETRY": value}).on is on


def test_a_value_no_switch_lists_falls_through_to_the_next_switch():
    config = {"telemetry": {"enabled": False}}
    state = decided({}, config)
    assert not state.on
    assert state.value == telemetry.Value("false", "config")


def test_values_come_from_the_first_source_that_sets_them_and_empty_is_unset():
    values = telemetry.read_values(
        demo(),
        [("env", {"DEMO_TELEMETRY": "", "DEMO_OFFLINE": "1"}), ("file", {"DEMO_TELEMETRY": "0"})],
    )
    assert values["DEMO_TELEMETRY"] == telemetry.Value("0", "file")
    assert values["DEMO_OFFLINE"] == telemetry.Value("1", "env")


def test_a_stream_is_not_stated_without_its_markers_or_a_binary(tmp_path: Path):
    report = installed(tmp_path, ["something-else"])
    assert telemetry.notes(context(tmp_path), demo(), report, []) == []
    report.binaries = []
    assert telemetry.notes(context(tmp_path), demo(), report, []) == []


def test_a_stream_that_is_on_names_another_tools_login_keys_never_values(tmp_path: Path):
    codex_login(tmp_path, {"account_id": SECRET})
    report = installed(tmp_path, ["usage-marker", "reads-marker"])
    sources = [("the environment", {})]
    [stream, login] = telemetry.notes(context(tmp_path), demo(), report, sources)
    assert stream.topic == USAGE and stream.concern and not stream.signal
    assert stream.text.startswith("Usage events to ingest.example.com: on by default.")
    assert login.signal == OTHER_TOOL_LOGIN and login.concern
    held = "Codex CLI's login file ~/.codex/auth.json, which holds tokens.account_id here."
    assert held in login.text
    assert SECRET not in login.text


def test_no_login_note_when_the_stream_is_off(tmp_path: Path):
    codex_login(tmp_path, {"account_id": SECRET})
    report = installed(tmp_path, ["usage-marker", "reads-marker"])
    sources = [("the environment", {"DEMO_TELEMETRY": "0"})]
    [stream] = telemetry.notes(context(tmp_path), demo(), report, sources)
    assert not stream.concern
    assert "off (DEMO_TELEMETRY=0 in the environment)" in stream.text


@pytest.mark.parametrize(
    ("markers", "tokens"),
    [
        (["usage-marker"], {"account_id": SECRET}),
        (["usage-marker", "reads-marker"], {"account_id": ""}),
        (["usage-marker", "reads-marker"], {}),
    ],
)
def test_no_login_note_without_the_read_marker_or_the_keys(
    tmp_path: Path, markers: list[str], tokens: dict[str, str]
):
    codex_login(tmp_path, tokens)
    report = installed(tmp_path, markers)
    found = telemetry.notes(context(tmp_path), demo(), report, [])
    assert [n.signal for n in found] == [""]


def test_a_missing_or_malformed_login_file_yields_no_login_note(tmp_path: Path):
    report = installed(tmp_path, ["usage-marker", "reads-marker"])
    assert len(telemetry.notes(context(tmp_path), demo(), report, [])) == 1
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "auth.json").write_text("[not an object]")
    assert len(telemetry.notes(context(tmp_path), demo(), report, [])) == 1


def rule_ctx(home: Path) -> checks.RuleContext:
    host = HostReport(
        os="macOS",
        kernel="",
        arch="arm64",
        hostname="h",
        user="u",
        uid=501,
        home=str(home),
        home_mode="drwx------",
    )
    return checks.RuleContext(host=host, platform="darwin", home=home)


def test_each_check_reads_only_its_own_notes(tmp_path: Path):
    codex_login(tmp_path, {"account_id": SECRET})
    report = installed(tmp_path, ["usage-marker", "reads-marker"])
    report.account = telemetry.notes(context(tmp_path), demo(), report, [])
    ctx = rule_ctx(tmp_path)
    [usage] = provider_copies.rule_usage_data(report, ctx)
    [logins] = provider_copies.rule_other_logins(report, ctx)
    assert usage.id == "demo:usage-data" and usage.statement.startswith("Usage events")
    assert logins.id == "demo:other-logins" and "Codex CLI's login file" in logins.statement
    assert usage.fix is not None and usage.fix.summary == "Turn off the tool's usage data"


def test_a_stream_that_is_off_raises_neither_check(tmp_path: Path):
    report = installed(tmp_path, ["usage-marker"])
    sources = [("the environment", {"DEMO_OFFLINE": "1"})]
    report.account = telemetry.notes(context(tmp_path), demo(), report, sources)
    ctx = rule_ctx(tmp_path)
    assert provider_copies.rule_usage_data(report, ctx) == []
    assert provider_copies.rule_other_logins(report, ctx) == []
    assert needs.needs_usage_notes(report, ctx) == ""


def test_not_checked_says_whether_telemetry_is_unknown_or_unconfirmed(tmp_path: Path):
    ctx = rule_ctx(tmp_path)
    unknown = ToolReport(name="opencode", display_name="OpenCode", installed=True)
    unconfirmed = ToolReport(name="pi", display_name="pi", installed=True)
    assert "is known to this audit" in needs.needs_usage_notes(unknown, ctx)
    assert "does not confirm" in needs.needs_usage_notes(unconfirmed, ctx)


def claude_usage(home: Path, settings_env: dict, shell: dict, config: dict) -> list[AccountNote]:
    (home / ".claude").mkdir(exist_ok=True)
    (home / ".claude" / "settings.json").write_text(json.dumps({"env": settings_env}))
    report = installed(home, bundle_markers("claude"), name="claude")
    return claude_account.usage_notes(context(home, shell), report, config)


def test_claude_settings_env_block_turns_metrics_off(tmp_path: Path):
    [metrics, _errors] = claude_usage(tmp_path, {"DISABLE_TELEMETRY": "1"}, {}, {})
    assert not metrics.concern
    assert "off (DISABLE_TELEMETRY=1 in the env block of ~/.claude/settings.json)" in metrics.text


def test_claude_settings_env_block_overrides_the_shell(tmp_path: Path):
    [metrics, _errors] = claude_usage(tmp_path, {"DO_NOT_TRACK": "0"}, {"DO_NOT_TRACK": "1"}, {})
    assert metrics.concern


@pytest.mark.parametrize(
    ("org", "settings_env", "on"),
    [
        ("claude_max", {}, True),
        ("claude_team", {}, False),
        ("claude_max", {"DISABLE_ERROR_REPORTING": "0"}, False),
        ("claude_pro", {"CLAUDE_CODE_USE_BEDROCK": "true"}, False),
    ],
)
def test_claude_error_reports_follow_the_plan_unless_turned_off(
    tmp_path: Path, org: str, settings_env: dict, on: bool
):
    config = {"oauthAccount": {"organizationType": org}}
    [_metrics, errors] = claude_usage(tmp_path, settings_env, {}, config)
    assert errors.concern is on


def test_codex_analytics_is_on_until_config_toml_turns_it_off(tmp_path: Path):
    report = installed(tmp_path, bundle_markers("codex"), name="codex")
    ctx = context(tmp_path)
    [on] = [n for n in codex_account.notes(ctx, report, tmp_path, {}) if n.topic == USAGE]
    assert on.concern and "on by default" in on.text
    config = {"analytics": {"enabled": False}}
    [off] = [n for n in codex_account.notes(ctx, report, tmp_path, config) if n.topic == USAGE]
    assert not off.concern
    assert "analytics.enabled=false in " in off.text
