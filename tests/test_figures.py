"""Figures count what they say, and the independent recount catches any number that drifts."""

import copy
import json
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from ai_footprint import document, figurecheck, figures, fsinfo, rules
from ai_footprint.audit import run_audit
from ai_footprint.model import (
    Artifact,
    AuditReport,
    Category,
    CommandValidation,
    ExecRecord,
    Exposure,
    HostReport,
    Lens,
    SecretKindSummary,
    SecretScan,
    Setting,
    ToolReport,
)
from tests.conftest import (
    FakeSystem,
    build_claude_home,
    build_codex_home,
    build_opencode_home,
    build_pi_home,
)


class QuietFakeSystem(FakeSystem):
    def validate_probes(self) -> list[CommandValidation]:
        return []


@pytest.fixture(scope="module")
def doc() -> Iterator[dict]:
    home = Path(tempfile.mkdtemp(prefix="aifp-fig-", dir="/tmp"))
    home.chmod(0o755)
    build_claude_home(home)
    build_codex_home(home)
    build_opencode_home(home)
    build_pi_home(home)
    audit, checklist = run_audit(
        system=QuietFakeSystem(other_users=("guest",)), home=home, scan=True, workers=1
    )
    yield json.loads(json.dumps(document.build(audit, checklist)))
    shutil.rmtree(home)


def artifact(path: str, size: int, category: Category = Category.SESSION) -> Artifact:
    return Artifact("x", path, category, "", exists=True, size_bytes=size)


def scanned(name: str, unique: int, files: int) -> ToolReport:
    tool = ToolReport(name, name.title(), installed=True)
    tool.secret_scan = SecretScan(
        roots=[f"~/.{name}"],
        files_scanned=files,
        kinds=[SecretKindSummary("k", "Kind", unique=unique, files=1)],
    )
    return tool


# --- what each figure counts ----------------------------------------------------------------


def test_nested_and_repeated_locations_are_added_once():
    listed = [
        artifact("/h/.tool", 100),
        artifact("/h/.tool/logs", 40),
        artifact("/h/.tool/", 100),
        artifact("/h/.tool-other", 7),
    ]
    assert [a.path for a in fsinfo.outermost(listed)] == ["/h/.tool", "/h/.tool-other"]
    assert fsinfo.disk_bytes(listed) == 107


def test_secret_count_across_tools_never_calls_itself_distinct():
    one = figures.for_tool(scanned("claude", 3, 10), [])
    [single] = [f for f in one if f.id == "secrets"]
    assert single.detail.startswith("distinct values")
    audit_tools = [scanned("claude", 3, 10), scanned("codex", 4, 1200)]
    [summed] = [f for f in figures.machine(_audit(audit_tools), [], []) if f.id == "secrets"]
    assert summed.value == 7
    assert summed.display == "7"
    assert (
        summed.detail
        == "distinct within each tool's data, added across 2 tools; 1,210 files scanned"
    )


def test_approval_is_found_not_found_or_not_checked_from_recorded_settings():
    tool = ToolReport("opencode", "OpenCode", installed=True)
    assert figures.approval(tool).value == "not checked"
    codex = ToolReport("codex", "Codex CLI", installed=True)
    codex.settings.append(Setting("approval_policy", "not set", ""))
    state = figures.approval(codex)
    assert state.value == "not found"
    assert "approval_policy = not set" in state.detail
    codex.exposures.append(
        Exposure("codex:no-approval", "codex", Lens.MODEL, "", evidence=["approval_policy = never"])
    )
    assert figures.approval(codex).value == "found"


def test_method_summary_counts_probe_and_tool_runs_from_the_command_log():
    audit = _audit([])
    audit.executed = [
        ExecRecord(["/usr/bin/codesign"], 0, "Verify probe binary is Apple-signed"),
        ExecRecord(["/x/codex", "--version"], 0, "Confirm tool version"),
        ExecRecord(["/x/codex", "login", "--help"], 0, "Confirm subcommand exists"),
    ]
    text = figures.method_summary(audit)
    assert "It ran 3 commands" in text
    assert "1 from its probe registry and 2 of installed AI-tool binaries" in text
    assert "Apple" not in text


# --- the independent recount ----------------------------------------------------------------


def failures(doc: dict) -> list[str]:
    return [
        f"{v.command}: {c.name}"
        for v in figurecheck.check_figures(doc)
        for c in v.checks
        if not c.passed
    ]


def test_recount_agrees_with_every_figure_of_a_real_audit(doc: dict):
    assert failures(doc) == []


def _set(doc: dict, path: list, value: object) -> dict:
    changed = copy.deepcopy(doc)
    target = changed
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return changed


def _machine_index(doc: dict, figure_id: str) -> int:
    return next(i for i, f in enumerate(doc["views"]["figures"]["machine"]) if f["id"] == figure_id)


@pytest.mark.parametrize(
    ("figure_id", "field", "value"),
    [
        ("disk", "value", 1),
        ("secrets", "display", "1 distinct"),
        ("signals", "value", 0),
        ("checks", "display", "0 of 1"),
        ("tools", "value", 99),
        ("secrets", "detail", "distinct values"),
    ],
)
def test_recount_catches_a_tampered_overview_figure(doc: dict, figure_id, field, value):
    index = _machine_index(doc, figure_id)
    tampered = _set(doc, ["views", "figures", "machine", index, field], value)
    assert failures(tampered)


def test_recount_catches_a_tampered_tool_figure_grid_cell_and_chart(doc: dict):
    tools = doc["views"]["figures"]["tools"]
    name = next(iter(tools))
    index = next(i for i, f in enumerate(tools[name]) if f["id"] == "approval")
    assert failures(_set(doc, ["views", "figures", "tools", name, index, "value"], "not found"))
    lens = next(iter(doc["views"]["signals_matrix"]))
    assert failures(_set(doc, ["views", "signals_matrix", lens, "host"], 42))
    assert failures(_set(doc, ["views", "disk", 0, "parts", "session"], 1))
    assert failures(_set(doc, ["views", "method"], "The audit ran 1 command."))


def test_recount_catches_a_check_marked_clear_or_unchecked_against_its_signals(doc: dict):
    exposed = next(i for i, c in enumerate(doc["checklist"]) if c["exposures"])
    assert failures(_set(doc, ["checklist", exposed, "exposed"], False))
    assert failures(_set(doc, ["checklist", exposed, "unchecked"], "no input"))


def test_recount_adds_a_location_listed_inside_another_once(doc: dict):
    tool = doc["tools"][0]
    inner = {**tool["artifacts"][0], "path": tool["artifacts"][0]["path"] + "/inner"}
    nested = _set(doc, ["tools", 0, "artifacts"], [*tool["artifacts"], inner])
    assert figurecheck._bytes(nested["tools"][0]["artifacts"]) == figurecheck._bytes(
        tool["artifacts"]
    )


def test_recount_catches_overlapping_scan_roots(doc: dict):
    roots = doc["tools"][0]["secret_scan"]["roots"]
    overlapping = _set(doc, ["tools", 1, "secret_scan", "roots"], [roots[0] + "/sub"])
    assert any("never read the same folder" in f for f in failures(overlapping))


def test_recount_catches_a_headline_with_a_stale_secret_count(doc: dict):
    headline = doc["views"]["machine"]["headline"]
    index = next(i for i, line in enumerate(headline) if "holding" in line)
    stale = headline[index].replace("holding ", "holding 9", 1)
    assert failures(_set(doc, ["views", "machine", "headline", index], stale))


# --- checks that cannot run say so ----------------------------------------------------------


def test_a_check_without_its_input_is_not_checked_and_one_with_a_signal_never_is(doc: dict):
    rows = {(c["scope"], c["check"]): c for c in doc["checklist"]}
    approval = "Approval not turned off by a recorded setting"
    assert rows[("OpenCode", approval)]["unchecked"].startswith("this audit records no")
    assert not rows[("OpenCode", approval)]["exposures"]
    assert rows[("Claude Code", approval)]["exposed"]
    assert not rows[("Claude Code", approval)]["unchecked"]
    assert all(not (c["unchecked"] and c["exposures"]) for c in doc["checklist"])


def test_every_tool_rule_declares_why_it_could_not_run_or_always_can():
    tool = ToolReport("claude", "Claude Code", installed=True)
    ctx = rules.RuleContext(host=_audit([]).host, platform="darwin", home=Path("/h"))
    reasons = {rule.id: rule.needs(tool, ctx) for rule in rules.TOOL_RULES}
    always = {"instructions", "autostart", "daemons", "duplicate-installs"}
    assert {rule_id for rule_id, reason in reasons.items() if not reason} == always


def _audit(tools: list[ToolReport]) -> AuditReport:
    host = HostReport("macOS", "", "arm64", "mac", "me", 501, "/h", "700")
    return AuditReport(generated_at="", auditor_version="0", host=host, tools=tools)
