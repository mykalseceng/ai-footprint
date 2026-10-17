"""The host page's data: one answer per question, findings without a question, and fixes."""

from pathlib import Path

from ai_footprint import document, rules
from ai_footprint.model import (
    AuditReport,
    CheckResult,
    CommandValidation,
    Exposure,
    Fix,
    FixCommand,
    HostFact,
    HostReport,
    Lens,
    ToolReport,
)

HOME = "/Users/tester"
CLAUDE_BRIDGE = (
    f"{HOME}/Library/Application Support/Google/Chrome/NativeMessagingHosts/"
    "com.anthropic.claude_browser_extension.json"
)


def make_audit(
    facts: list[HostFact], exposures: list[Exposure], tools: list[ToolReport] | None = None
) -> AuditReport:
    host = HostReport(
        os="macOS 26.2",
        kernel="25.2.0",
        arch="arm64",
        hostname="mac",
        user="tester",
        uid=501,
        home=HOME,
        home_mode="drwx------",
        facts=facts,
    )
    return AuditReport(
        generated_at="2026-10-12T09:00:00",
        auditor_version="0",
        host=host,
        tools=tools or [],
        host_exposures=exposures,
    )


def host_exposures(audit: AuditReport) -> list[Exposure]:
    ctx = rules.RuleContext(host=audit.host, platform="darwin", home=Path(HOME))
    found = []
    for rule in rules.HOST_RULES:
        found.extend(rule.fn(audit, ctx))
    return found


def host_view(facts: list[HostFact], tools: list[ToolReport] | None = None) -> dict:
    audit = make_audit(facts, [], tools)
    audit.host_exposures = host_exposures(audit)
    return document.build(audit, [])["views"]["host"]


def question(view: dict, finding_id: str) -> dict:
    return next(q for q in view["questions"] if q["finding_id"] == finding_id)


def pid(number: int, days: int, command: str) -> HostFact:
    return HostFact(
        "unattended", f"pid {number}", f"running for {days} days: {command}", concern=True
    )


def test_host_finding_names_itself_and_keeps_commands_in_evidence():
    audit = make_audit([pid(4242, 3, "claude --dangerously-skip-permissions")], [])
    [finding] = [x for x in host_exposures(audit) if x.id == "host:unattended"]
    assert finding.label == "Processes running without a session"
    assert "pid 4242" not in finding.statement
    assert any("--dangerously-skip-permissions" in line for line in finding.evidence)


def test_host_question_with_a_finding_is_answered_by_its_statement():
    facts = [
        HostFact(
            "control",
            "com.anthropic.claude_browser_extension",
            "Chrome bridge",
            CLAUDE_BRIDGE,
            concern=True,
        ),
        HostFact("control", "macOS privacy permissions", "could not read the TCC database"),
    ]
    audit = make_audit(facts, [])
    audit.host_exposures = host_exposures(audit)
    data = document.build(audit, [])
    control = question(data["views"]["host"], "host:computer-control")
    assert control["question"] == "What can drive this computer besides the terminal?"
    assert control["status"] == "review"
    [finding] = [x for x in audit.host_exposures if x.id == "host:computer-control"]
    assert control["answer"] == finding.statement
    assert finding.fix and finding.fix.summary == "Remove bridges and permissions you do not use"


def test_question_without_facts_gives_the_fallback_answer():
    other = question(host_view([]), "host:other-tools")
    assert other == {
        "topic": "other-tools",
        "question": "What about AI tools this audit doesn't cover?",
        "status": "clear",
        "answer": "None found.",
        "finding_id": "host:other-tools",
    }


def test_question_with_facts_but_no_finding_has_nothing_to_review():
    facts = [HostFact("backup", "Time Machine", "no backup destination configured")]
    backup = question(host_view(facts), "host:backups")
    assert backup["status"] == "clear"
    assert backup["answer"] == "Nothing to review."


def test_finding_without_a_question_is_listed_across_tools():
    finding = Exposure(
        id="host:shared-surfaces",
        tool="host",
        lens=Lens.MODEL,
        statement="~/.claude/skills is loaded by more than one tool.",
        label="One folder steers several tools",
        evidence=["~/.claude/skills: Claude Code, OpenCode"],
    )
    view = document.build(make_audit([], [finding]), [])["views"]["host"]
    assert view["across"] == ["host:shared-surfaces"]
    assert "host:shared-surfaces" not in {q["finding_id"] for q in view["questions"]}


def test_unattended_statement_counts_instead_of_listing_commands():
    long_command = f"{HOME}/.codex/packages/app-server-daemon/bin/codex app-server --listen"
    facts = [
        pid(1, 2, long_command),
        pid(2, 5, "claude --dangerously-skip-permissions"),
        HostFact(
            "unattended",
            "MCP server 'hopper' (claude)",
            "1 orphaned process(es) still running after their session ended",
            "/Apps/HopperMCPServer",
            concern=True,
        ),
        HostFact("unattended", "com.example.agent", "starts at login: claude", concern=True),
    ]
    audit = make_audit(facts, [])
    [finding] = [x for x in host_exposures(audit) if x.id == "host:unattended"]
    assert finding.statement == (
        "These keep running as you when you are not there: 2 AI-tool processes running for a "
        "day or more, 1 MCP server left running after the session ended and 1 login item. "
        "1 of them was started with approval prompts turned off."
    )
    assert any(long_command in line for line in finding.evidence)


def test_control_statement_leaves_paths_to_the_table():
    facts = [
        HostFact(
            "control",
            "Claude Desktop MCP 'hopper'",
            "/Apps/Hopper.app/MacOS/Hopper",
            "config.json",
            concern=True,
        ),
        HostFact(
            "control",
            "Codex Computer Use",
            "screen and input control helper",
            "/Apps/Codex Computer Use.app",
            concern=True,
        ),
    ]
    audit = make_audit(facts, [])
    [finding] = [x for x in host_exposures(audit) if x.id == "host:computer-control"]
    assert "/Apps/Hopper.app" not in finding.statement
    assert "Claude Desktop MCP 'hopper'" in finding.statement
    assert "Codex Computer Use (screen and input control helper)" in finding.statement


def test_inherited_credentials_sentence_agrees_with_one_tool():
    tool = ToolReport(name="claude", display_name="Claude Code", installed=True)
    tool.exposures.append(
        Exposure(id="claude:no-approval", tool="claude", lens=Lens.MODEL, statement="")
    )
    facts = [
        HostFact("reach", "GitHub CLI", "logged in", f"{HOME}/.config/gh/hosts.yml", concern=True)
    ]
    audit = make_audit(facts, [], [tool])
    [finding] = [x for x in host_exposures(audit) if x.id == "host:inherited-creds"]
    assert "Claude Code skips approval prompts in some sessions" in finding.statement


def test_manual_fix_steps_are_labelled_as_manual():
    fix = Fix(
        "Stop processes that outlived their sessions",
        [FixCommand("Quit the listed processes", manual=True)],
        [CommandValidation("Quit the listed processes", [CheckResult("manual step", True, "")])],
    )
    finding = Exposure(
        id="host:unattended",
        tool="host",
        lens=Lens.CODE,
        statement="These keep running as you when you are not there: 1 AI-tool process.",
        label="Processes running without a session",
        fix=fix,
    )
    data = document.build(make_audit([pid(7, 2, "codex app-server")], [finding]), [])
    assert data["views"]["fix_labels"]["host:unattended"] == [
        {
            "label": "manual step (not machine-checkable)",
            "badge": "manual step (not machine-checkable)",
            "tone": "neutral",
        }
    ]
    assert question(data["views"]["host"], "host:unattended")["status"] == "review"
