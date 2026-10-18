import html
import re
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from ai_footprint import document, report_html, rules
from ai_footprint.model import (
    AuditReport,
    Exposure,
    FactKind,
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


def host_view(audit: AuditReport) -> str:
    return report_html._host_view(audit, document.build(audit, [])["views"])


def host_page(facts: list[HostFact], tools: list[ToolReport] | None = None) -> str:
    audit = make_audit(facts, [], tools)
    audit.host_exposures = host_exposures(audit)
    return host_view(audit)


def block(page: str, anchor: str) -> str:
    start = page.index(f'id="{anchor}"')
    end = page.find('<div class="anchor"', start + 1)
    return page[start : end if end != -1 else len(page)]


def pid(number: int, days: int, command: str) -> HostFact:
    return HostFact(
        "unattended",
        f"pid {number}",
        f"running for {days} days: {command}",
        concern=True,
        kind=FactKind.LONG_RUNNING,
    )


def test_breakable_escapes_markup():
    out = report_html.breakable("<script>alert(1)</script><img src=x onerror=alert(1)>")
    assert "<script" not in out
    assert "<img" not in out
    assert out.replace("<wbr>", "") == html.escape(
        "<script>alert(1)</script><img src=x onerror=alert(1)>"
    )


def test_breakable_leaves_short_words_whole():
    for text in ("OpenCode", "zai-coding-plan", "Claude Code", "~/.claude"):
        assert report_html.breakable(text) == html.escape(text)


def test_breakable_adds_break_points_at_separators_in_long_paths():
    out = report_html.breakable(CLAUDE_BRIDGE)
    assert "Google/<wbr>Chrome/<wbr>NativeMessagingHosts/<wbr>" in out
    assert "com.<wbr>anthropic.<wbr>claude_<wbr>browser_<wbr>extension.<wbr>json" in out


@given(st.text(alphabet=st.sampled_from("ab/._:=|,@&<>\"' -"), max_size=80))
def test_breakable_only_adds_break_points_to_escaped_text(text: str):
    out = report_html.breakable(text)
    assert out.replace("<wbr>", "") == html.escape(text)
    assert not re.search(r"&[a-z#0-9]*<wbr>", out)


def test_host_tldr_names_findings_and_links_to_them():
    page = host_page([pid(4242, 3, "claude --dangerously-skip-permissions")])
    tldr = page[page.index('<div class="tldr">') : page.index("</header>")]
    assert '<a href="#host:unattended">Long-running or orphaned AI processes</a>' in tldr
    assert "pid 4242" not in tldr
    assert "--dangerously-skip-permissions" not in tldr


def test_host_question_tabulates_facts_with_home_shortened_and_fix():
    page = host_page(
        [
            HostFact(
                "control",
                "com.anthropic.claude_browser_extension",
                "Chrome bridge",
                CLAUDE_BRIDGE,
                concern=True,
            ),
            HostFact("control", "macOS privacy permissions", "could not read the TCC database"),
        ]
    )
    section = block(page, "host:computer-control")
    assert "What can drive this computer besides the terminal?" in section
    assert "<th>File</th>" in section
    assert "~/Library/Application Support/<wbr>Google/<wbr>Chrome/" in section
    assert HOME not in section
    assert "Remove bridges and permissions you do not use" in section
    assert section.index("Chrome bridge") < section.index("could not read the TCC database")


def test_file_column_appears_only_when_a_fact_has_a_file():
    page = host_page([pid(4242, 3, "codex app-server --listen")])
    section = block(page, "host:unattended")
    assert "<th>Found</th>" in section
    assert "<th>File</th>" not in section


def test_question_without_facts_gives_the_fallback_answer():
    page = host_page([])
    section = block(page, "host:other-tools")
    assert "None found." in section
    assert "p-ok" in section
    assert "<table>" not in section


def test_finding_without_a_question_gets_its_own_block():
    finding = Exposure(
        id="host:shared-surfaces",
        tool="host",
        lens=Lens.MODEL,
        statement="~/.claude/skills is loaded by more than one tool.",
        label="One folder steers several tools",
        evidence=["~/.claude/skills: Claude Code, OpenCode"],
    )
    page = host_view(make_audit([], [finding]))
    assert "<h2>Across tools</h2>" in page
    section = block(page, "host:shared-surfaces")
    assert "One folder steers several tools" in section
    assert "~/.claude/skills: Claude Code, OpenCode" in section


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
            kind=FactKind.ORPHAN,
        ),
        HostFact(
            "unattended",
            "com.example.agent",
            "starts at login: claude",
            concern=True,
            kind=FactKind.LOGIN_ITEM,
        ),
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


def test_fix_steps_render_under_their_question():
    fix = Fix(
        "Stop processes that outlived their sessions",
        [FixCommand("Quit the listed processes", manual=True)],
    )
    finding = Exposure(
        id="host:unattended",
        tool="host",
        lens=Lens.CODE,
        statement="These keep running as you when you are not there: 1 AI-tool process.",
        label="Processes running without a session",
        fix=fix,
    )
    page = host_view(make_audit([pid(7, 2, "codex app-server")], [finding]))
    section = block(page, "host:unattended")
    assert "Stop processes that outlived their sessions" in section
    assert "p-concern" in section
