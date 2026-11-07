"""Claude Code settings from each repo and from managed policy, and transcript sub-artifacts."""

import json
from pathlib import Path

from ai_footprint import checks
from ai_footprint.checks import local_code, steering
from ai_footprint.fsinfo import disk_bytes
from ai_footprint.harnesses import registry
from ai_footprint.harnesses.claude import scopes
from ai_footprint.harnesses.common import Context
from ai_footprint.model import HostReport, ToolReport
from tests.conftest import FakeSystem

CLAUDE = registry()["claude"]


def context(home: Path, root: Path | None = None) -> Context:
    system = FakeSystem()
    if root is not None:
        system.root = root
    return Context(home=home, system=system, now=0, scan=False)


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


def build_repo(home: Path) -> Path:
    """A repo Claude Code knows, whose own files turn on bypass, add a hook and an MCP server."""
    repo = home / "repo"
    (repo / ".claude" / "skills" / "deploy").mkdir(parents=True)
    (repo / ".claude" / "agents").mkdir()
    (repo / ".claude" / "settings.local.json").write_text(
        json.dumps(
            {
                "permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]},
                "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "./notify.sh"}]}]},
            }
        )
    )
    (repo / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"tools": {"command": "node", "args": [str(repo / "gone.js")]}}})
    )
    (repo / ".claude" / "skills" / "deploy" / "SKILL.md").write_text(
        "---\ndescription: Deploys the app\n---\n"
    )
    (repo / ".claude" / "agents" / "reviewer.md").write_text("Review the diff.\n")
    (home / ".claude").mkdir()
    (home / ".claude.json").write_text(json.dumps({"projects": {str(repo): {}}}))
    return repo


def collect(home: Path, root: Path | None = None) -> ToolReport:
    return CLAUDE.collect(context(home, root))


def test_a_repo_that_turns_on_bypass_is_an_approval_signal(tmp_path: Path):
    build_repo(tmp_path)
    report = collect(tmp_path)
    flagged = {s.key: s for s in report.settings}[scopes.PROJECTS_BYPASS]
    assert flagged.concern and flagged.value == "~/repo/.claude/settings.local.json"
    [signal] = steering.rule_no_approval(report, rule_ctx(tmp_path))
    assert scopes.PROJECTS_BYPASS in signal.statement
    rules = {s.key: s.value for s in report.settings}["project permission rules"]
    assert rules == "0 deny / 1 allow in 1 project settings files"


def test_repo_hooks_mcp_servers_skills_and_agents_are_collected(tmp_path: Path):
    build_repo(tmp_path)
    report = collect(tmp_path)
    by_kind = {(x.kind, x.name): x for x in report.extensions}
    assert by_kind[("hook", "Stop [*]")].source == "~/repo/.claude/settings.local.json"
    server = by_kind[("mcp", "tools")]
    assert server.source == "repo ~/repo" and server.dangling
    assert by_kind[("skill", "deploy")].source == "project ~/repo"
    assert any(i.scope == "agent" and i.path.endswith("reviewer.md") for i in report.instructions)


def test_a_repo_server_is_removed_from_the_project_scope(tmp_path: Path):
    build_repo(tmp_path)
    report = collect(tmp_path)
    [signal] = local_code.rule_dangling(report, rule_ctx(tmp_path))
    assert signal.fix is not None
    [command] = signal.fix.commands
    assert command.text.endswith("claude mcp remove tools -s project")


def test_repo_files_are_listed_as_artifacts_of_that_repo(tmp_path: Path):
    build_repo(tmp_path)
    labels = {a.label for a in collect(tmp_path).artifacts}
    assert {
        "Project local settings · ~/repo",
        "Project MCP servers · ~/repo",
        "Project skills · ~/repo",
        "Project agents · ~/repo",
    } <= labels


def test_the_home_folder_is_user_scope_not_a_project(tmp_path: Path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"permissions": {}}))
    (tmp_path / ".claude.json").write_text(json.dumps({"projects": {str(tmp_path): {}}}))
    report = collect(tmp_path)
    assert not [a for a in report.artifacts if a.label.startswith("Project ")]
    assert "project permission rules" not in {s.key for s in report.settings}


def test_a_project_folder_that_is_gone_is_skipped(tmp_path: Path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(json.dumps({"projects": {"/no/such/repo": {}}}))
    report = collect(tmp_path)
    assert "project permission rules" not in {s.key for s in report.settings}


def test_managed_policy_is_read_from_the_machine_folder(tmp_path: Path):
    home, root = tmp_path / "home", tmp_path / "root"
    (home / ".claude").mkdir(parents=True)
    managed = root / "Library" / "Application Support" / "ClaudeCode"
    managed.mkdir(parents=True)
    (managed / "managed-settings.json").write_text(
        json.dumps(
            {
                "permissions": {"disableBypassPermissionsMode": "disable"},
                "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "audit"}]}]},
            }
        )
    )
    (managed / "managed-mcp.json").write_text(
        json.dumps({"mcpServers": {"corp": {"url": "https://mcp.example.com"}}})
    )
    report = collect(home, root)
    settings = {s.key: s.value for s in report.settings}
    assert settings["managed permissions.disableBypassPermissionsMode"] == "disable"
    assert {(x.kind, x.source) for x in report.extensions} >= {
        ("hook", "managed settings"),
        ("mcp", "managed"),
    }
    assert "Managed settings" in {a.label for a in report.artifacts}


def test_no_managed_policy_says_so(tmp_path: Path):
    (tmp_path / ".claude").mkdir()
    assert {s.key: s.value for s in collect(tmp_path).settings}["managed policy"] == "none"


def test_tool_results_subagents_and_memory_are_counted_inside_transcripts(tmp_path: Path):
    session = tmp_path / ".claude" / "projects" / "-repo" / "abc"
    (session / "tool-results").mkdir(parents=True)
    (session / "subagents").mkdir()
    (session / "tool-results" / "1.txt").write_text("x" * 10)
    (session / "tool-results" / "2.txt").write_text("y" * 5)
    (session / "subagents" / "agent-1.jsonl").write_text("{}")
    (tmp_path / ".claude" / "projects" / "-repo" / "memory").mkdir()
    (tmp_path / ".claude" / "projects" / "-repo" / "memory" / "MEMORY.md").write_text("note")
    report = collect(tmp_path)
    by_label = {a.label: a for a in report.artifacts}
    assert by_label["Tool results"].file_count == 2
    assert by_label["Tool results"].size_bytes == 15
    assert by_label["Subagent transcripts"].file_count == 1
    assert by_label["Memory files"].file_count == 1
    transcripts = by_label["Transcripts"]
    assert disk_bytes(report.artifacts) == transcripts.size_bytes
