"""Skills, plugins and MCP servers are described by their own files, listed once each."""

import json
import time
from pathlib import Path

from ai_footprint import document, extensions
from ai_footprint.collectors import claude, opencode
from ai_footprint.collectors.common import Context
from ai_footprint.model import AuditReport, Extension, HostReport
from tests.conftest import FakeSystem, build_claude_home

SKILL = """---
name: grill
description: >
  Interview the user about a plan until every branch is settled. Use when the plan is
  vague. Third sentence that should be dropped.
allowed-tools:
  - Read
  - Grep
---
# Grill
"""


def context(home: Path) -> Context:
    return Context(home=home, system=FakeSystem(path=str(home / "bin")), now=time.time())


def test_frontmatter_reads_scalars_blocks_and_lists():
    meta = extensions.frontmatter(SKILL)
    assert meta["name"] == "grill"
    assert meta["description"].startswith("Interview the user about a plan")
    assert meta["allowed-tools"] == "Read, Grep"
    assert extensions.frontmatter("no frontmatter here") == {}


def test_two_sentences_caps_the_description():
    text = "First one. Second one! Third one? Fourth."
    assert extensions.two_sentences(text) == "First one. Second one!"
    assert extensions.two_sentences("Does X. Use when you need X. Also Y.") == "Does X."
    assert extensions.two_sentences("") == ""
    long = "A" * 300 + ". B."
    assert len(extensions.two_sentences(long)) == extensions.MAX_DESCRIPTION
    words = "word " * 80
    cut = extensions.two_sentences(words)
    assert cut.endswith("word…") and len(cut) <= extensions.MAX_DESCRIPTION


def test_npx_package_strips_versions_and_flags():
    assert extensions.npx_package("npx", ["-y", "chrome-devtools-mcp@latest", "--x"]) == (
        "chrome-devtools-mcp"
    )
    assert extensions.npx_package("npx", ["@scope/pkg@1.2.3"]) == "@scope/pkg"
    assert extensions.npx_package("/usr/bin/python3", ["server.py"]) == ""


def test_npm_description_comes_from_the_cached_package_json(tmp_path: Path):
    manifest = tmp_path / ".npm" / "_npx" / "abc" / "node_modules" / "demo-mcp" / "package.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"description": "MCP server for demos. More. Even more."}))
    assert extensions.npm_description("demo-mcp", home=tmp_path) == "MCP server for demos. More."
    assert extensions.npm_description("missing", home=tmp_path) == ""


def test_skill_rows_describe_each_skill_from_its_own_file(tmp_path: Path):
    skills = tmp_path / "skills"
    (skills / "grill").mkdir(parents=True)
    (skills / "grill" / "SKILL.md").write_text(SKILL)
    (skills / "bare").mkdir()
    [bare, grill] = extensions.skill_rows(skills, "claude", context(tmp_path))
    assert grill.name == "grill"
    assert grill.description == "Interview the user about a plan until every branch is settled."
    assert grill.access == "Read, Grep"
    assert grill.identity == str((skills / "grill").resolve())
    assert bare.description == extensions.NO_SKILL_TEXT and bare.access == ""


def test_plugin_manifest_reports_description_and_components(tmp_path: Path):
    install = tmp_path / "plugin"
    (install / ".claude-plugin").mkdir(parents=True)
    (install / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"description": "Audit things. Carefully. Very."})
    )
    (install / "skills" / "a").mkdir(parents=True)
    (install / "skills" / "b").mkdir()
    (install / "commands").mkdir()
    (install / "commands" / "x.md").write_text("")
    (install / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": {"url": "https://x/"}}}))
    description, components = extensions.plugin_manifest(install)
    assert description == "Audit things. Carefully."
    assert components == "2 skills, 1 command, 1 MCP server"
    [server] = extensions.plugin_mcp_rows(install, "claude", "p@m")
    assert (server.source, server.identity, server.access) == (
        "plugin p@m",
        "https://x/",
        "http https://x/",
    )


def test_dedupe_merges_sources_of_the_same_identity():
    first = Extension("t", "skill", "s", "local", "~/.claude/skills/s", identity="/real/s")
    second = Extension(
        "t", "skill", "s", "symlink → /real/s", "~/.agents/skills/s", identity="/real/s"
    )
    other = Extension("t", "skill", "s", "local", "~/x/s", identity="/other/s")
    out = extensions.dedupe([first, second, other])
    assert [x.identity for x in out] == ["/real/s", "/other/s"]
    assert out[0].source == "local; symlink → /real/s"


def test_extensions_page_lists_a_shared_skill_once_with_both_tools(tmp_path: Path):
    build_claude_home(tmp_path)
    (tmp_path / ".claude" / "skills" / "grill").mkdir(parents=True)
    (tmp_path / ".claude" / "skills" / "grill" / "SKILL.md").write_text(SKILL)
    (tmp_path / ".config" / "opencode").mkdir(parents=True)
    (tmp_path / ".local" / "share" / "opencode").mkdir(parents=True)
    ctx = context(tmp_path)
    claude_report, _f = claude.collect(ctx)
    opencode_report, _f = opencode.collect(ctx)
    host = HostReport(
        os="macOS",
        kernel="",
        arch="arm64",
        hostname="mac",
        user="me",
        uid=501,
        home=str(tmp_path),
        home_mode="drwx------",
    )
    audit = AuditReport(
        generated_at="", auditor_version="0", host=host, tools=[claude_report, opencode_report]
    )
    grouped = document.grouped_extensions(audit)
    [(skill, used_by)] = [(x, t) for x, t in grouped if x.kind == "skill" and x.name == "grill"]
    assert used_by == ["Claude Code", "OpenCode"]
    assert skill.description == "Interview the user about a plan until every branch is settled."
    views = document.build(audit, [])["views"]
    [row] = [x for x in views["extensions"] if x["name"] == "grill"]
    assert row["used_by"] == ["Claude Code", "OpenCode"]
    assert row["group"] == document.USER_SKILLS
    assert "Read, Grep" in row["access"]
    assert "loaded by more than one tool" in views["pages"]["skills"]


def test_tool_lists_are_summarised_not_listed():
    declared = "Read, Write, Bash(uname:*), Bash(ls -l *), Bash(grep *), AskUserQuestion"
    assert extensions.summarise_tools(declared) == "Read, Write, Bash (3 patterns), AskUserQuestion"
    assert extensions.summarise_tools("") == ""


def test_skill_without_frontmatter_description_uses_its_first_paragraph(tmp_path: Path):
    skills = tmp_path / "skills"
    (skills / "plain").mkdir(parents=True)
    (skills / "plain" / "SKILL.md").write_text("# Plain\n\nDoes one thing. Does it well. Third.\n")
    (skills / "empty").mkdir()
    (skills / "empty" / "SKILL.md").write_text("---\nname: empty\n---\n")
    [empty, plain] = extensions.skill_rows(skills, "codex", context(tmp_path))
    assert plain.description == "Does one thing. Does it well."
    assert empty.description == extensions.NO_SKILL_TEXT


def test_category_folders_list_the_skills_inside_them(tmp_path: Path):
    skills = tmp_path / "skills"
    (skills / "engineering" / "review").mkdir(parents=True)
    (skills / "engineering" / "review" / "SKILL.md").write_text(SKILL)
    [row] = extensions.skill_rows(skills, "codex", context(tmp_path))
    assert row.name == "review"
    assert row.source.endswith("skills/engineering")


def test_mcp_row_summarises_long_env_lists():
    spec = {"command": "/usr/bin/true", "env": {f"VAR_{i}": "x" for i in range(5)}}
    row = extensions.mcp_row("codex", "s", spec, "config.toml")
    assert row.notes == "env: 5 variables (VAR_0, VAR_1, VAR_2, …)"
    short = extensions.mcp_row("codex", "s", {"command": "/usr/bin/true", "env": {"A": 1}}, "c")
    assert short.notes == "env: A"
