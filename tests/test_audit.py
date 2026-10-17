"""End-to-end: fake homes for every tool through collectors, rules, validator, renderers."""

import json
import re
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from ai_footprint import (
    answers,
    cli,
    dashboard,
    document,
    figures,
    fsinfo,
    report_html,
    reportcheck,
    surface,
)
from ai_footprint.audit import detect_tools, run_audit
from ai_footprint.model import (
    Artifact,
    AuditReport,
    BinaryInfo,
    Category,
    CommandValidation,
    HostReport,
    ToolReport,
)
from ai_footprint.report_text import Style, render_doctor, render_summary
from tests.conftest import (
    FAKE_ANTHROPIC_ACCESS,
    FAKE_ANTHROPIC_REFRESH,
    FAKE_API_KEY,
    FAKE_DEEPSEEK,
    FakeSystem,
    build_claude_home,
    build_codex_home,
    build_opencode_home,
    build_pi_home,
)


class QuietFakeSystem(FakeSystem):
    """Fake that reports no probe problems (real probe binaries are a host concern)."""

    def validate_probes(self) -> list[CommandValidation]:
        return []


@pytest.fixture
def open_home() -> Iterator[Path]:
    """A home directory under /tmp whose parents are traversable by other accounts."""
    home = Path(tempfile.mkdtemp(prefix="aifp-", dir="/tmp"))
    home.chmod(0o755)
    yield home
    shutil.rmtree(home)


@pytest.fixture
def audited(open_home: Path) -> tuple[AuditReport, list, str]:
    build_claude_home(open_home)
    access = build_codex_home(open_home)
    build_opencode_home(open_home)
    build_pi_home(open_home)
    system = QuietFakeSystem(other_users=("guest",))
    audit, checklist = run_audit(system=system, home=open_home, scan=True, workers=1)
    return audit, checklist, access


def ids(audit: AuditReport) -> set[str]:
    return {x.id.rsplit("-", 1)[0] if x.id[-1].isdigit() else x.id for x in audit.all_exposures()}


def test_expected_exposures_for_each_tool(audited):
    audit, _checklist, _access = audited
    assert {
        "claude:no-approval",
        "claude:creds-readable",
        "claude:dangling",
        "claude:live-token-on-disk",
        "claude:secrets-at-rest",
        "claude:instructions",
        "claude:token-reach",
        "codex:no-approval",
        "codex:creds-plaintext",
        "codex:instructions",
        "codex:token-reach",
        "opencode:creds-readable",
        "opencode:creds-plaintext",
        "pi:creds-plaintext",
        "pi:instructions",
        "pi:token-reach",
        "pi:trust",
        "pi:dangling",
        "host:other-accounts",
    } <= ids(audit)


def test_exposures_carry_no_rating_only_a_position(audited):
    audit, _c, _a = audited
    for exposure in audit.all_exposures():
        assert exposure.lens.value in {"remote", "code", "model", "account", "copies"}
        assert exposure.label
        assert not hasattr(exposure, "severity")


def test_hidden_character_in_agents_md_is_stated(audited):
    audit, _c, _a = audited
    exposure = next(x for x in audit.all_exposures() if x.id.startswith("codex:instructions"))
    assert exposure.lens.value == "model"
    assert "U+200B" in exposure.statement


def test_narrative_names_what_each_position_gets(audited):
    audit, _c, _a = audited
    story = surface.for_machine(audit)
    headline = " ".join(story.headline)
    assert "Anything that runs as you can take" in headline
    assert "skip approval prompts in some sessions" in headline
    assert "guest" in headline
    remote = next(v for v in story.lenses if v.lens.value == "remote")
    assert any("API keys for DeepSeek" in p.text for p in remote.points)
    assert all(p.text.count("utc") == 0 for p in remote.points)


def test_duplicate_dangling_entries_become_one_statement(audited):
    audit, _c, _a = audited
    dangling = [x for x in audit.all_exposures() if x.id.startswith("claude:dangling")]
    assert len(dangling) == 1
    assert "index.js" in dangling[0].statement


def test_faq_answers_every_original_question(audited):
    audit, _c, _a = audited
    claude = next(t for t in audit.tools if t.name == "claude")
    answered = answers.for_tool(claude, audit.host)
    questions = [a.question for a in answered]
    assert len(questions) == 15
    assert questions[0] == "Where are the log files?"
    assert "How do I revoke this token, and how would I prove it?" in questions
    assert questions[-1] == "Would I notice if someone else used it?"
    sessions = answered[1]
    assert sessions.headers == ("Path", "Size", "Files", "Modified")
    assert sessions.rows and all(row[0].startswith("`~/") for row in sessions.rows)
    revoke = next(a for a in answered if a.question.startswith("How do I revoke"))
    assert revoke.headers == ("Fact", "Source") and revoke.rows and not revoke.text
    assert all(not a.text or a.text.count(". ") == 0 for a in answered)


def test_cvp_evidence_comes_from_refusal_markers(audited):
    audit, _c, _a = audited
    claude = next(t for t in audit.tools if t.name == "claude")
    assert claude.programs[0].status == "refusal marker found in Claude Code data"
    assert (
        claude.programs[0]
        .evidence[0]
        .startswith('The marker apiRefusalCategory "cyber" appears 1 time in 1 file')
    )


def test_jwt_claims_and_connector_scopes_are_reported(audited):
    audit, _c, _a = audited
    codex = next(t for t in audit.tools if t.name == "codex")
    token = next(t for t in codex.credentials[0].tokens if t.field == "access_token")
    assert token.issuer == "https://auth.example.com"
    assert "api.connectors.read" in token.scopes
    reach = next(x for x in codex.exposures if x.id == "codex:token-reach")
    assert reach.statement == (
        "The Codex CLI token carries 1 connector scope: api.connectors.read."
    )
    claude = next(t for t in audit.tools if t.name == "claude")
    reach = next(x for x in claude.exposures if x.id == "claude:token-reach")
    assert "user:mcp_servers" in reach.statement
    assert "connected to claude.ai Gmail" in reach.statement


def test_no_secret_value_reaches_any_output(audited):
    audit, checklist, access = audited
    data = document.build(audit, checklist)
    page = dashboard.render(data)
    report = report_html.render(audit, checklist, data["views"])
    dump = json.dumps(data)
    doctor, _code = render_doctor(audit, checklist, Style(enabled=False))
    for secret in (
        FAKE_ANTHROPIC_ACCESS,
        FAKE_ANTHROPIC_REFRESH,
        FAKE_API_KEY,
        FAKE_DEEPSEEK,
        access,
        "rt.1." + "R" * 80,
    ):
        assert secret not in page
        assert secret not in report
        assert secret not in dump
        assert secret not in doctor


def test_collected_markup_stays_data_and_only_pinned_code_runs(audited):
    audit, checklist, _a = audited
    data = document.build(audit, checklist)
    page = dashboard.render(data)
    assert "<script>alert(1)</script>" not in page
    assert "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e" in page
    scripts = re.findall(r"<script>(.*?)</script>", page, re.S)
    styles = re.findall(r"<style>(.*?)</style>", page, re.S)
    assert len(scripts) == 1 and len(styles) == 1
    [policy] = re.findall(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page)
    assert "default-src &#x27;none&#x27;" in policy
    assert dashboard.csp_hash(scripts[0]).replace("'", "&#x27;") in policy
    assert dashboard.csp_hash(styles[0]).replace("'", "&#x27;") in policy
    assert "unsafe" not in policy
    assert "<link" not in page and " src=" not in page


def test_static_report_escapes_collected_strings_and_has_no_scripts(audited):
    audit, checklist, _a = audited
    page = report_html.render(audit, checklist, document.build(audit, checklist)["views"])
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "default-src 'none'" in page
    assert "<script" not in page
    assert "<link" not in page
    for page_id in ("summary", "tool-claude", "tool-codex", "host", "checklist", "method"):
        assert f'<section class="view" id="{page_id}">' in page


def test_static_report_passes_its_layout_checks(audited):
    audit, checklist, _a = audited
    views = document.build(audit, checklist)["views"]
    validations = reportcheck.check_report(report_html.render(audit, checklist, views))
    assert {v.command for v in validations} >= {"page summary", "page skills", "page host"}
    assert all(v.ok for v in validations), [
        (v.command, c.name, c.detail) for v in validations for c in v.checks if not c.passed
    ]


def test_dashboard_embeds_the_document_unchanged(audited):
    audit, checklist, _a = audited
    data = document.build(audit, checklist)
    page = dashboard.render(data)
    [embedded] = re.findall(
        r'<script type="application/json" id="audit-data">(.*?)</script>', page, re.S
    )
    assert json.loads(embedded) == json.loads(json.dumps(data))


def test_document_has_a_view_per_installed_tool_and_resolvable_links(audited):
    audit, checklist, _a = audited
    data = document.build(audit, checklist)
    views = data["views"]
    assert list(views["tools"]) == [t.name for t in audit.tools if t.installed]
    exposure_ids = {x.id for x in audit.all_exposures()}
    linked = {c for row in data["checklist"] for c in row["exposures"]}
    linked |= {
        p["exposure_id"]
        for lenses in [views["machine"]["lenses"], *(t["lenses"] for t in views["tools"].values())]
        for lens in lenses
        for p in lens["points"]
        if p["exposure_id"]
    }
    assert linked and linked <= exposure_ids
    assert set(views["fix_labels"]) == {x.id for x in audit.all_exposures() if x.fix}
    assert len(data["checklist"]) == len(checklist)
    assert [lens["id"] for lens in views["lenses"]] == [
        "remote",
        "code",
        "model",
        "account",
        "copies",
    ]
    assert "critical" not in json.dumps(views).lower()


def test_each_tool_answers_every_question_without_cutting_rows(audited):
    audit, checklist, _a = audited
    views = document.build(audit, checklist)["views"]
    codex = next(t for t in audit.tools if t.name == "codex")
    [trusted] = [
        a for a in views["tools"]["codex"]["answers"] if a["question"].startswith("What does my")
    ]
    assert len(trusted["rows"]) == len(codex.trusted_folders)
    assert "shown" not in trusted["text"]


def test_every_fix_command_was_validated(audited):
    audit, _c, _a = audited
    fixes = [x.fix for x in audit.all_exposures() if x.fix]
    assert fixes
    for fix in fixes:
        assert len(fix.validations) == len(fix.commands)


def test_doctor_fails_when_anything_needs_review(audited):
    audit, checklist, _a = audited
    text, code = render_doctor(audit, checklist, Style(enabled=False))
    assert code == 1
    assert "REVIEW   Approval not turned off by a recorded setting" in text


def test_clean_home_passes_doctor(tmp_path: Path):
    audit, checklist = run_audit(system=QuietFakeSystem(), home=tmp_path, scan=False)
    text, code = render_doctor(audit, checklist, Style(enabled=False))
    assert code == 0, text
    assert all(not t.installed for t in audit.tools)


def test_cli_writes_private_dashboard(open_home: Path, monkeypatch: pytest.MonkeyPatch):
    build_claude_home(open_home)
    monkeypatch.setattr(cli, "System", QuietFakeSystem)
    out = open_home / "dashboard.html"
    code = cli.main(["claude", "--home", str(open_home), "--dashboard", str(out), "--workers", "1"])
    assert code == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert "Claude Code" in out.read_text()


def test_cli_rejects_unknown_tool(open_home: Path, monkeypatch: pytest.MonkeyPatch):
    build_claude_home(open_home)
    monkeypatch.setattr(cli, "System", QuietFakeSystem)
    with pytest.raises(SystemExit, match="unknown tool"):
        cli.main(["--doctor", "cursor", "--home", str(open_home)])


def test_dashboard_views_pass_the_consistency_checks(audited):
    audit, checklist, _a = audited
    validations = reportcheck.check_document(document.build(audit, checklist))
    assert {v.command for v in validations} >= {"page summary", "page skills", "page host"}
    assert all(v.ok for v in validations), [
        (v.command, c.name, c.detail) for v in validations for c in v.checks if not c.passed
    ]


def test_summary_line_sizes_only_outermost_locations_and_says_how_many(audited):
    audit, _checklist, _access = audited
    text = render_summary(audit, Style(enabled=False), [])
    codex = next(t for t in audit.tools if t.name == "codex")
    listed = sum(1 for a in figures.outermost(codex.artifacts) if a.exists)
    size = fsinfo.human_size(figures.disk_bytes(codex.artifacts))
    line = next(line for line in text.splitlines() if line.strip().startswith("Codex CLI"))
    assert f"{size} in {surface.plural(listed, 'listed location')} · " in line


def test_headline_names_every_installed_version():
    tool = ToolReport(name="opencode", display_name="OpenCode", installed=True)
    tool.binaries = [
        BinaryInfo(path="/a/opencode", resolved="/a/opencode", version="1.4.6"),
        BinaryInfo(path="/b/opencode", resolved="/b/opencode", version="2.0.26"),
    ]
    assert surface._named(tool) == "OpenCode (1.4.6 and 2.0.26)"
    tool.binaries = tool.binaries[:1]
    assert surface._named(tool) == "OpenCode 1.4.6"
    tool.binaries = []
    assert surface._named(tool) == "OpenCode"


def test_plural_handles_words_ending_in_y():
    assert surface.plural(2, "entry") == "2 entries"
    assert surface.plural(1, "entry") == "1 entry"
    assert surface.plural(2, "key") == "2 keys"


def test_readers_answer_says_how_many_files_the_group_can_read(tmp_path: Path):
    tool = ToolReport(name="claude", display_name="Claude Code", installed=True)
    tool.artifacts = [
        Artifact(
            "Projects",
            f"{tmp_path}/p",
            Category.SESSION,
            "",
            exists=True,
            is_dir=True,
            file_count=10,
            mode="755",
            group_readable="staff",
            group_readable_files=0,
        ),
        Artifact(
            "Logs",
            f"{tmp_path}/l",
            Category.LOG,
            "",
            exists=True,
            is_dir=True,
            file_count=4,
            mode="755",
            group_readable="staff",
            group_readable_files=3,
        ),
    ]
    host = HostReport("macOS", "", "arm64", "mac", "me", 501, str(tmp_path), "750")
    answer = answers._readers_answer(tool, host)
    assert answer.text.endswith("and no other local account exists today.")
    assert [row[2] for row in answer.rows] == [
        "group `staff`: file names only",
        "group `staff`: 3 of 4 files",
    ]


def test_detected_binaries_are_probed_once_per_audit(tmp_path: Path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    binary = bin_dir / "claude"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    system = QuietFakeSystem(path=str(bin_dir))
    presences = detect_tools(system=system, home=tmp_path)
    run_audit(system=system, home=tmp_path, tools=["claude"], scan=False, presences=presences)
    resolved = str(binary.resolve())
    signature_checks = [r for r in system.executed if r.argv[-1:] == [resolved]]
    version_runs = [r for r in system.executed if r.argv == [resolved, "--version"]]
    assert len(signature_checks) == 1
    assert len(version_runs) == 1


def test_collect_detects_by_itself_when_no_presence_is_given(tmp_path: Path):
    (tmp_path / ".claude").mkdir()
    audit, _checklist = run_audit(system=QuietFakeSystem(), home=tmp_path, scan=False)
    installed = {t.name: t.installed for t in audit.tools}
    assert installed == {"claude": True, "codex": False, "opencode": False, "pi": False}
