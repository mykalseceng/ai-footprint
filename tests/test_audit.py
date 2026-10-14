"""End-to-end: fake homes for all three tools through collectors, rules, validator, renderers."""

import dataclasses
import json
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from ai_footprint import answers, cli, report_html, reportcheck, surface
from ai_footprint.audit import run_audit
from ai_footprint.model import AuditReport, CommandValidation
from ai_footprint.report_text import Style, render_doctor
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
    assert "run commands without asking" in headline
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
    answered = answers.for_tool(claude, audit.host.home)
    questions = [a.question for a in answered]
    assert len(questions) == 15
    assert questions[0] == "Where are the log files?"
    assert "How do I revoke this token, and how would I prove it?" in questions
    assert questions[-1] == "Would I notice if someone else used it?"
    sessions = answered[1]
    assert sessions.headers == ("Path", "Size", "Files", "Since")
    assert sessions.rows and all(row[0].startswith("`~/") for row in sessions.rows)
    revoke = next(a for a in answered if a.question.startswith("How do I revoke"))
    assert revoke.headers == ("Fact", "Source") and revoke.rows and not revoke.text
    assert all(not a.text or a.text.count(". ") == 0 for a in answered)


def test_cvp_evidence_comes_from_refusal_markers(audited):
    audit, _c, _a = audited
    claude = next(t for t in audit.tools if t.name == "claude")
    assert claude.programs[0].status == "cyber-safeguard refusals in transcripts"
    assert "1 API responses" in claude.programs[0].evidence[0]


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
    page = report_html.render(audit, checklist)
    dump = json.dumps(dataclasses.asdict(audit), default=str)
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
        assert secret not in dump
        assert secret not in doctor


def test_html_escapes_collected_strings_and_blocks_scripts(audited):
    audit, checklist, _a = audited
    page = report_html.render(audit, checklist)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "default-src 'none'" in page
    assert "<script" not in page
    assert "<link" not in page


def test_report_opens_on_summary_with_a_tab_per_tool(audited):
    audit, checklist, _a = audited
    page = report_html.render(audit, checklist)
    for page_id in (
        "summary",
        "tool-claude",
        "tool-codex",
        "tool-opencode",
        "host",
        "checklist",
        "method",
    ):
        assert f'<section class="view" id="{page_id}">' in page
        assert f'href="#{page_id}"' in page
    assert ".pages:not(:has(:target)) > #summary { display: block; }" in page
    assert "<b>TL;DR</b>" in page
    assert "critical" not in page.lower()


def test_each_exposure_lives_in_its_own_tool_page(audited):
    audit, checklist, _a = audited
    page = report_html.render(audit, checklist)
    for tool in ("claude", "codex", "opencode"):
        start = page.index(f'id="tool-{tool}"')
        end = page.index('<section class="view"', start + 1)
        tab = page[start:end]
        assert f'id="{tool}:no-approval"' in tab or tool == "opencode"
        assert f'id="{tool}:creds-' in tab


def test_every_fix_command_was_validated(audited):
    audit, _c, _a = audited
    fixes = [x.fix for x in audit.all_exposures() if x.fix]
    assert fixes
    for fix in fixes:
        assert len(fix.validations) == len(fix.commands)


def test_doctor_fails_on_exposed_home(audited):
    audit, checklist, _a = audited
    text, code = render_doctor(audit, checklist, Style(enabled=False))
    assert code == 1
    assert "EXPOSED  Commands require approval" in text


def test_clean_home_passes_doctor(tmp_path: Path):
    audit, checklist = run_audit(system=QuietFakeSystem(), home=tmp_path, scan=False)
    text, code = render_doctor(audit, checklist, Style(enabled=False))
    assert code == 0, text
    assert all(not t.installed for t in audit.tools)


def test_cli_writes_private_html_report(open_home: Path, monkeypatch: pytest.MonkeyPatch):
    build_claude_home(open_home)
    monkeypatch.setattr(cli, "System", QuietFakeSystem)
    out = open_home / "report.html"
    code = cli.main(["claude", "--home", str(open_home), "--html", str(out), "--workers", "1"])
    assert code == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert "Claude Code" in out.read_text()


def test_cli_rejects_unknown_tool(open_home: Path, monkeypatch: pytest.MonkeyPatch):
    build_claude_home(open_home)
    monkeypatch.setattr(cli, "System", QuietFakeSystem)
    with pytest.raises(SystemExit, match="unknown tool"):
        cli.main(["--doctor", "cursor", "--home", str(open_home)])


def test_rendered_report_passes_the_layout_checks(audited):
    audit, checklist, _a = audited
    page = report_html.render(audit, checklist)
    validations = reportcheck.check_report(page)
    assert {v.command for v in validations} >= {"page summary", "page skills", "page host"}
    assert all(v.ok for v in validations), [
        (v.command, c.name, c.detail) for v in validations for c in v.checks if not c.passed
    ]
