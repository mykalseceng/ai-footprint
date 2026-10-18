"""Duplicate installs, code signers, stale logins, revoke advice and copied credentials."""

import time
from pathlib import Path

import pytest

from ai_footprint import accounts, rules
from ai_footprint.collectors.common import AD_HOC, Context, signer
from ai_footprint.model import (
    BinaryInfo,
    Credential,
    HostReport,
    ProcessInfo,
    SecretKindSummary,
    SecretScan,
    StoreKind,
    ToolReport,
)
from ai_footprint.tokens import inspect_token
from tests.conftest import FakeSystem

NODE = "/u/.nvm/versions/node/v24/lib/node_modules/@opencode/cli/bin/opencode.exe"


def rule_ctx(home: Path) -> rules.RuleContext:
    host = HostReport(
        os="macOS",
        kernel="",
        arch="arm64",
        hostname="mac",
        user="me",
        uid=501,
        home=str(home),
        home_mode="drwx------",
    )
    return rules.RuleContext(host=host, platform="darwin", home=home)


def opencode_with(*binaries: BinaryInfo) -> ToolReport:
    return ToolReport(
        name="opencode", display_name="OpenCode", installed=True, binaries=list(binaries)
    )


OLD = BinaryInfo("/u/.opencode/bin/opencode", "/u/.opencode/bin/opencode", version="1.4.6")
NEW = BinaryInfo("/u/.nvm/versions/node/v24/bin/opencode", NODE, version="2.0.26")


def test_an_older_copy_first_on_path_is_the_one_to_remove():
    report = opencode_with(OLD, NEW)
    report.processes = [ProcessInfo(50615, "", f"{NODE} serve --service", ppid=50614)]
    [found] = rules.rule_duplicate_installs(report, rule_ctx(Path("/u")))
    assert found.statement == (
        "2 copies of OpenCode are installed: 1.4.6 at `~/.opencode/bin/opencode` and 2.0.26 at "
        "`~/.nvm/versions/node/v24/bin/opencode`. A shell runs the first on PATH, 1.4.6, which "
        "is older than 2.0.26."
    )
    assert "no updates" not in found.statement
    assert found.fix is not None
    texts = [c.text for c in found.fix.commands]
    assert texts[0].startswith("Remove /u/.opencode/bin/opencode")
    assert not any("@opencode/cli" in t for t in texts)
    assert any("a running process uses it" in e and NODE in e for e in found.evidence)


def test_an_older_npm_copy_later_on_path_is_uninstalled_with_npm(tmp_path: Path):
    old_npm = BinaryInfo("/u/.nvm/bin/opencode", NODE, version="1.0.0")
    newer = BinaryInfo("/u/.opencode/bin/opencode", "/u/.opencode/bin/opencode", version="1.10.0")
    [found] = rules.rule_duplicate_installs(opencode_with(newer, old_npm), rule_ctx(tmp_path))
    assert found.statement.endswith("A shell runs the first on PATH, 1.10.0, the newest.")
    assert found.fix is not None
    assert [c.text for c in found.fix.commands] == ["npm uninstall -g @opencode/cli"]


def test_copies_of_one_version_are_not_a_finding(tmp_path: Path):
    same = BinaryInfo("/b/opencode", "/b/opencode", version="1.4.6")
    assert rules.rule_duplicate_installs(opencode_with(OLD, same), rule_ctx(tmp_path)) == []


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("Authority=Developer ID Application: X (ABC)\nTeamIdentifier=ABC\n", "Developer ID"),
        ("Format=Mach-O thin (arm64)\nSignature=adhoc\nTeamIdentifier=not set\n", AD_HOC),
        ("x: code object is not signed at all\n", "unsigned or not a Mach-O binary"),
        ("x: bundle format unrecognized, invalid, or unsuitable\n", "unsigned or not"),
    ],
)
def test_codesign_output_names_the_signer(output: str, expected: str):
    assert signer(output).startswith(expected)


def oauth(provider: str, *, issued: float, expires: float) -> Credential:
    access = inspect_token("access", "a" * 40, now=time.time(), expires_at=expires)
    access.issued_at = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(issued))
    refresh = inspect_token("refresh", "rt_" + "r" * 60, now=time.time())
    return Credential("pi", provider, StoreKind.FILE, "/a.json", "", tokens=[access, refresh])


def test_an_expired_login_states_issue_and_expiry_dates_only(tmp_path: Path):
    report = ToolReport(name="pi", display_name="pi", installed=True)
    report.credentials = [oauth("OpenAI", issued=1777413000, expires=1778278200)]
    [note] = [n for n in accounts.pi(_ctx(tmp_path), report, {}) if n.topic == "detect"]
    assert note.text == (
        "Stored pi logins whose access token expired and was not replaced: OpenAI access token "
        "issued 2026-04-28, expired 2026-05-08. Their refresh tokens have no recorded expiry."
    )
    assert "use elsewhere" not in note.text and "refreshed" not in note.text


def test_a_current_login_raises_no_stale_note(tmp_path: Path):
    report = ToolReport(name="pi", display_name="pi", installed=True)
    report.credentials = [oauth("OpenAI", issued=time.time(), expires=time.time() + 3600)]
    assert not [n for n in accounts.pi(_ctx(tmp_path), report, {}) if n.topic == "detect"]


def test_revoke_advice_names_only_the_stored_providers(tmp_path: Path):
    report = ToolReport(name="opencode", display_name="OpenCode", installed=True)
    report.credentials = [
        oauth("OpenAI", issued=time.time(), expires=time.time() + 60),
        Credential("opencode", "zai", StoreKind.SQLITE, "/db", ""),
        Credential(
            "opencode", "OpenCode local server", StoreKind.FILE, "/s.json", "", local_service=True
        ),
    ]
    notes = accounts.opencode(_ctx(tmp_path), report, {"config": {}})
    [revoke] = [n.text for n in notes if n.topic == "revoke"]
    assert "claude.ai" not in revoke
    assert "sign out of all devices in ChatGPT security settings" in revoke
    assert "delete each API key in its provider's console (zai)" in revoke


def _ctx(home: Path) -> Context:
    return Context(home=home, system=FakeSystem(), now=time.time())


def scanned(total: int, current: int) -> ToolReport:
    report = ToolReport(name="pi", display_name="pi", installed=True)
    report.secret_scan = SecretScan(
        roots=["~/.pi/agent"],
        kinds=[SecretKindSummary("generic_sk_key", "API key (sk-)", total, 1, ["~/s.jsonl"])],
        current_credential_hits=["pi deepseek key found in ~/s.jsonl"] if current else [],
        current_credential_values=current,
    )
    return report


def test_secrets_that_are_all_current_credentials_are_not_called_test_data(tmp_path: Path):
    live, at_rest = rules.rule_secrets(scanned(1, 1), rule_ctx(tmp_path))
    assert live.statement == (
        "1 current pi credential is copied into data files outside its credential store."
    )
    assert live.fix is not None
    assert "Rotate API keys in the provider's console" in live.fix.commands[0].text
    assert "test data" not in at_rest.statement
    assert at_rest.statement.endswith("Each is a current credential of this tool.")


def test_other_secrets_are_counted_without_guessing_where_they_came_from(tmp_path: Path):
    _live, at_rest = rules.rule_secrets(scanned(3, 1), rule_ctx(tmp_path))
    assert "test data" not in at_rest.statement
    assert "current credential" not in at_rest.statement
    [only] = rules.rule_secrets(scanned(2, 0), rule_ctx(tmp_path))
    assert only.id.endswith("secrets-at-rest")
