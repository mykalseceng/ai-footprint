"""Rules read typed fields; the prose they show is never parsed back."""

from ai_footprint import daemons, document, surface
from ai_footprint.collectors import claude
from ai_footprint.model import (
    BARE_SECURITY,
    Credential,
    Daemon,
    FactKind,
    HostFact,
    StoreKind,
    TokenInfo,
    ToolReport,
)
from tests.test_host_view import host_exposures, make_audit


def keychain(silent: float | None) -> Credential:
    return Credential(
        "claude",
        "Anthropic",
        StoreKind.KEYCHAIN,
        "login.keychain-db",
        "display text that no rule reads",
        silent_read_seconds=silent,
        keychain_written="2026-10-17 17:58:16",
    )


def test_store_kind_shows_as_its_text():
    assert f"{StoreKind.SQLITE}" == "SQLite table credential"
    assert StoreKind.FILE == "plaintext file"


def test_silent_keychain_read_comes_from_the_typed_field():
    assert keychain(0.01).readable_without_prompt
    assert not keychain(None).readable_without_prompt
    tool = ToolReport(name="claude", display_name="Claude Code", installed=True)
    tool.credentials = [keychain(0.01)]
    audit = make_audit([], [], [tool])
    assert "in 0.01 seconds, with no prompt" in document.proof(audit)
    tool.credentials = [keychain(None)]
    assert document.proof(audit) == "This audit never writes a secret value to this report."


def test_local_service_passwords_are_flagged_not_matched_by_name():
    named = Credential("opencode", "OpenCode local server", StoreKind.FILE, "/s.json", "")
    flagged = Credential("opencode", "anything", StoreKind.FILE, "/s.json", "", local_service=True)
    assert not surface.is_local_secret(named)
    assert surface.is_local_secret(flagged)


def test_surface_and_keys_agree_on_what_an_api_key_is():
    token = TokenInfo("token", "github_pat_fine", "", "github_pat_", 93, "f1")
    cred = Credential("codex", "GitHub", StoreKind.ENV, "$GH_TOKEN", "", tokens=[token])
    assert surface._is_api_key([cred])


def test_host_rules_read_fact_kinds_not_wording():
    facts = [
        HostFact("reach", "deploy key", "worded differently", "/k", True, FactKind.SSH_KEY_OPEN),
        HostFact("unattended", "worker", "worded differently", "", True, FactKind.LONG_RUNNING),
        HostFact("control", "bridge", "worded differently", "/m.json", True, FactKind.BRIDGE),
    ]
    found = {x.id: x for x in host_exposures(make_audit(facts, []))}
    reach = found["host:inherited-creds"]
    assert reach.fix is not None
    assert any(c.text.startswith("ssh-keygen -p -f") for c in reach.fix.commands)
    assert "1 AI-tool process running for a day or more" in found["host:unattended"].statement
    assert "browser bridges" in found["host:computer-control"].statement


def test_environment_facts_are_not_counted_as_stored_credentials():
    facts = [
        HostFact("reach", "GitHub CLI", "logged in", "/gh/hosts.yml", True),
        HostFact("reach", "Secret-looking variables", "A_TOKEN", "", True, FactKind.ENV),
    ]
    audit = make_audit(facts, [])
    tool = ToolReport(name="claude", display_name="Claude Code", installed=True)
    tool.credentials = [keychain(0.01)]
    audit.tools = [tool, ToolReport(name="codex", display_name="Codex CLI", installed=True)]
    headline = " ".join(surface.for_machine(audit).headline)
    assert "1 other credential on this machine: GitHub CLI." in headline


def test_off_path_binary_is_described_from_the_typed_flag():
    daemon = Daemon(
        pid=1,
        ppid=1,
        started="",
        command="/opt/codex app-server",
        binary="/opt/codex",
        detached=True,
        days=0,
        notes=["any wording at all"],
        off_path=True,
    )
    _what, _listens, notes = daemons.describe(daemon, "/Users/me")
    assert notes == ["binary /opt/codex, not the one on PATH"]


def test_bare_security_trait_is_the_shared_constant():
    assert any(value == BARE_SECURITY for _label, value, _marker in claude.FINGERPRINT)
