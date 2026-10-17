import base64
import datetime
import shlex
from pathlib import Path

from ai_footprint import accounts, hostscan
from ai_footprint.collectors import claude as claude_cli
from ai_footprint.collectors.common import Context
from ai_footprint.host import all_processes
from ai_footprint.model import Credential, Extension, ProcessInfo, TokenInfo, ToolReport
from ai_footprint.system import ProbeResult
from tests.conftest import FakeSystem


def openssh_key(cipher: bytes) -> str:
    blob = b"openssh-key-v1\x00" + len(cipher).to_bytes(4, "big") + cipher + b"\x00" * 40
    body = base64.b64encode(blob).decode()
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"


def test_ssh_cipher_distinguishes_open_and_protected_keys(tmp_path: Path):
    (tmp_path / "open").write_text(openssh_key(b"none"))
    (tmp_path / "locked").write_text(openssh_key(b"aes256-ctr"))
    (tmp_path / "pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n")
    (tmp_path / "id.pub").write_text("ssh-ed25519 AAAA")
    assert hostscan.ssh_key_cipher(tmp_path / "open") == "none"
    assert hostscan.ssh_key_cipher(tmp_path / "locked") == "aes256-ctr"
    assert hostscan.ssh_key_cipher(tmp_path / "pem") == "encrypted (PEM)"
    assert hostscan.ssh_key_cipher(tmp_path / "id.pub") is None


def test_reach_reports_presence_never_values(tmp_path: Path):
    secret = "AKIAABCDEFGHIJKLMNOP"
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_ed25519").write_text(openssh_key(b"none"))
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text(
        f"[default]\naws_access_key_id = {secret}\naws_secret_access_key = x\n"
    )
    (tmp_path / ".config" / "gh").mkdir(parents=True)
    (tmp_path / ".config" / "gh" / "hosts.yml").write_text("github.com:\n    user: me\n")
    system = FakeSystem()
    system.env["GITHUB_TOKEN"] = "ghp_value"
    facts = {f.name: f for f in hostscan.reach(tmp_path, system)}
    assert facts["SSH key id_ed25519"].detail == "no passphrase"
    assert facts["AWS credentials"].detail == "1 access key(s) in plaintext"
    assert (
        facts["GitHub CLI"].detail
        == "logged in; hosts.yml holds no token, so it is stored elsewhere"
    )
    assert (
        "GITHUB_TOKEN"
        in facts["Secret-looking environment variables in the audit's environment"].detail
    )
    assert secret not in repr(facts)
    assert "ghp_value" not in repr(facts)


def test_backups_flag_included_tool_folders(tmp_path: Path):
    folder = tmp_path / ".claude"
    folder.mkdir()
    system = FakeSystem()

    def respond(argv: list[str]) -> ProbeResult | None:
        if argv[1:] == ["destinationinfo"]:
            return ProbeResult(0, "Name          : Drive\nKind          : Local\n", "")
        if argv[1] == "isexcluded":
            return ProbeResult(0, f"[Included]    {argv[2]}\n", "")
        return None

    system.responders.append(respond)
    facts = hostscan.backups(system, [folder, tmp_path / "missing"])
    included = [f for f in facts if f.concern]
    assert [f.name for f in included] == [".claude"]
    assert "Drive (local)" in included[0].detail


def test_orphaned_mcp_servers_are_found():
    tool = ToolReport(
        name="claude",
        display_name="Claude Code",
        installed=True,
        extensions=[Extension("claude", "mcp", "hopper", "user", "/Apps/HopperMCPServer")],
    )
    system = FakeSystem()
    rows = "\n".join(
        [
            "  101     1 Sun Oct  4 10:00:00 2026 /Apps/HopperMCPServer",
            "  102   500 Sun Oct 11 10:00:00 2026 /Apps/HopperMCPServer",
        ]
    )
    system.responders.append(
        lambda argv: ProbeResult(0, rows, "") if argv[0].endswith("ps") else None
    )
    facts = hostscan.unattended(system, [tool], Path("/none"), datetime.datetime(2026, 10, 12))
    orphan = next(f for f in facts if "orphaned" in f.detail)
    assert orphan.detail.startswith("1 orphaned process")
    assert "2026-10-04" in orphan.detail


def test_tool_processes_running_a_day_or_more_are_reported():
    tool = ToolReport(name="claude", display_name="Claude Code", installed=True)
    tool.processes = [
        ProcessInfo(1, "Sun Oct  4 10:00:00 2026", "claude --dangerously-skip-permissions"),
        ProcessInfo(2, "Sun Oct 11 23:00:00 2026", "claude"),
        ProcessInfo(3, "not a date", "claude"),
    ]
    facts = hostscan.unattended(
        FakeSystem(), [tool], Path("/none"), datetime.datetime(2026, 10, 12)
    )
    [old] = [f for f in facts if f.name.startswith("pid ")]
    assert old.name == "pid 1"
    assert old.detail.startswith("Claude Code running since 2026-10-04: claude --dangerously")


def test_other_tools_are_inventoried_with_mcp_servers(tmp_path: Path):
    cursor = tmp_path / ".cursor"
    cursor.mkdir()
    (cursor / "mcp.json").write_text('{"mcpServers": {"github": {"command": "npx"}}}')
    facts = {f.name: f for f in hostscan.other_tools(tmp_path)}
    assert "MCP servers: github" in facts["Cursor"].detail


def test_claude_grove_cache_is_reported_as_the_notice_config_not_the_choice(tmp_path: Path):
    ctx = Context(home=tmp_path, system=FakeSystem(), now=0.0)
    config = {
        "oauthAccount": {"accountUuid": "u1"},
        "groveConfigCache": {"u1": {"grove_enabled": True, "timestamp": 1791742272447}},
    }
    assert accounts._claude_data(ctx, config, "") == []
    binary = tmp_path / "claude"
    markers = [*claude_cli.TRAINING_MARKERS, claude_cli.GROVE_NOTICE_MARKER]
    binary.write_bytes(b"".join(m.encode() + b"\0" for m in markers))
    [wording, grove] = accounts._claude_data(ctx, config, str(binary))
    assert "extends data retention from 30 days to 5 years" in wording.text
    assert grove.text.startswith("The cached Grove notice config has grove_enabled true")
    assert "not cached on disk" in grove.text
    assert not wording.concern and not grove.concern


def test_log_markers_count_only_the_markers_asked_for(tmp_path: Path):
    log = tmp_path / "debug.txt"
    log.write_text('{"error":"refresh_token_reused"} ... Please run /login ... Please run /login')
    markers = accounts.log_markers([tmp_path], claude_cli.LOG_MARKERS)
    assert markers == {"Please run /login": (2, markers["Please run /login"][1])}
    assert "refresh_token_reused" not in claude_cli.LOG_MARKERS


def test_codex_group_claim_is_stated_as_recorded_not_as_a_concern(tmp_path: Path):
    token = TokenInfo(
        field="id_token",
        kind="jwt",
        description="JWT",
        prefix="eyJ…",
        length=10,
        fingerprint="f",
        claims={"https://api.openai.com/auth.groups": "api-data-sharing-incentives-program"},
    )
    report = ToolReport(
        name="codex",
        display_name="Codex CLI",
        installed=True,
        credentials=[
            Credential("codex", "OpenAI", "plaintext file", "auth.json", "", tokens=[token])
        ],
    )
    notes = accounts._codex_data(report, tmp_path, {})
    assert "api-data-sharing-incentives-program" in notes[0].text
    assert "training" not in notes[0].text
    assert not notes[0].concern


def test_account_collect_skips_uninstalled_tools(tmp_path: Path):
    ctx = Context(home=tmp_path, system=FakeSystem(), now=0)
    assert accounts.collect(ctx, ToolReport(name="claude", display_name="Claude Code"), {}) == []


def test_process_parent_ids_are_parsed():
    system = FakeSystem()
    system.responders.append(
        lambda argv: (
            ProbeResult(0, "  42     1 Mon Oct  5 18:01:05 2026 claude --x", "")
            if argv[0].endswith("ps")
            else None
        )
    )
    assert all_processes(system) == [ProcessInfo(42, "Mon Oct  5 18:01:05 2026", "claude --x", 1)]


def test_shell_wrapped_mcp_command_with_escaped_space_does_not_crash():
    script = r"/Applications/Hopper\ Disassembler.app/Contents/MacOS/HopperMCPServer"
    direct = "/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer"
    tool = ToolReport(
        name="codex",
        display_name="Codex CLI",
        installed=True,
        extensions=[
            Extension(
                "codex", "mcp", "hopper", "config.toml", shlex.join(["/bin/bash", "-lc", script])
            ),
            Extension("codex", "mcp", "direct", "config.toml", shlex.join([direct])),
            Extension("codex", "mcp", "broken", "config.toml", "/bin/bash -lc 'unterminated"),
        ],
    )
    needles = hostscan._mcp_needles([tool])
    assert needles[direct] == ("hopper", ["Codex CLI"])


def test_long_desktop_mcp_commands_are_cut_with_an_ellipsis(tmp_path: Path):
    config = tmp_path / "Library/Application Support/Claude/claude_desktop_config.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        '{"mcpServers": {"big": {"command": "/opt/server", "args": ["' + "x" * 300 + '"]}}}'
    )
    [fact] = hostscan._desktop_mcp(tmp_path)
    assert fact.detail.startswith("/opt/server x")
    assert fact.detail.endswith("…")
    assert len(fact.detail) == 240


def test_bridges_for_browsers_that_are_not_installed_are_not_concerns(tmp_path: Path):
    hosts = tmp_path / "Library/Application Support/Microsoft Edge/NativeMessagingHosts"
    hosts.mkdir(parents=True)
    (hosts / "com.anthropic.claude_browser_extension.json").write_text(
        '{"name": "com.anthropic.claude_browser_extension", "path": "/bin/sh"}'
    )
    installed = (Path("/Applications") / "Microsoft Edge.app").exists()
    [fact] = hostscan._native_hosts(tmp_path)
    assert fact.concern is installed
    assert ("Edge is not installed" in fact.detail) is not installed


def test_other_tools_note_private_keys_without_a_passphrase(tmp_path: Path):
    ollama = tmp_path / ".ollama"
    ollama.mkdir()
    (ollama / "id_ed25519").write_text(openssh_key(b"none"))
    (ollama / "id_ed25519.pub").write_text("ssh-ed25519 AAAA")
    facts = {f.name: f for f in hostscan.other_tools(tmp_path)}
    assert facts["Ollama"].detail.endswith("; private key without a passphrase: id_ed25519")
