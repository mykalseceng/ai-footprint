"""Claude Desktop: install, MCP servers, credentials, approval modes and remote signals."""

from pathlib import Path

from ai_footprint import checks, extensions
from ai_footprint.checks import local_code, steering, stolen_token
from ai_footprint.harnesses import registry
from ai_footprint.harnesses.claude_desktop import collector as desktop
from ai_footprint.harnesses.common import Context
from ai_footprint.model import HostReport, StoreKind, ToolReport
from tests.conftest import FakeSystem, build_claude_desktop_home, safe_storage

DESKTOP = registry()["claude_desktop"]


def context(home: Path) -> Context:
    return Context(home=home, system=FakeSystem(), now=1_790_000_000, scan=False)


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


def settings(report: ToolReport) -> dict[str, str]:
    return {s.key: s.value for s in report.settings}


def collect(home: Path) -> ToolReport:
    return DESKTOP.collect(context(home))


def test_the_app_bundle_in_user_applications_is_the_binary(tmp_path: Path):
    build_claude_desktop_home(tmp_path)
    found = DESKTOP.detect(context(tmp_path))
    assert found.installed
    [binary] = found.binaries
    assert binary.version == "4.23118.0"
    assert binary.resolved == str(tmp_path / "Applications/Claude.app/Contents/Resources/app.asar")


def test_the_data_folder_alone_marks_it_installed(tmp_path: Path):
    (tmp_path / "Library" / "Logs" / "Claude").mkdir(parents=True)
    assert DESKTOP.detect(context(tmp_path)).installed
    assert not DESKTOP.detect(context(tmp_path / "empty")).installed


def test_mcp_servers_start_at_launch_and_a_missing_target_is_dangling(tmp_path: Path):
    build_claude_desktop_home(tmp_path)
    report = collect(tmp_path)
    servers = {x.name: x for x in report.extensions if x.source == desktop.CONFIG}
    assert set(servers) == {"local-tool", "gone"}
    assert all(s.autostart and s.kind == "mcp" for s in servers.values())
    assert servers["gone"].dangling and not servers["local-tool"].dangling
    [dangling] = local_code.rule_dangling(report, rule_ctx(tmp_path))
    assert "server.js" in dangling.statement
    assert dangling.fix is not None
    assert "mcpServers.gone" in dangling.fix.commands[0].text


def test_servers_an_extension_installed_are_listed_once_as_the_extension(tmp_path: Path):
    support = build_claude_desktop_home(tmp_path)
    config = support / desktop.CONFIG
    config.write_text('{"mcpServers": {"weather": {"command": "x", "extensionId": "ext.weather"}}}')
    report = collect(tmp_path)
    [extension] = [x for x in report.extensions if x.kind == "mcp"]
    install = support / desktop.EXTENSIONS_DIR / "ext.weather"
    assert extension.name == "Weather"
    assert extension.source == "desktop extension ext.weather"
    assert extension.autostart and extension.access == "stdio"
    assert extension.detail == f"node {install}/server/index.js"
    assert extension.description == "Looks up the weather."
    assert not extension.dangling
    (install / "server" / "index.js").unlink()
    assert [x.name for x in collect(tmp_path).extensions if x.dangling] == ["Weather"]


def test_an_extension_mcp_config_resolves_its_folder(tmp_path: Path):
    support = build_claude_desktop_home(tmp_path)
    install = support / desktop.EXTENSIONS_DIR / "ext.weather"
    manifest = install / "manifest.json"
    manifest.write_text(
        '{"name": "weather", "server": {"type": "binary", "mcp_config":'
        ' {"command": "${__dirname}/bin/weather", "args": ["--port", "1"]}}}'
    )
    [row] = [x for x in collect(tmp_path).extensions if x.source.startswith("desktop extension")]
    assert row.detail == f"{install}/bin/weather --port 1"
    assert row.description == extensions.NO_MANIFEST


def test_safestorage_ciphertext_is_an_encrypted_file_not_plaintext(tmp_path: Path):
    build_claude_desktop_home(tmp_path, ssh_hosts=2)
    report = collect(tmp_path)
    creds = {c.provider: c for c in report.credentials}
    account = creds["claude.ai account (OAuth)"]
    assert account.store is StoreKind.ENCRYPTED_FILE
    assert account.tokens == []
    assert "safeStorage" in account.protection
    assert creds["SSH remote controller tokens"].store is StoreKind.ENCRYPTED_FILE
    assert "2 SSH hosts" in creds["SSH remote controller tokens"].protection
    assert creds["desktop extension Weather"].store is StoreKind.ENCRYPTED_FILE
    assert not local_code.rule_plaintext_credentials(report, rule_ctx(tmp_path))


def test_a_token_cache_without_the_safestorage_prefix_is_plaintext(tmp_path: Path):
    build_claude_desktop_home(tmp_path, oauth_cache='{"accessToken": "opaque"}')
    report = collect(tmp_path)
    account = next(c for c in report.credentials if c.provider == "claude.ai account (OAuth)")
    assert account.store is StoreKind.FILE
    assert "not safeStorage ciphertext" in account.protection
    [plain] = local_code.rule_plaintext_credentials(report, rule_ctx(tmp_path))
    assert "claude.ai account" in plain.statement


def test_a_sensitive_extension_value_stored_in_the_clear_is_plaintext(tmp_path: Path):
    support = build_claude_desktop_home(tmp_path)
    settings_file = support / desktop.EXTENSION_SETTINGS_DIR / "ext.weather.json"
    settings_file.write_text('{"isEnabled": false, "userConfig": {"api_key": "sk-live"}}')
    report = collect(tmp_path)
    extension = next(c for c in report.credentials if c.provider == "desktop extension Weather")
    assert extension.store is StoreKind.FILE
    assert "api_key stored as plaintext" in extension.protection
    [row] = [x for x in report.extensions if x.source == "desktop extension ext.weather"]
    assert not row.autostart


def test_ciphertext_is_recognised_raw_or_base64():
    assert desktop.is_ciphertext("v10abc")
    assert desktop.is_ciphertext(safe_storage(b"x"))
    assert not desktop.is_ciphertext("djEw not base64")
    assert not desktop.is_ciphertext('{"token": 1}')


def test_bypass_and_skipped_chrome_approvals_are_an_approval_exposure(tmp_path: Path):
    build_claude_desktop_home(tmp_path)
    report = collect(tmp_path)
    assert settings(report)[desktop.SESSIONS_BYPASS] == "1 of 3 sessions (1 Code)"
    assert settings(report)[desktop.SESSIONS_CHROME_SKIP] == "1 of 3 sessions (1 Code)"
    assert settings(report)[desktop.TASKS_SKIP] == "0 of 1 task"
    [exposure] = steering.rule_no_approval(report, rule_ctx(tmp_path))
    assert desktop.SESSIONS_BYPASS in exposure.statement
    assert exposure.fix is not None
    assert "Allow bypass permissions mode" in exposure.fix.commands[0].text


def test_sessions_that_keep_approvals_raise_nothing(tmp_path: Path):
    build_claude_desktop_home(tmp_path, sessions=(("Code", "default", "ask"), ("Cowork", "", "")))
    report = collect(tmp_path)
    assert not steering.rule_no_approval(report, rule_ctx(tmp_path))


def test_dispatch_code_tasks_in_bypass_turn_approval_off(tmp_path: Path):
    support = build_claude_desktop_home(tmp_path, sessions=())
    (support / desktop.CONFIG).write_text(
        '{"preferences": {"dispatchCodeTasksPermissionMode": "bypassPermissions"}}'
    )
    report = collect(tmp_path)
    [exposure] = steering.rule_no_approval(report, rule_ctx(tmp_path))
    assert "preferences.dispatchCodeTasksPermissionMode = bypassPermissions" in exposure.statement


def test_an_enabled_scheduled_task_runs_unattended(tmp_path: Path):
    build_claude_desktop_home(tmp_path)
    report = collect(tmp_path)
    [task] = [x for x in report.extensions if x.kind == "scheduled-task"]
    assert task.name == "nightly"
    assert task.autostart
    assert task.detail == "cron 0 9 * * *"
    assert report.stats["Code sessions"] == "2"
    assert report.stats["Cowork sessions"] == "1"
    assert report.stats["scheduled tasks"] == "1"


def test_nothing_paired_or_registered_raises_no_account_signal(tmp_path: Path):
    build_claude_desktop_home(tmp_path)
    report = collect(tmp_path)
    assert not stolen_token.rule_remote_control(report, rule_ctx(tmp_path))
    assert any(n.topic == "revoke" and "disableRemoteControl" in n.text for n in report.account)


def test_remote_control_and_ssh_hosts_are_account_signals(tmp_path: Path):
    build_claude_desktop_home(tmp_path, remote=True, ssh_hosts=1)
    report = collect(tmp_path)
    [signal] = stolen_token.rule_remote_control(report, rule_ctx(tmp_path))
    assert "Remote Control has 1 folder registered" in signal.statement
    assert "Connect new sessions to Remote Control is on" in signal.statement
    assert "1 SSH remote machine" in signal.statement


def test_a_session_steered_from_another_device_is_a_signal(tmp_path: Path):
    support = build_claude_desktop_home(tmp_path, sessions=())
    record = support / "claude-code-sessions" / "acct" / "org" / "local_9.json"
    record.write_text('{"permissionMode": "default", "steeredByRemoteClient": true}')
    [signal] = stolen_token.rule_remote_control(collect(tmp_path), rule_ctx(tmp_path))
    assert "1 session (1 Code) took input from a Remote Control client" in signal.statement


def test_malformed_files_yield_no_rows(tmp_path: Path):
    support = tmp_path / "Library" / "Application Support" / "Claude"
    (support / "claude-code-sessions" / "a" / "o").mkdir(parents=True)
    for name in ("config.json", desktop.CONFIG, desktop.SSH_STATE, desktop.REMOTE_STATE):
        (support / name).write_text("[not json")
    (support / "claude-code-sessions" / "a" / "o" / "local_1.json").write_text("[1, 2]")
    report = collect(tmp_path)
    assert report.installed
    assert report.credentials == []
    assert [x for x in report.extensions if x.kind == "mcp"] == []
    assert settings(report)[desktop.SESSIONS_BYPASS] == "0 of 1 session"
